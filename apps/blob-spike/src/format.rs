// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements the diagnostic candidate blob format.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const FORMAT_VERSION: u8 = 1;
pub(crate) const CHUNK_SIZE: usize = 64 * 1024;
pub(crate) const MAX_TOTAL_LENGTH: u64 = 4 * 1024 * 1024;
pub(crate) const HEADER_LENGTH: usize = 21;
pub(crate) const NONCE_LENGTH: usize = 24;
pub(crate) const TAG_LENGTH: usize = 16;
pub(crate) const CONTENT_ID_LENGTH: usize = 32;
const MAGIC: [u8; 8] = *b"TRSABLOB";
const CONTENT_ID_DOMAIN: &[u8] = b"tersa-blob-content-id-v1";
const STAGING_PREFIX: &str = "pending.staging-";
const STAGING_RANDOM_LENGTH: usize = 12;

type HmacSha256 = Hmac<Sha256>;
type Result<T> = std::result::Result<T, FormatError>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AccountContext(pub(crate) [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct BlobId(pub(crate) [u8; 16]);

#[derive(Clone)]
pub(crate) struct BlobKeys {
    aead: Zeroizing<[u8; 32]>,
    content_id: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for BlobKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlobKeys([REDACTED])")
    }
}

impl BlobKeys {
    pub(crate) fn new(aead: Zeroizing<[u8; 32]>, content_id: Zeroizing<[u8; 32]>) -> Self {
        Self { aead, content_id }
    }
}

#[derive(Debug, Default)]
pub(crate) struct NonceRegistry {
    values: BTreeSet<[u8; NONCE_LENGTH]>,
}

impl NonceRegistry {
    pub(crate) fn count(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn observe(&mut self, nonce: [u8; NONCE_LENGTH]) -> Result<()> {
        if !self.values.insert(nonce) {
            return Err(FormatError("nonce-collision"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedBlob {
    pub(crate) account: AccountContext,
    pub(crate) blob_id: BlobId,
}

#[derive(Debug)]
pub(crate) struct WriteOutcome {
    pub(crate) path: PathBuf,
    pub(crate) content_id: [u8; CONTENT_ID_LENGTH],
    pub(crate) reused_existing_binding: bool,
    pub(crate) chunk_count: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReadMetrics {
    pub(crate) decrypted_chunks: u32,
}

pub(crate) struct BlobReader {
    file: File,
    cipher: XChaCha20Poly1305,
    expected: ExpectedBlob,
    header: Header,
}

impl BlobReader {
    pub(crate) fn open(path: &Path, keys: &BlobKeys, expected: ExpectedBlob) -> Result<Self> {
        validate_published_name(path)?;
        let (file, _identity) = open_regular_nofollow(path)?;
        Self::from_file(file, keys, expected)
    }

    fn from_file(mut file: File, keys: &BlobKeys, expected: ExpectedBlob) -> Result<Self> {
        let header = Header::read(&mut file)?;
        header.validate()?;
        let actual_size = file
            .metadata()
            .map_err(|_error| FormatError("metadata"))?
            .len();
        if actual_size != header.canonical_file_size()? {
            return Err(FormatError("size"));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(keys.aead.as_ref())
            .map_err(|_error| FormatError("key"))?;
        Ok(Self {
            file,
            cipher,
            expected,
            header,
        })
    }

    pub(crate) fn total_length(&self) -> u64 {
        self.header.total_length
    }

    pub(crate) fn read_all(&mut self) -> Result<(Vec<u8>, ReadMetrics)> {
        if self.header.total_length == 0 {
            self.decrypt_chunk(0)?;
            return Ok((
                Vec::new(),
                ReadMetrics {
                    decrypted_chunks: 1,
                },
            ));
        }
        let length =
            usize::try_from(self.header.total_length).map_err(|_error| FormatError("length"))?;
        self.read_range(0, length)
    }

    pub(crate) fn read_range(
        &mut self,
        start: u64,
        length: usize,
    ) -> Result<(Vec<u8>, ReadMetrics)> {
        let length_u64 = u64::try_from(length).map_err(|_error| FormatError("range"))?;
        let end = start.checked_add(length_u64).ok_or(FormatError("range"))?;
        if end > self.header.total_length {
            return Err(FormatError("range"));
        }
        if length == 0 {
            return Ok((Vec::new(), ReadMetrics::default()));
        }
        let first = start / u64::try_from(CHUNK_SIZE).map_err(|_error| FormatError("chunk"))?;
        let last = (end - 1) / u64::try_from(CHUNK_SIZE).map_err(|_error| FormatError("chunk"))?;
        let mut output = Vec::with_capacity(length);
        let mut metrics = ReadMetrics::default();
        for index in first..=last {
            let index_u32 = u32::try_from(index).map_err(|_error| FormatError("index"))?;
            let plaintext = self.decrypt_chunk(index_u32)?;
            metrics.decrypted_chunks = metrics
                .decrypted_chunks
                .checked_add(1)
                .ok_or(FormatError("metrics"))?;
            let chunk_start = index
                .checked_mul(u64::try_from(CHUNK_SIZE).map_err(|_error| FormatError("chunk"))?)
                .ok_or(FormatError("range"))?;
            let copy_start = usize::try_from(start.saturating_sub(chunk_start))
                .map_err(|_error| FormatError("range"))?;
            let copy_end_u64 = end.min(
                chunk_start
                    .checked_add(
                        u64::try_from(plaintext.len()).map_err(|_error| FormatError("range"))?,
                    )
                    .ok_or(FormatError("range"))?,
            );
            let copy_end = usize::try_from(copy_end_u64 - chunk_start)
                .map_err(|_error| FormatError("range"))?;
            output.extend_from_slice(&plaintext[copy_start..copy_end]);
        }
        if output.len() != length {
            return Err(FormatError("range"));
        }
        Ok((output, metrics))
    }

    fn verify_content_identifier(
        &mut self,
        keys: &BlobKeys,
        expected_content_id: &[u8; CONTENT_ID_LENGTH],
    ) -> Result<()> {
        let mut content_hmac = new_content_hmac(keys, self.expected.account)?;
        for index in 0..self.header.chunk_count {
            let plaintext = Zeroizing::new(self.decrypt_chunk(index)?);
            content_hmac.update(&plaintext);
        }
        let content_id: [u8; CONTENT_ID_LENGTH] = content_hmac.finalize().into_bytes().into();
        if !content_ids_equal(&content_id, expected_content_id) {
            return Err(FormatError("reuse-content"));
        }
        Ok(())
    }

    fn decrypt_chunk(&mut self, index: u32) -> Result<Vec<u8>> {
        if index >= self.header.chunk_count {
            return Err(FormatError("index"));
        }
        let plaintext_length = self.header.chunk_plaintext_length(index)?;
        self.file
            .seek(SeekFrom::Start(self.header.chunk_offset(index)?))
            .map_err(|_error| FormatError("seek"))?;
        let mut nonce = [0_u8; NONCE_LENGTH];
        self.file
            .read_exact(&mut nonce)
            .map_err(|_error| FormatError("nonce"))?;
        let encrypted_length = plaintext_length
            .checked_add(TAG_LENGTH)
            .ok_or(FormatError("length"))?;
        let mut encrypted = vec![0_u8; encrypted_length];
        self.file
            .read_exact(&mut encrypted)
            .map_err(|_error| FormatError("ciphertext"))?;
        let aad = chunk_aad(
            self.expected,
            index,
            u32::try_from(plaintext_length).map_err(|_error| FormatError("length"))?,
            self.header,
        );
        self.cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &encrypted,
                    aad: &aad,
                },
            )
            .map_err(|_error| FormatError("authentication"))
    }
}

pub(crate) fn write_blob<R, F>(
    directory: &Path,
    reader: &mut R,
    total_length: u64,
    keys: &BlobKeys,
    expected: ExpectedBlob,
    nonces: &mut NonceRegistry,
    after_chunk: F,
) -> Result<WriteOutcome>
where
    R: Read,
    F: FnMut(u32, &File, &Path) -> Result<()>,
{
    write_blob_with_hooks(
        directory,
        reader,
        total_length,
        keys,
        expected,
        nonces,
        WriteHooks {
            after_chunk,
            after_reuse_lstat: no_op_reuse_lstat,
        },
    )
}

fn no_op_reuse_lstat(_path: &Path) {}

struct WriteHooks<F, H> {
    after_chunk: F,
    after_reuse_lstat: H,
}

fn write_blob_with_hooks<R, F, H>(
    directory: &Path,
    reader: &mut R,
    total_length: u64,
    keys: &BlobKeys,
    expected: ExpectedBlob,
    nonces: &mut NonceRegistry,
    mut hooks: WriteHooks<F, H>,
) -> Result<WriteOutcome>
where
    R: Read,
    F: FnMut(u32, &File, &Path) -> Result<()>,
    H: FnOnce(&Path),
{
    let header = Header::for_length(total_length)?;
    fs::create_dir_all(directory).map_err(|_error| FormatError("directory"))?;
    let staging_path = staging_path(directory)?;
    let mut staging = StagingGuard::create(staging_path)?;
    header.write(staging.file_mut())?;
    let cipher = XChaCha20Poly1305::new_from_slice(keys.aead.as_ref())
        .map_err(|_error| FormatError("key"))?;
    let mut content_hmac = new_content_hmac(keys, expected.account)?;
    let mut remaining = total_length;
    let mut chunk_buffer = Zeroizing::new(vec![0_u8; CHUNK_SIZE]);
    for index in 0..header.chunk_count {
        let plaintext_length = header.chunk_plaintext_length(index)?;
        if plaintext_length > 0 {
            reader
                .read_exact(&mut chunk_buffer[..plaintext_length])
                .map_err(|_error| FormatError("input"))?;
            content_hmac.update(&chunk_buffer[..plaintext_length]);
        }
        remaining = remaining
            .checked_sub(u64::try_from(plaintext_length).map_err(|_error| FormatError("length"))?)
            .ok_or(FormatError("length"))?;
        let nonce = unique_nonce(nonces)?;
        let aad = chunk_aad(
            expected,
            index,
            u32::try_from(plaintext_length).map_err(|_error| FormatError("length"))?,
            header,
        );
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &chunk_buffer[..plaintext_length],
                    aad: &aad,
                },
            )
            .map_err(|_error| FormatError("encryption"))?;
        staging
            .file_mut()
            .write_all(&nonce)
            .and_then(|()| staging.file_mut().write_all(&encrypted))
            .map_err(|_error| FormatError("write"))?;
        (hooks.after_chunk)(index, staging.file(), staging.path())?;
    }
    if remaining != 0 {
        return Err(FormatError("length"));
    }
    let mut extra = [0_u8; 1];
    if reader
        .read(&mut extra)
        .map_err(|_error| FormatError("input"))?
        != 0
    {
        return Err(FormatError("input"));
    }
    staging
        .file()
        .sync_all()
        .map_err(|_error| FormatError("sync"))?;
    let content_id: [u8; CONTENT_ID_LENGTH] = content_hmac.finalize().into_bytes().into();
    let final_path = directory.join(lower_hex(&content_id));
    let reused_existing_binding = match staging.link_final(&final_path) {
        Ok(()) => {
            staging.discard()?;
            sync_directory(directory)?;
            false
        }
        Err(link_error) if link_error.kind() == ErrorKind::AlreadyExists => {
            if let Err(validation_error) = validate_existing_final_with_hook(
                &final_path,
                keys,
                expected,
                total_length,
                &content_id,
                hooks.after_reuse_lstat,
            ) {
                staging.discard()?;
                sync_directory(directory)?;
                return Err(validation_error);
            }
            staging.discard()?;
            sync_directory(directory)?;
            true
        }
        Err(_link_error) => {
            staging.discard()?;
            sync_directory(directory)?;
            return Err(FormatError("publish-link"));
        }
    };
    Ok(WriteOutcome {
        path: final_path,
        content_id,
        reused_existing_binding,
        chunk_count: header.chunk_count,
    })
}

fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_error| FormatError("directory-sync"))
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn validate_existing_final_with_hook<H>(
    path: &Path,
    keys: &BlobKeys,
    expected: ExpectedBlob,
    total_length: u64,
    candidate_content_id: &[u8; CONTENT_ID_LENGTH],
    after_lstat: H,
) -> Result<()>
where
    H: FnOnce(&Path),
{
    use rustix::fs::{AtFlags, CWD, FileType, statat};

    validate_published_name(path)?;
    let before = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_error| FormatError("reuse-lstat"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
        return Err(FormatError("reuse-file-type"));
    }
    after_lstat(path);
    let (file, opened) = open_regular_nofollow(path)?;
    if opened.st_dev != before.st_dev || opened.st_ino != before.st_ino {
        return Err(FormatError("reuse-identity"));
    }
    let mut existing = BlobReader::from_file(file, keys, expected)?;
    if existing.total_length() != total_length {
        return Err(FormatError("reuse-length"));
    }
    existing.verify_content_identifier(keys, candidate_content_id)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn validate_existing_final_with_hook<H>(
    path: &Path,
    keys: &BlobKeys,
    expected: ExpectedBlob,
    total_length: u64,
    candidate_content_id: &[u8; CONTENT_ID_LENGTH],
    after_lstat: H,
) -> Result<()>
where
    H: FnOnce(&Path),
{
    let _ = (
        path,
        keys,
        expected,
        total_length,
        candidate_content_id,
        after_lstat,
    );
    Err(FormatError("reuse-platform"))
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn open_regular_nofollow(path: &Path) -> Result<(File, rustix::fs::Stat)> {
    use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};

    let descriptor = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_error| FormatError("nofollow-open"))?;
    let metadata = fstat(&descriptor).map_err(|_error| FormatError("nofollow-fstat"))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(FormatError("nofollow-file-type"));
    }
    Ok((File::from(descriptor), metadata))
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn open_regular_nofollow(_path: &Path) -> Result<(File, ())> {
    Err(FormatError("nofollow-platform"))
}

fn new_content_hmac(keys: &BlobKeys, account: AccountContext) -> Result<HmacSha256> {
    let mut content_hmac = <HmacSha256 as Mac>::new_from_slice(keys.content_id.as_ref())
        .map_err(|_error| FormatError("hmac"))?;
    content_hmac.update(CONTENT_ID_DOMAIN);
    content_hmac.update(&account.0);
    Ok(content_hmac)
}

pub(crate) fn content_identifier(
    keys: &BlobKeys,
    account: AccountContext,
    plaintext: &[u8],
) -> Result<[u8; CONTENT_ID_LENGTH]> {
    let mut content_hmac = new_content_hmac(keys, account)?;
    content_hmac.update(plaintext);
    Ok(content_hmac.finalize().into_bytes().into())
}

pub(crate) fn cleanup_staging(directory: &Path) -> Result<usize> {
    let mut removed = 0_usize;
    for entry in fs::read_dir(directory).map_err(|_error| FormatError("directory"))? {
        let entry = entry.map_err(|_error| FormatError("directory"))?;
        if entry
            .file_type()
            .map_err(|_error| FormatError("directory"))?
            .is_file()
            && is_reserved_staging_name(&entry.file_name().to_string_lossy())
        {
            fs::remove_file(entry.path()).map_err(|_error| FormatError("cleanup"))?;
            removed = removed.checked_add(1).ok_or(FormatError("cleanup"))?;
        }
    }
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_error| FormatError("directory-sync"))?;
    Ok(removed)
}

pub(crate) fn content_ids_equal(
    left: &[u8; CONTENT_ID_LENGTH],
    right: &[u8; CONTENT_ID_LENGTH],
) -> bool {
    bool::from(left.ct_eq(right))
}

pub(crate) fn is_reserved_staging_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(STAGING_PREFIX) else {
        return false;
    };
    suffix.len() == STAGING_RANDOM_LENGTH * 2
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Header {
    total_length: u64,
    chunk_count: u32,
}

impl Header {
    fn for_length(total_length: u64) -> Result<Self> {
        if total_length > MAX_TOTAL_LENGTH {
            return Err(FormatError("bound"));
        }
        let chunk_size = u64::try_from(CHUNK_SIZE).map_err(|_error| FormatError("chunk"))?;
        let chunk_count = if total_length == 0 {
            1
        } else {
            u32::try_from(total_length.div_ceil(chunk_size))
                .map_err(|_error| FormatError("count"))?
        };
        Ok(Self {
            total_length,
            chunk_count,
        })
    }

    fn validate(self) -> Result<()> {
        if Self::for_length(self.total_length)? != self {
            return Err(FormatError("canonical"));
        }
        Ok(())
    }

    fn write(self, file: &mut File) -> Result<()> {
        file.write_all(&MAGIC)
            .and_then(|()| file.write_all(&[FORMAT_VERSION]))
            .and_then(|()| file.write_all(&self.total_length.to_le_bytes()))
            .and_then(|()| file.write_all(&self.chunk_count.to_le_bytes()))
            .map_err(|_error| FormatError("header"))
    }

    fn read(file: &mut File) -> Result<Self> {
        let mut bytes = [0_u8; HEADER_LENGTH];
        file.read_exact(&mut bytes)
            .map_err(|_error| FormatError("header"))?;
        if bytes[..MAGIC.len()] != MAGIC || bytes[MAGIC.len()] != FORMAT_VERSION {
            return Err(FormatError("header"));
        }
        let total_start = MAGIC.len() + 1;
        let count_start = total_start + 8;
        let total_length = u64::from_le_bytes(
            bytes[total_start..count_start]
                .try_into()
                .map_err(|_error| FormatError("header"))?,
        );
        let chunk_count = u32::from_le_bytes(
            bytes[count_start..]
                .try_into()
                .map_err(|_error| FormatError("header"))?,
        );
        Ok(Self {
            total_length,
            chunk_count,
        })
    }

    fn chunk_plaintext_length(self, index: u32) -> Result<usize> {
        if index >= self.chunk_count {
            return Err(FormatError("index"));
        }
        if self.total_length == 0 {
            return Ok(0);
        }
        if index + 1 < self.chunk_count {
            return Ok(CHUNK_SIZE);
        }
        let preceding = u64::from(index)
            .checked_mul(u64::try_from(CHUNK_SIZE).map_err(|_error| FormatError("chunk"))?)
            .ok_or(FormatError("length"))?;
        let last = self
            .total_length
            .checked_sub(preceding)
            .ok_or(FormatError("length"))?;
        let last = usize::try_from(last).map_err(|_error| FormatError("length"))?;
        if !(1..=CHUNK_SIZE).contains(&last) {
            return Err(FormatError("canonical"));
        }
        Ok(last)
    }

    fn chunk_offset(self, index: u32) -> Result<u64> {
        if index >= self.chunk_count {
            return Err(FormatError("index"));
        }
        let full_record = CHUNK_SIZE
            .checked_add(NONCE_LENGTH)
            .and_then(|value| value.checked_add(TAG_LENGTH))
            .ok_or(FormatError("size"))?;
        u64::try_from(HEADER_LENGTH)
            .map_err(|_error| FormatError("size"))?
            .checked_add(
                u64::from(index)
                    .checked_mul(u64::try_from(full_record).map_err(|_error| FormatError("size"))?)
                    .ok_or(FormatError("size"))?,
            )
            .ok_or(FormatError("size"))
    }

    fn canonical_file_size(self) -> Result<u64> {
        self.validate()?;
        let record_overhead = NONCE_LENGTH
            .checked_add(TAG_LENGTH)
            .ok_or(FormatError("size"))?;
        let overhead = u64::from(self.chunk_count)
            .checked_mul(u64::try_from(record_overhead).map_err(|_error| FormatError("size"))?)
            .ok_or(FormatError("size"))?;
        u64::try_from(HEADER_LENGTH)
            .map_err(|_error| FormatError("size"))?
            .checked_add(self.total_length)
            .and_then(|value| value.checked_add(overhead))
            .ok_or(FormatError("size"))
    }
}

fn chunk_aad(expected: ExpectedBlob, index: u32, plaintext_length: u32, header: Header) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 16 + 16 + 4 + 4 + 8 + 4);
    aad.push(FORMAT_VERSION);
    aad.extend_from_slice(&expected.account.0);
    aad.extend_from_slice(&expected.blob_id.0);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&plaintext_length.to_le_bytes());
    aad.extend_from_slice(&header.total_length.to_le_bytes());
    aad.extend_from_slice(&header.chunk_count.to_le_bytes());
    aad
}

fn unique_nonce(registry: &mut NonceRegistry) -> Result<[u8; NONCE_LENGTH]> {
    let mut nonce = [0_u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_error| FormatError("random"))?;
    registry.observe(nonce)?;
    Ok(nonce)
}

fn staging_path(directory: &Path) -> Result<PathBuf> {
    let mut random = [0_u8; STAGING_RANDOM_LENGTH];
    getrandom::fill(&mut random).map_err(|_error| FormatError("random"))?;
    Ok(directory.join(format!("{STAGING_PREFIX}{}", lower_hex(&random))))
}

fn validate_published_name(path: &Path) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(FormatError("filename"))?;
    if name.len() != CONTENT_ID_LENGTH * 2
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FormatError("filename"));
    }
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FormatError(pub(crate) &'static str);

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("blob format operation failed")
    }
}

impl Error for FormatError {}

#[derive(Debug)]
struct StagingGuard {
    file: File,
    path: PathBuf,
    published: bool,
}

impl StagingGuard {
    fn create(path: PathBuf) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_error| FormatError("staging"))?;
        Ok(Self {
            file,
            path,
            published: false,
        })
    }

    fn file(&self) -> &File {
        &self.file
    }

    fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn link_final(&self, final_path: &Path) -> std::io::Result<()> {
        fs::hard_link(&self.path, final_path)
    }

    fn discard(mut self) -> Result<()> {
        fs::remove_file(&self.path).map_err(|_error| FormatError("staging-discard"))?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
            if let Some(directory) = self.path.parent() {
                let _ = File::open(directory).and_then(|file| file.sync_all());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::sync::mpsc;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::time::Duration;

    use zeroize::Zeroizing;

    use super::{
        AccountContext, BlobId, BlobKeys, BlobReader, CHUNK_SIZE, CONTENT_ID_LENGTH, ExpectedBlob,
        FormatError, HEADER_LENGTH, NONCE_LENGTH, NonceRegistry, StagingGuard, WriteHooks,
        content_identifier, is_reserved_staging_name, lower_hex, write_blob, write_blob_with_hooks,
    };

    fn fixture() -> (BlobKeys, ExpectedBlob) {
        (
            BlobKeys::new(Zeroizing::new([7; 32]), Zeroizing::new([9; 32])),
            ExpectedBlob {
                account: AccountContext([3; 16]),
                blob_id: BlobId([5; 16]),
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn create_fifo(path: &std::path::Path) {
        use rustix::fs::{CWD, Mode, mkfifoat};

        mkfifoat(CWD, path, Mode::RUSR | Mode::WUSR).expect("test FIFO must be created");
    }

    #[cfg(target_os = "macos")]
    fn create_fifo(path: &std::path::Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("macOS mkfifo must start");
        assert!(status.success(), "macOS mkfifo must create the test FIFO");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn run_promptly<T, F>(operation: F) -> T
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = operation();
            let _ = sender.send(result);
        });
        receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("FIFO operation must reject promptly without a writer")
    }

    #[test]
    fn blob_keys_debug_is_always_redacted() {
        let keys = BlobKeys::new(Zeroizing::new([7; 32]), Zeroizing::new([9; 32]));
        let rendered = format!("{keys:?}");

        assert_eq!(rendered, "BlobKeys([REDACTED])");
        assert!(!rendered.contains("7, 7"));
        assert!(!rendered.contains("9, 9"));
    }

    #[test]
    fn empty_blob_has_one_authenticated_chunk() {
        let directory = std::env::temp_dir().join("tersa-blob-empty-test");
        let _ = std::fs::remove_dir_all(&directory);
        let (keys, expected) = fixture();
        let mut input = Cursor::new(Vec::<u8>::new());
        let outcome = write_blob(
            &directory,
            &mut input,
            0,
            &keys,
            expected,
            &mut NonceRegistry::default(),
            |_index, _file, _path| Ok(()),
        )
        .expect("empty blob must write");
        assert_eq!(outcome.chunk_count, 1);
        let (plaintext, metrics) = BlobReader::open(&outcome.path, &keys, expected)
            .and_then(|mut reader| reader.read_all())
            .expect("empty blob must authenticate");
        assert!(plaintext.is_empty());
        assert_eq!(metrics.decrypted_chunks, 1);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn boundary_range_decrypts_only_intersecting_chunks() {
        let directory = std::env::temp_dir().join("tersa-blob-range-test");
        let _ = std::fs::remove_dir_all(&directory);
        let (keys, expected) = fixture();
        let plaintext = vec![11_u8; CHUNK_SIZE + 1];
        let mut input = Cursor::new(&plaintext);
        let outcome = write_blob(
            &directory,
            &mut input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            expected,
            &mut NonceRegistry::default(),
            |_index, _file, _path| Ok(()),
        )
        .expect("boundary blob must write");
        let mut reader = BlobReader::open(&outcome.path, &keys, expected).expect("blob must open");
        let (range, metrics) = reader
            .read_range(u64::try_from(CHUNK_SIZE - 2).expect("offset must fit"), 3)
            .expect("range must decrypt");
        assert_eq!(range, plaintext[(CHUNK_SIZE - 2)..=CHUNK_SIZE]);
        assert_eq!(metrics.decrypted_chunks, 2);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn same_content_with_a_different_blob_id_is_not_reused() {
        let directory = std::env::temp_dir().join("tersa-blob-binding-test");
        let _ = std::fs::remove_dir_all(&directory);
        let (keys, expected) = fixture();
        let plaintext = vec![17_u8; CHUNK_SIZE + 3];
        let mut original_input = Cursor::new(&plaintext);
        let original = write_blob(
            &directory,
            &mut original_input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            expected,
            &mut NonceRegistry::default(),
            |_index, _file, _path| Ok(()),
        )
        .expect("original blob must write");
        let original_bytes = std::fs::read(&original.path).expect("original blob must read");
        let different_binding = ExpectedBlob {
            blob_id: BlobId([6; 16]),
            ..expected
        };
        let mut replacement_input = Cursor::new(&plaintext);
        let replacement = write_blob(
            &directory,
            &mut replacement_input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            different_binding,
            &mut NonceRegistry::default(),
            |_index, _file, _path| Ok(()),
        );
        assert!(replacement.is_err());
        assert_eq!(
            std::fs::read(&original.path).expect("original blob must remain"),
            original_bytes
        );
        assert_no_staging(&directory);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn corrupt_existing_final_is_rejected_without_replacement() {
        let directory = std::env::temp_dir().join("tersa-blob-corrupt-final-test");
        let _ = std::fs::remove_dir_all(&directory);
        let (keys, expected) = fixture();
        let plaintext = vec![23_u8; CHUNK_SIZE + 5];
        let mut original_input = Cursor::new(&plaintext);
        let original = write_blob(
            &directory,
            &mut original_input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            expected,
            &mut NonceRegistry::default(),
            |_index, _file, _path| Ok(()),
        )
        .expect("original blob must write");
        let mut corrupted = std::fs::read(&original.path).expect("original blob must read");
        corrupted[HEADER_LENGTH + NONCE_LENGTH] ^= 1;
        std::fs::write(&original.path, &corrupted).expect("corruption must be written");
        let mut replacement_input = Cursor::new(&plaintext);
        let replacement = write_blob(
            &directory,
            &mut replacement_input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            expected,
            &mut NonceRegistry::default(),
            |_index, _file, _path| Ok(()),
        );
        assert!(replacement.is_err());
        assert_eq!(
            std::fs::read(&original.path).expect("corrupt final must remain"),
            corrupted
        );
        assert_no_staging(&directory);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn final_created_after_staging_is_never_replaced() {
        let directory = std::env::temp_dir().join("tersa-blob-publish-conflict-test");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("test directory must exist");
        let (keys, expected) = fixture();
        let plaintext = vec![29_u8; CHUNK_SIZE + 7];
        let content_id = content_identifier(&keys, expected.account, &plaintext)
            .expect("content identifier must compute");
        let final_path = directory.join(lower_hex(&content_id));
        let conflict = vec![31_u8; 113];
        let mut input = Cursor::new(&plaintext);
        let mut conflict_created = false;
        let result = write_blob(
            &directory,
            &mut input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            expected,
            &mut NonceRegistry::default(),
            |index, _file, _staging_path| {
                if index == 0 && !conflict_created {
                    std::fs::write(&final_path, &conflict)
                        .map_err(|_error| FormatError("test-conflict"))?;
                    conflict_created = true;
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(conflict_created);
        assert_eq!(
            std::fs::read(&final_path).expect("conflict final must remain"),
            conflict
        );
        assert_no_staging(&directory);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_final_created_after_staging_is_rejected_without_following() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join("tersa-blob-symlink-conflict-test");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("test directory must exist");
        let (keys, expected) = fixture();
        let plaintext = vec![37_u8; CHUNK_SIZE + 9];
        let content_id = content_identifier(&keys, expected.account, &plaintext)
            .expect("content identifier must compute");
        let final_path = directory.join(lower_hex(&content_id));
        let target_path = directory.join("symlink-target");
        let target_bytes = b"symlink-target-control";
        std::fs::write(&target_path, target_bytes).expect("symlink target must write");
        let mut input = Cursor::new(&plaintext);
        let mut conflict_created = false;
        let result = write_blob(
            &directory,
            &mut input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            expected,
            &mut NonceRegistry::default(),
            |index, _file, _staging_path| {
                if index == 0 && !conflict_created {
                    symlink(&target_path, &final_path)
                        .map_err(|_error| FormatError("test-symlink-conflict"))?;
                    conflict_created = true;
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(conflict_created);
        assert!(
            std::fs::symlink_metadata(&final_path)
                .expect("symlink conflict must remain")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read(&target_path).expect("symlink target must remain"),
            target_bytes
        );
        assert_no_staging(&directory);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_read_rejects_canonical_symlink_without_following() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join("tersa-blob-read-symlink-test");
        let target_directory = std::env::temp_dir().join("tersa-blob-read-symlink-target-test");
        let _ = std::fs::remove_dir_all(&directory);
        let _ = std::fs::remove_dir_all(&target_directory);
        std::fs::create_dir_all(&directory).expect("test directory must exist");
        let (keys, expected) = fixture();
        let plaintext = vec![39_u8; CHUNK_SIZE + 10];
        let mut target_input = Cursor::new(&plaintext);
        let target = write_blob(
            &target_directory,
            &mut target_input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            expected,
            &mut NonceRegistry::default(),
            |_index, _file, _staging_path| Ok(()),
        )
        .expect("control target must be a valid authenticated blob");
        let target_bytes = std::fs::read(&target.path).expect("control target must read");
        let symlink_path = directory.join(
            target
                .path
                .file_name()
                .expect("control target must have a canonical name"),
        );
        symlink(&target.path, &symlink_path).expect("canonical symlink must be created");

        assert!(BlobReader::open(&symlink_path, &keys, expected).is_err());
        assert_eq!(
            std::fs::read(&target.path).expect("control target must remain"),
            target_bytes
        );
        let _ = std::fs::remove_dir_all(directory);
        let _ = std::fs::remove_dir_all(target_directory);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn ordinary_read_rejects_canonical_fifo_promptly() {
        use std::os::unix::fs::FileTypeExt;

        let directory = std::env::temp_dir().join("tersa-blob-read-fifo-test");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("test directory must exist");
        let fifo_path = directory.join("b".repeat(CONTENT_ID_LENGTH * 2));
        create_fifo(&fifo_path);
        assert!(
            std::fs::symlink_metadata(&fifo_path)
                .expect("test FIFO must exist")
                .file_type()
                .is_fifo()
        );
        let (keys, expected) = fixture();
        let read_path = fifo_path.clone();

        let rejected = run_promptly(move || BlobReader::open(&read_path, &keys, expected).is_err());

        assert!(rejected);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn final_swapped_to_symlink_after_lstat_is_rejected_without_following() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join("tersa-blob-lstat-swap-test");
        let target_directory = std::env::temp_dir().join("tersa-blob-lstat-swap-target-test");
        let _ = std::fs::remove_dir_all(&directory);
        let _ = std::fs::remove_dir_all(&target_directory);
        std::fs::create_dir_all(&directory).expect("test directory must exist");
        let (keys, expected) = fixture();
        let plaintext = vec![41_u8; CHUNK_SIZE + 11];

        let mut target_input = Cursor::new(&plaintext);
        let target = write_blob(
            &target_directory,
            &mut target_input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            expected,
            &mut NonceRegistry::default(),
            |_index, _file, _staging_path| Ok(()),
        )
        .expect("control target must be a valid authenticated blob");
        let target_bytes = std::fs::read(&target.path).expect("control target must read");

        let content_id = content_identifier(&keys, expected.account, &plaintext)
            .expect("content identifier must compute");
        let final_path = directory.join(lower_hex(&content_id));
        let swap_path = directory.join("atomic-symlink-swap");
        let mut input = Cursor::new(&plaintext);
        let mut conflict_created = false;
        let mut swap_performed = false;
        let result = write_blob_with_hooks(
            &directory,
            &mut input,
            u64::try_from(plaintext.len()).expect("fixture length must fit"),
            &keys,
            expected,
            &mut NonceRegistry::default(),
            WriteHooks {
                after_chunk: |index, _file: &std::fs::File, _staging_path: &std::path::Path| {
                    if index == 0 && !conflict_created {
                        std::fs::write(&final_path, b"regular-file-before-lstat")
                            .map_err(|_error| FormatError("test-regular-conflict"))?;
                        conflict_created = true;
                    }
                    Ok(())
                },
                after_reuse_lstat: |path: &std::path::Path| {
                    symlink(&target.path, &swap_path).expect("atomic swap symlink must be created");
                    std::fs::rename(&swap_path, path)
                        .expect("atomic symlink swap must replace the regular final");
                    swap_performed = true;
                },
            },
        );

        assert!(result.is_err());
        assert!(conflict_created);
        assert!(swap_performed);
        assert!(
            std::fs::symlink_metadata(&final_path)
                .expect("swapped symlink must remain")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read(&target.path).expect("control target must remain"),
            target_bytes
        );
        assert_no_staging(&directory);
        let _ = std::fs::remove_dir_all(directory);
        let _ = std::fs::remove_dir_all(target_directory);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn final_swapped_to_fifo_after_lstat_is_rejected_promptly() {
        use std::os::unix::fs::FileTypeExt;

        let directory = std::env::temp_dir().join("tersa-blob-lstat-fifo-swap-test");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("test directory must exist");
        let (keys, expected) = fixture();
        let plaintext = vec![43_u8; CHUNK_SIZE + 13];
        let content_id = content_identifier(&keys, expected.account, &plaintext)
            .expect("content identifier must compute");
        let final_path = directory.join(lower_hex(&content_id));
        let fifo_swap_path = directory.join("atomic-fifo-swap");
        create_fifo(&fifo_swap_path);
        let worker_directory = directory.clone();
        let worker_final_path = final_path.clone();

        let (rejected, conflict_created, swap_performed) = run_promptly(move || {
            let mut input = Cursor::new(&plaintext);
            let mut conflict_created = false;
            let mut swap_performed = false;
            let result = write_blob_with_hooks(
                &worker_directory,
                &mut input,
                u64::try_from(plaintext.len()).expect("fixture length must fit"),
                &keys,
                expected,
                &mut NonceRegistry::default(),
                WriteHooks {
                    after_chunk: |index, _file: &std::fs::File, _staging_path: &std::path::Path| {
                        if index == 0 && !conflict_created {
                            std::fs::write(&worker_final_path, b"regular-file-before-lstat")
                                .map_err(|_error| FormatError("test-regular-conflict"))?;
                            conflict_created = true;
                        }
                        Ok(())
                    },
                    after_reuse_lstat: |path: &std::path::Path| {
                        std::fs::rename(&fifo_swap_path, path)
                            .expect("atomic FIFO swap must replace the regular final");
                        swap_performed = true;
                    },
                },
            );
            (result.is_err(), conflict_created, swap_performed)
        });

        assert!(rejected);
        assert!(conflict_created);
        assert!(swap_performed);
        assert!(
            std::fs::symlink_metadata(&final_path)
                .expect("swapped FIFO must remain")
                .file_type()
                .is_fifo()
        );
        assert_no_staging(&directory);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn removing_staging_link_preserves_the_published_hard_link() {
        use std::os::unix::fs::MetadataExt;

        let directory = std::env::temp_dir().join("tersa-blob-hard-link-cleanup-test");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("test directory must exist");
        let staging_path = directory.join("pending.staging-0123456789abcdef01234567");
        let final_path = directory.join("a".repeat(64));
        let mut staging =
            StagingGuard::create(staging_path.clone()).expect("staging file must be created");
        staging
            .file_mut()
            .write_all(b"hard-link-control")
            .expect("staging bytes must write");
        staging
            .link_final(&final_path)
            .expect("hard-link publication must succeed");
        assert_eq!(
            std::fs::metadata(&final_path)
                .expect("published link must exist")
                .nlink(),
            2
        );
        staging.discard().expect("staging link must be removed");
        assert!(!staging_path.exists());
        assert_eq!(
            std::fs::read(&final_path).expect("published link must remain"),
            b"hard-link-control"
        );
        assert_eq!(
            std::fs::metadata(&final_path)
                .expect("published link must remain")
                .nlink(),
            1
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    fn assert_no_staging(directory: &std::path::Path) {
        let contains_staging = std::fs::read_dir(directory)
            .expect("test directory must exist")
            .filter_map(std::result::Result::ok)
            .any(|entry| is_reserved_staging_name(&entry.file_name().to_string_lossy()));
        assert!(!contains_staging);
    }

    #[test]
    fn staging_name_is_narrowly_reserved() {
        assert!(is_reserved_staging_name(
            "pending.staging-0123456789abcdef01234567"
        ));
        assert!(!is_reserved_staging_name(
            "published.staging-0123456789abcdef01234567"
        ));
        assert!(!is_reserved_staging_name("pending.staging-not-hex"));
    }
}

// Rust guideline compliant 1.0.
