// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Installation root key, purpose-separated key derivation, and passphrase
//! wrapping (ADR 0031).
//!
//! One random 32-byte root key exists per installation. Every database and
//! comparison key is derived from it with HKDF-SHA256 under a length-framed,
//! purpose-specific `info`, so no two purposes or accounts can share a key.
//! When the user enables a passphrase, the root key is stored only in the
//! [`wrap_root_key`] format: Argon2id stretches the passphrase and
//! XChaCha20-Poly1305 seals the key, authenticating the parameters too.
//!
//! This crate performs no I/O beyond reading the OS random source.

#![forbid(unsafe_code)]

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tersa_domain::mailbox::AccountId;
use zeroize::{Zeroize, Zeroizing};

/// Length in bytes of the root key and of every derived key.
pub const KEY_LEN: usize = 32;

const ROOT_SALT: &[u8] = b"tersa/root-key/v1";
const ACCOUNT_PREFIX: &[u8] = b"tersa/hkdf-sha256/account/v1";
const INSTALLATION_PREFIX: &[u8] = b"tersa/hkdf-sha256/installation/v1";
const ACCOUNT_DATABASE_PURPOSE: &[u8] = b"sqlcipher/account-database/v1";
const ACCOUNT_IDENTITY_PURPOSE: &[u8] = b"account-subject/v1";
const REGISTRY_DATABASE_PURPOSE: &[u8] = b"sqlcipher/registry/v1";
const REGISTRY_DEDUP_PURPOSE: &[u8] = b"registry-subject-dedup/v1";

const WRAP_MAGIC: &[u8; 6] = b"TRSKW1";
const WRAP_SALT_LEN: usize = 16;
const WRAP_NONCE_LEN: usize = 24;
const WRAP_TAG_LEN: usize = 16;
const WRAP_HEADER_LEN: usize = WRAP_MAGIC.len() + 12 + WRAP_SALT_LEN + WRAP_NONCE_LEN;
/// Exact length of a wrapped root key produced by [`wrap_root_key`].
pub const WRAPPED_LEN: usize = WRAP_HEADER_LEN + KEY_LEN + WRAP_TAG_LEN;

/// Errors from key generation, derivation, and wrapping.
///
/// Variants carry no key material, so they are safe to log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyError {
    /// The operating-system random source failed.
    Entropy,
    /// The passphrase does not open the wrapped key, or the blob was altered.
    WrongPassphraseOrTampered,
    /// The wrapped key is not in a recognized format or exceeds the
    /// accepted cost bounds.
    Malformed,
    /// Key-derivation parameters are outside the supported range.
    InvalidParameters,
    /// An input exceeded a framing limit.
    InputTooLong,
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Entropy => "the system random source failed",
            Self::WrongPassphraseOrTampered => "wrong passphrase or altered key file",
            Self::Malformed => "the wrapped key is malformed",
            Self::InvalidParameters => "key-derivation parameters are out of range",
            Self::InputTooLong => "a key-derivation input is too long",
        })
    }
}

impl std::error::Error for KeyError {}

/// The installation root key. Zeroized on drop; never printed.
#[derive(Clone)]
pub struct RootKey(Zeroizing<[u8; KEY_LEN]>);

impl RootKey {
    /// Generates a new root key from the operating-system random source.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Entropy`] if the random source fails.
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = Zeroizing::new([0_u8; KEY_LEN]);
        getrandom::fill(bytes.as_mut()).map_err(|_error| KeyError::Entropy)?;
        Ok(Self(bytes))
    }

    /// Rebuilds a root key read back from secret storage.
    #[must_use]
    pub fn from_bytes(bytes: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(bytes)
    }

    /// Exposes the raw key so a secret-storage adapter can persist it.
    #[must_use]
    pub fn expose_for_storage(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootKey([REDACTED])")
    }
}

/// A key derived for one purpose. Zeroized on drop; never printed.
pub struct DerivedKey(Zeroizing<[u8; KEY_LEN]>);

impl DerivedKey {
    /// Returns the key bytes for handing to a cipher or database.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Moves the key bytes out without leaving a copy behind.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<[u8; KEY_LEN]> {
        self.0
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DerivedKey([REDACTED])")
    }
}

/// Keys bound to one account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AccountKeyPurpose {
    /// `SQLCipher` key of the account's mail database.
    SqlCipherDatabaseV1,
}

/// Keys shared by the whole installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InstallationKeyPurpose {
    /// `SQLCipher` key of the account registry.
    RegistryDatabaseV1,
    /// HMAC key for detecting the same Google account added twice.
    RegistrySubjectDedupV1,
}

/// Derives a key bound to `account` for `purpose`.
///
/// # Errors
///
/// Returns [`KeyError::InputTooLong`] if the account identifier exceeds the
/// framing limit.
pub fn derive_account_key(
    root: &RootKey,
    account: &AccountId,
    purpose: AccountKeyPurpose,
) -> Result<DerivedKey, KeyError> {
    let purpose = match purpose {
        AccountKeyPurpose::SqlCipherDatabaseV1 => ACCOUNT_DATABASE_PURPOSE,
    };
    let info = account_info(account, purpose)?;
    expand(root, &info)
}

/// Derives an installation-wide key for `purpose`.
///
/// Its `info` uses a separate prefix and carries no account, so it can never
/// collide with an account-bound key.
///
/// # Errors
///
/// Never fails for the defined purposes; the `Result` keeps the signature
/// uniform with [`derive_account_key`].
pub fn derive_installation_key(
    root: &RootKey,
    purpose: InstallationKeyPurpose,
) -> Result<DerivedKey, KeyError> {
    let purpose = match purpose {
        InstallationKeyPurpose::RegistryDatabaseV1 => REGISTRY_DATABASE_PURPOSE,
        InstallationKeyPurpose::RegistrySubjectDedupV1 => REGISTRY_DEDUP_PURPOSE,
    };
    let mut info = Vec::with_capacity(INSTALLATION_PREFIX.len() + 2 + purpose.len());
    info.extend_from_slice(INSTALLATION_PREFIX);
    push_framed(&mut info, purpose)?;
    expand(root, &info)
}

/// Computes the account-bound identity hash of a normalized OAuth subject.
///
/// HKDF-Expand is an HMAC-based PRF over `info`, so the result is a keyed,
/// account-bound MAC of the subject that cannot be computed without the root
/// key. It is a comparison value, not a secret.
///
/// # Errors
///
/// Returns [`KeyError::InputTooLong`] if an input exceeds the framing limit.
pub fn account_identity_hash(
    root: &RootKey,
    account: &AccountId,
    normalized_subject: &[u8],
) -> Result<[u8; KEY_LEN], KeyError> {
    let mut info = account_info(account, ACCOUNT_IDENTITY_PURPOSE)?;
    let framed = push_framed(&mut info, normalized_subject);
    let result = framed.and_then(|()| expand(root, &info));
    info.zeroize();
    Ok(*result?.as_bytes())
}

/// Computes the registry dedup tag of an OAuth subject.
///
/// HMAC-SHA256 keyed by the [`InstallationKeyPurpose::RegistrySubjectDedupV1`]
/// key: equal subjects give equal tags on this installation only, and the
/// tag reveals nothing about the subject without the root key.
///
/// # Errors
///
/// Never fails for a valid root key; the `Result` mirrors the derivations.
pub fn registry_dedup_tag(root: &RootKey, subject: &[u8]) -> Result<[u8; KEY_LEN], KeyError> {
    let key = derive_installation_key(root, InstallationKeyPurpose::RegistrySubjectDedupV1)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
        .map_err(|_error| KeyError::InputTooLong)?;
    mac.update(subject);
    Ok(mac.finalize().into_bytes().into())
}

fn account_info(account: &AccountId, purpose: &[u8]) -> Result<Vec<u8>, KeyError> {
    let account = account.as_str().as_bytes();
    let mut info = Vec::with_capacity(ACCOUNT_PREFIX.len() + 4 + account.len() + purpose.len());
    info.extend_from_slice(ACCOUNT_PREFIX);
    push_framed(&mut info, account)?;
    push_framed(&mut info, purpose)?;
    Ok(info)
}

fn push_framed(buffer: &mut Vec<u8>, value: &[u8]) -> Result<(), KeyError> {
    let length = u16::try_from(value.len()).map_err(|_error| KeyError::InputTooLong)?;
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.extend_from_slice(value);
    Ok(())
}

fn expand(root: &RootKey, info: &[u8]) -> Result<DerivedKey, KeyError> {
    let hkdf = Hkdf::<Sha256>::new(Some(ROOT_SALT), root.0.as_ref());
    let mut output = Zeroizing::new([0_u8; KEY_LEN]);
    hkdf.expand(info, output.as_mut())
        .map_err(|_error| KeyError::InputTooLong)?;
    Ok(DerivedKey(output))
}

/// Argon2id cost parameters for passphrase wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl KdfParams {
    /// Parameters used for new wrapped keys: 64 MiB, 3 passes, 1 lane
    /// (RFC 9106's second recommended profile with one lane).
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Largest accepted memory cost (1 GiB), bounding work a tampered file
    /// can demand before authentication fails.
    pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    /// Largest accepted pass count.
    pub const MAX_ITERATIONS: u32 = 16;
    /// Largest accepted lane count.
    pub const MAX_PARALLELISM: u32 = 8;

    fn to_argon2(self) -> Result<Argon2<'static>, KeyError> {
        if self.memory_kib > Self::MAX_MEMORY_KIB
            || self.iterations == 0
            || self.iterations > Self::MAX_ITERATIONS
            || self.parallelism == 0
            || self.parallelism > Self::MAX_PARALLELISM
        {
            return Err(KeyError::InvalidParameters);
        }
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_error| KeyError::InvalidParameters)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Seals the root key under a passphrase.
///
/// Layout: `"TRSKW1" || m || t || p || salt(16) || nonce(24) || ciphertext(32) || tag(16)`,
/// with the cost parameters as big-endian `u32`. Everything before the
/// ciphertext is authenticated as associated data.
///
/// # Errors
///
/// Returns [`KeyError::InvalidParameters`] for out-of-range parameters or
/// [`KeyError::Entropy`] if the random source fails.
pub fn wrap_root_key(
    root: &RootKey,
    passphrase: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>, KeyError> {
    let argon2 = params.to_argon2()?;
    let mut salt = [0_u8; WRAP_SALT_LEN];
    let mut nonce = [0_u8; WRAP_NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_error| KeyError::Entropy)?;
    getrandom::fill(&mut nonce).map_err(|_error| KeyError::Entropy)?;

    let mut header = Vec::with_capacity(WRAPPED_LEN);
    header.extend_from_slice(WRAP_MAGIC);
    header.extend_from_slice(&params.memory_kib.to_be_bytes());
    header.extend_from_slice(&params.iterations.to_be_bytes());
    header.extend_from_slice(&params.parallelism.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let kek = stretch(&argon2, passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: root.0.as_ref(),
                aad: &header,
            },
        )
        .map_err(|_error| KeyError::InvalidParameters)?;
    header.extend_from_slice(&sealed);
    Ok(header)
}

/// Opens a root key sealed by [`wrap_root_key`].
///
/// Cost parameters are bounds-checked before any Argon2 work runs.
///
/// # Errors
///
/// Returns [`KeyError::Malformed`] for an unrecognized or oversized blob and
/// [`KeyError::WrongPassphraseOrTampered`] when authentication fails.
pub fn unwrap_root_key(wrapped: &[u8], passphrase: &[u8]) -> Result<RootKey, KeyError> {
    if wrapped.len() != WRAPPED_LEN || !wrapped.starts_with(WRAP_MAGIC) {
        return Err(KeyError::Malformed);
    }
    let (header, sealed) = wrapped.split_at(WRAP_HEADER_LEN);
    let field = |index: usize| {
        let start = WRAP_MAGIC.len() + index * 4;
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(&header[start..start + 4]);
        u32::from_be_bytes(bytes)
    };
    let params = KdfParams {
        memory_kib: field(0),
        iterations: field(1),
        parallelism: field(2),
    };
    let argon2 = params.to_argon2().map_err(|_error| KeyError::Malformed)?;
    let salt_start = WRAP_MAGIC.len() + 12;
    let salt = &header[salt_start..salt_start + WRAP_SALT_LEN];
    let nonce = &header[salt_start + WRAP_SALT_LEN..];

    let kek = stretch(&argon2, passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
    let opened = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: header,
                },
            )
            .map_err(|_error| KeyError::WrongPassphraseOrTampered)?,
    );
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    if opened.len() != KEY_LEN {
        return Err(KeyError::Malformed);
    }
    key.copy_from_slice(&opened);
    Ok(RootKey(key))
}

fn stretch(
    argon2: &Argon2<'_>,
    passphrase: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, KeyError> {
    let mut kek = Zeroizing::new([0_u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, kek.as_mut())
        .map_err(|_error| KeyError::InvalidParameters)?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use tersa_domain::mailbox::AccountId;
    use zeroize::Zeroizing;

    use super::{
        AccountKeyPurpose, InstallationKeyPurpose, KdfParams, KeyError, RootKey, WRAPPED_LEN,
        account_identity_hash, account_info, derive_account_key, derive_installation_key,
        registry_dedup_tag, unwrap_root_key, wrap_root_key,
    };

    // Cheap parameters keep the tests fast; production uses DEFAULT.
    const TEST_PARAMS: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    fn root() -> RootKey {
        RootKey::from_bytes(Zeroizing::new(core::array::from_fn(|index| {
            u8::try_from(index).expect("index fits in u8")
        })))
    }

    fn account(value: &str) -> AccountId {
        AccountId::new(value).expect("valid account id")
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn account_info_is_length_framed() {
        assert_eq!(
            hex(&account_info(&account("acct-test-1"), b"p").expect("framed")),
            "74657273612f686b64662d7368613235362f6163636f756e742f7631000b616363742d746573742d31000170"
        );
    }

    #[test]
    fn derivations_are_stable_and_separated() {
        let root = root();
        let first = derive_account_key(
            &root,
            &account("acct-test-1"),
            AccountKeyPurpose::SqlCipherDatabaseV1,
        )
        .expect("derive");
        let second = derive_account_key(
            &root,
            &account("acct-test-2"),
            AccountKeyPurpose::SqlCipherDatabaseV1,
        )
        .expect("derive");
        let registry = derive_installation_key(&root, InstallationKeyPurpose::RegistryDatabaseV1)
            .expect("derive");
        let dedup = derive_installation_key(&root, InstallationKeyPurpose::RegistrySubjectDedupV1)
            .expect("derive");
        let identity =
            account_identity_hash(&root, &account("acct-test-1"), b"subject").expect("hash");

        let outputs = [
            hex(first.as_bytes()),
            hex(second.as_bytes()),
            hex(registry.as_bytes()),
            hex(dedup.as_bytes()),
            hex(&identity),
        ];
        for (index, left) in outputs.iter().enumerate() {
            for right in &outputs[index + 1..] {
                assert_ne!(left, right);
            }
        }
        // Known answer pins the derivation so a refactor cannot silently
        // change every database key.
        // The expected value was computed independently (Python hmac/hashlib).
        assert_eq!(
            outputs[0],
            "f176fddf4500f948f47a5ec7e9a1e26867d0d9f24ccebe1390f21c3d1693aaef"
        );
    }

    #[test]
    fn dedup_tag_matches_an_independent_hmac() {
        // HMAC-SHA256(HKDF(root, installation dedup purpose), "subject"),
        // computed independently with Python hmac/hashlib.
        assert_eq!(
            hex(&registry_dedup_tag(&root(), b"subject").expect("tag")),
            "ea367e0233fbe54e1c1aff844700d93d005af750d1bc1c774185bec098dc9461"
        );
        assert_ne!(
            registry_dedup_tag(&root(), b"a").expect("tag"),
            registry_dedup_tag(&root(), b"b").expect("tag")
        );
    }

    #[test]
    fn identity_hash_depends_on_subject() {
        let root = root();
        let acct = account("acct-test-1");
        assert_ne!(
            account_identity_hash(&root, &acct, b"a").expect("hash"),
            account_identity_hash(&root, &acct, b"b").expect("hash")
        );
    }

    #[test]
    fn wrap_round_trips_and_rejects_wrong_passphrase() {
        let root = root();
        let wrapped = wrap_root_key(&root, b"correct horse", TEST_PARAMS).expect("wrap");
        assert_eq!(wrapped.len(), WRAPPED_LEN);
        let opened = unwrap_root_key(&wrapped, b"correct horse").expect("unwrap");
        assert_eq!(opened.expose_for_storage(), root.expose_for_storage());
        assert_eq!(
            unwrap_root_key(&wrapped, b"wrong").map(|_key| ()),
            Err(KeyError::WrongPassphraseOrTampered)
        );
    }

    #[test]
    fn wrap_uses_fresh_salt_and_nonce() {
        let root = root();
        assert_ne!(
            wrap_root_key(&root, b"pass", TEST_PARAMS).expect("wrap"),
            wrap_root_key(&root, b"pass", TEST_PARAMS).expect("wrap")
        );
    }

    #[test]
    fn tampering_any_byte_fails_authentication_or_parsing() {
        let wrapped = wrap_root_key(&root(), b"pass", TEST_PARAMS).expect("wrap");
        for index in 0..wrapped.len() {
            let mut altered = wrapped.clone();
            altered[index] ^= 0x01;
            assert!(
                unwrap_root_key(&altered, b"pass").is_err(),
                "byte {index} was not authenticated"
            );
        }
    }

    #[test]
    fn oversized_costs_are_rejected_before_stretching() {
        let mut wrapped = wrap_root_key(&root(), b"pass", TEST_PARAMS).expect("wrap");
        wrapped[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            unwrap_root_key(&wrapped, b"pass").map(|_key| ()),
            Err(KeyError::Malformed)
        );
        assert_eq!(
            wrap_root_key(
                &root(),
                b"pass",
                KdfParams {
                    parallelism: 0,
                    ..TEST_PARAMS
                }
            )
            .map(|_blob| ()),
            Err(KeyError::InvalidParameters)
        );
    }

    #[test]
    fn malformed_blobs_are_rejected() {
        assert_eq!(
            unwrap_root_key(b"short", b"pass").map(|_key| ()),
            Err(KeyError::Malformed)
        );
        let mut wrapped = wrap_root_key(&root(), b"pass", TEST_PARAMS).expect("wrap");
        wrapped[0] = b'X';
        assert_eq!(
            unwrap_root_key(&wrapped, b"pass").map(|_key| ()),
            Err(KeyError::Malformed)
        );
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        assert_eq!(format!("{:?}", root()), "RootKey([REDACTED])");
        let derived = derive_installation_key(&root(), InstallationKeyPurpose::RegistryDatabaseV1)
            .expect("derive");
        assert_eq!(format!("{derived:?}"), "DerivedKey([REDACTED])");
    }
}
