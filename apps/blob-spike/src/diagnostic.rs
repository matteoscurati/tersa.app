// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Orchestrates the Unix process-crash and tamper evidence protocol.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::format::{
    AccountContext, BlobId, BlobKeys, BlobReader, CHUNK_SIZE, ExpectedBlob, FORMAT_VERSION,
    FormatError, HEADER_LENGTH, MAX_TOTAL_LENGTH, NONCE_LENGTH, NonceRegistry, TAG_LENGTH,
    cleanup_staging, content_identifier, content_ids_equal, is_reserved_staging_name, write_blob,
};

const PASS_LINE: &str = "Blob AEAD M0 feasibility PASS";
const SENTINEL_LENGTH: usize = 80;
const KEY_LENGTH: usize = 32;
const ID_LENGTH: usize = 16;
const RECORD_OVERHEAD: usize = NONCE_LENGTH + TAG_LENGTH;
const FIRST_DURABLE_RECORD_LENGTH: usize = HEADER_LENGTH + CHUNK_SIZE + RECORD_OVERHEAD;

type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
type ChildProtocol = (
    Zeroizing<[u8; KEY_LENGTH]>,
    Zeroizing<[u8; KEY_LENGTH]>,
    [u8; ID_LENGTH],
    [u8; ID_LENGTH],
    String,
);
pub(crate) type DiagnosticResult = std::result::Result<(), &'static str>;

pub(crate) fn run() -> DiagnosticResult {
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("child")) {
        child()
    } else {
        parent()
    }
}

fn parent() -> DiagnosticResult {
    let workspace = EvidenceWorkspace::new().map_err(|_error| "P01")?;
    let account_a = AccountContext(random_array().map_err(|_error| "P02")?);
    let account_b = AccountContext(random_array().map_err(|_error| "P03")?);
    let aead_a = random_key().map_err(|_error| "P04")?;
    let content_a = random_key().map_err(|_error| "P05")?;
    let aead_b = random_key().map_err(|_error| "P06")?;
    let content_b = random_key().map_err(|_error| "P07")?;
    let keys_a = BlobKeys::new(aead_a.clone(), content_a.clone());
    let keys_b = BlobKeys::new(aead_b.clone(), content_b.clone());
    let sentinel = random_sentinel().map_err(|_error| "P08")?;
    let mut nonces = NonceRegistry::default();

    prove_round_trips(
        &workspace,
        &keys_a,
        account_a,
        &keys_b,
        account_b,
        &mut nonces,
    )
    .map_err(|_error| "P09")?;
    prove_negative_matrix(
        &workspace,
        &keys_a,
        account_a,
        &keys_b,
        account_b,
        &aead_a,
        &content_a,
        &mut nonces,
    )
    .map_err(|_error| "P10")?;
    prove_crash_recovery(
        &workspace,
        &keys_a,
        account_a,
        &aead_a,
        &content_a,
        &sentinel,
        &mut nonces,
    )
    .map_err(|_error| "P11")?;
    assert_absent(
        &workspace.regular_files().map_err(|_error| "P12")?,
        &sentinel,
    )
    .map_err(|_error| "P13")?;
    plaintext_positive_control(&workspace, &sentinel).map_err(|_error| "P14")?;
    if nonces.count() == 0 {
        return Err("P15");
    }
    println!("{PASS_LINE}");
    println!("Blob format version {FORMAT_VERSION}");
    println!("NOT A DEVICE-GATE RESULT");
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "The feasibility proof keeps its bounded acceptance cases together."
)]
fn prove_round_trips(
    workspace: &EvidenceWorkspace,
    keys_a: &BlobKeys,
    account_a: AccountContext,
    keys_b: &BlobKeys,
    account_b: AccountContext,
    nonces: &mut NonceRegistry,
) -> Result {
    let lengths = [
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        CHUNK_SIZE * 3 + 17,
        usize::try_from(MAX_TOTAL_LENGTH)?,
    ];
    for (case, length) in lengths.into_iter().enumerate() {
        let plaintext = fixture_bytes(length, u8::try_from(case + 1)?);
        let expected = ExpectedBlob {
            account: account_a,
            blob_id: BlobId(random_array()?),
        };
        let outcome = write_fixture(
            &workspace.case_directory(&format!("roundtrip-{case}")),
            &plaintext,
            keys_a,
            expected,
            nonces,
        )?;
        if length == 0 && outcome.chunk_count != 1 {
            return Err("empty blob did not use one authenticated chunk".into());
        }
        let mut reader = BlobReader::open(&outcome.path, keys_a, expected)?;
        if reader.total_length() != u64::try_from(length)? {
            return Err("round-trip length differs".into());
        }
        let (reconstructed, _metrics) = reader.read_all()?;
        if reconstructed != plaintext {
            return Err("round-trip bytes differ".into());
        }
    }

    let range_plaintext = fixture_bytes(CHUNK_SIZE * 3 + 9, 31);
    let range_expected = ExpectedBlob {
        account: account_a,
        blob_id: BlobId(random_array()?),
    };
    let range_outcome = write_fixture(
        &workspace.case_directory("random-access"),
        &range_plaintext,
        keys_a,
        range_expected,
        nonces,
    )?;
    let mut reader = BlobReader::open(&range_outcome.path, keys_a, range_expected)?;
    let start = CHUNK_SIZE - 7;
    let (range, metrics) = reader.read_range(u64::try_from(start)?, 19)?;
    if range != range_plaintext[start..start + 19] || metrics.decrypted_chunks != 2 {
        return Err("random-access chunk accounting differs".into());
    }

    let content_plaintext = fixture_bytes(CHUNK_SIZE + 23, 47);
    let same_a = write_fixture(
        &workspace.case_directory("content-a-one"),
        &content_plaintext,
        keys_a,
        ExpectedBlob {
            account: account_a,
            blob_id: BlobId(random_array()?),
        },
        nonces,
    )?;
    let same_b = write_fixture(
        &workspace.case_directory("content-a-two"),
        &content_plaintext,
        keys_a,
        ExpectedBlob {
            account: account_a,
            blob_id: BlobId(random_array()?),
        },
        nonces,
    )?;
    let other_account = write_fixture(
        &workspace.case_directory("content-b"),
        &content_plaintext,
        keys_b,
        ExpectedBlob {
            account: account_b,
            blob_id: BlobId(random_array()?),
        },
        nonces,
    )?;
    if !content_ids_equal(&same_a.content_id, &same_b.content_id)
        || content_ids_equal(&same_a.content_id, &other_account.content_id)
    {
        return Err("content identifier separation differs".into());
    }

    prove_authenticated_reuse(workspace, keys_a, account_a, &content_plaintext, nonces)?;
    Ok(())
}

fn prove_authenticated_reuse(
    workspace: &EvidenceWorkspace,
    keys: &BlobKeys,
    account: AccountContext,
    plaintext: &[u8],
    nonces: &mut NonceRegistry,
) -> Result {
    let directory = workspace.case_directory("same-binding-reuse");
    let expected = ExpectedBlob {
        account,
        blob_id: BlobId(random_array()?),
    };
    let first = write_fixture(&directory, plaintext, keys, expected, nonces)?;
    let original = fs::read(&first.path)?;
    let second = write_fixture(&directory, plaintext, keys, expected, nonces)?;
    if !second.reused_existing_binding || fs::read(&second.path)? != original {
        return Err("same-binding reuse semantics differ".into());
    }

    let different_binding = ExpectedBlob {
        account,
        blob_id: BlobId(random_array()?),
    };
    if write_fixture(&directory, plaintext, keys, different_binding, nonces).is_ok()
        || fs::read(&first.path)? != original
        || find_staging(&directory)?.is_some()
    {
        return Err("cross-binding reuse was accepted or changed the final".into());
    }

    let corrupt_directory = workspace.case_directory("corrupt-existing-final");
    let corrupt_expected = ExpectedBlob {
        account,
        blob_id: BlobId(random_array()?),
    };
    let corrupt = write_fixture(
        &corrupt_directory,
        plaintext,
        keys,
        corrupt_expected,
        nonces,
    )?;
    let mut corrupted_bytes = fs::read(&corrupt.path)?;
    corrupted_bytes[HEADER_LENGTH + NONCE_LENGTH] ^= 1;
    fs::write(&corrupt.path, &corrupted_bytes)?;
    if write_fixture(
        &corrupt_directory,
        plaintext,
        keys,
        corrupt_expected,
        nonces,
    )
    .is_ok()
        || fs::read(&corrupt.path)? != corrupted_bytes
        || find_staging(&corrupt_directory)?.is_some()
    {
        return Err("corrupt existing final was accepted or replaced".into());
    }
    prove_publish_conflict(workspace, keys, account, plaintext, nonces)?;
    Ok(())
}

fn prove_publish_conflict(
    workspace: &EvidenceWorkspace,
    keys: &BlobKeys,
    account: AccountContext,
    plaintext: &[u8],
    nonces: &mut NonceRegistry,
) -> Result {
    let directory = workspace.case_directory("publish-conflict");
    fs::create_dir_all(&directory)?;
    let expected = ExpectedBlob {
        account,
        blob_id: BlobId(random_array()?),
    };
    let candidate_id = content_identifier(keys, account, plaintext)?;
    let final_path = directory.join(lower_hex(&candidate_id));
    let conflict_bytes = fixture_bytes(97, 211);
    let mut input = Cursor::new(plaintext);
    let mut conflict_created = false;
    let result = write_blob(
        &directory,
        &mut input,
        u64::try_from(plaintext.len())?,
        keys,
        expected,
        nonces,
        |index, _file, _staging_path| {
            if index == 0 && !conflict_created {
                fs::write(&final_path, &conflict_bytes)
                    .map_err(|_error| FormatError("conflict-write"))?;
                File::open(&final_path)
                    .and_then(|file| file.sync_all())
                    .map_err(|_error| FormatError("conflict-sync"))?;
                File::open(&directory)
                    .and_then(|file| file.sync_all())
                    .map_err(|_error| FormatError("conflict-directory-sync"))?;
                conflict_created = true;
            }
            Ok(())
        },
    );
    if result.is_ok()
        || !conflict_created
        || fs::read(&final_path)? != conflict_bytes
        || find_staging(&directory)?.is_some()
    {
        return Err("publish conflict replaced a final or retained staging".into());
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "The diagnostic keeps both synthetic account boundaries explicit."
)]
fn prove_negative_matrix(
    workspace: &EvidenceWorkspace,
    keys_a: &BlobKeys,
    account_a: AccountContext,
    keys_b: &BlobKeys,
    account_b: AccountContext,
    aead_a: &Zeroizing<[u8; KEY_LENGTH]>,
    content_a: &Zeroizing<[u8; KEY_LENGTH]>,
    nonces: &mut NonceRegistry,
) -> Result {
    let plaintext = fixture_bytes(CHUNK_SIZE * 3, 71);
    let expected = ExpectedBlob {
        account: account_a,
        blob_id: BlobId(random_array()?),
    };
    let outcome = write_fixture(
        &workspace.case_directory("negative-source"),
        &plaintext,
        keys_a,
        expected,
        nonces,
    )?;
    let valid = fs::read(&outcome.path)?;

    let mut wrong_aead = aead_a.clone();
    wrong_aead[0] ^= 1;
    assert_reader_rejected(
        &outcome.path,
        &BlobKeys::new(wrong_aead, content_a.clone()),
        expected,
    )?;
    assert_reader_rejected(
        &outcome.path,
        keys_b,
        ExpectedBlob {
            account: account_b,
            blob_id: expected.blob_id,
        },
    )?;
    assert_reader_rejected(
        &outcome.path,
        keys_a,
        ExpectedBlob {
            account: account_b,
            blob_id: expected.blob_id,
        },
    )?;
    let mut wrong_blob_id = expected.blob_id;
    wrong_blob_id.0[0] ^= 1;
    assert_reader_rejected(
        &outcome.path,
        keys_a,
        ExpectedBlob {
            blob_id: wrong_blob_id,
            ..expected
        },
    )?;

    let mut magic = valid.clone();
    magic[0] ^= 1;
    assert_mutation_rejected(
        workspace,
        "header-magic",
        &outcome.path,
        &magic,
        keys_a,
        expected,
    )?;
    let mut version = valid.clone();
    version[8] = FORMAT_VERSION + 1;
    assert_mutation_rejected(
        workspace,
        "header-version",
        &outcome.path,
        &version,
        keys_a,
        expected,
    )?;
    let mut total = valid.clone();
    total[9..17].copy_from_slice(&(u64::try_from(plaintext.len())? + 1).to_le_bytes());
    assert_mutation_rejected(
        workspace,
        "header-total",
        &outcome.path,
        &total,
        keys_a,
        expected,
    )?;
    let mut count = valid.clone();
    count[17..21].copy_from_slice(&4_u32.to_le_bytes());
    assert_mutation_rejected(
        workspace,
        "header-count",
        &outcome.path,
        &count,
        keys_a,
        expected,
    )?;

    let first_nonce = HEADER_LENGTH;
    let first_ciphertext = first_nonce + NONCE_LENGTH;
    let first_tag = first_ciphertext + CHUNK_SIZE;
    for (case, offset) in [
        ("nonce-bit", first_nonce),
        ("ciphertext-bit", first_ciphertext),
        ("tag-bit", first_tag),
    ] {
        let mut mutated = valid.clone();
        mutated[offset] ^= 1;
        assert_mutation_rejected(workspace, case, &outcome.path, &mutated, keys_a, expected)?;
    }

    let record_length = CHUNK_SIZE + RECORD_OVERHEAD;
    let first_start = HEADER_LENGTH;
    let second_start = first_start + record_length;
    let third_start = second_start + record_length;
    let mut reordered = valid.clone();
    reordered[first_start..second_start].copy_from_slice(&valid[second_start..third_start]);
    reordered[second_start..third_start].copy_from_slice(&valid[first_start..second_start]);
    assert_mutation_rejected(
        workspace,
        "chunk-reorder",
        &outcome.path,
        &reordered,
        keys_a,
        expected,
    )?;
    let mut duplicated = valid.clone();
    duplicated[second_start..third_start].copy_from_slice(&valid[first_start..second_start]);
    assert_mutation_rejected(
        workspace,
        "chunk-duplicate",
        &outcome.path,
        &duplicated,
        keys_a,
        expected,
    )?;
    let mut mid_deleted = valid.clone();
    mid_deleted.drain(second_start..third_start);
    assert_mutation_rejected(
        workspace,
        "chunk-delete",
        &outcome.path,
        &mid_deleted,
        keys_a,
        expected,
    )?;
    let partial_truncation = &valid[..valid.len() - 1];
    assert_mutation_rejected(
        workspace,
        "truncate-partial",
        &outcome.path,
        partial_truncation,
        keys_a,
        expected,
    )?;
    let whole_tail = &valid[..third_start];
    let tail_path = mutation_path(workspace, "truncate-whole", &outcome.path, whole_tail)?;
    if BlobReader::open(&tail_path, keys_a, expected)
        .and_then(|mut reader| reader.read_range(0, 1))
        .is_ok()
    {
        return Err("early random access accepted missing tail".into());
    }
    let mut garbage = valid.clone();
    garbage.push(0);
    assert_mutation_rejected(
        workspace,
        "append-garbage",
        &outcome.path,
        &garbage,
        keys_a,
        expected,
    )?;
    let mut extra_chunk = valid.clone();
    extra_chunk.extend_from_slice(&valid[first_start..second_start]);
    assert_mutation_rejected(
        workspace,
        "append-chunk",
        &outcome.path,
        &extra_chunk,
        keys_a,
        expected,
    )?;

    let replay_expected = ExpectedBlob {
        account: account_a,
        blob_id: BlobId(random_array()?),
    };
    let replay = write_fixture(
        &workspace.case_directory("replay-source"),
        &fixture_bytes(CHUNK_SIZE * 3, 72),
        keys_a,
        replay_expected,
        nonces,
    )?;
    let replay_bytes = fs::read(replay.path)?;
    let mut replayed = valid.clone();
    replayed[first_start..second_start].copy_from_slice(&replay_bytes[first_start..second_start]);
    assert_mutation_rejected(
        workspace,
        "chunk-replay",
        &outcome.path,
        &replayed,
        keys_a,
        expected,
    )?;

    for (case, hostile_total, hostile_count) in [
        ("hostile-huge", MAX_TOTAL_LENGTH + 1, 1_u32),
        ("hostile-overflow", u64::MAX, u32::MAX),
        ("hostile-mismatch", 1_u64, u32::MAX),
    ] {
        let mut hostile = valid.clone();
        hostile[9..17].copy_from_slice(&hostile_total.to_le_bytes());
        hostile[17..21].copy_from_slice(&hostile_count.to_le_bytes());
        assert_mutation_rejected(workspace, case, &outcome.path, &hostile, keys_a, expected)?;
    }

    let staging = workspace
        .case_directory("staging-open")
        .join("pending.staging-0123456789abcdef01234567");
    fs::create_dir_all(staging.parent().ok_or("staging parent unavailable")?)?;
    fs::write(&staging, &valid)?;
    assert_reader_rejected(&staging, keys_a, expected)?;

    let original_expected = ExpectedBlob {
        account: account_a,
        blob_id: BlobId(random_array()?),
    };
    let replacement_expected = ExpectedBlob {
        account: account_a,
        blob_id: BlobId(random_array()?),
    };
    let swap_a = write_fixture(
        &workspace.case_directory("swap-a"),
        &fixture_bytes(CHUNK_SIZE + 3, 81),
        keys_a,
        original_expected,
        nonces,
    )?;
    let swap_b = write_fixture(
        &workspace.case_directory("swap-b"),
        &fixture_bytes(CHUNK_SIZE + 3, 82),
        keys_a,
        replacement_expected,
        nonces,
    )?;
    let swapped_path = mutation_path(
        workspace,
        "filename-swap",
        &swap_b.path,
        &fs::read(swap_a.path)?,
    )?;
    assert_reader_rejected(&swapped_path, keys_a, replacement_expected)
}

#[allow(
    clippy::too_many_arguments,
    reason = "The child protocol transmits every independent synthetic secret explicitly."
)]
fn prove_crash_recovery(
    workspace: &EvidenceWorkspace,
    keys: &BlobKeys,
    account: AccountContext,
    aead: &Zeroizing<[u8; KEY_LENGTH]>,
    content_id: &Zeroizing<[u8; KEY_LENGTH]>,
    sentinel: &str,
    nonces: &mut NonceRegistry,
) -> Result {
    let directory = workspace.case_directory("crash");
    let control_plaintext = fixture_bytes(CHUNK_SIZE + 5, 91);
    let control_expected = ExpectedBlob {
        account,
        blob_id: BlobId(random_array()?),
    };
    let control = write_fixture(
        &directory,
        &control_plaintext,
        keys,
        control_expected,
        nonces,
    )?;
    let crash_blob_id = BlobId(random_array()?);
    let crash_plaintext = crash_plaintext(sentinel);
    let mut child = ChildGuard::new(spawn_child(
        workspace,
        &directory,
        aead,
        content_id,
        &account.0,
        &crash_blob_id.0,
        sentinel,
    )?);
    wait_for_crash_ready(&mut child, workspace, &directory)?;
    let staging = find_staging(&directory)?.ok_or("durable staging file unavailable")?;
    observe_first_nonce(&staging, nonces)?;
    assert_reader_rejected(
        &staging,
        keys,
        ExpectedBlob {
            account,
            blob_id: crash_blob_id,
        },
    )?;
    assert_absent(&workspace.regular_files()?, sentinel)?;
    let status = child.kill_and_wait()?;
    if status.signal() != Some(9) {
        return Err("crash child did not terminate with signal 9".into());
    }
    if published_files(&directory)?.len() != 1 || !control.path.is_file() {
        return Err("crash published a final or removed the control final".into());
    }
    if cleanup_staging(&directory)? != 1 || !control.path.is_file() {
        return Err("recovery cleanup did not remove only staging".into());
    }
    let expected = ExpectedBlob {
        account,
        blob_id: crash_blob_id,
    };
    let published = write_fixture(&directory, &crash_plaintext, keys, expected, nonces)?;
    let (recovered, _metrics) = BlobReader::open(&published.path, keys, expected)?.read_all()?;
    if recovered != crash_plaintext || published_files(&directory)?.len() != 2 {
        return Err("normal publish after recovery differs".into());
    }
    Ok(())
}

fn observe_first_nonce(path: &Path, nonces: &mut NonceRegistry) -> Result {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(u64::try_from(HEADER_LENGTH)?))?;
    let mut nonce = [0_u8; NONCE_LENGTH];
    file.read_exact(&mut nonce)?;
    nonces.observe(nonce)?;
    Ok(())
}

fn child() -> DiagnosticResult {
    let workspace = EvidenceWorkspace::from_environment().map_err(|_error| "C01")?;
    let directory = PathBuf::from(env::var_os("TERSA_BLOB_CRASH_DIR").ok_or("C02")?);
    let (aead, content, account, blob_id, sentinel) = receive_protocol().map_err(|_error| "C03")?;
    let keys = BlobKeys::new(aead, content);
    let expected = ExpectedBlob {
        account: AccountContext(account),
        blob_id: BlobId(blob_id),
    };
    let plaintext = crash_plaintext(&sentinel);
    let mut input = Cursor::new(&plaintext);
    let mut registry = NonceRegistry::default();
    write_blob(
        &directory,
        &mut input,
        u64::try_from(plaintext.len()).map_err(|_error| "C04")?,
        &keys,
        expected,
        &mut registry,
        |index, file, _path| {
            if index == 0 {
                file.sync_all()
                    .map_err(|_error| FormatError("child-sync"))?;
                File::open(&directory)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_error| FormatError("child-directory-sync"))?;
                let marker = File::create(workspace.ready())
                    .map_err(|_error| FormatError("ready-create"))?;
                marker
                    .sync_all()
                    .map_err(|_error| FormatError("ready-sync"))?;
                File::open(workspace.root())
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_error| FormatError("ready-directory-sync"))?;
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        },
    )
    .map_err(|_error| "C05")?;
    Err("C06")
}

#[allow(
    clippy::too_many_arguments,
    reason = "The private pipe keeps every child input out of process arguments and files."
)]
fn spawn_child(
    workspace: &EvidenceWorkspace,
    directory: &Path,
    aead: &[u8; KEY_LENGTH],
    content: &[u8; KEY_LENGTH],
    account: &[u8; ID_LENGTH],
    blob_id: &[u8; ID_LENGTH],
    sentinel: &str,
) -> Result<Child> {
    let mut child = Command::new(env::current_exe()?)
        .arg("child")
        .env("TERSA_BLOB_EVIDENCE_DIR", workspace.root())
        .env("TERSA_BLOB_CRASH_DIR", directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdin = child.stdin.as_mut().ok_or("child stdin unavailable")?;
    stdin.write_all(aead)?;
    stdin.write_all(content)?;
    stdin.write_all(account)?;
    stdin.write_all(blob_id)?;
    stdin.write_all(sentinel.as_bytes())?;
    stdin.flush()?;
    drop(child.stdin.take());
    Ok(child)
}

fn receive_protocol() -> Result<ChildProtocol> {
    let mut input = std::io::stdin().lock();
    let mut aead = Zeroizing::new([0_u8; KEY_LENGTH]);
    let mut content = Zeroizing::new([0_u8; KEY_LENGTH]);
    let mut account = [0_u8; ID_LENGTH];
    let mut blob_id = [0_u8; ID_LENGTH];
    let mut sentinel = vec![0_u8; SENTINEL_LENGTH];
    input.read_exact(aead.as_mut())?;
    input.read_exact(content.as_mut())?;
    input.read_exact(&mut account)?;
    input.read_exact(&mut blob_id)?;
    input.read_exact(&mut sentinel)?;
    Ok((
        aead,
        content,
        account,
        blob_id,
        String::from_utf8(sentinel)?,
    ))
}

fn wait_for_crash_ready(
    child: &mut ChildGuard,
    workspace: &EvidenceWorkspace,
    directory: &Path,
) -> Result {
    let deadline = Instant::now() + Duration::from_secs(20);
    let first_record_length = u64::try_from(FIRST_DURABLE_RECORD_LENGTH)?;
    while Instant::now() < deadline {
        if let Some(status) = child.child_mut().try_wait()? {
            child.mark_reaped();
            return Err(format!("crash child exited before ready: {status}").into());
        }
        if workspace.ready().is_file()
            && find_staging(directory)?.is_some_and(|path| {
                path.metadata()
                    .is_ok_and(|meta| meta.len() == first_record_length)
            })
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("crash child did not expose durable staging before timeout".into())
}

fn write_fixture(
    directory: &Path,
    plaintext: &[u8],
    keys: &BlobKeys,
    expected: ExpectedBlob,
    nonces: &mut NonceRegistry,
) -> Result<crate::format::WriteOutcome> {
    let mut input = Cursor::new(plaintext);
    write_blob(
        directory,
        &mut input,
        u64::try_from(plaintext.len())?,
        keys,
        expected,
        nonces,
        |_index, _file, _path| Ok(()),
    )
    .map_err(Into::into)
}

fn assert_reader_rejected(path: &Path, keys: &BlobKeys, expected: ExpectedBlob) -> Result {
    let accepted = BlobReader::open(path, keys, expected)
        .and_then(|mut reader| reader.read_all())
        .is_ok();
    if accepted {
        return Err("invalid blob was accepted".into());
    }
    Ok(())
}

fn assert_mutation_rejected(
    workspace: &EvidenceWorkspace,
    case: &str,
    source_path: &Path,
    bytes: &[u8],
    keys: &BlobKeys,
    expected: ExpectedBlob,
) -> Result {
    let path = mutation_path(workspace, case, source_path, bytes)?;
    assert_reader_rejected(&path, keys, expected)
}

fn mutation_path(
    workspace: &EvidenceWorkspace,
    case: &str,
    source_path: &Path,
    bytes: &[u8],
) -> Result<PathBuf> {
    let directory = workspace.case_directory(case);
    fs::create_dir_all(&directory)?;
    let path = directory.join(
        source_path
            .file_name()
            .ok_or("source filename unavailable")?,
    );
    fs::write(&path, bytes)?;
    Ok(path)
}

fn fixture_bytes(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add(u8::try_from(index % 251).unwrap_or(0)))
        .collect()
}

fn crash_plaintext(sentinel: &str) -> Vec<u8> {
    let mut plaintext = fixture_bytes(CHUNK_SIZE * 3 + 29, 103);
    for offset in [19, CHUNK_SIZE + 31, CHUNK_SIZE * 2 + 43] {
        plaintext[offset..offset + sentinel.len()].copy_from_slice(sentinel.as_bytes());
    }
    plaintext
}

fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut value = [0_u8; N];
    getrandom::fill(&mut value)?;
    Ok(value)
}

fn random_key() -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    Ok(Zeroizing::new(random_array()?))
}

fn random_sentinel() -> Result<String> {
    let bytes: [u8; 31] = random_array()?;
    Ok(format!("TERSA-M0-SENTINEL-{}", lower_hex(&bytes)))
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

fn find_staging(directory: &Path) -> Result<Option<PathBuf>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && is_reserved_staging_name(&entry.file_name().to_string_lossy())
        {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn published_files(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type()?.is_file()
            && name.len() == 64
            && name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            files.push(entry.path());
        }
    }
    Ok(files)
}

fn assert_absent(files: &[PathBuf], sentinel: &str) -> Result {
    if files
        .iter()
        .any(|path| file_contains(path, sentinel.as_bytes()).unwrap_or(true))
    {
        return Err("plaintext sentinel found in controlled blob artifact".into());
    }
    Ok(())
}

fn file_contains(path: &Path, needle: &[u8]) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data.windows(needle.len()).any(|window| window == needle))
}

fn plaintext_positive_control(workspace: &EvidenceWorkspace, sentinel: &str) -> Result {
    let control = workspace.root().join("plaintext-positive-control");
    fs::write(&control, sentinel.as_bytes())?;
    if !file_contains(&control, sentinel.as_bytes())? {
        return Err("plaintext scanner positive control did not detect its sentinel".into());
    }
    Ok(())
}

#[derive(Debug)]
struct EvidenceWorkspace {
    root: PathBuf,
    owns_root: bool,
}

impl EvidenceWorkspace {
    fn new() -> Result<Self> {
        let root =
            env::temp_dir().join(format!("tersa-blob-{}", lower_hex(&random_array::<12>()?)));
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            owns_root: true,
        })
    }

    fn from_environment() -> Result<Self> {
        Ok(Self {
            root: PathBuf::from(
                env::var_os("TERSA_BLOB_EVIDENCE_DIR").ok_or("evidence directory unavailable")?,
            ),
            owns_root: false,
        })
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn case_directory(&self, case: &str) -> PathBuf {
        self.root.join(case)
    }

    fn ready(&self) -> PathBuf {
        self.root.join("crash-ready")
    }

    fn regular_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        collect_regular_files(&self.root, &mut files)?;
        Ok(files)
    }
}

impl Drop for EvidenceWorkspace {
    fn drop(&mut self) {
        if self.owns_root {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn collect_regular_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_regular_files(&entry.path(), files)?;
        } else if entry.file_type()?.is_file() {
            files.push(entry.path());
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn mark_reaped(&mut self) {
        self.reaped = true;
    }

    fn kill_and_wait(&mut self) -> Result<ExitStatus> {
        self.child.kill()?;
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

// Rust guideline compliant 1.0.
