// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded correctness, privacy, and host-performance evidence for M0 search.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode, OpenFlags, params};
use tantivy::collector::TopDocs;
use tantivy::directory::{Directory, TerminatingWrite};
use tantivy::query::QueryParser;
use tantivy::schema::{STORED, STRING, Schema, TEXT, Value};
use tantivy::{Index, IndexSettings, ReloadPolicy, TantivyDocument, doc};
use zeroize::{Zeroize, Zeroizing};

use crate::directory::{CHUNK_SIZE, CIPHER_VERSION, SQLITE_VERSION, SqlCipherDirectory};

const PASS_LINE: &str = "Encrypted search M0 feasibility PASS";
const SENTINEL_LENGTH: usize = 80;
const QUERY_RUNS: usize = 20;

type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Ci,
    Manual,
    Smoke,
}

impl Profile {
    fn from_args() -> Result<Self> {
        let mut arguments = std::env::args().skip(1);
        match (arguments.next().as_deref(), arguments.next().as_deref()) {
            (None, None) | (Some("--profile"), Some("ci")) => Ok(Self::Ci),
            (Some("--profile"), Some("manual")) => Ok(Self::Manual),
            (Some("--profile"), Some("smoke")) => Ok(Self::Smoke),
            _ => Err("usage: tersa-search-spike [--profile ci|manual|smoke]".into()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Ci => "ci",
            Self::Manual => "manual",
            Self::Smoke => "smoke",
        }
    }

    fn message_count(self) -> usize {
        match self {
            Self::Ci => 10_000,
            Self::Manual => 100_000,
            Self::Smoke => 100,
        }
    }

    fn normalized_text_target(self) -> usize {
        match self {
            Self::Ci => 128 * 1024 * 1024,
            Self::Manual => 2 * 1024 * 1024 * 1024,
            Self::Smoke => 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Evidence {
    profile: Profile,
    messages: usize,
    normalized_text_bytes: usize,
    index_bytes: u64,
    fts_p95: Duration,
    tantivy_p95: Duration,
}

/// Runs synthetic checks and emits only aggregate, non-content evidence.
pub(crate) fn run() -> Result {
    let profile = Profile::from_args()?;
    let workspace = Workspace::new()?;
    let mut key = random_bytes(32)?;
    let sentinel = random_sentinel()?;
    let directory = SqlCipherDirectory::create(workspace.database(), &key)?;

    let (normalized_text_bytes, fts_p95) = build_and_verify_fts(&directory, profile, &sentinel)?;
    let (index_bytes, tantivy_p95) = build_and_verify_tantivy(&directory, profile, &sentinel)?;
    verify_directory_contract(&directory)?;
    verify_integrity(&directory)?;
    assert_absent(&workspace.controlled_files()?, &sentinel)?;
    verify_reopen(&workspace, directory, &key, &sentinel, profile)?;
    plaintext_positive_control(&workspace)?;
    key.zeroize();

    emit(Evidence {
        profile,
        messages: profile.message_count(),
        normalized_text_bytes,
        index_bytes,
        fts_p95,
        tantivy_p95,
    });
    Ok(())
}

fn build_and_verify_fts(
    directory: &SqlCipherDirectory,
    profile: Profile,
    sentinel: &str,
) -> Result<(usize, Duration)> {
    let mut connection = directory.connection()?;
    connection.execute_batch(
        "CREATE VIRTUAL TABLE mail_fts USING fts5(
             message_id UNINDEXED,
             subject,
             body
         );",
    )?;
    let transaction = connection.transaction()?;
    let mut normalized_text_bytes = 0_usize;
    for index in 0..profile.message_count() {
        let fixture = fixture(index, profile, sentinel);
        normalized_text_bytes = normalized_text_bytes
            .saturating_add(fixture.subject.len())
            .saturating_add(fixture.body.len());
        transaction.execute(
            "INSERT INTO mail_fts (message_id, subject, body) VALUES (?1, ?2, ?3)",
            params![fixture.id, fixture.subject, fixture.body],
        )?;
    }
    transaction.commit()?;
    if normalized_text_bytes < profile.normalized_text_target() {
        return Err("synthetic FTS corpus missed its normalized-text target".into());
    }
    let actual = fts_ids(&connection, "orchard")?;
    assert_ids("SQLCipher FTS5", &actual, &expected_ids(profile))?;
    let p95 = query_p95(|| {
        let mut statement = connection.prepare(
            "SELECT message_id FROM mail_fts
             WHERE mail_fts MATCH 'orchard' LIMIT 50",
        )?;
        let count = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .len();
        if count != top_result_count(profile) {
            return Err("FTS top-50 query returned the wrong result count".into());
        }
        Ok(())
    })?;
    Ok((normalized_text_bytes, p95))
}

fn build_and_verify_tantivy(
    directory: &SqlCipherDirectory,
    profile: Profile,
    sentinel: &str,
) -> Result<(u64, Duration)> {
    let mut schema_builder = Schema::builder();
    let id = schema_builder.add_text_field("id", STRING | STORED);
    let subject = schema_builder.add_text_field("subject", TEXT);
    let body = schema_builder.add_text_field("body", TEXT);
    let schema = schema_builder.build();
    let index = Index::create(directory.clone(), schema, IndexSettings::default())?;
    let mut writer = index.writer_with_num_threads::<TantivyDocument>(1, 30_000_000)?;
    for message_index in 0..profile.message_count() {
        let fixture = fixture(message_index, profile, sentinel);
        writer.add_document(doc!(
            id => fixture.id,
            subject => fixture.subject,
            body => fixture.body
        ))?;
    }
    writer.commit()?;
    drop(writer);

    let reader = index
        .reader_builder()
        .reload_policy(ReloadPolicy::Manual)
        .try_into()?;
    reader.reload()?;
    let parser = QueryParser::for_index(&index, vec![subject, body]);
    let query = parser.parse_query("orchard")?;
    let searcher = reader.searcher();
    let actual = tantivy_ids(&searcher, query.as_ref(), id, profile.message_count())?;
    assert_ids("Tantivy", &actual, &expected_ids(profile))?;

    let p95 = query_p95(|| {
        let results = searcher.search(&query, &TopDocs::with_limit(50).order_by_score())?;
        if results.len() != top_result_count(profile) {
            return Err("Tantivy top-50 query returned the wrong result count".into());
        }
        Ok(())
    })?;

    let held_writer = index.writer_with_num_threads::<TantivyDocument>(1, 30_000_000)?;
    if index
        .writer_with_num_threads::<TantivyDocument>(1, 30_000_000)
        .is_ok()
    {
        return Err("a second Tantivy writer bypassed the directory lock".into());
    }
    let reader_index = index.clone();
    let reader_searcher = reader.searcher();
    let reader_thread = std::thread::spawn(move || -> Result<usize> {
        let parser = QueryParser::for_index(&reader_index, vec![subject, body]);
        let query = parser.parse_query("orchard")?;
        Ok(reader_searcher
            .search(&query, &TopDocs::with_limit(50).order_by_score())?
            .len())
    });
    if reader_thread
        .join()
        .map_err(|_panic| "concurrent search reader panicked")??
        != top_result_count(profile)
    {
        return Err("concurrent search reader returned the wrong result count".into());
    }
    drop(held_writer);

    let index_bytes = directory.current_index_bytes()?;
    drop(reader);
    drop(index);
    Ok((index_bytes, p95))
}

fn verify_directory_contract(directory: &SqlCipherDirectory) -> Result {
    let immutable_path = Path::new("immutable-handle");
    let original = vec![b'a'; CHUNK_SIZE * 3];
    directory.atomic_write(immutable_path, &original)?;
    let immutable = directory.open_read(immutable_path)?;
    directory.atomic_write(immutable_path, b"replacement")?;
    directory.delete(immutable_path)?;
    if immutable.read_bytes()?.as_slice() != original {
        return Err("open handle changed after replacement and deletion".into());
    }

    let unpublished = Path::new("unpublished-generation");
    let mut provisional = directory.open_write(unpublished)?;
    provisional.write_all(b"not visible before termination")?;
    if directory.exists(unpublished)? {
        return Err("staged generation became visible before termination".into());
    }
    if directory.open_write(unpublished).is_ok() {
        return Err("a second staged writer reserved the same path".into());
    }
    provisional.terminate()?;
    if !directory.exists(unpublished)? {
        return Err("terminated generation was not published".into());
    }

    let range_path = Path::new("range-read");
    directory.atomic_write(range_path, &vec![b'r'; CHUNK_SIZE * 3])?;
    let handle = directory.open_read(range_path)?;
    let before = directory.read_metrics();
    let result = handle
        .slice(CHUNK_SIZE + 17..CHUNK_SIZE + 49)
        .read_bytes()?;
    let after = directory.read_metrics();
    if result.len() != 32
        || after.requests != before.requests + 1
        || after.chunks_loaded != before.chunks_loaded + 1
        || after.storage_bytes_loaded != before.storage_bytes_loaded + CHUNK_SIZE
        || after.bytes_returned != before.bytes_returned + 32
    {
        return Err("range read did not load exactly one intersecting SQLCipher chunk".into());
    }
    Ok(())
}

fn verify_reopen(
    workspace: &Workspace,
    directory: SqlCipherDirectory,
    key: &[u8],
    sentinel: &str,
    profile: Profile,
) -> Result {
    directory.sync_directory()?;
    assert_absent(&workspace.controlled_files()?, sentinel)?;
    drop(directory);

    let keyless =
        Connection::open_with_flags(workspace.database(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    expect_not_a_database(&keyless)?;
    drop(keyless);
    let wrong_key = [0_u8; 32];
    if SqlCipherDirectory::open_existing(workspace.database(), &wrong_key).is_ok() {
        return Err("wrong SQLCipher key opened the search store".into());
    }

    let reopened = SqlCipherDirectory::open_existing(workspace.database(), key)?;
    let connection = reopened.connection()?;
    let ids = fts_ids(&connection, "orchard")?;
    drop(connection);
    assert_ids("reopened SQLCipher FTS5", &ids, &expected_ids(profile))?;
    verify_integrity(&reopened)?;
    assert_absent(&workspace.controlled_files()?, sentinel)
}

fn verify_integrity(directory: &SqlCipherDirectory) -> Result {
    let connection = directory.connection()?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err("SQLite integrity_check failed".into());
    }
    let mut statement = connection.prepare("PRAGMA cipher_integrity_check")?;
    if statement.query([])?.next()?.is_some() {
        return Err("SQLCipher cipher_integrity_check failed".into());
    }
    Ok(())
}

fn expect_not_a_database(connection: &Connection) -> Result {
    match connection.query_row("SELECT name FROM sqlite_master LIMIT 1", [], |row| {
        row.get::<_, String>(0)
    }) {
        Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == ErrorCode::NotADatabase => {
            Ok(())
        }
        _ => Err("missing SQLCipher key did not fail closed".into()),
    }
}

#[derive(Debug)]
struct Fixture {
    id: String,
    subject: String,
    body: String,
}

fn fixture(index: usize, profile: Profile, sentinel: &str) -> Fixture {
    let id = format!("m-{index:06}");
    let subject = if index.is_multiple_of(10) {
        format!("Synthetic orchard message {index}")
    } else {
        format!("Synthetic harbor message {index}")
    };
    let minimum_body_bytes = profile
        .normalized_text_target()
        .div_ceil(profile.message_count());
    let prefix = if index == 1 {
        format!("{sentinel} synthetic privacy fixture ")
    } else {
        "synthetic corpus fixture ".to_owned()
    };
    let filler = "bounded local search content ";
    let repeats = minimum_body_bytes
        .saturating_sub(prefix.len())
        .div_ceil(filler.len());
    let mut body = String::with_capacity(prefix.len() + repeats * filler.len());
    body.push_str(&prefix);
    for _ in 0..repeats {
        body.push_str(filler);
    }
    Fixture { id, subject, body }
}

fn expected_ids(profile: Profile) -> Vec<String> {
    (0..profile.message_count())
        .step_by(10)
        .map(|index| format!("m-{index:06}"))
        .collect()
}

fn top_result_count(profile: Profile) -> usize {
    expected_ids(profile).len().min(50)
}

fn fts_ids(connection: &Connection, query: &str) -> Result<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT message_id FROM mail_fts WHERE mail_fts MATCH ?1 ORDER BY message_id")?;
    Ok(statement
        .query_map([query], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?)
}

fn tantivy_ids(
    searcher: &tantivy::Searcher,
    query: &dyn tantivy::query::Query,
    id: tantivy::schema::Field,
    limit: usize,
) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    for (_, address) in searcher.search(query, &TopDocs::with_limit(limit).order_by_score())? {
        let document: TantivyDocument = searcher.doc(address)?;
        let value = document
            .get_first(id)
            .ok_or("result missing stored identifier")?;
        ids.push(
            value
                .as_str()
                .ok_or("stored identifier was not text")?
                .to_owned(),
        );
    }
    ids.sort();
    Ok(ids)
}

fn assert_ids(label: &str, actual: &[String], expected: &[String]) -> Result {
    let actual: BTreeSet<_> = actual.iter().collect();
    let expected: BTreeSet<_> = expected.iter().collect();
    if actual != expected {
        return Err(format!("{label} exact ID match set differs").into());
    }
    Ok(())
}

fn query_p95(mut query: impl FnMut() -> Result) -> Result<Duration> {
    let mut durations = Vec::with_capacity(QUERY_RUNS);
    for _ in 0..QUERY_RUNS {
        let started = Instant::now();
        query()?;
        durations.push(started.elapsed());
    }
    durations.sort_unstable();
    Ok(durations[QUERY_RUNS * 95 / 100 - 1])
}

fn emit(evidence: Evidence) {
    println!("{PASS_LINE}");
    println!(
        "Profile {} messages={} normalized_text_bytes={}",
        evidence.profile.name(),
        evidence.messages,
        evidence.normalized_text_bytes
    );
    println!(
        "Search engine SQLCipher {CIPHER_VERSION} SQLite {SQLITE_VERSION} FTS5 and Tantivy 0.26.1"
    );
    println!(
        "Host metrics fts_p95_ms={} tantivy_p95_ms={} current_index_bytes={}",
        evidence.fts_p95.as_millis(),
        evidence.tantivy_p95.as_millis(),
        evidence.index_bytes
    );
    println!("NOT A DEVICE-GATE RESULT");
}

#[derive(Debug)]
struct Workspace {
    root: PathBuf,
    database: PathBuf,
    positive_control: PathBuf,
}

impl Workspace {
    fn new() -> Result<Self> {
        let random = random_bytes(8)?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random.iter() {
            use std::fmt::Write as _;
            write!(&mut suffix, "{byte:02x}")?;
        }
        let root = std::env::temp_dir().join(format!("tersa-search-{suffix}"));
        fs::create_dir_all(&root)?;
        Ok(Self {
            database: root.join("search.sqlite"),
            positive_control: root.join("positive-control.txt"),
            root,
        })
    }

    fn database(&self) -> &Path {
        &self.database
    }

    fn controlled_files(&self) -> Result<Vec<PathBuf>> {
        Ok(fs::read_dir(&self.root)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_file() && path != &self.positive_control)
            .collect())
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn random_bytes(length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

fn random_sentinel() -> Result<Zeroizing<String>> {
    let bytes = random_bytes(SENTINEL_LENGTH / 2)?;
    let mut sentinel = Zeroizing::new(String::with_capacity(SENTINEL_LENGTH));
    for byte in bytes.iter() {
        use std::fmt::Write as _;
        write!(&mut sentinel, "{byte:02x}")?;
    }
    Ok(sentinel)
}

fn assert_absent(files: &[PathBuf], sentinel: &str) -> Result {
    for path in files {
        if contains(path, sentinel.as_bytes())? {
            return Err("random sentinel appeared in an encrypted search artifact".into());
        }
    }
    Ok(())
}

fn plaintext_positive_control(workspace: &Workspace) -> Result {
    let sentinel = random_sentinel()?;
    File::create(&workspace.positive_control)?.write_all(sentinel.as_bytes())?;
    if !contains(&workspace.positive_control, sentinel.as_bytes())? {
        return Err("plaintext privacy-scanner positive control failed".into());
    }
    Ok(())
}

fn contains(path: &Path, needle: &[u8]) -> Result<bool> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    Ok(bytes.windows(needle.len()).any(|window| window == needle))
}

#[cfg(test)]
mod tests {
    use super::{Profile, SENTINEL_LENGTH, expected_ids, fixture, random_sentinel};

    #[test]
    fn profiles_keep_the_agreed_corpus_sizes() {
        assert_eq!(Profile::Ci.message_count(), 10_000);
        assert_eq!(Profile::Ci.normalized_text_target(), 128 * 1024 * 1024);
        assert_eq!(Profile::Manual.message_count(), 100_000);
        assert_eq!(
            Profile::Manual.normalized_text_target(),
            2 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn fixtures_have_deterministic_exact_match_ids() {
        let sentinel = "s".repeat(SENTINEL_LENGTH);
        let actual = (0..Profile::Smoke.message_count())
            .filter_map(|index| {
                let fixture = fixture(index, Profile::Smoke, &sentinel);
                fixture.subject.contains("orchard").then_some(fixture.id)
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected_ids(Profile::Smoke));
    }

    #[test]
    fn privacy_sentinels_are_random_hex_values() {
        let first = random_sentinel().expect("first random sentinel");
        let second = random_sentinel().expect("second random sentinel");
        assert_eq!(first.len(), SENTINEL_LENGTH);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first.as_str(), second.as_str());
    }
}
