// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Proves the bounded Apple `SQLCipher` storage feasibility contract.

#![forbid(unsafe_code)]

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use std::env;
    use std::error::Error;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use rusqlite::{Connection, Error as SqlError, ErrorCode, OpenFlags, params};
    use zeroize::{Zeroize, Zeroizing};

    const ROW_COUNT: i64 = 3;
    const SENTINEL_LENGTH: usize = 80;
    const CIPHER_VERSION: &str = "4.10.0 community";
    const PASS_LINE: &str = "SQLCipher M0 feasibility PASS";

    type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

    /// Runs the parent or child half of the storage evidence protocol.
    pub fn run() -> Result {
        if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("child")) {
            child()
        } else {
            parent()
        }
    }

    fn parent() -> Result {
        let workspace = EvidenceWorkspace::new()?;
        let key = random_bytes(32)?;
        let sentinel = random_sentinel()?;
        let temp_sentinel = random_sentinel()?;
        let mut child = ChildGuard::new(spawn_child(&workspace)?);
        send_protocol(child.child_mut(), &key, &sentinel, &temp_sentinel)?;
        wait_for_ready(&mut child, &workspace)?;
        assert_absent(&workspace.controlled_files()?, &sentinel)?;
        assert_absent(&workspace.controlled_files()?, &temp_sentinel)?;

        let status = child.kill_and_wait()?;
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if status.signal() != Some(9) {
                return Err("storage child was not terminated with SIGKILL".into());
            }
        }
        #[cfg(not(unix))]
        if status.success() {
            return Err("storage child unexpectedly exited successfully".into());
        }

        reopen_and_verify(&workspace, &key, &sentinel, &temp_sentinel)?;
        plaintext_positive_control(&workspace)?;
        println!("{PASS_LINE}");
        println!("SQLCipher provider commoncrypto");
        println!("SQLCipher version {CIPHER_VERSION}");
        println!("SQLCipher journal mode wal");
        Ok(())
    }

    fn child() -> Result {
        let (mut key, sentinel, temp_sentinel) = receive_protocol()?;
        let workspace = EvidenceWorkspace::from_environment()?;
        let connection = open_encrypted(workspace.database(), &key)?;
        key.zeroize();
        configure(&connection)?;
        verify_cipher(&connection)?;
        connection.execute_batch(
            "PRAGMA wal_autocheckpoint = 0; \
             CREATE TABLE records (id INTEGER PRIMARY KEY, payload TEXT NOT NULL);",
        )?;
        let auto_checkpoint: i64 =
            connection.query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))?;
        if auto_checkpoint != 0 {
            return Err("SQLCipher WAL auto-checkpoint is not disabled".into());
        }
        {
            let transaction = connection.unchecked_transaction()?;
            for index in 0..ROW_COUNT {
                let payload = if index == 1 {
                    &sentinel
                } else {
                    "non-sensitive fixture"
                };
                transaction.execute("INSERT INTO records (payload) VALUES (?1)", [payload])?;
            }
            transaction.commit()?;
        }
        exercise_memory_temp_store(&connection, &workspace, &temp_sentinel)?;
        let ready = File::create(workspace.ready())?;
        ready.sync_all()?;
        loop {
            std::thread::park();
        }
    }

    fn reopen_and_verify(
        workspace: &EvidenceWorkspace,
        key: &[u8],
        sentinel: &str,
        temp_sentinel: &str,
    ) -> Result {
        expect_not_a_database(workspace.database(), None)?;
        let wrong_key = [0_u8; 32];
        expect_not_a_database(workspace.database(), Some(&wrong_key))?;

        let connection = open_encrypted(workspace.database(), key)?;
        configure(&connection)?;
        let rows: i64 =
            connection.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
        if rows != ROW_COUNT {
            return Err("recovered row count differs from the committed transaction".into());
        }
        let recovered: String =
            connection.query_row("SELECT payload FROM records WHERE id = 2", [], |row| {
                row.get(0)
            })?;
        if recovered != sentinel {
            return Err("recovered committed rows differ from the expected values".into());
        }
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err("SQLite integrity_check did not return ok".into());
        }
        let mut cipher_integrity = connection.prepare("PRAGMA cipher_integrity_check")?;
        let mut cipher_failures = cipher_integrity.query([])?;
        if cipher_failures.next()?.is_some() {
            return Err("cipher_integrity_check returned a failure".into());
        }
        drop(cipher_failures);
        drop(cipher_integrity);
        drop(connection);

        assert_absent(&workspace.controlled_files()?, sentinel)?;
        assert_absent(&workspace.controlled_files()?, temp_sentinel)?;
        assert_not_sqlite_header(workspace.database())
    }

    fn expect_not_a_database(database: &Path, key: Option<&[u8]>) -> Result {
        let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        if let Some(key) = key {
            apply_key(&connection, key)?;
        }
        match connection.query_row("SELECT name FROM sqlite_master LIMIT 1", [], |row| {
            row.get::<_, String>(0)
        }) {
            Err(SqlError::SqliteFailure(error, _)) if error.code == ErrorCode::NotADatabase => {
                Ok(())
            }
            _ => Err("missing or wrong key did not fail schema access with NOTADB".into()),
        }
    }

    fn open_encrypted(database: &Path, key: &[u8]) -> Result<Connection> {
        let connection = Connection::open(database)?;
        apply_key(&connection, key)?;
        Ok(connection)
    }

    fn apply_key(connection: &Connection, key: &[u8]) -> Result {
        let mut key_literal = Zeroizing::new(String::with_capacity(
            key.len().saturating_mul(2).saturating_add(3),
        ));
        key_literal.push_str("x'");
        append_hex(&mut key_literal, key);
        key_literal.push('\'');
        connection.pragma_update(None, "key", key_literal.as_str())?;
        Ok(())
    }

    fn configure(connection: &Connection) -> Result {
        connection.execute_batch(
            "PRAGMA journal_mode = WAL; \
             PRAGMA secure_delete = ON; \
             PRAGMA temp_store = MEMORY;",
        )?;
        Ok(())
    }

    fn verify_cipher(connection: &Connection) -> Result {
        let provider: String =
            connection.query_row("PRAGMA cipher_provider", [], |row| row.get(0))?;
        if provider != "commoncrypto" {
            return Err("SQLCipher provider is not CommonCrypto".into());
        }
        let version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if version != CIPHER_VERSION {
            return Err("SQLCipher version is not the required community release".into());
        }
        let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if journal != "wal" {
            return Err("SQLCipher WAL mode is not enabled".into());
        }
        let secure_delete: i64 =
            connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
        if secure_delete != 1 {
            return Err("SQLCipher secure-delete pragma is not enabled".into());
        }
        let temp_store: i64 = connection.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
        if temp_store != 2 {
            return Err("SQLCipher in-memory temporary-store pragma is not enabled".into());
        }
        Ok(())
    }

    fn exercise_memory_temp_store(
        connection: &Connection,
        workspace: &EvidenceWorkspace,
        sentinel: &str,
    ) -> Result {
        connection.execute_batch("CREATE TEMP TABLE spill (payload TEXT NOT NULL);")?;
        let payload = format!("{sentinel}{}", "x".repeat(262_144));
        let transaction = connection.unchecked_transaction()?;
        for _ in 0..32 {
            transaction.execute("INSERT INTO spill (payload) VALUES (?1)", params![payload])?;
        }
        transaction.commit()?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM spill", [], |row| row.get(0))?;
        if count != 32 {
            return Err("in-memory temporary-store control did not preserve every row".into());
        }
        if !regular_files(workspace.temp())?.is_empty() {
            return Err("in-memory temporary store created a filesystem artifact".into());
        }
        assert_absent(&workspace.controlled_files()?, sentinel)
    }

    fn regular_files(directory: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        collect_regular_files(directory, &mut files)?;
        Ok(files)
    }

    fn spawn_child(workspace: &EvidenceWorkspace) -> Result<Child> {
        let executable = env::current_exe()?;
        Command::new(executable)
            .arg("child")
            .env("TERSA_SQLCIPHER_EVIDENCE_DIR", workspace.root())
            .env("SQLITE_TMPDIR", workspace.temp())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(Into::into)
    }

    fn send_protocol(child: &mut Child, key: &[u8], sentinel: &str, temp_sentinel: &str) -> Result {
        if sentinel.len() != SENTINEL_LENGTH || temp_sentinel.len() != SENTINEL_LENGTH {
            return Err("storage evidence sentinel has an invalid length".into());
        }
        let stdin = child.stdin.as_mut().ok_or("child stdin unavailable")?;
        stdin.write_all(key)?;
        stdin.write_all(sentinel.as_bytes())?;
        stdin.write_all(temp_sentinel.as_bytes())?;
        stdin.flush()?;
        drop(child.stdin.take());
        Ok(())
    }

    fn wait_for_ready(child: &mut ChildGuard, workspace: &EvidenceWorkspace) -> Result {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(status) = child.child_mut().try_wait()? {
                child.mark_reaped();
                return Err(format!(
                    "storage child exited before the committed WAL checkpoint: {status}"
                )
                .into());
            }
            if workspace.ready().is_file() && wal_is_non_empty(workspace.database())? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err("storage child did not reach the committed WAL checkpoint before timeout".into())
    }

    fn receive_protocol() -> Result<(Zeroizing<Vec<u8>>, String, String)> {
        let mut input = std::io::stdin().lock();
        let mut key = Zeroizing::new(vec![0_u8; 32]);
        let mut sentinel = vec![0_u8; SENTINEL_LENGTH];
        let mut temp_sentinel = vec![0_u8; SENTINEL_LENGTH];
        input.read_exact(&mut key)?;
        input.read_exact(&mut sentinel)?;
        input.read_exact(&mut temp_sentinel)?;
        Ok((
            key,
            String::from_utf8(sentinel)?,
            String::from_utf8(temp_sentinel)?,
        ))
    }

    fn random_bytes(length: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(vec![0_u8; length]);
        getrandom::fill(&mut bytes)?;
        Ok(bytes)
    }

    fn random_sentinel() -> Result<String> {
        let bytes = random_bytes(31)?;
        Ok(format!("TERSA-M0-SENTINEL-{}", hex(&bytes)))
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len().saturating_mul(2));
        append_hex(&mut output, bytes);
        output
    }

    fn append_hex(output: &mut String, bytes: &[u8]) {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
    }

    fn wal_is_non_empty(database: &Path) -> Result<bool> {
        match fs::metadata(database.with_extension("sqlite-wal")) {
            Ok(metadata) => Ok(metadata.len() > 0),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn assert_absent(files: &[PathBuf], sentinel: &str) -> Result {
        if files
            .iter()
            .any(|path| file_contains(path, sentinel.as_bytes()).unwrap_or(true))
        {
            return Err(
                "plaintext sentinel found in a controlled encrypted artifact: M0 finding".into(),
            );
        }
        Ok(())
    }

    fn file_contains(path: &Path, needle: &[u8]) -> Result<bool> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data.windows(needle.len()).any(|window| window == needle))
    }

    fn assert_not_sqlite_header(database: &Path) -> Result {
        let mut header = [0_u8; 16];
        File::open(database)?.read_exact(&mut header)?;
        if header == *b"SQLite format 3\0" {
            return Err("encrypted main database retains the SQLite format 3 header".into());
        }
        Ok(())
    }

    fn plaintext_positive_control(workspace: &EvidenceWorkspace) -> Result {
        let control = workspace.root().join("plaintext-control.sqlite");
        let sentinel = random_sentinel()?;
        let connection = Connection::open(&control)?;
        connection.execute("CREATE TABLE control (payload TEXT NOT NULL)", [])?;
        connection.execute(
            "INSERT INTO control (payload) VALUES (?1)",
            [sentinel.as_str()],
        )?;
        drop(connection);
        if !file_contains(&control, sentinel.as_bytes())? {
            return Err(
                "plaintext SQLite scanner positive control did not detect its sentinel".into(),
            );
        }
        Ok(())
    }

    #[derive(Debug)]
    struct EvidenceWorkspace {
        root: PathBuf,
        database: PathBuf,
        temp: PathBuf,
    }

    impl EvidenceWorkspace {
        fn new() -> Result<Self> {
            let root = env::temp_dir().join(format!("tersa-sqlcipher-{}", hex(&random_bytes(12)?)));
            fs::create_dir_all(root.join("encrypted"))?;
            fs::create_dir_all(root.join("temp"))?;
            Ok(Self {
                database: root.join("encrypted/storage.sqlite"),
                temp: root.join("temp"),
                root,
            })
        }

        fn from_environment() -> Result<Self> {
            let root = PathBuf::from(
                env::var_os("TERSA_SQLCIPHER_EVIDENCE_DIR")
                    .ok_or("evidence directory unavailable")?,
            );
            Ok(Self {
                database: root.join("encrypted/storage.sqlite"),
                temp: root.join("temp"),
                root,
            })
        }

        fn root(&self) -> &Path {
            &self.root
        }
        fn database(&self) -> &Path {
            &self.database
        }
        fn temp(&self) -> &Path {
            &self.temp
        }

        fn ready(&self) -> PathBuf {
            self.root.join("ready")
        }

        fn controlled_files(&self) -> Result<Vec<PathBuf>> {
            let mut files = Vec::new();
            collect_regular_files(&self.root, &mut files)?;
            Ok(files)
        }
    }

    impl Drop for EvidenceWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
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

    fn collect_regular_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                collect_regular_files(&path, files)?;
            } else if kind.is_file() {
                files.push(path);
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    apple::run().map_err(|_error| "SQLCipher feasibility failed".into())
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {
    println!("SQLCipher Apple-only diagnostic is unavailable on this target.");
}

// Rust guideline compliant 1.0.
