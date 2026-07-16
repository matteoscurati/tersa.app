// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides an account-scoped `SQLCipher` mailbox store for macOS.
//!
//! This adapter has synchronous database internals and lazy runtime-free
//! futures. Callers must poll it on a bounded blocking executor rather than a
//! latency-sensitive async executor thread. It deliberately owns neither blob
//! encryption nor cross-file commit orchestration.

#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
mod macos {
    use std::fmt;
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::Duration;

    use rusqlite::{Connection, ErrorCode, OpenFlags, Transaction, params};
    use tersa_application::mailbox::{BoxFuture, MailboxStore, MailboxStoreError, StoreLimit};
    use tersa_domain::mailbox::{
        AccountId, HeaderText, Message, MessageContent, MessageEnvelope, MessageId, ThreadId,
        UnixTimestampMillis,
    };
    use zeroize::{Zeroize, Zeroizing};

    // Fixed ownership marker for this product account-store schema.
    const APPLICATION_ID: i64 = 0x5453_4D31;
    const VERSION: i64 = 1;
    const CANONICAL_SCHEMA_OBJECT_COUNT: usize = 4;
    const MAX_SCHEMA_KIND_LEN: i64 = 16;
    const MAX_SCHEMA_NAME_LEN: i64 = 256;
    const MAX_SCHEMA_SQL_LEN: i64 = 16 * 1_024;
    // Bounds lock waits without introducing retries or background work.
    const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
    const MIGRATION: &str = include_str!("../migrations/0001_account_mailbox.sql");

    /// Owns a redacted, zeroizing `SQLCipher` database key.
    pub struct DatabaseKey(Zeroizing<[u8; 32]>);

    impl DatabaseKey {
        /// Creates a database key from exactly 32 raw bytes.
        #[must_use]
        pub fn new(bytes: [u8; 32]) -> Self {
            Self(Zeroizing::new(bytes))
        }
    }

    impl fmt::Debug for DatabaseKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("DatabaseKey([REDACTED])")
        }
    }

    /// Stores one account's mailbox in one `SQLCipher` database file.
    pub struct SqlCipherMailboxStore {
        account: AccountId,
        connection: Mutex<Connection>,
        #[cfg(test)]
        fail_next_mutation: Mutex<bool>,
    }

    impl fmt::Debug for SqlCipherMailboxStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SqlCipherMailboxStore([REDACTED])")
        }
    }

    impl SqlCipherMailboxStore {
        /// Opens or creates the database for `account` at caller-selected `path`.
        ///
        /// The key is consumed, applied before schema reads, and zeroized after
        /// use. A fresh file is claimed only when its `SQLite` schema is empty.
        ///
        /// # Errors
        ///
        /// Returns opaque corruption for a wrong key, unknown owner, invalid
        /// schema, or failed integrity validation; operational failures return
        /// opaque storage errors.
        pub fn open<P: AsRef<Path>>(
            account: AccountId,
            path: P,
            mut key: DatabaseKey,
        ) -> Result<Self, MailboxStoreError> {
            let connection = open_connection(path.as_ref()).map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })?;
            let outcome = configure_and_migrate(&connection, &account, &key.0);
            key.0.zeroize();
            outcome.map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })?;
            Ok(Self {
                account,
                connection: Mutex::new(connection),
                #[cfg(test)]
                fail_next_mutation: Mutex::new(false),
            })
        }

        #[cfg(test)]
        fn fail_next_mutation(&self) {
            if let Ok(mut failpoint) = self.fail_next_mutation.lock() {
                *failpoint = true;
            }
        }

        #[cfg(test)]
        fn take_failpoint(&self) -> Result<bool, MailboxStoreError> {
            let mut failpoint = self
                .fail_next_mutation
                .lock()
                .map_err(|_poison| MailboxStoreError::Storage)?;
            Ok(std::mem::take(&mut *failpoint))
        }

        fn checked_account(&self, account: &AccountId) -> Result<(), MailboxStoreError> {
            (self.account == *account)
                .then_some(())
                .ok_or(MailboxStoreError::Storage)
        }

        fn with_connection<T>(
            &self,
            operation: impl FnOnce(&mut Connection) -> Result<T, MailboxStoreError>,
        ) -> Result<T, MailboxStoreError> {
            let mut connection = self
                .connection
                .lock()
                .map_err(|_poison| MailboxStoreError::Storage)?;
            operation(&mut connection)
        }

        fn upsert(&self, envelopes: &[MessageEnvelope]) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                let transaction = connection.transaction().map_err(store_error)?;
                for envelope in envelopes {
                    write_envelope(&transaction, envelope, None)?;
                    #[cfg(test)]
                    if self.take_failpoint()? {
                        return Err(MailboxStoreError::Storage);
                    }
                }
                transaction.commit().map_err(store_error)
            })
        }

        fn put(&self, message: &Message) -> Result<(), MailboxStoreError> {
            self.with_connection(|connection| {
                let transaction = connection.transaction().map_err(store_error)?;
                write_envelope(
                    &transaction,
                    message.envelope(),
                    Some(message.content().as_bytes()),
                )?;
                #[cfg(test)]
                if self.take_failpoint()? {
                    return Err(MailboxStoreError::Storage);
                }
                transaction.commit().map_err(store_error)
            })
        }

        fn list(
            &self,
            thread: Option<&ThreadId>,
            limit: StoreLimit,
        ) -> Result<Vec<MessageEnvelope>, MailboxStoreError> {
            self.with_connection(|connection| {
                let sql = if thread.is_some() {
                    "SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, CASE WHEN typeof(received_at) = 'integer' THEN received_at END, CASE WHEN typeof(unread) = 'integer' THEN unread END FROM messages WHERE thread_id = ?1 ORDER BY received_at ASC, message_id ASC LIMIT ?2"
                } else {
                    "SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, CASE WHEN typeof(received_at) = 'integer' THEN received_at END, CASE WHEN typeof(unread) = 'integer' THEN unread END FROM messages ORDER BY received_at DESC, message_id ASC LIMIT ?1"
                };
                let mut statement = connection.prepare(sql).map_err(store_error)?;
                let mut rows = match thread {
                    Some(thread_id) => statement.query(params![thread_id.as_str(), i64::from(limit.get())]),
                    None => statement.query(params![i64::from(limit.get())]),
                }.map_err(store_error)?;
                let mut result = Vec::new();
                while let Some(row) = rows.next().map_err(store_error)? {
                    result.push(envelope_from_row(row)?);
                }
                Ok(result)
            })
        }

        fn get_message(&self, id: &MessageId) -> Result<Option<Message>, MailboxStoreError> {
            self.with_connection(|connection| {
                let max_content_len = i64::try_from(MessageContent::MAX_LEN)
                    .map_err(|_error| MailboxStoreError::Corrupted)?;
                let mut statement = connection.prepare("SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, CASE WHEN typeof(received_at) = 'integer' THEN received_at END, CASE WHEN typeof(unread) = 'integer' THEN unread END, CASE WHEN content IS NULL THEN 0 WHEN typeof(content) = 'blob' AND length(content) <= ?2 THEN 1 ELSE -1 END, CASE WHEN typeof(content) = 'blob' AND length(content) <= ?2 THEN content END FROM messages WHERE message_id = ?1").map_err(store_error)?;
                let mut rows = statement
                    .query(params![id.as_str(), max_content_len])
                    .map_err(store_error)?;
                let Some(row) = rows.next().map_err(store_error)? else { return Ok(None); };
                let envelope = envelope_from_row(row)?;
                match row.get::<_, i64>(7).map_err(corrupted)? {
                    0 => Ok(None),
                    1 => {
                        let content: Vec<u8> = row.get(8).map_err(corrupted)?;
                        MessageContent::new(content)
                            .map_err(|_error| MailboxStoreError::Corrupted)
                            .map(|content| Some(Message::new(envelope, content)))
                    }
                    _ => Err(MailboxStoreError::Corrupted),
                }
            })
        }
    }

    fn open_connection(path: &Path) -> Result<Connection, OpenFailure> {
        let file_name = path.file_name().ok_or(OpenFailure::Storage)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let canonical_parent =
            std::fs::canonicalize(parent).map_err(|_error| OpenFailure::Storage)?;
        let canonical_path = canonical_parent.join(file_name);
        let base_flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        Connection::open_with_flags(canonical_path, base_flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
            .map_err(|_error| OpenFailure::Storage)
    }

    impl MailboxStore for SqlCipherMailboxStore {
        fn upsert_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            envelopes: &'a [MessageEnvelope],
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.upsert(envelopes)
            })
        }
        fn put_message<'a>(
            &'a self,
            account: &'a AccountId,
            message: &'a Message,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.put(message)
            })
        }
        fn list_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.list(None, limit)
            })
        }
        fn thread_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            thread_id: &'a ThreadId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.list(Some(thread_id), limit)
            })
        }
        fn message<'a>(
            &'a self,
            account: &'a AccountId,
            message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.get_message(message_id)
            })
        }
    }

    fn write_envelope(
        transaction: &Transaction<'_>,
        envelope: &MessageEnvelope,
        content: Option<&[u8]>,
    ) -> Result<(), MailboxStoreError> {
        match content {
            Some(content) => transaction.execute("INSERT INTO messages (message_id, thread_id, sender, subject, preview, received_at, unread, content) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(message_id) DO UPDATE SET thread_id = excluded.thread_id, sender = excluded.sender, subject = excluded.subject, preview = excluded.preview, received_at = excluded.received_at, unread = excluded.unread, content = excluded.content", params![envelope.message_id().as_str(), envelope.thread_id().as_str(), envelope.from().as_str(), envelope.subject().as_str(), envelope.preview().as_str(), envelope.received_at().as_millis(), i64::from(envelope.is_unread()), content]).map_err(store_error)?,
            None => transaction.execute("INSERT INTO messages (message_id, thread_id, sender, subject, preview, received_at, unread, content) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL) ON CONFLICT(message_id) DO UPDATE SET thread_id = excluded.thread_id, sender = excluded.sender, subject = excluded.subject, preview = excluded.preview, received_at = excluded.received_at, unread = excluded.unread", params![envelope.message_id().as_str(), envelope.thread_id().as_str(), envelope.from().as_str(), envelope.subject().as_str(), envelope.preview().as_str(), envelope.received_at().as_millis(), i64::from(envelope.is_unread())]).map_err(store_error)?,
        };
        Ok(())
    }

    fn envelope_from_row(row: &rusqlite::Row<'_>) -> Result<MessageEnvelope, MailboxStoreError> {
        let message_id: String = row.get(0).map_err(corrupted)?;
        let thread_id: String = row.get(1).map_err(corrupted)?;
        let sender: String = row.get(2).map_err(corrupted)?;
        let subject: String = row.get(3).map_err(corrupted)?;
        let preview: String = row.get(4).map_err(corrupted)?;
        let received_at: i64 = row.get(5).map_err(corrupted)?;
        let unread: i64 = row.get(6).map_err(corrupted)?;
        let unread = match unread {
            0 => false,
            1 => true,
            _ => return Err(MailboxStoreError::Corrupted),
        };
        Ok(MessageEnvelope::new(
            MessageId::new(message_id).map_err(|_error| MailboxStoreError::Corrupted)?,
            ThreadId::new(thread_id).map_err(|_error| MailboxStoreError::Corrupted)?,
            HeaderText::new(sender).map_err(|_error| MailboxStoreError::Corrupted)?,
            HeaderText::new(subject).map_err(|_error| MailboxStoreError::Corrupted)?,
            HeaderText::new(preview).map_err(|_error| MailboxStoreError::Corrupted)?,
            UnixTimestampMillis::new(received_at).map_err(|_error| MailboxStoreError::Corrupted)?,
            unread,
        ))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum OpenFailure {
        Corrupted,
        Storage,
    }
    fn configure_and_migrate(
        connection: &Connection,
        account: &AccountId,
        key: &[u8; 32],
    ) -> Result<(), OpenFailure> {
        apply_key(connection, key).map_err(|_error| OpenFailure::Corrupted)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|_error| OpenFailure::Storage)?;
        connection
            .execute_batch(
                "PRAGMA cipher_memory_security = ON;
                 PRAGMA foreign_keys = ON;
                 PRAGMA temp_store = MEMORY;",
            )
            .map_err(classify_open)?;
        let cipher_version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(|_error| OpenFailure::Corrupted)?;
        if cipher_version.is_empty() {
            return Err(OpenFailure::Corrupted);
        }
        let application_id: i64 = connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .map_err(classify_open)?;
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(classify_open)?;
        let schema = schema(connection).map_err(classify_open)?;
        let fresh = application_id == 0 && user_version == 0 && schema.is_empty();
        if fresh {
            configure_owned_storage(connection)?;
            let transaction = connection
                .unchecked_transaction()
                .map_err(|_error| OpenFailure::Storage)?;
            transaction
                .execute_batch(MIGRATION)
                .map_err(classify_open)?;
            transaction
                .execute(
                    "INSERT INTO account_binding (singleton, account_id) VALUES (1, ?1)",
                    params![account.as_str()],
                )
                .map_err(classify_open)?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(classify_open)?;
            transaction
                .pragma_update(None, "user_version", VERSION)
                .map_err(classify_open)?;
            transaction.commit().map_err(classify_open)?;
        } else if application_id != APPLICATION_ID
            || user_version != VERSION
            || schema != canonical_schema()
        {
            return Err(OpenFailure::Corrupted);
        }
        let owner: String = connection
            .query_row(
                "SELECT CASE WHEN typeof(account_id) = 'text' AND length(CAST(account_id AS BLOB)) <= 256 THEN account_id END FROM account_binding WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_error| OpenFailure::Corrupted)?;
        if AccountId::new(owner).ok().as_ref() != Some(account) {
            return Err(OpenFailure::Corrupted);
        }
        if !fresh {
            configure_owned_storage(connection)?;
        }
        validate_health(connection)
    }

    fn configure_owned_storage(connection: &Connection) -> Result<(), OpenFailure> {
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA secure_delete = ON;",
            )
            .map_err(classify_open)
    }

    fn validate_health(connection: &Connection) -> Result<(), OpenFailure> {
        let foreign_keys: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .map_err(classify_open)?;
        let temp_store: i64 = connection
            .query_row("PRAGMA temp_store", [], |row| row.get(0))
            .map_err(classify_open)?;
        let secure_delete: i64 = connection
            .query_row("PRAGMA secure_delete", [], |row| row.get(0))
            .map_err(classify_open)?;
        let journal: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(classify_open)?;
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(classify_open)?;
        let foreign_key_failure = connection
            .prepare("PRAGMA foreign_key_check")
            .and_then(|mut statement| statement.query([])?.next().map(|row| row.is_some()))
            .map_err(classify_open)?;
        let cipher_failure = connection
            .prepare("PRAGMA cipher_integrity_check")
            .and_then(|mut statement| statement.query([])?.next().map(|row| row.is_some()))
            .map_err(classify_open)?;
        if foreign_keys != 1
            || temp_store != 2
            || secure_delete != 1
            || journal != "wal"
            || integrity != "ok"
            || foreign_key_failure
            || cipher_failure
        {
            return Err(OpenFailure::Corrupted);
        }
        Ok(())
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "rusqlite Result::map_err supplies owned errors"
    )]
    fn classify_open(error: rusqlite::Error) -> OpenFailure {
        match error {
            rusqlite::Error::SqliteFailure(sqlite, _)
                if matches!(
                    sqlite.code,
                    ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
                ) =>
            {
                OpenFailure::Corrupted
            }
            rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::IntegralValueOutOfRange(..)
            | rusqlite::Error::InvalidColumnType(..)
            | rusqlite::Error::InvalidQuery => OpenFailure::Corrupted,
            _ => OpenFailure::Storage,
        }
    }

    fn apply_key(connection: &Connection, key: &[u8; 32]) -> rusqlite::Result<()> {
        let mut literal = Zeroizing::new(String::with_capacity(67));
        literal.push_str("x'");
        for byte in key {
            use std::fmt::Write as _;
            let _ = write!(literal, "{byte:02x}");
        }
        literal.push('\'');
        connection.pragma_update(None, "key", literal.as_str())
    }
    fn schema(connection: &Connection) -> rusqlite::Result<Vec<(String, String, String)>> {
        let mut statement = connection.prepare(
            "SELECT
                CASE WHEN typeof(type) = 'text' AND length(CAST(type AS BLOB)) <= ?1 THEN type END,
                CASE WHEN typeof(name) = 'text' AND length(CAST(name AS BLOB)) <= ?2 THEN name END,
                CASE
                    WHEN sql IS NULL THEN ''
                    WHEN typeof(sql) = 'text' AND length(CAST(sql AS BLOB)) <= ?3 THEN sql
                END
             FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type, name
             LIMIT ?4",
        )?;
        let row_limit = i64::try_from(CANONICAL_SCHEMA_OBJECT_COUNT + 1)
            .map_err(|_error| rusqlite::Error::InvalidQuery)?;
        let mut rows = statement.query(params![
            MAX_SCHEMA_KIND_LEN,
            MAX_SCHEMA_NAME_LEN,
            MAX_SCHEMA_SQL_LEN,
            row_limit
        ])?;
        let mut objects = Vec::with_capacity(CANONICAL_SCHEMA_OBJECT_COUNT);
        while let Some(row) = rows.next()? {
            if objects.len() == CANONICAL_SCHEMA_OBJECT_COUNT {
                return Err(rusqlite::Error::InvalidQuery);
            }
            objects.push((
                row.get(0)?,
                row.get(1)?,
                normalize(&row.get::<_, String>(2)?),
            ));
        }
        Ok(objects)
    }
    fn canonical_schema() -> Vec<(String, String, String)> {
        vec![
            (
                "index".into(),
                "messages_list_order".into(),
                normalize(
                    "CREATE INDEX messages_list_order ON messages (received_at DESC, message_id ASC)",
                ),
            ),
            (
                "index".into(),
                "messages_thread_order".into(),
                normalize(
                    "CREATE INDEX messages_thread_order ON messages (thread_id ASC, received_at ASC, message_id ASC)",
                ),
            ),
            (
                "table".into(),
                "account_binding".into(),
                normalize(
                    "CREATE TABLE account_binding ( singleton INTEGER PRIMARY KEY CHECK (singleton = 1), account_id TEXT NOT NULL )",
                ),
            ),
            (
                "table".into(),
                "messages".into(),
                normalize(
                    "CREATE TABLE messages ( message_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, sender TEXT NOT NULL, subject TEXT NOT NULL, preview TEXT NOT NULL, received_at INTEGER NOT NULL, unread INTEGER NOT NULL CHECK (unread IN (0, 1)), content BLOB NULL )",
                ),
            ),
        ]
    }
    fn normalize(sql: &str) -> String {
        sql.trim_end_matches(';')
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }
    #[expect(
        clippy::needless_pass_by_value,
        reason = "rusqlite Result::map_err supplies owned errors"
    )]
    fn store_error(error: rusqlite::Error) -> MailboxStoreError {
        match error {
            rusqlite::Error::SqliteFailure(sqlite, _)
                if matches!(
                    sqlite.code,
                    ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
                ) =>
            {
                MailboxStoreError::Corrupted
            }
            _ => MailboxStoreError::Storage,
        }
    }
    fn corrupted(_error: rusqlite::Error) -> MailboxStoreError {
        MailboxStoreError::Corrupted
    }

    #[cfg(test)]
    mod tests {
        #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

        use std::fs;
        use std::panic::{AssertUnwindSafe, catch_unwind};
        use std::pin::pin;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::task::{Context, Poll, Waker};

        use super::*;

        static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        struct TestDatabase {
            directory: std::path::PathBuf,
            path: std::path::PathBuf,
        }

        impl TestDatabase {
            fn new(label: &str) -> Self {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let directory = std::env::temp_dir().join(format!(
                    "tersa-store-{label}-{}-{sequence}",
                    std::process::id()
                ));
                fs::create_dir(&directory).unwrap();
                let path = directory.join("account.sqlite3");
                Self { directory, path }
            }

            fn path(&self) -> &Path {
                &self.path
            }

            fn files(&self) -> Vec<std::path::PathBuf> {
                fs::read_dir(&self.directory)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.is_file())
                    .collect()
            }
        }

        impl Drop for TestDatabase {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.directory);
            }
        }

        fn account() -> AccountId {
            AccountId::new("account-a").unwrap()
        }
        fn key(byte: u8) -> DatabaseKey {
            DatabaseKey::new([byte; 32])
        }
        fn envelope(id: &str, thread: &str, received_at: i64) -> MessageEnvelope {
            MessageEnvelope::new(
                MessageId::new(id).unwrap(),
                ThreadId::new(thread).unwrap(),
                HeaderText::new("from").unwrap(),
                HeaderText::new("subject").unwrap(),
                HeaderText::new("preview").unwrap(),
                UnixTimestampMillis::new(received_at).unwrap(),
                true,
            )
        }
        fn run<T>(future: impl Future<Output = T>) -> T {
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);
            let mut future = pin!(future);
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => value,
                Poll::Pending => panic!("store future must complete synchronously"),
            }
        }
        fn open(name: &str) -> (TestDatabase, SqlCipherMailboxStore) {
            let database = TestDatabase::new(name);
            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            (database, store)
        }

        fn schema_state(
            store: &SqlCipherMailboxStore,
        ) -> (i64, i64, Vec<(String, String, String)>) {
            let connection = store.connection.lock().unwrap();
            (
                connection
                    .query_row("PRAGMA application_id", [], |row| row.get(0))
                    .unwrap(),
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get(0))
                    .unwrap(),
                schema(&connection).unwrap(),
            )
        }

        #[expect(
            clippy::needless_pass_by_value,
            reason = "the assertion owns and drops any unexpected opened store"
        )]
        fn assert_corrupted(result: Result<SqlCipherMailboxStore, MailboxStoreError>) {
            assert!(matches!(result, Err(MailboxStoreError::Corrupted)));
        }

        #[test]
        fn fresh_create_converges_reopen_is_noop_and_wrong_key_is_rejected() {
            let database = TestDatabase::new("reopen");
            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            let expected_state = (APPLICATION_ID, VERSION, canonical_schema());
            assert_eq!(schema_state(&store), expected_state);
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(schema_state(&reopened), expected_state);
            drop(reopened);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                database.path(),
                key(8),
            ));
        }

        #[test]
        fn unknown_noncanonical_and_future_schemas_are_rejected() {
            let unknown = TestDatabase::new("unknown-owner");
            let connection = open_connection(unknown.path()).unwrap();
            apply_key(&connection, &key(7).0).unwrap();
            connection
                .execute_batch("CREATE TABLE foreign_owner (value TEXT NOT NULL);")
                .unwrap();
            let unknown_schema = schema(&connection).unwrap();
            let unknown_journal: String = connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            drop(connection);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                unknown.path(),
                key(7),
            ));
            let unchanged = open_connection(unknown.path()).unwrap();
            apply_key(&unchanged, &key(7).0).unwrap();
            assert_eq!(schema(&unchanged).unwrap(), unknown_schema);
            assert_eq!(
                unchanged
                    .query_row::<String, _, _>("PRAGMA journal_mode", [], |row| row.get(0))
                    .unwrap(),
                unknown_journal
            );
            drop(unchanged);

            let excessive = TestDatabase::new("excessive-schema");
            let excessive_connection = open_connection(excessive.path()).unwrap();
            apply_key(&excessive_connection, &key(7).0).unwrap();
            excessive_connection
                .execute_batch(
                    "CREATE TABLE one (value TEXT);
                     CREATE TABLE two (value TEXT);
                     CREATE TABLE three (value TEXT);
                     CREATE TABLE four (value TEXT);
                     CREATE TABLE five (value TEXT);",
                )
                .unwrap();
            drop(excessive_connection);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                excessive.path(),
                key(7),
            ));

            let oversized = TestDatabase::new("oversized-schema");
            let oversized_connection = open_connection(oversized.path()).unwrap();
            apply_key(&oversized_connection, &key(7).0).unwrap();
            oversized_connection
                .execute_batch(&format!(
                    "CREATE TABLE oversized_sql (value TEXT CHECK (value != '{}'));",
                    "x".repeat(usize::try_from(MAX_SCHEMA_SQL_LEN).unwrap() + 1)
                ))
                .unwrap();
            drop(oversized_connection);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                oversized.path(),
                key(7),
            ));

            let (modified_database, modified) = open("modified-schema");
            modified
                .connection
                .lock()
                .unwrap()
                .execute_batch("ALTER TABLE messages ADD COLUMN unexpected TEXT;")
                .unwrap();
            drop(modified);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                modified_database.path(),
                key(7),
            ));

            let (future_database, future) = open("future-schema");
            future
                .connection
                .lock()
                .unwrap()
                .pragma_update(None, "user_version", VERSION + 1)
                .unwrap();
            drop(future);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                future_database.path(),
                key(7),
            ));
        }

        #[test]
        fn envelope_upsert_preserves_content_and_put_replaces_every_field() {
            let (_database, store) = open("content");
            let initial = envelope("m1", "t1", 10);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&initial))).unwrap();
            assert!(
                run(store.message(&account(), initial.message_id()))
                    .unwrap()
                    .is_none()
            );
            let message = Message::new(
                initial.clone(),
                MessageContent::new(b"body one".to_vec()).unwrap(),
            );
            run(store.put_message(&account(), &message)).unwrap();
            run(store.put_message(&account(), &message)).unwrap();
            let changed = envelope("m1", "t2", 20);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&changed))).unwrap();
            assert_eq!(
                run(store.message(&account(), changed.message_id()))
                    .unwrap()
                    .unwrap()
                    .content()
                    .as_bytes(),
                b"body one"
            );
            let replacement = Message::new(
                changed.clone(),
                MessageContent::new(b"body two".to_vec()).unwrap(),
            );
            run(store.put_message(&account(), &replacement)).unwrap();
            assert_eq!(
                run(store.message(&account(), changed.message_id()))
                    .unwrap()
                    .unwrap(),
                replacement
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .len(),
                1
            );
        }

        #[test]
        fn ordering_limits_rollback_and_unpolled_cancellation_are_exact() {
            let (_database, store) = open("order");
            let values = [
                envelope("b", "thread", 10),
                envelope("a", "thread", 10),
                envelope("c", "other", 20),
            ];
            let local_account = account();
            let cancelled = store.upsert_envelopes(&local_account, &values);
            drop(cancelled);
            assert!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .is_empty()
            );
            run(store.upsert_envelopes(&account(), &values)).unwrap();
            let listed =
                run(store.list_envelopes(&account(), StoreLimit::new(2).unwrap())).unwrap();
            assert_eq!(
                listed
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                vec!["c", "a"]
            );
            let threaded = run(store.thread_envelopes(
                &account(),
                values[0].thread_id(),
                StoreLimit::new(2).unwrap(),
            ))
            .unwrap();
            assert_eq!(
                threaded
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                vec!["a", "b"]
            );
            store.fail_next_mutation();
            assert_eq!(
                run(store
                    .upsert_envelopes(&account(), &[envelope("d", "t", 1), envelope("e", "t", 2)])),
                Err(MailboxStoreError::Storage)
            );
            assert!(
                run(store.message(&account(), &MessageId::new("d").unwrap()))
                    .unwrap()
                    .is_none()
            );
            assert!(
                run(store.message(&account(), &MessageId::new("e").unwrap()))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .len(),
                3
            );
        }

        #[test]
        fn account_binding_and_method_mismatch_fail_closed_without_database_work() {
            let (database, store) = open("mismatch");
            let foreign = AccountId::new("account-b").unwrap();
            let changes_before = store.connection.lock().unwrap().total_changes();
            let error =
                run(store.list_envelopes(&foreign, StoreLimit::new(1).unwrap())).unwrap_err();
            assert_eq!(error, MailboxStoreError::Storage);
            assert_eq!(
                store.connection.lock().unwrap().total_changes(),
                changes_before
            );
            assert!(!format!("{store:?}").contains("account-a"));
            assert!(!error.to_string().contains("account-a"));
            drop(store);
            assert_corrupted(SqlCipherMailboxStore::open(
                foreign,
                database.path(),
                key(7),
            ));
        }

        #[test]
        fn invalid_stored_values_are_corruption_without_large_body_allocation() {
            let (_database, store) = open("corrupt-row");
            let value = envelope("m1", "thread", 1);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&value))).unwrap();
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE messages SET subject = ?1, content = CAST(?2 AS TEXT) WHERE message_id = ?3",
                    params!["x".repeat(1_025), "not-a-blob", value.message_id().as_str()],
                )
                .unwrap();
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap())),
                Err(MailboxStoreError::Corrupted)
            );
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE messages SET subject = ?1 WHERE message_id = ?2",
                    params!["valid", value.message_id().as_str()],
                )
                .unwrap();
            assert_eq!(
                run(store.message(&account(), value.message_id())),
                Err(MailboxStoreError::Corrupted)
            );
        }

        #[test]
        fn encrypted_database_and_sidecars_contain_no_plaintext_sentinel() {
            let database = TestDatabase::new("plaintext-control");
            let secret_account = AccountId::new("account-plaintext-sentinel").unwrap();
            let store =
                SqlCipherMailboxStore::open(secret_account.clone(), database.path(), key(17))
                    .unwrap();
            let value = Message::new(
                MessageEnvelope::new(
                    MessageId::new("message-plaintext-sentinel").unwrap(),
                    ThreadId::new("thread-plaintext-sentinel").unwrap(),
                    HeaderText::new("from-plaintext-sentinel").unwrap(),
                    HeaderText::new("subject-plaintext-sentinel").unwrap(),
                    HeaderText::new("preview-plaintext-sentinel").unwrap(),
                    UnixTimestampMillis::new(1).unwrap(),
                    true,
                ),
                MessageContent::new(b"body-plaintext-sentinel".to_vec()).unwrap(),
            );
            run(store.put_message(&secret_account, &value)).unwrap();
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(FULL);")
                .unwrap();
            let files = database.files();
            assert!(!files.is_empty());
            for path in files {
                let bytes = fs::read(path).unwrap();
                assert!(!contains_bytes(&bytes, b"plaintext-sentinel"));
            }
            let key_debug = format!("{:?}", key(17));
            let store_debug = format!("{store:?}");
            assert!(!key_debug.contains("17"));
            assert!(!store_debug.contains("plaintext"));
        }

        #[test]
        fn symlink_leaf_and_poisoned_connection_are_opaque_storage_failures() {
            let target_database = TestDatabase::new("symlink-target");
            let target =
                SqlCipherMailboxStore::open(account(), target_database.path(), key(7)).unwrap();
            drop(target);
            let link_database = TestDatabase::new("symlink-link");
            std::os::unix::fs::symlink(target_database.path(), link_database.path()).unwrap();
            assert!(matches!(
                SqlCipherMailboxStore::open(account(), link_database.path(), key(7)),
                Err(MailboxStoreError::Storage)
            ));

            let (_database, poisoned) = open("poisoned");
            let panic = catch_unwind(AssertUnwindSafe(|| {
                let _guard = poisoned.connection.lock().unwrap();
                panic!("intentional mutex poison");
            }));
            assert!(panic.is_err());
            assert_eq!(
                run(poisoned.list_envelopes(&account(), StoreLimit::new(1).unwrap())),
                Err(MailboxStoreError::Storage)
            );
        }

        fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
            haystack
                .windows(needle.len())
                .any(|window| window == needle)
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::{DatabaseKey, SqlCipherMailboxStore};
