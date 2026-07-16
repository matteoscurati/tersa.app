// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides an account-scoped `SQLCipher` mailbox store for macOS.
//!
//! This adapter has synchronous database internals and lazy runtime-free
//! futures. Callers must poll it on a bounded blocking executor rather than a
//! latency-sensitive async executor thread. It deliberately owns neither blob
//! encryption nor cross-file commit orchestration.

#![deny(unsafe_code)]

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::OsString;
    use std::fmt;
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
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
            key: DatabaseKey,
        ) -> Result<Self, MailboxStoreError> {
            Self::open_inner(account, path.as_ref(), key, |_path| {})
        }

        fn open_inner(
            account: AccountId,
            path: &Path,
            key: DatabaseKey,
            after_preflight: impl FnOnce(&Path),
        ) -> Result<Self, MailboxStoreError> {
            Self::open_inner_with_hooks(account, path, key, after_preflight, |_path| {})
        }

        fn open_inner_with_hooks(
            account: AccountId,
            path: &Path,
            mut key: DatabaseKey,
            after_preflight: impl FnOnce(&Path),
            after_open: impl FnOnce(&Path),
        ) -> Result<Self, MailboxStoreError> {
            let canonical_path = canonical_database_path(path).map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })?;
            let prepared = prepare_database_leaf(&canonical_path).map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })?;
            if !prepared.created {
                let preflight = preflight_existing(&canonical_path, &account, &key.0);
                if let Err(kind) = preflight {
                    key.0.zeroize();
                    return Err(match kind {
                        OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                        OpenFailure::Storage => MailboxStoreError::Storage,
                    });
                }
            }
            after_preflight(&canonical_path);
            let connection = open_connection(&canonical_path).map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })?;
            after_open(&canonical_path);
            if opened_file_has_moved(&connection).is_err() {
                key.0.zeroize();
                return Err(MailboxStoreError::Storage);
            }
            if file_identity(&canonical_path).map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })? != prepared.identity
            {
                key.0.zeroize();
                return Err(MailboxStoreError::Storage);
            }
            if prepared.created
                && database_sidecar_exists(&canonical_path).map_err(|kind| match kind {
                    OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                    OpenFailure::Storage => MailboxStoreError::Storage,
                })?
            {
                key.0.zeroize();
                drop(connection);
                let _ = std::fs::remove_file(&canonical_path);
                return Err(MailboxStoreError::Corrupted);
            }
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

        fn reconcile(
            &self,
            envelopes: &[MessageEnvelope],
            keep_limit: StoreLimit,
        ) -> Result<Vec<MessageId>, MailboxStoreError> {
            if envelopes.len() > usize::from(StoreLimit::MAX) {
                return Err(MailboxStoreError::Storage);
            }
            self.with_connection(|connection| {
                let transaction = connection.transaction().map_err(store_error)?;
                for envelope in envelopes {
                    write_envelope(&transaction, envelope, None)?;
                    #[cfg(test)]
                    if self.take_failpoint()? {
                        return Err(MailboxStoreError::Storage);
                    }
                }
                transaction.execute(
                    "DELETE FROM messages WHERE message_id NOT IN (SELECT message_id FROM messages ORDER BY received_at DESC, message_id ASC LIMIT ?1)",
                    params![i64::from(keep_limit.get())],
                ).map_err(store_error)?;
                #[cfg(test)]
                if self.take_failpoint()? {
                    return Err(MailboxStoreError::Storage);
                }
                let mut survivors = Vec::with_capacity(envelopes.len());
                for envelope in envelopes {
                    if survivors.iter().any(|id: &MessageId| id == envelope.message_id()) {
                        continue;
                    }
                    let exists: bool = transaction.query_row(
                        "SELECT EXISTS(SELECT 1 FROM messages WHERE message_id = ?1)",
                        params![envelope.message_id().as_str()],
                        |row| row.get(0),
                    ).map_err(store_error)?;
                    if exists {
                        survivors.push(envelope.message_id().clone());
                    }
                }
                transaction.commit().map_err(store_error)?;
                Ok(survivors)
            })
        }

        fn cache_if_present(&self, message: &Message) -> Result<bool, MailboxStoreError> {
            self.with_connection(|connection| {
                let transaction = connection.transaction().map_err(store_error)?;
                let changed = transaction.execute(
                    "UPDATE messages SET thread_id = ?2, sender = ?3, subject = ?4, preview = ?5, received_at = ?6, unread = ?7, content = ?8 WHERE message_id = ?1",
                    params![message.envelope().message_id().as_str(), message.envelope().thread_id().as_str(), message.envelope().from().as_str(), message.envelope().subject().as_str(), message.envelope().preview().as_str(), message.envelope().received_at().as_millis(), i64::from(message.envelope().is_unread()), message.content().as_bytes()],
                ).map_err(store_error)?;
                #[cfg(test)]
                if self.take_failpoint()? {
                    return Err(MailboxStoreError::Storage);
                }
                transaction.commit().map_err(store_error)?;
                Ok(changed == 1)
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PreparedLeaf {
        created: bool,
        identity: FileIdentity,
    }

    fn canonical_database_path(path: &Path) -> Result<PathBuf, OpenFailure> {
        let file_name = path.file_name().ok_or(OpenFailure::Storage)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let canonical_parent =
            std::fs::canonicalize(parent).map_err(|_error| OpenFailure::Storage)?;
        Ok(canonical_parent.join(file_name))
    }

    fn prepare_database_leaf(path: &Path) -> Result<PreparedLeaf, OpenFailure> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(PreparedLeaf {
                created: false,
                identity: identity_from_metadata(&metadata),
            }),
            Ok(_metadata) => Err(OpenFailure::Storage),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if database_sidecar_exists(path)? {
                    return Err(OpenFailure::Corrupted);
                }
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                {
                    Ok(file) => {
                        drop(file);
                        if database_sidecar_exists(path)? {
                            let _ = std::fs::remove_file(path);
                            return Err(OpenFailure::Corrupted);
                        }
                        Ok(PreparedLeaf {
                            created: true,
                            identity: file_identity(path)?,
                        })
                    }
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                        let metadata = std::fs::symlink_metadata(path)
                            .map_err(|_error| OpenFailure::Storage)?;
                        if !metadata.file_type().is_file() {
                            return Err(OpenFailure::Storage);
                        }
                        Ok(PreparedLeaf {
                            created: false,
                            identity: identity_from_metadata(&metadata),
                        })
                    }
                    Err(_error) => Err(OpenFailure::Storage),
                }
            }
            Err(_error) => Err(OpenFailure::Storage),
        }
    }

    fn file_identity(path: &Path) -> Result<FileIdentity, OpenFailure> {
        let metadata = std::fs::symlink_metadata(path).map_err(|_error| OpenFailure::Storage)?;
        if !metadata.file_type().is_file() {
            return Err(OpenFailure::Storage);
        }
        Ok(identity_from_metadata(&metadata))
    }

    fn identity_from_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn open_connection(path: &Path) -> Result<Connection, OpenFailure> {
        let base_flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        Connection::open_with_flags(path, base_flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
            .map_err(|_error| OpenFailure::Storage)
    }

    #[allow(
        unsafe_code,
        reason = "SQLite requires a mutable integer pointer for SQLITE_FCNTL_HAS_MOVED"
    )]
    fn opened_file_has_moved(connection: &Connection) -> Result<(), OpenFailure> {
        let mut has_moved = 0;
        // SAFETY: `connection.handle()` remains valid for this synchronous call;
        // `main` is a static NUL-terminated database name; and `has_moved` is a
        // writable `i32` whose address remains valid until SQLite returns.
        let result = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
                (&raw mut has_moved).cast::<std::ffi::c_void>(),
            )
        };
        if result == rusqlite::ffi::SQLITE_OK && has_moved == 0 {
            Ok(())
        } else {
            // Unsupported file controls, unexpected VFS results, and a moved
            // opened file all fail closed before the key or database is read.
            Err(OpenFailure::Storage)
        }
    }

    fn preflight_existing(
        path: &Path,
        account: &AccountId,
        key: &[u8; 32],
    ) -> Result<(), OpenFailure> {
        let uri = immutable_file_uri(path);
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(PathBuf::from(uri), flags)
            .map_err(|_error| OpenFailure::Storage)?;
        apply_key(&connection, key).map_err(classify_key)?;
        let fresh = validate_identity(&connection, account)?;
        if fresh && database_sidecar_exists(path)? {
            return Err(OpenFailure::Corrupted);
        }
        Ok(())
    }

    fn immutable_file_uri(path: &Path) -> OsString {
        let mut uri = Vec::with_capacity(path.as_os_str().as_bytes().len() + 32);
        uri.extend_from_slice(b"file:");
        for byte in path.as_os_str().as_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
                uri.push(*byte);
            } else {
                uri.push(b'%');
                uri.push(hex_digit(byte >> 4));
                uri.push(hex_digit(byte & 0x0f));
            }
        }
        uri.extend_from_slice(b"?immutable=1");
        OsString::from_vec(uri)
    }

    const fn hex_digit(value: u8) -> u8 {
        match value {
            0..=9 => b'0' + value,
            _ => b'A' + (value - 10),
        }
    }

    fn database_sidecar_exists(path: &Path) -> Result<bool, OpenFailure> {
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            match std::fs::symlink_metadata(PathBuf::from(name)) {
                Ok(_metadata) => return Ok(true),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(_error) => return Err(OpenFailure::Storage),
            }
        }
        Ok(false)
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
        fn reconcile_recent_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            envelopes: &'a [MessageEnvelope],
            keep_limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.reconcile(envelopes, keep_limit)
            })
        }
        fn cache_message_if_present<'a>(
            &'a self,
            account: &'a AccountId,
            message: &'a Message,
        ) -> BoxFuture<'a, Result<bool, MailboxStoreError>> {
            Box::pin(async move {
                self.checked_account(account)?;
                self.cache_if_present(message)
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
        apply_key(connection, key).map_err(classify_key)?;
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
        let fresh = validate_identity(connection, account)?;
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
        } else {
            configure_owned_storage(connection)?;
        }
        validate_health(connection)
    }

    fn validate_identity(
        connection: &Connection,
        account: &AccountId,
    ) -> Result<bool, OpenFailure> {
        let cipher_version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(classify_open)?;
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
            return Ok(true);
        }
        if application_id != APPLICATION_ID
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
            .map_err(classify_open)?;
        if AccountId::new(owner).ok().as_ref() != Some(account) {
            return Err(OpenFailure::Corrupted);
        }
        Ok(false)
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
            | rusqlite::Error::InvalidQuery
            | rusqlite::Error::QueryReturnedNoRows
            | rusqlite::Error::Utf8Error(..) => OpenFailure::Corrupted,
            _ => OpenFailure::Storage,
        }
    }

    #[allow(
        unsafe_code,
        reason = "SQLCipher's raw-key API avoids copying the key into an ordinary SQL string"
    )]
    fn apply_key(connection: &Connection, key: &[u8; 32]) -> rusqlite::Result<()> {
        let key_length =
            i32::try_from(key.len()).map_err(|_error| rusqlite::Error::InvalidQuery)?;
        // SAFETY: `connection.handle()` remains valid for this call, SQLCipher
        // copies exactly `key_length` bytes before returning, and the borrowed
        // key buffer remains alive and immutable for the complete call.
        let result = unsafe {
            rusqlite::ffi::sqlite3_key(
                connection.handle(),
                key.as_ptr().cast::<std::ffi::c_void>(),
                key_length,
            )
        };
        key_result(result)
    }

    fn key_result(result: i32) -> rusqlite::Result<()> {
        if result == rusqlite::ffi::SQLITE_OK {
            Ok(())
        } else {
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(result),
                None,
            ))
        }
    }

    fn classify_key(_error: rusqlite::Error) -> OpenFailure {
        // Wrong keys are accepted by `sqlite3_key` and surface as corruption on
        // the first database read. A non-OK keying result is therefore an
        // operational setup failure, most notably `SQLITE_NOMEM`.
        OpenFailure::Storage
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
             WHERE name NOT GLOB 'sqlite_*'
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
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::task::{Context, Poll, Waker};
        use std::thread;
        use std::time::Instant;

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

        fn raw_connection(database: &TestDatabase) -> Connection {
            let path = canonical_database_path(database.path()).unwrap();
            assert!(prepare_database_leaf(&path).unwrap().created);
            open_connection(&path).unwrap()
        }

        fn raw_existing_connection(database: &TestDatabase) -> Connection {
            let path = canonical_database_path(database.path()).unwrap();
            open_connection(&path).unwrap()
        }

        fn journal_path(database: &TestDatabase) -> PathBuf {
            let mut name = database.path().as_os_str().to_os_string();
            name.push("-journal");
            PathBuf::from(name)
        }

        fn leave_foreign_hot_journal(database: &TestDatabase) {
            let connection = raw_connection(database);
            apply_key(&connection, &key(7).0).unwrap();
            connection
                .execute_batch(
                    "PRAGMA journal_mode = DELETE;
                     PRAGMA synchronous = FULL;
                     CREATE TABLE foreign_owner (value BLOB NOT NULL);
                     INSERT INTO foreign_owner (value) VALUES (zeroblob(4096));",
                )
                .unwrap();
            drop(connection);

            let ready = database.directory.join("hot-journal-ready");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "macos::tests::foreign_hot_journal_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_STORE_HOT_JOURNAL_DATABASE", database.path())
                .env("TERSA_STORE_HOT_JOURNAL_READY", &ready)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() && Instant::now() < deadline {
                assert!(child.try_wait().unwrap().is_none());
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                ready.exists(),
                "hot-journal child did not reach its checkpoint"
            );
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            assert!(journal_path(database).exists());
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
            assert_eq!(
                key_result(rusqlite::ffi::SQLITE_NOMEM).map_err(classify_key),
                Err(OpenFailure::Storage)
            );
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

            let existing_empty = TestDatabase::new("existing empty ?#%");
            fs::File::create(existing_empty.path()).unwrap();
            let existing_store =
                SqlCipherMailboxStore::open(account(), existing_empty.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&existing_store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            drop(existing_store);
            let reopened_special =
                SqlCipherMailboxStore::open(account(), existing_empty.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&reopened_special),
                (APPLICATION_ID, VERSION, canonical_schema())
            );

            let empty_with_sidecar = TestDatabase::new("empty-with-sidecar");
            fs::File::create(empty_with_sidecar.path()).unwrap();
            let mut journal_name = empty_with_sidecar.path().as_os_str().to_os_string();
            journal_name.push("-journal");
            let existing_journal_path = PathBuf::from(journal_name);
            fs::write(&existing_journal_path, b"foreign-sidecar").unwrap();
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                empty_with_sidecar.path(),
                key(7),
            ));
            assert_eq!(fs::read(existing_journal_path).unwrap(), b"foreign-sidecar");

            let absent_with_sidecar = TestDatabase::new("absent-with-sidecar");
            let absent_journal = journal_path(&absent_with_sidecar);
            fs::write(&absent_journal, b"orphan-foreign-sidecar").unwrap();
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                absent_with_sidecar.path(),
                key(7),
            ));
            assert!(!absent_with_sidecar.path().exists());
            assert_eq!(fs::read(absent_journal).unwrap(), b"orphan-foreign-sidecar");
        }

        #[test]
        fn identity_queries_classify_operational_sqlite_failures_as_storage() {
            for code in [
                rusqlite::ffi::SQLITE_NOMEM,
                rusqlite::ffi::SQLITE_IOERR,
                rusqlite::ffi::SQLITE_BUSY,
                rusqlite::ffi::SQLITE_FULL,
                rusqlite::ffi::SQLITE_CANTOPEN,
            ] {
                assert_eq!(
                    classify_open(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(code),
                        None,
                    )),
                    OpenFailure::Storage
                );
            }
            assert_eq!(
                classify_open(rusqlite::Error::QueryReturnedNoRows),
                OpenFailure::Corrupted
            );
            assert_eq!(
                classify_open(rusqlite::Error::InvalidColumnType(
                    0,
                    "cipher_version".into(),
                    rusqlite::types::Type::Integer,
                )),
                OpenFailure::Corrupted
            );
            assert_eq!(
                classify_open(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
                    None,
                )),
                OpenFailure::Corrupted
            );

            let (database, store) = open("invalid-owner-utf8");
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch(
                    "UPDATE account_binding SET account_id = CAST(X'80' AS TEXT) WHERE singleton = 1;",
                )
                .unwrap();
            drop(store);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                database.path(),
                key(7),
            ));
        }

        #[test]
        fn unknown_noncanonical_and_future_schemas_are_rejected() {
            let unknown = TestDatabase::new("unknown-owner");
            let connection = raw_connection(&unknown);
            apply_key(&connection, &key(7).0).unwrap();
            connection
                .execute_batch("CREATE TABLE sqliteX (value TEXT NOT NULL);")
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
            let unchanged = raw_existing_connection(&unknown);
            apply_key(&unchanged, &key(7).0).unwrap();
            assert_eq!(schema(&unchanged).unwrap(), unknown_schema);
            assert_eq!(
                unchanged
                    .query_row::<String, _, _>("PRAGMA journal_mode", [], |row| row.get(0))
                    .unwrap(),
                unknown_journal
            );
            drop(unchanged);

            let (hidden_extra_database, hidden_extra) = open("hidden-extra-schema");
            hidden_extra
                .connection
                .lock()
                .unwrap()
                .execute_batch("CREATE TABLE sqliteX (value TEXT NOT NULL);")
                .unwrap();
            drop(hidden_extra);
            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                hidden_extra_database.path(),
                key(7),
            ));

            let excessive = TestDatabase::new("excessive-schema");
            let excessive_connection = raw_connection(&excessive);
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
            let oversized_connection = raw_connection(&oversized);
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
        fn foreign_hot_journal_is_rejected_without_recovery_or_mutation() {
            let database = TestDatabase::new("foreign-hot-journal");
            leave_foreign_hot_journal(&database);
            let journal_path = journal_path(&database);
            let database_before = fs::read(database.path()).unwrap();
            let journal_before = fs::read(&journal_path).unwrap();

            assert_corrupted(SqlCipherMailboxStore::open(
                account(),
                database.path(),
                key(7),
            ));
            assert_eq!(fs::read(database.path()).unwrap(), database_before);
            assert_eq!(fs::read(journal_path).unwrap(), journal_before);
        }

        #[test]
        fn replacement_between_preflight_and_reopen_is_rejected_before_database_reads() {
            let original = TestDatabase::new("preflight-original");
            let store = SqlCipherMailboxStore::open(account(), original.path(), key(7)).unwrap();
            drop(store);
            let replacement = TestDatabase::new("preflight-replacement");
            leave_foreign_hot_journal(&replacement);
            let replacement_database = fs::read(replacement.path()).unwrap();
            let replacement_journal_path = journal_path(&replacement);
            let replacement_journal = fs::read(&replacement_journal_path).unwrap();
            let original_backup = original.directory.join("owned-backup.sqlite3");
            let original_journal_path = journal_path(&original);

            let result = SqlCipherMailboxStore::open_inner(
                account(),
                original.path(),
                key(7),
                |_canonical_path| {
                    fs::rename(original.path(), &original_backup).unwrap();
                    fs::rename(replacement.path(), original.path()).unwrap();
                    fs::rename(&replacement_journal_path, &original_journal_path).unwrap();
                },
            );
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::read(original.path()).unwrap(), replacement_database);
            assert_eq!(
                fs::read(original_journal_path).unwrap(),
                replacement_journal
            );
        }

        #[test]
        fn moved_opened_file_is_rejected_before_key_or_database_reads() {
            let original = TestDatabase::new("moved-opened-original");
            let store = SqlCipherMailboxStore::open(account(), original.path(), key(7)).unwrap();
            drop(store);
            let original_bytes = fs::read(original.path()).unwrap();

            let replacement = TestDatabase::new("moved-opened-replacement");
            fs::write(replacement.path(), b"replacement remains unchanged").unwrap();
            let replacement_bytes = fs::read(replacement.path()).unwrap();
            let original_backup = original.directory.join("original-backup.sqlite3");
            let replacement_backup = replacement.directory.join("replacement-backup.sqlite3");

            let result = SqlCipherMailboxStore::open_inner_with_hooks(
                account(),
                original.path(),
                key(7),
                |_canonical_path| {
                    fs::rename(original.path(), &original_backup).unwrap();
                    fs::rename(replacement.path(), original.path()).unwrap();
                },
                |_canonical_path| {
                    fs::rename(original.path(), &replacement_backup).unwrap();
                    fs::rename(&original_backup, original.path()).unwrap();
                },
            );

            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::read(original.path()).unwrap(), original_bytes);
            assert_eq!(fs::read(&replacement_backup).unwrap(), replacement_bytes);
        }

        #[test]
        #[ignore = "subprocess helper for the foreign hot-journal regression"]
        fn foreign_hot_journal_child() {
            let Some(database) = std::env::var_os("TERSA_STORE_HOT_JOURNAL_DATABASE") else {
                return;
            };
            let Some(ready) = std::env::var_os("TERSA_STORE_HOT_JOURNAL_READY") else {
                return;
            };
            let path = canonical_database_path(Path::new(&database)).unwrap();
            let connection = open_connection(&path).unwrap();
            apply_key(&connection, &key(7).0).unwrap();
            connection
                .execute_batch(
                    "PRAGMA journal_mode = DELETE;
                     PRAGMA synchronous = FULL;
                     PRAGMA cache_size = 1;
                     BEGIN IMMEDIATE;
                     UPDATE foreign_owner SET value = zeroblob(1048576);",
                )
                .unwrap();
            fs::write(ready, b"ready").unwrap();
            loop {
                thread::park();
            }
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
        fn reconcile_prunes_in_exact_order_preserves_bodies_and_caches_conditionally() {
            let (_database, store) = open("reconcile");
            let retained = envelope("retained", "thread", 70);
            let displaced = envelope("displaced", "thread", 40);
            run(store.upsert_envelopes(&account(), &[retained.clone(), displaced.clone()]))
                .unwrap();
            let retained_message = Message::new(
                retained.clone(),
                MessageContent::new(b"retained body".to_vec()).unwrap(),
            );
            run(store.put_message(&account(), &retained_message)).unwrap();

            let input = [
                envelope("old", "thread", 10),
                retained.clone(),
                envelope("tie-b", "thread", 50),
                envelope("tie-a", "thread", 50),
            ];
            let survivors = run(store.reconcile_recent_envelopes(
                &account(),
                &input,
                StoreLimit::new(3).unwrap(),
            ))
            .unwrap();
            assert_eq!(
                survivors.iter().map(MessageId::as_str).collect::<Vec<_>>(),
                ["retained", "tie-b", "tie-a"]
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|item| item.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["retained", "tie-a", "tie-b"]
            );
            assert_eq!(
                run(store.message(&account(), retained.message_id()))
                    .unwrap()
                    .unwrap(),
                retained_message
            );

            let missing = Message::new(
                envelope("missing", "thread", 60),
                MessageContent::new(b"missing body".to_vec()).unwrap(),
            );
            assert!(!run(store.cache_message_if_present(&account(), &missing)).unwrap());
            let cached = Message::new(
                envelope("tie-a", "thread", 50),
                MessageContent::new(b"cached body".to_vec()).unwrap(),
            );
            assert!(run(store.cache_message_if_present(&account(), &cached)).unwrap());
            assert_eq!(
                run(store.message(&account(), cached.envelope().message_id()))
                    .unwrap()
                    .unwrap(),
                cached
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .len(),
                3
            );
        }

        #[test]
        fn reconcile_rolls_back_on_failpoints_and_remains_exact_after_reopen() {
            let (database, store) = open("reconcile-rollback");
            let initial = envelope("initial", "thread", 10);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&initial))).unwrap();
            store.fail_next_mutation();
            assert_eq!(
                run(store.reconcile_recent_envelopes(
                    &account(),
                    &[envelope("new", "thread", 20)],
                    StoreLimit::new(1).unwrap(),
                )),
                Err(MailboxStoreError::Storage)
            );
            assert_eq!(
                run(store.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap(),
                vec![initial.clone()]
            );
            store.fail_next_mutation();
            assert_eq!(
                run(store.reconcile_recent_envelopes(&account(), &[], StoreLimit::new(1).unwrap(),)),
                Err(MailboxStoreError::Storage)
            );
            drop(store);
            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                run(reopened.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap(),
                vec![initial]
            );
        }

        #[test]
        fn conditional_cache_rolls_back_and_never_reinserts_a_missing_row() {
            let (database, store) = open("conditional-cache-rollback");
            let present = envelope("present", "thread", 20);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&present))).unwrap();
            let body = Message::new(
                present.clone(),
                MessageContent::new(b"sensitive body".to_vec()).unwrap(),
            );
            store.fail_next_mutation();
            assert_eq!(
                run(store.cache_message_if_present(&account(), &body)),
                Err(MailboxStoreError::Storage)
            );
            drop(store);

            let reopened = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert!(
                run(reopened.message(&account(), present.message_id()))
                    .unwrap()
                    .is_none()
            );
            run(reopened.reconcile_recent_envelopes(
                &account(),
                &[envelope("newer", "thread", 30)],
                StoreLimit::new(1).unwrap(),
            ))
            .unwrap();
            assert!(!run(reopened.cache_message_if_present(&account(), &body)).unwrap());
            assert_eq!(
                run(reopened.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["newer"]
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
