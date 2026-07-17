// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides an account-scoped `SQLCipher` mailbox store for macOS.
//!
//! This adapter has synchronous database internals and lazy runtime-free
//! futures. Callers must poll it on a bounded blocking executor rather than a
//! latency-sensitive async executor thread. It deliberately owns neither blob
//! encryption nor cross-file commit orchestration.
// Rust guideline compliant 1.0.

#![deny(unsafe_code)]

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashSet;
    use std::ffi::{OsStr, OsString};
    use std::fmt;
    use std::io::{self, ErrorKind};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;

    use rusqlite::config::DbConfig;
    use rusqlite::{Connection, ErrorCode, OpenFlags, Transaction, params};
    use rustix::fd::OwnedFd;
    use rustix::fs::{self, AtFlags, CWD, FileType, Mode, OFlags};
    use tersa_application::mailbox::{
        BoxFuture, MailboxReader, MailboxStore, MailboxStoreError, StoreLimit,
    };
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
    const RECOVERY_STAGE_LIMIT: usize = 8;

    /// Owns a redacted, zeroizing `SQLCipher` database key.
    pub struct DatabaseKey(Zeroizing<[u8; 32]>);

    impl DatabaseKey {
        /// Creates a database key from exactly 32 raw bytes.
        #[must_use]
        pub fn new(bytes: [u8; 32]) -> Self {
            Self(Zeroizing::new(bytes))
        }

        /// Consumes an already protected key without materializing raw bytes.
        #[must_use]
        pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
            Self(bytes)
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

    /// Classifies strict read-only opening without exposing backend details.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ReadOnlyMailboxOpenFailure {
        /// The existing profile or its coordination files are unavailable.
        Storage,
        /// The key, owner, schema, rows, or integrity checks were invalid.
        Corrupted,
    }

    /// Reads envelope rows, but no complete message bodies, from one account database.
    ///
    /// This type intentionally implements `MailboxReader`, not `MailboxStore`:
    ///
    /// ```compile_fail
    /// use tersa_application::mailbox::MailboxStore;
    /// use tersa_store_sqlcipher_macos::SqlCipherMailboxReader;
    ///
    /// fn require_store<T: MailboxStore>() {}
    /// require_store::<SqlCipherMailboxReader>();
    /// ```
    pub struct SqlCipherMailboxReader {
        account: AccountId,
        connection: Mutex<Connection>,
    }

    impl fmt::Debug for SqlCipherMailboxReader {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SqlCipherMailboxReader([REDACTED])")
        }
    }

    impl SqlCipherMailboxReader {
        /// Opens an existing persistent-WAL account database without write authority.
        ///
        /// The main database, WAL, and shared-memory sidecar must already be
        /// regular files. It exposes no creation, migration, checkpoint,
        /// repair, or journal-mode operation. The bundled VFS can internally
        /// recreate a sidecar if same-user malware deletes it after preflight;
        /// the post-read identity check fails that open, but cannot undo the
        /// already-created entry.
        ///
        /// # Errors
        ///
        /// Returns opaque corruption for an invalid key, owner, schema, row,
        /// or integrity result. Missing, moved, or unusable files return an
        /// opaque storage error.
        pub fn open_read_only<P: AsRef<Path>>(
            account: AccountId,
            path: P,
            key: DatabaseKey,
        ) -> Result<Self, MailboxStoreError> {
            Self::open_read_only_classified(account, path, key).map_err(|failure| match failure {
                ReadOnlyMailboxOpenFailure::Storage => MailboxStoreError::Storage,
                ReadOnlyMailboxOpenFailure::Corrupted => MailboxStoreError::Corrupted,
            })
        }

        /// Opens an existing account database and preserves the closed failure class.
        ///
        /// This constructor has the same strict read-only behavior as
        /// [`Self::open_read_only`]. It exists so a trusted composition crate
        /// can map the two approved failure classes without depending directly
        /// on the application port crate.
        ///
        /// # Errors
        ///
        /// Returns storage for an unavailable profile or coordination file and
        /// corruption for invalid encrypted or persisted state.
        pub fn open_read_only_classified<P: AsRef<Path>>(
            account: AccountId,
            path: P,
            key: DatabaseKey,
        ) -> Result<Self, ReadOnlyMailboxOpenFailure> {
            Self::open_read_only_with_hooks(
                account,
                path.as_ref(),
                key,
                |_path| {},
                |_path| {},
                |_path| {},
            )
            .map_err(|error| match error {
                MailboxStoreError::Storage => ReadOnlyMailboxOpenFailure::Storage,
                _ => ReadOnlyMailboxOpenFailure::Corrupted,
            })
        }

        fn open_read_only_with_hooks(
            account: AccountId,
            path: &Path,
            mut key: DatabaseKey,
            after_preflight: impl FnOnce(&Path),
            before_live_read: impl FnOnce(&Path),
            after_live_read: impl FnOnce(&Path),
        ) -> Result<Self, MailboxStoreError> {
            let outcome = (|| {
                let canonical_path = canonical_database_path(path)?;
                let identities = preflight_read_only_files(&canonical_path)?;
                after_preflight(&canonical_path);
                let connection = open_read_only_connection(&canonical_path)?;
                disable_and_verify_checkpoint_on_close(&connection)?;
                opened_file_has_moved(&connection)?;
                verify_read_only_file_identities(&canonical_path, identities)?;
                set_and_verify_persistent_wal(&connection)?;
                before_live_read(&canonical_path);
                configure_read_only(&connection, &account, &key.0)?;
                after_live_read(&canonical_path);
                verify_read_only_file_identities(&canonical_path, identities)?;
                Ok(Self {
                    account,
                    connection: Mutex::new(connection),
                })
            })();
            key.0.zeroize();
            outcome.map_err(mailbox_open_error)
        }

        fn checked_account(&self, account: &AccountId) -> Result<(), MailboxStoreError> {
            (self.account == *account)
                .then_some(())
                .ok_or(MailboxStoreError::Storage)
        }

        fn list(
            &self,
            thread: Option<&ThreadId>,
            limit: StoreLimit,
        ) -> Result<Vec<MessageEnvelope>, MailboxStoreError> {
            let mut connection = self
                .connection
                .lock()
                .map_err(|_poison| MailboxStoreError::Storage)?;
            list_envelopes(&mut connection, thread, limit)
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
            Self::open_inner_impl(account, path.as_ref(), key, &mut |_point, _path| Ok(()))
        }

        #[cfg(test)]
        fn open_inner(
            account: AccountId,
            path: &Path,
            key: DatabaseKey,
            after_preflight: impl FnOnce(&Path),
        ) -> Result<Self, MailboxStoreError> {
            let mut after_preflight = Some(after_preflight);
            Self::open_inner_impl(account, path, key, &mut |point, canonical_path| {
                if point == WriterHook::AfterSnapshot {
                    after_preflight.take().expect("hook runs once")(canonical_path);
                }
                Ok(())
            })
        }

        #[cfg(test)]
        fn open_inner_with_hooks(
            account: AccountId,
            path: &Path,
            key: DatabaseKey,
            after_preflight: impl FnOnce(&Path),
            after_open: impl FnOnce(&Path),
        ) -> Result<Self, MailboxStoreError> {
            let mut after_preflight = Some(after_preflight);
            let mut after_open = Some(after_open);
            Self::open_inner_impl(account, path, key, &mut |point, canonical_path| {
                match point {
                    WriterHook::AfterSnapshot => {
                        after_preflight.take().expect("hook runs once")(canonical_path);
                    }
                    WriterHook::AfterOpen => {
                        after_open.take().expect("hook runs once")(canonical_path);
                    }
                    _ => {}
                }
                Ok(())
            })
        }

        #[cfg(test)]
        fn open_inner_with_writer_hook(
            account: AccountId,
            path: &Path,
            key: DatabaseKey,
            hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
        ) -> Result<Self, MailboxStoreError> {
            Self::open_inner_impl(account, path, key, hook)
        }

        fn open_inner_impl(
            account: AccountId,
            path: &Path,
            mut key: DatabaseKey,
            hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
        ) -> Result<Self, MailboxStoreError> {
            let canonical_path = canonical_database_path(path).map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })?;
            let mut leaf = LeafGuard::open(&canonical_path).map_err(|kind| match kind {
                OpenFailure::Corrupted => MailboxStoreError::Corrupted,
                OpenFailure::Storage => MailboxStoreError::Storage,
            })?;
            let existing_preflight = if leaf.snapshot.main.is_some() {
                let preflight = match preflight_existing(&canonical_path, &account, &key.0, &leaf) {
                    Ok(preflight) => preflight,
                    Err(kind) => {
                        key.0.zeroize();
                        return Err(mailbox_open_error(kind));
                    }
                };
                if let Err(kind) = leaf.require_snapshot_unchanged() {
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
                Some(preflight)
            } else {
                None
            };
            if let Err(kind) = hook(WriterHook::AfterSnapshot, &canonical_path) {
                leaf.cleanup_fresh_candidates(hook, &canonical_path);
                key.0.zeroize();
                return Err(mailbox_open_error(kind));
            }
            if leaf.snapshot.is_fresh() {
                if let Err(kind) = hook(WriterHook::BeforeFreshClaim, &canonical_path) {
                    leaf.cleanup_fresh_candidates(hook, &canonical_path);
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
                if let Err(kind) = leaf.claim_fresh_main() {
                    leaf.cleanup_fresh_candidates(hook, &canonical_path);
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
                if let Err(kind) = hook(WriterHook::AfterFreshClaim, &canonical_path) {
                    leaf.cleanup_fresh_candidates(hook, &canonical_path);
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
            }
            let connection = match open_connection(&canonical_path) {
                Ok(connection) => connection,
                Err(kind) => {
                    leaf.cleanup_fresh_candidates(hook, &canonical_path);
                    key.0.zeroize();
                    return Err(mailbox_open_error(kind));
                }
            };
            let outcome = (|| {
                hook(WriterHook::AfterOpen, &canonical_path)?;
                if existing_preflight.is_some() {
                    leaf.require_snapshot_unchanged()?;
                }
                opened_file_has_moved(&connection)?;
                leaf.require_main_identity()?;
                let fresh = configure_storage(&connection, &account, &key.0)?;
                if fresh {
                    materialize_fresh_wal(&connection)?;
                }
                if fresh || existing_preflight.is_some_and(ExistingPreflight::permits_new_sidecars)
                {
                    // SQLite creates the WAL and SHM leaves under the process
                    // umask as soon as WAL is selected. Normalize those leaves
                    // through identity-bound descriptors before migration or
                    // final validation. Cleanup authority remains fresh-main
                    // O_EXCL provenance only.
                    leaf.normalize_fresh_leaves(hook, &canonical_path)?;
                }
                if fresh {
                    hook(WriterHook::AfterFreshWalNormalization, &canonical_path)?;
                    hook(WriterHook::BeforeFreshMigration, &canonical_path)?;
                    migrate_fresh(&connection, &account)?;
                    // Migration can create another coordination leaf; repeat
                    // the identity-bound normalization before accepting it.
                    leaf.normalize_fresh_leaves(hook, &canonical_path)?;
                    leaf.mark_fresh_migration_succeeded();
                    hook(WriterHook::AfterFreshMigration, &canonical_path)?;
                }
                set_and_verify_persistent_wal(&connection)?;
                validate_health(&connection)?;
                if let Some(preflight) = existing_preflight {
                    leaf.require_existing_writer_state(preflight)?;
                }
                Ok(())
            })();
            key.0.zeroize();
            if let Err(kind) = outcome {
                // SQLite must release its handles before descriptor-relative cleanup.
                drop(connection);
                leaf.cleanup_fresh_candidates(hook, &canonical_path);
                return Err(mailbox_open_error(kind));
            }
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
                let has_null_identifier: bool = transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM messages WHERE message_id IS NULL)",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(store_error)?;
                if has_null_identifier {
                    return Err(MailboxStoreError::Corrupted);
                }
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
                let mut seen = HashSet::with_capacity(envelopes.len());
                {
                    let mut statement = transaction
                        .prepare("SELECT EXISTS(SELECT 1 FROM messages WHERE message_id = ?1)")
                        .map_err(store_error)?;
                    for envelope in envelopes {
                        if !seen.insert(envelope.message_id().clone()) {
                            continue;
                        }
                        let exists: bool = statement
                            .query_row(params![envelope.message_id().as_str()], |row| row.get(0))
                            .map_err(store_error)?;
                        if exists {
                            survivors.push(envelope.message_id().clone());
                        }
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
            self.with_connection(|connection| list_envelopes(connection, thread, limit))
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
        owner: u32,
        mode: u16,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DirectoryIdentity {
        device: u64,
        inode: u64,
        owner: u32,
        mode: u16,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct RecoveryStageLeaves {
        main: Option<FileIdentity>,
        wal: Option<FileIdentity>,
        shm: Option<FileIdentity>,
    }

    const OWNER_ONLY_FILE_MODE: u16 = 0o600;

    /// Testable boundaries around fresh-leaf claiming, migration, and cleanup.
    ///
    /// The cleanup gaps are intentionally observable: a same-user process can
    /// insert after the snapshot or replace after final revalidation. macOS has
    /// no unlink-if-inode primitive, so those two cases are documented residuals.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WriterHook {
        AfterSnapshot,
        BeforeFreshClaim,
        AfterFreshClaim,
        AfterOpen,
        BeforeFreshMigration,
        AfterFreshWalNormalization,
        AfterFreshMigration,
        CleanupBeforeRecord(usize),
        CleanupAfterRecord(usize),
        CleanupAfterRevalidate(usize),
        NormalizeAfterOpen(usize),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LeafSnapshot {
        main: Option<FileIdentity>,
        journal: Option<FileIdentity>,
        wal: Option<FileIdentity>,
        shm: Option<FileIdentity>,
    }

    impl LeafSnapshot {
        fn is_fresh(self) -> bool {
            self.main.is_none()
                && self.journal.is_none()
                && self.wal.is_none()
                && self.shm.is_none()
        }
    }

    /// Retains the validated account parent while a writer claims a fresh leaf.
    ///
    /// The `SQLite` opener remains pathname-based. This guard exists only for
    /// no-follow snapshots and bounded cleanup of files absent at preflight.
    struct LeafGuard {
        parent: OwnedFd,
        parent_owner: u32,
        names: [OsString; 4],
        snapshot: LeafSnapshot,
        fresh_main: Option<FileIdentity>,
        fresh_migration_succeeded: bool,
    }

    impl LeafGuard {
        fn open(path: &Path) -> Result<Self, OpenFailure> {
            let parent = path.parent().ok_or(OpenFailure::Storage)?;
            let name = path.file_name().ok_or(OpenFailure::Storage)?;
            let names = leaf_names(name);
            let parent = fs::openat(
                CWD,
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_error| OpenFailure::Storage)?;
            let parent_stat = fs::fstat(&parent).map_err(|_error| OpenFailure::Storage)?;
            if FileType::from_raw_mode(parent_stat.st_mode) != FileType::Directory {
                return Err(OpenFailure::Storage);
            }
            let parent_owner = parent_stat.st_uid;
            let snapshot = snapshot_leaf_entries(&parent, parent_owner, &names)?;
            // Existing writer-visible leaves are accepted only at the exact
            // owner-only mode. A pre-existing leaf has no creation provenance
            // from this opener and is never normalized or adopted.
            if [snapshot.main, snapshot.wal, snapshot.shm]
                .into_iter()
                .flatten()
                .any(|identity| identity.mode != OWNER_ONLY_FILE_MODE)
            {
                return Err(OpenFailure::Storage);
            }
            if snapshot.main.is_none()
                && (snapshot.journal.is_some() || snapshot.wal.is_some() || snapshot.shm.is_some())
            {
                return Err(OpenFailure::Corrupted);
            }
            Ok(Self {
                parent,
                parent_owner,
                names,
                snapshot,
                fresh_main: None,
                fresh_migration_succeeded: false,
            })
        }

        fn claim_fresh_main(&mut self) -> Result<(), OpenFailure> {
            let descriptor = fs::openat(
                &self.parent,
                &self.names[0],
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from(OWNER_ONLY_FILE_MODE),
            )
            .map_err(|_error| OpenFailure::Storage)?;
            // O_CREAT's mode is filtered by umask.  This descriptor is still
            // exclusively ours, so normalize before exact-mode validation.
            fs::fchmod(&descriptor, Mode::from(OWNER_ONLY_FILE_MODE))
                .map_err(|_error| OpenFailure::Storage)?;
            let identity = restrictive_regular_identity(
                &fs::fstat(&descriptor).map_err(|_error| OpenFailure::Storage)?,
                self.parent_owner,
            )?;
            drop(descriptor);
            self.fresh_main = Some(identity);
            Ok(())
        }

        fn require_main_identity(&self) -> Result<(), OpenFailure> {
            let expected = self
                .fresh_main
                .or(self.snapshot.main)
                .ok_or(OpenFailure::Storage)?;
            let actual = leaf_entry(&self.parent, &self.names[0], self.parent_owner)?
                .ok_or(OpenFailure::Storage)?;
            (actual == expected)
                .then_some(())
                .ok_or(OpenFailure::Storage)
        }

        fn require_snapshot_unchanged(&self) -> Result<(), OpenFailure> {
            (snapshot_leaf_entries(&self.parent, self.parent_owner, &self.names)? == self.snapshot)
                .then_some(())
                .ok_or(OpenFailure::Storage)
        }

        fn require_existing_writer_state(
            &self,
            preflight: ExistingPreflight,
        ) -> Result<(), OpenFailure> {
            let actual = snapshot_leaf_entries(&self.parent, self.parent_owner, &self.names)?;
            let unchanged = actual.main == self.snapshot.main
                && actual.journal == self.snapshot.journal
                && match preflight {
                    ExistingPreflight::Stable | ExistingPreflight::FreshWal => {
                        actual.wal == self.snapshot.wal && actual.shm == self.snapshot.shm
                    }
                    ExistingPreflight::MainWithoutSidecars => {
                        actual.wal.is_some() && actual.shm.is_some()
                    }
                    ExistingPreflight::WalWithoutShm | ExistingPreflight::FreshWalWithoutShm => {
                        actual.wal == self.snapshot.wal && actual.shm.is_some()
                    }
                };
            let exact_owner_only_modes = [actual.main, actual.wal, actual.shm]
                .into_iter()
                .flatten()
                .all(|identity| identity.mode == OWNER_ONLY_FILE_MODE);
            (unchanged && exact_owner_only_modes)
                .then_some(())
                .ok_or(OpenFailure::Storage)
        }

        fn mark_fresh_migration_succeeded(&mut self) {
            self.fresh_migration_succeeded = true;
        }

        fn normalize_fresh_leaves(
            &mut self,
            hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
            canonical_path: &Path,
        ) -> Result<(), OpenFailure> {
            let before = [
                self.snapshot.main,
                self.snapshot.journal,
                self.snapshot.wal,
                self.snapshot.shm,
            ];
            for (index, (name, prior)) in self.names.iter().zip(before).enumerate() {
                let Some(identity) = leaf_entry(&self.parent, name, self.parent_owner)? else {
                    continue;
                };
                if prior.is_none() {
                    if identity.mode != OWNER_ONLY_FILE_MODE {
                        // SQLite may create a sidecar as 0000 under a highly
                        // restrictive umask. Normalize through the retained
                        // parent before opening, then bind the descriptor to
                        // this pre-chmod identity and normalize it again.
                        fs::chmodat(
                            &self.parent,
                            name,
                            Mode::from(OWNER_ONLY_FILE_MODE),
                            AtFlags::SYMLINK_NOFOLLOW,
                        )
                        .map_err(|_error| OpenFailure::Storage)?;
                    }
                    let descriptor = fs::openat(
                        &self.parent,
                        name,
                        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_error| OpenFailure::Storage)?;
                    let opened = regular_identity(
                        &fs::fstat(&descriptor).map_err(|_error| OpenFailure::Storage)?,
                        self.parent_owner,
                    )?;
                    if opened.device != identity.device || opened.inode != identity.inode {
                        return Err(OpenFailure::Storage);
                    }
                    hook(WriterHook::NormalizeAfterOpen(index), canonical_path)?;
                    fs::fchmod(&descriptor, Mode::from(OWNER_ONLY_FILE_MODE))
                        .map_err(|_error| OpenFailure::Storage)?;
                    let normalized_descriptor = restrictive_regular_identity(
                        &fs::fstat(&descriptor).map_err(|_error| OpenFailure::Storage)?,
                        self.parent_owner,
                    )?;
                    if normalized_descriptor.device != identity.device
                        || normalized_descriptor.inode != identity.inode
                    {
                        return Err(OpenFailure::Storage);
                    }
                }
                let normalized = leaf_entry(&self.parent, name, self.parent_owner)?
                    .ok_or(OpenFailure::Storage)?;
                if normalized.device != identity.device
                    || normalized.inode != identity.inode
                    || normalized.mode != OWNER_ONLY_FILE_MODE
                {
                    return Err(OpenFailure::Storage);
                }
            }
            self.require_main_identity()
        }

        fn cleanup_fresh_candidates(
            &self,
            hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
            canonical_path: &Path,
        ) {
            // Cleanup authority exists only after this opener proved authorship
            // of the main leaf with an exclusive create. A pre-existing or
            // racing main file never grants cleanup authority for itself or for
            // any sidecar.
            let Some(fresh_main) = self.fresh_main else {
                return;
            };
            if self.fresh_migration_succeeded {
                return;
            }
            // Sidecars are removed before the main leaf. Before every unlink,
            // the main name must still resolve to the exact O_EXCL-created
            // identity that granted this cleanup authority. A replacement,
            // deletion, or pre-existing main therefore preserves every
            // remaining leaf instead of being adopted for cleanup.
            for index in [3, 2, 1, 0] {
                if leaf_entry(&self.parent, &self.names[0], self.parent_owner)
                    .ok()
                    .flatten()
                    != Some(fresh_main)
                {
                    return;
                }
                let expected = (index == 0).then_some(fresh_main);
                let _ = remove_unchanged_restrictive_leaf(
                    &self.parent,
                    &self.names[index],
                    self.parent_owner,
                    (index, expected),
                    (&self.names[0], fresh_main),
                    hook,
                    canonical_path,
                );
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ReadOnlyFileIdentities {
        main: FileIdentity,
        wal: FileIdentity,
        shm: FileIdentity,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExistingPreflight {
        Stable,
        MainWithoutSidecars,
        WalWithoutShm,
        FreshWal,
        FreshWalWithoutShm,
    }

    impl ExistingPreflight {
        const fn permits_new_sidecars(self) -> bool {
            matches!(
                self,
                Self::MainWithoutSidecars | Self::WalWithoutShm | Self::FreshWalWithoutShm
            )
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecoveryHook {
        AfterDirectoryCreate,
        AfterDirectoryNormalize,
        AfterMainCopy,
        AfterWalCopy,
        BeforeReadOnlyOpen,
        AfterReadOnlyOpen,
        BeforeOriginalFinalRevalidate,
        BeforeCleanup,
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

    fn leaf_names(name: &OsStr) -> [OsString; 4] {
        let mut journal = name.to_os_string();
        journal.push("-journal");
        let mut wal = name.to_os_string();
        wal.push("-wal");
        let mut shm = name.to_os_string();
        shm.push("-shm");
        [name.to_os_string(), journal, wal, shm]
    }

    fn snapshot_leaf_entries(
        parent: &OwnedFd,
        parent_owner: u32,
        names: &[OsString; 4],
    ) -> Result<LeafSnapshot, OpenFailure> {
        Ok(LeafSnapshot {
            main: leaf_entry(parent, &names[0], parent_owner)?,
            journal: leaf_entry(parent, &names[1], parent_owner)?,
            wal: leaf_entry(parent, &names[2], parent_owner)?,
            shm: leaf_entry(parent, &names[3], parent_owner)?,
        })
    }

    fn leaf_entry(
        parent: &OwnedFd,
        name: &OsStr,
        parent_owner: u32,
    ) -> Result<Option<FileIdentity>, OpenFailure> {
        match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => regular_identity(&stat, parent_owner).map(Some),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
            Err(_error) => Err(OpenFailure::Storage),
        }
    }

    fn regular_identity(stat: &fs::Stat, parent_owner: u32) -> Result<FileIdentity, OpenFailure> {
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != parent_owner
        {
            return Err(OpenFailure::Storage);
        }
        Ok(FileIdentity {
            device: u64::try_from(stat.st_dev).map_err(|_error| OpenFailure::Storage)?,
            inode: stat.st_ino,
            owner: stat.st_uid,
            mode: Mode::from_raw_mode(stat.st_mode).as_raw_mode(),
        })
    }

    fn restrictive_regular_identity(
        stat: &fs::Stat,
        parent_owner: u32,
    ) -> Result<FileIdentity, OpenFailure> {
        let identity = regular_identity(stat, parent_owner)?;
        (identity.mode == OWNER_ONLY_FILE_MODE)
            .then_some(identity)
            .ok_or(OpenFailure::Storage)
    }

    fn remove_unchanged_restrictive_leaf(
        parent: &OwnedFd,
        name: &OsStr,
        parent_owner: u32,
        candidate: (usize, Option<FileIdentity>),
        cleanup_authority: (&OsStr, FileIdentity),
        hook: &mut dyn FnMut(WriterHook, &Path) -> Result<(), OpenFailure>,
        canonical_path: &Path,
    ) -> Result<(), OpenFailure> {
        let (index, expected) = candidate;
        // A hook error only stops this best-effort cleanup; the caller retains
        // its original redacted failure class.
        hook(WriterHook::CleanupBeforeRecord(index), canonical_path)?;
        let recorded = leaf_entry(parent, name, parent_owner)?.ok_or(OpenFailure::Storage)?;
        if expected.is_some_and(|identity| identity != recorded) {
            return Err(OpenFailure::Storage);
        }
        hook(WriterHook::CleanupAfterRecord(index), canonical_path)?;
        let revalidated = leaf_entry(parent, name, parent_owner)?.ok_or(OpenFailure::Storage)?;
        if recorded != revalidated {
            return Err(OpenFailure::Storage);
        }
        if recorded.mode != OWNER_ONLY_FILE_MODE {
            return Err(OpenFailure::Storage);
        }
        hook(WriterHook::CleanupAfterRevalidate(index), canonical_path)?;
        if leaf_entry(parent, cleanup_authority.0, parent_owner)? != Some(cleanup_authority.1) {
            return Err(OpenFailure::Storage);
        }
        fs::unlinkat(parent, name, AtFlags::empty()).map_err(|_error| OpenFailure::Storage)
    }

    #[cfg(test)]
    fn prepare_database_leaf(path: &Path) -> Result<LeafSnapshot, OpenFailure> {
        let mut leaf = LeafGuard::open(path)?;
        if leaf.snapshot.is_fresh() {
            leaf.claim_fresh_main()?;
        }
        Ok(leaf.snapshot)
    }

    fn file_identity(path: &Path) -> Result<FileIdentity, OpenFailure> {
        let metadata = std::fs::symlink_metadata(path).map_err(|_error| OpenFailure::Storage)?;
        if !metadata.file_type().is_file() {
            return Err(OpenFailure::Storage);
        }
        Ok(identity_from_metadata(&metadata))
    }

    fn restrictive_file_identity(
        path: &Path,
        parent_owner: u32,
    ) -> Result<FileIdentity, OpenFailure> {
        let identity = file_identity(path)?;
        (identity.owner == parent_owner && identity.mode == OWNER_ONLY_FILE_MODE)
            .then_some(identity)
            .ok_or(OpenFailure::Storage)
    }

    fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    }

    fn create_recovery_stage(
        leaf: &LeafGuard,
        canonical_path: &Path,
        hook: &mut dyn FnMut(RecoveryHook, &Path) -> Result<(), OpenFailure>,
    ) -> Result<(OwnedFd, OsString, PathBuf, DirectoryIdentity), OpenFailure> {
        let parent_path = canonical_path.parent().ok_or(OpenFailure::Storage)?;
        for slot in 0..RECOVERY_STAGE_LIMIT {
            let name = OsString::from(format!(".tersa-wal-recovery-v1-{slot}"));
            let path = parent_path.join(&name);
            match fs::mkdirat(&leaf.parent, &name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    let initial = recovery_directory_identity_permissive(
                        &leaf.parent,
                        &name,
                        leaf.parent_owner,
                    )?;
                    let setup = (|| {
                        hook(RecoveryHook::AfterDirectoryCreate, &path)?;
                        fs::chmodat(
                            &leaf.parent,
                            &name,
                            Mode::from_raw_mode(0o700),
                            AtFlags::SYMLINK_NOFOLLOW,
                        )
                        .map_err(|_error| OpenFailure::Storage)?;
                        let normalized =
                            recovery_directory_identity(&leaf.parent, &name, leaf.parent_owner)?;
                        if !same_directory_object(initial, normalized) {
                            return Err(OpenFailure::Storage);
                        }
                        hook(RecoveryHook::AfterDirectoryNormalize, &path)?;
                        let directory = fs::openat(
                            &leaf.parent,
                            &name,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map_err(|_error| OpenFailure::Storage)?;
                        let opened = directory_identity_from_stat(
                            &fs::fstat(&directory).map_err(|_error| OpenFailure::Storage)?,
                            leaf.parent_owner,
                            true,
                        )?;
                        if opened != normalized {
                            return Err(OpenFailure::Storage);
                        }
                        Ok((directory, normalized))
                    })();
                    return match setup {
                        Ok((directory, identity)) => Ok((directory, name, path, identity)),
                        Err(error) => {
                            let _ = cleanup_created_empty_recovery_directory(leaf, &name, initial);
                            Err(error)
                        }
                    };
                }
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(_error) => return Err(OpenFailure::Storage),
            }
        }
        Err(OpenFailure::Storage)
    }

    fn copy_recovery_leaf(
        source_parent: &OwnedFd,
        source_name: &OsStr,
        source_owner: u32,
        expected: FileIdentity,
        destination_parent: &OwnedFd,
        destination_name: &OsStr,
        created: &mut Option<FileIdentity>,
    ) -> Result<FileIdentity, OpenFailure> {
        let source = fs::openat(
            source_parent,
            source_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_error| OpenFailure::Storage)?;
        let source_stat = fs::fstat(&source).map_err(|_error| OpenFailure::Storage)?;
        if source_stat.st_size < 32 {
            return Err(OpenFailure::Corrupted);
        }
        let source_identity = restrictive_regular_identity(&source_stat, source_owner)?;
        if source_identity != expected {
            return Err(OpenFailure::Storage);
        }
        let destination = fs::openat(
            destination_parent,
            destination_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(OWNER_ONLY_FILE_MODE),
        )
        .map_err(|_error| OpenFailure::Storage)?;
        fs::fchmod(&destination, Mode::from_raw_mode(OWNER_ONLY_FILE_MODE))
            .map_err(|_error| OpenFailure::Storage)?;
        let destination_identity = restrictive_regular_identity(
            &fs::fstat(&destination).map_err(|_error| OpenFailure::Storage)?,
            source_owner,
        )?;
        *created = Some(destination_identity);

        let mut source_file = std::fs::File::from(source);
        let mut destination_file = std::fs::File::from(destination);
        io::copy(&mut source_file, &mut destination_file).map_err(|_error| OpenFailure::Storage)?;
        destination_file
            .sync_all()
            .map_err(|_error| OpenFailure::Storage)?;
        Ok(destination_identity)
    }

    fn directory_identity_from_stat(
        stat: &fs::Stat,
        owner: u32,
        exact_mode: bool,
    ) -> Result<DirectoryIdentity, OpenFailure> {
        let mode = Mode::from_raw_mode(stat.st_mode).as_raw_mode();
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || stat.st_uid != owner
            || if exact_mode {
                mode != 0o700
            } else {
                mode & !0o700 != 0
            }
        {
            return Err(OpenFailure::Storage);
        }
        Ok(DirectoryIdentity {
            device: u64::try_from(stat.st_dev).map_err(|_error| OpenFailure::Storage)?,
            inode: stat.st_ino,
            owner: stat.st_uid,
            mode,
        })
    }

    const fn same_directory_object(left: DirectoryIdentity, right: DirectoryIdentity) -> bool {
        left.device == right.device && left.inode == right.inode && left.owner == right.owner
    }

    fn recovery_directory_identity_permissive(
        parent: &OwnedFd,
        name: &OsStr,
        owner: u32,
    ) -> Result<DirectoryIdentity, OpenFailure> {
        let stat = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_error| OpenFailure::Storage)?;
        directory_identity_from_stat(&stat, owner, false)
    }

    fn recovery_directory_identity(
        parent: &OwnedFd,
        name: &OsStr,
        owner: u32,
    ) -> Result<DirectoryIdentity, OpenFailure> {
        let stat = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_error| OpenFailure::Storage)?;
        directory_identity_from_stat(&stat, owner, true)
    }

    fn cleanup_created_empty_recovery_directory(
        leaf: &LeafGuard,
        name: &OsStr,
        expected: DirectoryIdentity,
    ) -> Result<(), OpenFailure> {
        let actual = recovery_directory_identity_permissive(&leaf.parent, name, leaf.parent_owner)?;
        if !same_directory_object(actual, expected) {
            return Err(OpenFailure::Storage);
        }
        fs::unlinkat(&leaf.parent, name, AtFlags::REMOVEDIR).map_err(|_error| OpenFailure::Storage)
    }

    fn recovery_stage_has_only_expected_names(
        directory: &OwnedFd,
        leaf: &LeafGuard,
        expected: RecoveryStageLeaves,
    ) -> Result<(), OpenFailure> {
        let expected_names = [
            expected.main.is_some().then_some(&leaf.names[0]),
            None,
            expected.wal.is_some().then_some(&leaf.names[2]),
            expected.shm.is_some().then_some(&leaf.names[3]),
        ];
        let entries = fs::Dir::read_from(directory).map_err(|_error| OpenFailure::Storage)?;
        for entry in entries {
            let entry = entry.map_err(|_error| OpenFailure::Storage)?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            if !expected_names
                .iter()
                .flatten()
                .any(|expected_name| expected_name.as_os_str().as_encoded_bytes() == name)
            {
                return Err(OpenFailure::Storage);
            }
        }
        Ok(())
    }

    fn cleanup_recovery_stage(
        leaf: &LeafGuard,
        directory: &OwnedFd,
        name: &OsStr,
        expected_directory: DirectoryIdentity,
        expected_leaves: RecoveryStageLeaves,
    ) -> Result<(), OpenFailure> {
        if recovery_directory_identity(&leaf.parent, name, leaf.parent_owner)? != expected_directory
            || directory_identity_from_stat(
                &fs::fstat(directory).map_err(|_error| OpenFailure::Storage)?,
                leaf.parent_owner,
                true,
            )? != expected_directory
        {
            return Err(OpenFailure::Storage);
        }
        recovery_stage_has_only_expected_names(directory, leaf, expected_leaves)?;

        let expected = [
            expected_leaves.main,
            None,
            expected_leaves.wal,
            expected_leaves.shm,
        ];
        for (leaf_name, expected_identity) in leaf.names.iter().zip(expected) {
            if leaf_entry(directory, leaf_name, leaf.parent_owner)? != expected_identity {
                return Err(OpenFailure::Storage);
            }
        }
        for (leaf_name, expected_identity) in leaf.names.iter().zip(expected).rev() {
            if let Some(expected_identity) = expected_identity {
                if leaf_entry(directory, leaf_name, leaf.parent_owner)? != Some(expected_identity) {
                    return Err(OpenFailure::Storage);
                }
                fs::unlinkat(directory, leaf_name, AtFlags::empty())
                    .map_err(|_error| OpenFailure::Storage)?;
            }
        }
        if recovery_directory_identity(&leaf.parent, name, leaf.parent_owner)? != expected_directory
        {
            return Err(OpenFailure::Storage);
        }
        fs::unlinkat(&leaf.parent, name, AtFlags::REMOVEDIR).map_err(|_error| OpenFailure::Storage)
    }

    fn verify_recovery_stage(
        leaf: &LeafGuard,
        directory: &OwnedFd,
        name: &OsStr,
        expected_directory: DirectoryIdentity,
        expected_main: FileIdentity,
        expected_wal: FileIdentity,
        expected_shm: FileIdentity,
    ) -> Result<(), OpenFailure> {
        if recovery_directory_identity(&leaf.parent, name, leaf.parent_owner)? != expected_directory
            || directory_identity_from_stat(
                &fs::fstat(directory).map_err(|_error| OpenFailure::Storage)?,
                leaf.parent_owner,
                true,
            )? != expected_directory
            || leaf_entry(directory, &leaf.names[0], leaf.parent_owner)? != Some(expected_main)
            || leaf_entry(directory, &leaf.names[2], leaf.parent_owner)? != Some(expected_wal)
            || leaf_entry(directory, &leaf.names[3], leaf.parent_owner)? != Some(expected_shm)
        {
            return Err(OpenFailure::Storage);
        }
        Ok(())
    }

    fn finish_recovery_validation(
        validation: Result<bool, OpenFailure>,
        cleanup_hook: Result<(), OpenFailure>,
        cleanup: Result<(), OpenFailure>,
    ) -> Result<bool, OpenFailure> {
        match validation {
            Err(error) => Err(error),
            Ok(fresh) => cleanup_hook.and(cleanup).map(|()| fresh),
        }
    }

    fn validate_wal_without_shm_from_private_copy(
        canonical_path: &Path,
        account: &AccountId,
        key: &[u8; 32],
        leaf: &LeafGuard,
    ) -> Result<bool, OpenFailure> {
        validate_wal_without_shm_from_private_copy_with_hook(
            canonical_path,
            account,
            key,
            leaf,
            &mut |_point, _path| Ok(()),
        )
    }

    fn validate_wal_without_shm_from_private_copy_with_hook(
        canonical_path: &Path,
        account: &AccountId,
        key: &[u8; 32],
        leaf: &LeafGuard,
        hook: &mut dyn FnMut(RecoveryHook, &Path) -> Result<(), OpenFailure>,
    ) -> Result<bool, OpenFailure> {
        let main = leaf.snapshot.main.ok_or(OpenFailure::Storage)?;
        let wal = leaf.snapshot.wal.ok_or(OpenFailure::Storage)?;
        let (directory, stage_name, stage_path, directory_identity) =
            create_recovery_stage(leaf, canonical_path, hook)?;
        let mut created_leaves = RecoveryStageLeaves::default();
        let validation = (|| {
            let copied_main = copy_recovery_leaf(
                &leaf.parent,
                &leaf.names[0],
                leaf.parent_owner,
                main,
                &directory,
                &leaf.names[0],
                &mut created_leaves.main,
            )?;
            hook(RecoveryHook::AfterMainCopy, &stage_path)?;
            let copied_wal = copy_recovery_leaf(
                &leaf.parent,
                &leaf.names[2],
                leaf.parent_owner,
                wal,
                &directory,
                &leaf.names[2],
                &mut created_leaves.wal,
            )?;
            hook(RecoveryHook::AfterWalCopy, &stage_path)?;
            let shm = fs::openat(
                &directory,
                &leaf.names[3],
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(OWNER_ONLY_FILE_MODE),
            )
            .map_err(|_error| OpenFailure::Storage)?;
            fs::fchmod(&shm, Mode::from_raw_mode(OWNER_ONLY_FILE_MODE))
                .map_err(|_error| OpenFailure::Storage)?;
            let copied_shm = restrictive_regular_identity(
                &fs::fstat(&shm).map_err(|_error| OpenFailure::Storage)?,
                leaf.parent_owner,
            )?;
            created_leaves.shm = Some(copied_shm);
            drop(shm);
            leaf.require_snapshot_unchanged()?;
            verify_recovery_stage(
                leaf,
                &directory,
                &stage_name,
                directory_identity,
                copied_main,
                copied_wal,
                copied_shm,
            )?;
            hook(RecoveryHook::BeforeReadOnlyOpen, &stage_path)?;
            let connection = open_read_only_connection(&stage_path.join(&leaf.names[0]))?;
            disable_and_verify_checkpoint_on_close(&connection)?;
            opened_file_has_moved(&connection)?;
            verify_recovery_stage(
                leaf,
                &directory,
                &stage_name,
                directory_identity,
                copied_main,
                copied_wal,
                copied_shm,
            )?;
            hook(RecoveryHook::AfterReadOnlyOpen, &stage_path)?;
            verify_recovery_stage(
                leaf,
                &directory,
                &stage_name,
                directory_identity,
                copied_main,
                copied_wal,
                copied_shm,
            )?;
            let fresh = validate_recovery_read_only(&connection, account, key)?;
            verify_recovery_stage(
                leaf,
                &directory,
                &stage_name,
                directory_identity,
                copied_main,
                copied_wal,
                copied_shm,
            )?;
            drop(connection);
            hook(RecoveryHook::BeforeOriginalFinalRevalidate, &stage_path)?;
            leaf.require_snapshot_unchanged()?;
            Ok(fresh)
        })();
        let cleanup_hook = hook(RecoveryHook::BeforeCleanup, &stage_path);
        let cleanup = cleanup_recovery_stage(
            leaf,
            &directory,
            &stage_name,
            directory_identity,
            created_leaves,
        );
        finish_recovery_validation(validation, cleanup_hook, cleanup)
    }

    fn preflight_read_only_files(path: &Path) -> Result<ReadOnlyFileIdentities, OpenFailure> {
        let parent = path.parent().ok_or(OpenFailure::Storage)?;
        let parent_metadata =
            std::fs::symlink_metadata(parent).map_err(|_error| OpenFailure::Storage)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(OpenFailure::Storage);
        }
        let parent_owner = parent_metadata.uid();
        let main_metadata =
            std::fs::symlink_metadata(path).map_err(|_error| OpenFailure::Storage)?;
        if !main_metadata.file_type().is_file() || main_metadata.len() < 512 {
            return Err(OpenFailure::Storage);
        }
        let main = identity_from_metadata(&main_metadata);
        if main.owner != parent_owner || main.mode != OWNER_ONLY_FILE_MODE {
            return Err(OpenFailure::Storage);
        }
        match std::fs::symlink_metadata(sidecar_path(path, "-journal")) {
            Ok(_metadata) => return Err(OpenFailure::Storage),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_error) => return Err(OpenFailure::Storage),
        }
        Ok(ReadOnlyFileIdentities {
            main,
            wal: restrictive_file_identity(&sidecar_path(path, "-wal"), parent_owner)?,
            shm: restrictive_file_identity(&sidecar_path(path, "-shm"), parent_owner)?,
        })
    }

    fn verify_read_only_file_identities(
        path: &Path,
        expected: ReadOnlyFileIdentities,
    ) -> Result<(), OpenFailure> {
        let parent_owner = expected.main.owner;
        let actual = ReadOnlyFileIdentities {
            main: restrictive_file_identity(path, parent_owner)?,
            wal: restrictive_file_identity(&sidecar_path(path, "-wal"), parent_owner)?,
            shm: restrictive_file_identity(&sidecar_path(path, "-shm"), parent_owner)?,
        };
        (actual == expected)
            .then_some(())
            .ok_or(OpenFailure::Storage)
    }

    fn identity_from_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: u16::try_from(metadata.mode() & 0o7777).unwrap_or_default(),
        }
    }

    fn open_connection(path: &Path) -> Result<Connection, OpenFailure> {
        let base_flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        Connection::open_with_flags(path, base_flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
            .map_err(|_error| OpenFailure::Storage)
    }

    fn open_read_only_connection(path: &Path) -> Result<Connection, OpenFailure> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        Connection::open_with_flags(path, flags).map_err(|_error| OpenFailure::Storage)
    }

    fn disable_and_verify_checkpoint_on_close(connection: &Connection) -> Result<(), OpenFailure> {
        let config = DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE;
        if !connection
            .set_db_config(config, true)
            .map_err(|_error| OpenFailure::Storage)?
            || !connection
                .db_config(config)
                .map_err(|_error| OpenFailure::Storage)?
        {
            return Err(OpenFailure::Storage);
        }
        Ok(())
    }

    #[expect(
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
        leaf: &LeafGuard,
    ) -> Result<ExistingPreflight, OpenFailure> {
        let snapshot = leaf.snapshot;
        if snapshot.journal.is_some() || (snapshot.wal.is_none() && snapshot.shm.is_some()) {
            return Err(OpenFailure::Corrupted);
        }
        if snapshot.wal.is_some() && snapshot.shm.is_none() {
            // SQLite rejects both immutable and normal read-only opens for a
            // WAL without its shared-memory index. Validate encrypted copies
            // in a private, identity-bound staging directory. The original
            // main/WAL pair remains read-only and is revalidated before and
            // after logical key, account, schema, and health checks.
            let fresh = validate_wal_without_shm_from_private_copy(path, account, key, leaf)?;
            return Ok(if fresh {
                ExistingPreflight::FreshWalWithoutShm
            } else {
                ExistingPreflight::WalWithoutShm
            });
        }

        let uri = immutable_file_uri(path);
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let main_connection = Connection::open_with_flags(PathBuf::from(uri), flags)
            .map_err(|_error| OpenFailure::Storage)?;
        apply_key(&main_connection, key).map_err(classify_key)?;
        let _main_is_fresh = validate_identity(&main_connection, account)?;
        let Some(_wal) = snapshot.wal else {
            return Ok(ExistingPreflight::MainWithoutSidecars);
        };

        // `immutable=1` deliberately ignores WAL. When an otherwise fresh main
        // has a WAL, validate the logical database through a non-checkpointing
        // read-only connection so an abrupt first-migration exit can recover
        // without granting write, repair, or cleanup authority. If SHM is
        // missing, a private encrypted-copy path above performs validation
        // without modifying the original leaf set.
        let wal_connection = open_read_only_connection(path)?;
        disable_and_verify_checkpoint_on_close(&wal_connection)?;
        opened_file_has_moved(&wal_connection)?;
        let fresh = validate_recovery_read_only(&wal_connection, account, key)?;
        Ok(if fresh {
            ExistingPreflight::FreshWal
        } else {
            ExistingPreflight::Stable
        })
    }

    fn immutable_file_uri(path: &Path) -> OsString {
        file_uri(path, b"?immutable=1")
    }

    fn file_uri(path: &Path, query: &[u8]) -> OsString {
        let mut uri =
            Vec::with_capacity(path.as_os_str().as_encoded_bytes().len() + query.len() + 8);
        uri.extend_from_slice(b"file:");
        for byte in path.as_os_str().as_encoded_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
                uri.push(*byte);
            } else {
                uri.push(b'%');
                uri.push(hex_digit(byte >> 4));
                uri.push(hex_digit(byte & 0x0f));
            }
        }
        uri.extend_from_slice(query);
        OsString::from_vec(uri)
    }

    const fn hex_digit(value: u8) -> u8 {
        match value {
            0..=9 => b'0' + value,
            _ => b'A' + (value - 10),
        }
    }

    fn list_envelopes(
        connection: &mut Connection,
        thread: Option<&ThreadId>,
        limit: StoreLimit,
    ) -> Result<Vec<MessageEnvelope>, MailboxStoreError> {
        let sql = if thread.is_some() {
            "SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, CASE WHEN typeof(received_at) = 'integer' THEN received_at END, CASE WHEN typeof(unread) = 'integer' THEN unread END FROM messages WHERE thread_id = ?1 ORDER BY received_at ASC, message_id ASC LIMIT ?2"
        } else {
            "SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) <= 256 THEN message_id END, CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) <= 256 THEN thread_id END, CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END, CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END, CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END, CASE WHEN typeof(received_at) = 'integer' THEN received_at END, CASE WHEN typeof(unread) = 'integer' THEN unread END FROM messages ORDER BY received_at DESC, message_id ASC LIMIT ?1"
        };
        let mut statement = connection.prepare(sql).map_err(store_error)?;
        let mut rows = match thread {
            Some(thread_id) => statement.query(params![thread_id.as_str(), i64::from(limit.get())]),
            None => statement.query(params![i64::from(limit.get())]),
        }
        .map_err(store_error)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(store_error)? {
            result.push(envelope_from_row(row)?);
        }
        Ok(result)
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

    impl MailboxReader for SqlCipherMailboxStore {
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
    }

    impl MailboxReader for SqlCipherMailboxReader {
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
    fn configure_storage(
        connection: &Connection,
        account: &AccountId,
        key: &[u8; 32],
    ) -> Result<bool, OpenFailure> {
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
        configure_owned_storage(connection)?;
        Ok(fresh)
    }

    fn migrate_fresh(connection: &Connection, account: &AccountId) -> Result<(), OpenFailure> {
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
        transaction.commit().map_err(classify_open)
    }

    fn materialize_fresh_wal(connection: &Connection) -> Result<(), OpenFailure> {
        connection
            .execute_batch("BEGIN IMMEDIATE; PRAGMA user_version = 0; COMMIT;")
            .map_err(classify_open)
    }

    fn configure_read_only(
        connection: &Connection,
        account: &AccountId,
        key: &[u8; 32],
    ) -> Result<(), OpenFailure> {
        if validate_recovery_read_only(connection, account, key)? {
            return Err(OpenFailure::Corrupted);
        }
        Ok(())
    }

    fn validate_recovery_read_only(
        connection: &Connection,
        account: &AccountId,
        key: &[u8; 32],
    ) -> Result<bool, OpenFailure> {
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
        let journal_size_limit: i64 = connection
            .query_row("PRAGMA journal_size_limit", [], |row| row.get(0))
            .map_err(classify_open)?;
        if journal_size_limit != -1 {
            return Err(OpenFailure::Corrupted);
        }

        connection.execute_batch("BEGIN;").map_err(classify_open)?;
        let validation = (|| {
            let fresh = validate_identity(connection, account)?;
            validate_health(connection)?;
            Ok(fresh)
        })();
        if validation.is_ok() {
            connection.execute_batch("COMMIT;").map_err(classify_open)?;
        } else {
            let _ = connection.execute_batch("ROLLBACK;");
        }
        validation
    }

    #[expect(
        unsafe_code,
        reason = "SQLite PERSIST_WAL file control accepts a mutable integer pointer"
    )]
    fn persistent_wal_control(connection: &Connection, value: &mut i32) -> Result<(), OpenFailure> {
        // SAFETY: `connection.handle()` remains valid for this synchronous call;
        // `main` is a static NUL-terminated database name; and `value` is a
        // writable `i32` whose address remains valid until SQLite returns.
        let result = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                std::ptr::from_mut(value).cast::<std::ffi::c_void>(),
            )
        };
        if result == rusqlite::ffi::SQLITE_OK {
            Ok(())
        } else {
            Err(OpenFailure::Storage)
        }
    }

    fn set_and_verify_persistent_wal(connection: &Connection) -> Result<(), OpenFailure> {
        let mut enabled = 1;
        persistent_wal_control(connection, &mut enabled)?;
        let mut current = -1;
        persistent_wal_control(connection, &mut current)?;
        (current == 1).then_some(()).ok_or(OpenFailure::Storage)
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

    #[expect(
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
    fn mailbox_open_error(kind: OpenFailure) -> MailboxStoreError {
        match kind {
            OpenFailure::Corrupted => MailboxStoreError::Corrupted,
            OpenFailure::Storage => MailboxStoreError::Storage,
        }
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
        use std::os::unix::fs::PermissionsExt;
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
                let path = directory.join("mail.sqlite3");
                Self { directory, path }
            }

            fn path(&self) -> &Path {
                &self.path
            }

            fn files(&self) -> Vec<std::path::PathBuf> {
                let mut files = fs::read_dir(&self.directory)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.is_file())
                    .collect::<Vec<_>>();
                files.sort();
                files
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
        fn accepts_reader<T: MailboxReader>(_reader: &T) {}
        fn open(name: &str) -> (TestDatabase, SqlCipherMailboxStore) {
            let database = TestDatabase::new(name);
            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            (database, store)
        }

        fn crash_store_at(database: &TestDatabase, point: &str) {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "macos::tests::wal_resident_first_migration_crash_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_STORE_CRASH_DATABASE", database.path())
                .env("TERSA_STORE_CRASH_POINT", point)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(73));
        }

        fn recovery_stage_paths(database: &TestDatabase) -> Vec<PathBuf> {
            (0..RECOVERY_STAGE_LIMIT)
                .map(|slot| {
                    database
                        .directory
                        .join(format!(".tersa-wal-recovery-v1-{slot}"))
                })
                .collect()
        }

        fn assert_no_recovery_stages(database: &TestDatabase) {
            assert!(
                recovery_stage_paths(database)
                    .into_iter()
                    .all(|path| !path.exists())
            );
        }

        fn open_existing_under_umask(database: &TestDatabase, mask: &str) {
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; shift; exec \"$@\"")
                .arg("tersa-existing-umask")
                .arg(mask)
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "macos::tests::restrictive_umask_existing_store_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_STORE_EXISTING_DATABASE", database.path())
                .stdin(Stdio::null())
                .status()
                .unwrap();
            assert!(
                status.success(),
                "existing store helper failed for umask {mask}"
            );
        }

        fn validate_missing_shm_under_umask(database: &TestDatabase, mask: &str) {
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; shift; exec \"$@\"")
                .arg("tersa-recovery-umask")
                .arg(mask)
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "macos::tests::restrictive_umask_existing_store_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_STORE_EXISTING_DATABASE", database.path())
                .env("TERSA_STORE_RECOVERY_ONLY", "1")
                .stdin(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "recovery helper failed for umask {mask}");
        }

        fn raw_connection(database: &TestDatabase) -> Connection {
            let path = canonical_database_path(database.path()).unwrap();
            assert!(prepare_database_leaf(&path).unwrap().is_fresh());
            open_connection(&path).unwrap()
        }

        fn raw_existing_connection(database: &TestDatabase) -> Connection {
            let path = canonical_database_path(database.path()).unwrap();
            open_connection(&path).unwrap()
        }

        fn journal_path(database: &TestDatabase) -> PathBuf {
            sidecar_path(database.path(), "-journal")
        }

        fn wal_path(database: &TestDatabase) -> PathBuf {
            sidecar_path(database.path(), "-wal")
        }

        fn shm_path(database: &TestDatabase) -> PathBuf {
            sidecar_path(database.path(), "-shm")
        }

        fn fixed_leaf_path(database: &TestDatabase, index: usize) -> PathBuf {
            match index {
                0 => database.path().to_path_buf(),
                1 => journal_path(database),
                2 => wal_path(database),
                3 => shm_path(database),
                _ => panic!("fixed leaf index must be in range"),
            }
        }

        fn write_restrictive(path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(u32::from(OWNER_ONLY_FILE_MODE)),
            )
            .unwrap();
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
            fs::set_permissions(
                existing_empty.path(),
                fs::Permissions::from_mode(u32::from(OWNER_ONLY_FILE_MODE)),
            )
            .unwrap();
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

            let unsafe_empty = TestDatabase::new("unsafe-existing-empty");
            fs::File::create(unsafe_empty.path()).unwrap();
            fs::set_permissions(unsafe_empty.path(), fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                SqlCipherMailboxStore::open(account(), unsafe_empty.path(), key(7)),
                Err(MailboxStoreError::Storage)
            ));
            assert_eq!(
                fs::metadata(unsafe_empty.path()).unwrap().mode() & 0o777,
                0o644
            );

            let empty_with_sidecar = TestDatabase::new("empty-with-sidecar");
            fs::File::create(empty_with_sidecar.path()).unwrap();
            fs::set_permissions(
                empty_with_sidecar.path(),
                fs::Permissions::from_mode(u32::from(OWNER_ONLY_FILE_MODE)),
            )
            .unwrap();
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
        fn writer_leaf_snapshot_accepts_existing_combinations_and_rejects_orphans() {
            for sidecars in 0_u8..8 {
                let existing = TestDatabase::new(&format!("existing-sidecars-{sidecars}"));
                write_restrictive(existing.path(), b"existing-main");
                for (index, suffix) in ["-journal", "-wal", "-shm"].into_iter().enumerate() {
                    if sidecars & (1 << index) != 0 {
                        write_restrictive(
                            &sidecar_path(existing.path(), suffix),
                            b"existing-sidecar",
                        );
                    }
                }
                let guard = LeafGuard::open(existing.path()).unwrap();
                assert!(guard.snapshot.main.is_some());
                assert!(!guard.snapshot.is_fresh());
                assert_corrupted(SqlCipherMailboxStore::open(
                    account(),
                    existing.path(),
                    key(7),
                ));
                assert!(existing.path().exists());
                assert!(existing.directory.exists());

                let orphan = TestDatabase::new(&format!("orphan-sidecars-{sidecars}"));
                if sidecars == 0 {
                    assert!(LeafGuard::open(orphan.path()).unwrap().snapshot.is_fresh());
                } else {
                    for (index, suffix) in ["-journal", "-wal", "-shm"].into_iter().enumerate() {
                        if sidecars & (1 << index) != 0 {
                            write_restrictive(
                                &sidecar_path(orphan.path(), suffix),
                                b"orphan-sidecar",
                            );
                        }
                    }
                    assert!(matches!(
                        LeafGuard::open(orphan.path()),
                        Err(OpenFailure::Corrupted)
                    ));
                    // Orphan sidecars fail before SQLite opens and are never
                    // granted fresh-cleanup authority.
                    assert_corrupted(SqlCipherMailboxStore::open(
                        account(),
                        orphan.path(),
                        key(7),
                    ));
                    assert!(!orphan.path().exists());
                    assert!(orphan.directory.exists());
                }
            }
        }

        #[test]
        fn fresh_failure_boundaries_keep_only_post_migration_state() {
            for point in [
                WriterHook::BeforeFreshClaim,
                WriterHook::AfterFreshClaim,
                WriterHook::AfterFreshWalNormalization,
                WriterHook::BeforeFreshMigration,
                WriterHook::AfterFreshMigration,
            ] {
                let database = TestDatabase::new(&format!("fresh-boundary-{point:?}"));
                let mut fired = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    database.path(),
                    key(7),
                    &mut |observed, _path| {
                        if observed == point {
                            fired = true;
                            return Err(OpenFailure::Storage);
                        }
                        Ok(())
                    },
                );
                assert!(fired);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                if point == WriterHook::AfterFreshMigration {
                    assert!(database.path().exists());
                } else {
                    assert!(database.files().is_empty());
                }
                assert!(database.directory.exists());
            }
        }

        #[test]
        fn preexisting_empty_main_failure_preserves_main_then_retries() {
            use std::os::unix::fs::MetadataExt;

            let database = TestDatabase::new("preexisting-empty-main");
            write_restrictive(database.path(), b"");
            let main_before = fs::metadata(database.path()).unwrap();
            let mut fired = false;
            let mut cleanup_observed = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::AfterFreshWalNormalization {
                        fired = true;
                        return Err(OpenFailure::Storage);
                    }
                    if matches!(
                        point,
                        WriterHook::CleanupBeforeRecord(_)
                            | WriterHook::CleanupAfterRecord(_)
                            | WriterHook::CleanupAfterRevalidate(_)
                    ) {
                        cleanup_observed = true;
                    }
                    Ok(())
                },
            );
            assert!(fired);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert!(!cleanup_observed);
            let main_after = fs::metadata(database.path()).unwrap();
            assert_eq!(main_after.dev(), main_before.dev());
            assert_eq!(main_after.ino(), main_before.ino());
            assert_eq!(main_after.mode() & 0o777, 0o600);

            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
        }

        fn crashed_missing_shm(label: &str) -> TestDatabase {
            let database = TestDatabase::new(label);
            crash_store_at(&database, "after-migration");
            fs::remove_file(shm_path(&database)).unwrap();
            database
        }

        fn canonical_pair_state(
            database: &TestDatabase,
        ) -> (Vec<u8>, Vec<u8>, FileIdentity, FileIdentity) {
            (
                fs::read(database.path()).unwrap(),
                fs::read(wal_path(database)).unwrap(),
                file_identity(database.path()).unwrap(),
                file_identity(&wal_path(database)).unwrap(),
            )
        }

        fn validate_missing_shm_with_hook(
            database: &TestDatabase,
            key_byte: u8,
            hook: &mut dyn FnMut(RecoveryHook, &Path) -> Result<(), OpenFailure>,
        ) -> Result<bool, OpenFailure> {
            let canonical_path = canonical_database_path(database.path()).unwrap();
            let leaf = LeafGuard::open(&canonical_path).unwrap();
            let database_key = key(key_byte);
            validate_wal_without_shm_from_private_copy_with_hook(
                &canonical_path,
                &account(),
                &database_key.0,
                &leaf,
                hook,
            )
        }

        #[test]
        fn existing_canonical_main_without_sidecars_rebuilds_owner_only_wal_state() {
            let (source, store) = open("canonical-main-source");
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(FULL);")
                .unwrap();
            drop(store);

            let database = TestDatabase::new("canonical-main-without-sidecars");
            fs::copy(source.path(), database.path()).unwrap();
            fs::set_permissions(
                database.path(),
                fs::Permissions::from_mode(OWNER_ONLY_FILE_MODE.into()),
            )
            .unwrap();
            assert!(!wal_path(&database).exists());
            assert!(!shm_path(&database).exists());

            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            for path in [database.path(), &wal_path(&database), &shm_path(&database)] {
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
            }
        }

        #[test]
        fn fresh_claim_eexist_preserves_the_racing_database_and_sidecars() {
            let database = TestDatabase::new("fresh-claim-eexist");
            let mut inserted = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::BeforeFreshClaim {
                        write_restrictive(database.path(), b"racing-owner");
                        write_restrictive(&wal_path(&database), b"racing-wal");
                        write_restrictive(&shm_path(&database), b"racing-shm");
                        inserted = true;
                    }
                    Ok(())
                },
            );
            assert!(inserted);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::read(database.path()).unwrap(), b"racing-owner");
            assert_eq!(fs::read(wal_path(&database)).unwrap(), b"racing-wal");
            assert_eq!(fs::read(shm_path(&database)).unwrap(), b"racing-shm");
            assert_eq!(fs::metadata(database.path()).unwrap().mode() & 0o777, 0o600);
        }

        #[test]
        fn wal_resident_first_migration_reopens_after_abrupt_exit() {
            let database = TestDatabase::new("wal-resident-first-migration");
            crash_store_at(&database, "after-migration");
            assert!(database.path().is_file());
            assert!(wal_path(&database).is_file());
            assert!(shm_path(&database).is_file());
            fs::remove_file(shm_path(&database)).unwrap();
            let main_before = fs::read(database.path()).unwrap();
            let wal_before = fs::read(wal_path(&database)).unwrap();
            let main_identity_before = file_identity(database.path()).unwrap();
            let wal_identity_before = file_identity(&wal_path(&database)).unwrap();
            let canonical_path = canonical_database_path(database.path()).unwrap();
            let leaf = LeafGuard::open(&canonical_path).unwrap();
            assert_eq!(
                preflight_existing(&canonical_path, &account(), &key(7).0, &leaf),
                Ok(ExistingPreflight::WalWithoutShm)
            );
            assert!(!shm_path(&database).exists());
            assert_eq!(fs::read(database.path()).unwrap(), main_before);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
            assert_eq!(
                file_identity(database.path()).unwrap(),
                main_identity_before
            );
            assert_eq!(
                file_identity(&wal_path(&database)).unwrap(),
                wal_identity_before
            );
            assert!(fs::read_dir(&database.directory).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tersa-wal-recovery-")
            }));

            let store = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            assert_eq!(fs::read(database.path()).unwrap(), main_before);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
            assert!(shm_path(&database).is_file());
        }

        #[test]
        fn fresh_wal_crash_before_migration_converges_with_or_without_shm() {
            for point in ["after-wal-normalization", "before-migration"] {
                for missing_shm in [false, true] {
                    let database = TestDatabase::new(&format!(
                        "fresh-wal-{point}-{}",
                        if missing_shm {
                            "missing-shm"
                        } else {
                            "complete"
                        }
                    ));
                    crash_store_at(&database, point);
                    if missing_shm {
                        fs::remove_file(shm_path(&database)).unwrap();
                    }
                    let canonical_path = canonical_database_path(database.path()).unwrap();
                    let leaf = LeafGuard::open(&canonical_path).unwrap();
                    let expected = if missing_shm {
                        ExistingPreflight::FreshWalWithoutShm
                    } else {
                        ExistingPreflight::FreshWal
                    };
                    assert_eq!(
                        preflight_existing(&canonical_path, &account(), &key(7).0, &leaf),
                        Ok(expected)
                    );
                    let mut cleanup_observed = false;
                    let store = SqlCipherMailboxStore::open_inner_with_writer_hook(
                        account(),
                        database.path(),
                        key(7),
                        &mut |observed, _path| {
                            if matches!(
                                observed,
                                WriterHook::CleanupBeforeRecord(_)
                                    | WriterHook::CleanupAfterRecord(_)
                                    | WriterHook::CleanupAfterRevalidate(_)
                            ) {
                                cleanup_observed = true;
                            }
                            Ok(())
                        },
                    )
                    .unwrap();
                    assert!(!cleanup_observed);
                    assert_eq!(
                        schema_state(&store),
                        (APPLICATION_ID, VERSION, canonical_schema())
                    );
                    assert_no_recovery_stages(&database);
                }
            }
        }

        #[test]
        fn missing_shm_recovery_normalizes_private_stage_under_restrictive_umasks() {
            for mask in ["0777", "0577", "0377"] {
                let database = TestDatabase::new(&format!("recovery-umask-{mask}"));
                crash_store_at(&database, "after-migration");
                fs::remove_file(shm_path(&database)).unwrap();
                let main_before = fs::read(database.path()).unwrap();
                let wal_before = fs::read(wal_path(&database)).unwrap();
                let main_identity = file_identity(database.path()).unwrap();
                let wal_identity = file_identity(&wal_path(&database)).unwrap();

                validate_missing_shm_under_umask(&database, mask);

                assert_eq!(fs::read(database.path()).unwrap(), main_before);
                assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
                assert_eq!(file_identity(database.path()).unwrap(), main_identity);
                assert_eq!(file_identity(&wal_path(&database)).unwrap(), wal_identity);
                assert_no_recovery_stages(&database);
            }
        }

        #[test]
        fn canonical_main_without_sidecars_normalizes_new_pair_under_restrictive_umasks() {
            let (source, store) = open("canonical-main-umask-source");
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(FULL);")
                .unwrap();
            drop(store);

            for mask in ["0777", "0577", "0377"] {
                let database = TestDatabase::new(&format!("canonical-main-umask-{mask}"));
                fs::copy(source.path(), database.path()).unwrap();
                fs::set_permissions(database.path(), fs::Permissions::from_mode(0o600)).unwrap();
                open_existing_under_umask(&database, mask);
                for path in [database.path(), &wal_path(&database), &shm_path(&database)] {
                    assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
                }
                assert_no_recovery_stages(&database);
            }
        }

        #[test]
        fn missing_shm_recovery_normal_errors_clean_the_bounded_stage() {
            let wrong_key = crashed_missing_shm("recovery-wrong-key");
            let wrong_key_before = canonical_pair_state(&wrong_key);
            assert_eq!(
                validate_missing_shm_with_hook(&wrong_key, 8, &mut |_point, _path| Ok(())),
                Err(OpenFailure::Corrupted)
            );
            assert_eq!(canonical_pair_state(&wrong_key), wrong_key_before);
            assert_no_recovery_stages(&wrong_key);

            let corrupt_wal = crashed_missing_shm("recovery-corrupt-wal");
            fs::write(wal_path(&corrupt_wal), b"corrupt-encrypted-wal").unwrap();
            let corrupt_wal_before = canonical_pair_state(&corrupt_wal);
            assert!(
                validate_missing_shm_with_hook(&corrupt_wal, 7, &mut |_point, _path| Ok(()))
                    .is_err()
            );
            assert_eq!(canonical_pair_state(&corrupt_wal), corrupt_wal_before);
            assert_no_recovery_stages(&corrupt_wal);

            for failure_point in [
                RecoveryHook::AfterDirectoryCreate,
                RecoveryHook::AfterDirectoryNormalize,
                RecoveryHook::AfterMainCopy,
                RecoveryHook::AfterWalCopy,
                RecoveryHook::BeforeReadOnlyOpen,
                RecoveryHook::AfterReadOnlyOpen,
                RecoveryHook::BeforeOriginalFinalRevalidate,
                RecoveryHook::BeforeCleanup,
            ] {
                let database = crashed_missing_shm(&format!("recovery-boundary-{failure_point:?}"));
                let before = canonical_pair_state(&database);
                let result = validate_missing_shm_with_hook(&database, 7, &mut |point, _path| {
                    if point == failure_point {
                        return Err(OpenFailure::Storage);
                    }
                    Ok(())
                });
                assert_eq!(result, Err(OpenFailure::Storage));
                assert_eq!(canonical_pair_state(&database), before);
                assert_no_recovery_stages(&database);
            }
        }

        #[test]
        fn missing_shm_recovery_preserves_validation_classification_when_cleanup_fails() {
            let database = crashed_missing_shm("recovery-corrupted-with-tampered-stage");
            let before = canonical_pair_state(&database);
            let mut tampered_stage = None;
            let result = validate_missing_shm_with_hook(&database, 8, &mut |point, stage| {
                if point == RecoveryHook::BeforeCleanup {
                    write_restrictive(&stage.join("mail.sqlite3-journal"), b"unexpected-journal");
                    tampered_stage = Some(stage.to_path_buf());
                }
                Ok(())
            });

            assert_eq!(result, Err(OpenFailure::Corrupted));
            assert_eq!(canonical_pair_state(&database), before);
            let tampered_stage = tampered_stage.unwrap();
            assert!(tampered_stage.join("mail.sqlite3").is_file());
            assert!(tampered_stage.join("mail.sqlite3-wal").is_file());
            assert!(tampered_stage.join("mail.sqlite3-shm").is_file());
            let unexpected_journal = tampered_stage.join("mail.sqlite3-journal");
            assert!(unexpected_journal.is_file());
            assert_eq!(
                fs::metadata(unexpected_journal).unwrap().mode() & 0o777,
                0o600
            );
        }

        #[test]
        fn missing_shm_recovery_original_drift_fails_closed_and_cleans_its_stage() {
            let database = crashed_missing_shm("recovery-original-drift");
            let replacement = database.directory.join("replacement-wal");
            write_restrictive(&replacement, b"replacement-wal");
            let original = database.directory.join("original-wal");
            let mut drifted = false;
            let result = validate_missing_shm_with_hook(&database, 7, &mut |point, _path| {
                if point == RecoveryHook::AfterWalCopy {
                    fs::rename(wal_path(&database), &original).unwrap();
                    fs::rename(&replacement, wal_path(&database)).unwrap();
                    drifted = true;
                }
                Ok(())
            });
            assert!(drifted);
            assert_eq!(result, Err(OpenFailure::Storage));
            assert_eq!(fs::read(wal_path(&database)).unwrap(), b"replacement-wal");
            assert!(original.is_file());
            assert_no_recovery_stages(&database);
        }

        #[test]
        fn missing_shm_recovery_preserves_tampered_stage_residue_fail_closed() {
            let mode_database = crashed_missing_shm("recovery-stage-mode-tamper");
            let mut mode_stage = None;
            let mode_result =
                validate_missing_shm_with_hook(&mode_database, 7, &mut |point, stage| {
                    if point == RecoveryHook::AfterReadOnlyOpen {
                        fs::set_permissions(
                            stage.join("mail.sqlite3-wal"),
                            fs::Permissions::from_mode(0o640),
                        )
                        .unwrap();
                        mode_stage = Some(stage.to_path_buf());
                    }
                    Ok(())
                });
            assert_eq!(mode_result, Err(OpenFailure::Storage));
            let mode_stage = mode_stage.unwrap();
            assert_eq!(
                fs::metadata(mode_stage.join("mail.sqlite3-wal"))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o640
            );

            let directory_database = crashed_missing_shm("recovery-stage-directory-tamper");
            let mut moved_stage = None;
            let directory_result =
                validate_missing_shm_with_hook(&directory_database, 7, &mut |point, stage| {
                    if point == RecoveryHook::AfterWalCopy {
                        let moved = directory_database.directory.join("moved-recovery-stage");
                        fs::rename(stage, &moved).unwrap();
                        fs::create_dir(stage).unwrap();
                        fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
                        moved_stage = Some((stage.to_path_buf(), moved));
                    }
                    Ok(())
                });
            assert_eq!(directory_result, Err(OpenFailure::Storage));
            let (replacement_stage, moved_stage) = moved_stage.unwrap();
            assert!(replacement_stage.is_dir());
            assert!(moved_stage.is_dir());
        }

        #[test]
        fn missing_shm_recovery_preserves_exact_mode_replacements_and_unknown_files() {
            let replacement_database = crashed_missing_shm("recovery-stage-inode-tamper");
            let captured_main = replacement_database.directory.join("captured-stage-main");
            let mut replacement_stage = None;
            let replacement_result =
                validate_missing_shm_with_hook(&replacement_database, 7, &mut |point, stage| {
                    if point == RecoveryHook::BeforeCleanup {
                        fs::rename(stage.join("mail.sqlite3"), &captured_main).unwrap();
                        write_restrictive(&stage.join("mail.sqlite3"), b"exact-mode-replacement");
                        replacement_stage = Some(stage.to_path_buf());
                    }
                    Ok(())
                });
            assert_eq!(replacement_result, Err(OpenFailure::Storage));
            let replacement_stage = replacement_stage.unwrap();
            assert!(captured_main.is_file());
            assert_eq!(
                fs::metadata(replacement_stage.join("mail.sqlite3"))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o600
            );

            let journal_database = crashed_missing_shm("recovery-stage-journal-tamper");
            let mut journal_stage = None;
            let journal_result =
                validate_missing_shm_with_hook(&journal_database, 7, &mut |point, stage| {
                    if point == RecoveryHook::BeforeCleanup {
                        write_restrictive(
                            &stage.join("mail.sqlite3-journal"),
                            b"unexpected-journal",
                        );
                        journal_stage = Some(stage.to_path_buf());
                    }
                    Ok(())
                });
            assert_eq!(journal_result, Err(OpenFailure::Storage));
            let journal_stage = journal_stage.unwrap();
            assert!(journal_stage.join("mail.sqlite3").is_file());
            assert!(journal_stage.join("mail.sqlite3-wal").is_file());
            assert!(journal_stage.join("mail.sqlite3-shm").is_file());
            assert!(journal_stage.join("mail.sqlite3-journal").is_file());
        }

        #[test]
        fn missing_shm_recovery_stage_attempts_are_strictly_bounded() {
            let database = crashed_missing_shm("recovery-stage-exhaustion");
            let stages = recovery_stage_paths(&database);
            for stage in &stages {
                fs::create_dir(stage).unwrap();
                fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let before = canonical_pair_state(&database);
            assert_eq!(
                validate_missing_shm_with_hook(&database, 7, &mut |_point, _path| Ok(())),
                Err(OpenFailure::Storage)
            );
            assert_eq!(canonical_pair_state(&database), before);
            assert!(stages.iter().all(|stage| stage.is_dir()));
            assert_eq!(
                fs::read_dir(&database.directory)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".tersa-wal-recovery-v1-")
                    })
                    .count(),
                RECOVERY_STAGE_LIMIT
            );
        }

        #[test]
        fn restrictive_umasks_cleanup_then_retry_with_owner_only_leaves() {
            let executable = std::env::current_exe().unwrap();
            for (label, mask) in [("zero", "0777"), ("write", "0577"), ("read", "0377")] {
                let database = TestDatabase::new(&format!("umask-{label}"));
                let status = Command::new("/bin/sh")
                    .arg("-c")
                    .arg("umask \"$1\"; shift; exec \"$@\"")
                    .arg("tersa-umask")
                    .arg(mask)
                    .arg(&executable)
                    .args([
                        "--exact",
                        "macos::tests::restrictive_umask_store_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("TERSA_STORE_UMASK_DATABASE", database.path())
                    .stdin(Stdio::null())
                    .status()
                    .unwrap();
                assert!(status.success(), "store helper failed for umask {mask}");
            }
        }

        #[test]
        fn fresh_leaf_normalization_is_bound_to_the_opened_descriptor() {
            use std::os::unix::fs::MetadataExt;

            let database = TestDatabase::new("normalize-replacement");
            let backup = database.directory.join("opened-main");
            let mut replaced = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, canonical_path| {
                    if point == WriterHook::NormalizeAfterOpen(0) {
                        fs::rename(canonical_path, &backup).unwrap();
                        write_restrictive(canonical_path, b"same-user-replacement");
                        replaced = true;
                    }
                    Ok(())
                },
            );
            assert!(replaced);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::metadata(&backup).unwrap().mode() & 0o777, 0o600);
            assert_eq!(fs::read(database.path()).unwrap(), b"same-user-replacement");
        }

        #[test]
        fn cleanup_hooks_require_an_exclusively_created_main() {
            // Sidecar cleanup is authorized only after this opener has proved
            // main-leaf authorship through O_EXCL. These cases exercise the
            // remaining mutable-name gaps after that proof.
            for index in 1..4 {
                let inserted = TestDatabase::new(&format!("cleanup-insert-{index}"));
                let inserted_path = fixed_leaf_path(&inserted, index);
                let mut injected = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    inserted.path(),
                    key(7),
                    &mut |point, _path| {
                        if point == WriterHook::AfterFreshClaim {
                            write_restrictive(&inserted_path, b"inserted-after-snapshot");
                            injected = true;
                            return Err(OpenFailure::Storage);
                        }
                        Ok(())
                    },
                );
                assert!(injected);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                // Sidecars absent at snapshot remain cleanup candidates.
                assert!(!inserted_path.exists());

                let replaced = TestDatabase::new(&format!("cleanup-middle-replace-{index}"));
                let replaced_path = fixed_leaf_path(&replaced, index);
                let backup = replaced.directory.join("recorded-before-replace");
                let mut replacement_done = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    replaced.path(),
                    key(7),
                    &mut |point, _path| {
                        if point == WriterHook::AfterFreshClaim {
                            write_restrictive(&replaced_path, b"recorded");
                            return Err(OpenFailure::Storage);
                        }
                        if point == WriterHook::CleanupAfterRecord(index) {
                            fs::rename(&replaced_path, &backup).unwrap();
                            write_restrictive(&replaced_path, b"replacement-preserved");
                            replacement_done = true;
                        }
                        Ok(())
                    },
                );
                assert!(replacement_done);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                // The middle revalidation observes the identity change and
                // preserves the replacement for all four fixed names.
                assert_eq!(fs::read(&replaced_path).unwrap(), b"replacement-preserved");

                let final_gap = TestDatabase::new(&format!("cleanup-final-gap-{index}"));
                let final_path = fixed_leaf_path(&final_gap, index);
                let final_backup = final_gap.directory.join("revalidated-before-unlink");
                let mut final_replacement = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    final_gap.path(),
                    key(7),
                    &mut |point, _path| {
                        if point == WriterHook::AfterFreshClaim {
                            write_restrictive(&final_path, b"revalidated");
                            return Err(OpenFailure::Storage);
                        }
                        if point == WriterHook::CleanupAfterRevalidate(index) {
                            fs::rename(&final_path, &final_backup).unwrap();
                            write_restrictive(&final_path, b"replacement-in-final-gap");
                            final_replacement = true;
                        }
                        Ok(())
                    },
                );
                assert!(final_replacement);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                // Accepted residual: unlinkat cannot bind deletion to the
                // revalidated inode, so this final-gap replacement is removed.
                assert!(!final_path.exists());
            }
        }

        #[test]
        fn cleanup_stops_when_fresh_main_authority_is_replaced() {
            let database = TestDatabase::new("cleanup-main-authority-race");
            let original_main = database.directory.join("original-fresh-main");
            let mut replaced_main = false;
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                database.path(),
                key(7),
                &mut |point, canonical_path| {
                    if point == WriterHook::AfterFreshClaim {
                        write_restrictive(&wal_path(&database), b"candidate-wal");
                        write_restrictive(&shm_path(&database), b"candidate-shm");
                        return Err(OpenFailure::Storage);
                    }
                    if point == WriterHook::CleanupAfterRevalidate(3) {
                        fs::rename(canonical_path, &original_main).unwrap();
                        write_restrictive(canonical_path, b"replacement-main");
                        replaced_main = true;
                    }
                    Ok(())
                },
            );
            assert!(replaced_main);
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert_eq!(fs::read(database.path()).unwrap(), b"replacement-main");
            assert_eq!(fs::read(wal_path(&database)).unwrap(), b"candidate-wal");
            assert_eq!(fs::read(shm_path(&database)).unwrap(), b"candidate-shm");
        }

        #[test]
        fn every_nonempty_residual_retries_through_the_state_matrix() {
            for subset in 1_u8..16 {
                let database = TestDatabase::new(&format!("residual-subset-{subset}"));
                for index in 0..4 {
                    if subset & (1 << index) != 0 {
                        write_restrictive(&fixed_leaf_path(&database, index), b"residual");
                    }
                }
                let result = SqlCipherMailboxStore::open(account(), database.path(), key(7));
                assert_corrupted(result);
                for index in 0..4 {
                    let present = subset & (1 << index) != 0;
                    assert_eq!(fixed_leaf_path(&database, index).exists(), present);
                }
                assert!(database.directory.exists());
            }
        }

        #[test]
        fn identity_queries_classify_operational_sqlite_failures_as_storage() {
            let memory = Connection::open_in_memory().unwrap();
            assert_eq!(
                set_and_verify_persistent_wal(&memory),
                Err(OpenFailure::Storage)
            );
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
        #[ignore = "subprocess helper for WAL-resident first-migration recovery"]
        #[expect(
            clippy::exit,
            reason = "the helper must terminate without running destructors to model a crash"
        )]
        fn wal_resident_first_migration_crash_child() {
            let Some(database) = std::env::var_os("TERSA_STORE_CRASH_DATABASE") else {
                return;
            };
            let Some(crash_point) = std::env::var_os("TERSA_STORE_CRASH_POINT") else {
                return;
            };
            let database = PathBuf::from(database);
            let crash_point = crash_point.to_string_lossy();
            let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                &database,
                key(7),
                &mut |point, _path| {
                    let should_crash = matches!(
                        (crash_point.as_ref(), point),
                        (
                            "after-wal-normalization",
                            WriterHook::AfterFreshWalNormalization
                        ) | ("before-migration", WriterHook::BeforeFreshMigration)
                            | ("after-migration", WriterHook::AfterFreshMigration)
                    );
                    if should_crash {
                        assert!(database.is_file());
                        assert!(sidecar_path(&database, "-wal").is_file());
                        assert!(sidecar_path(&database, "-shm").is_file());
                        std::process::exit(73);
                    }
                    Ok(())
                },
            );
            panic!("crash boundary was not reached: {result:?}");
        }

        #[test]
        #[ignore = "subprocess helper for restrictive-umask existing-store recovery"]
        fn restrictive_umask_existing_store_child() {
            let Some(database) = std::env::var_os("TERSA_STORE_EXISTING_DATABASE") else {
                return;
            };
            let database = PathBuf::from(database);
            if std::env::var_os("TERSA_STORE_RECOVERY_ONLY").is_some() {
                let canonical_path = canonical_database_path(&database).unwrap();
                let leaf = LeafGuard::open(&canonical_path).unwrap();
                assert!(
                    !validate_wal_without_shm_from_private_copy(
                        &canonical_path,
                        &account(),
                        &key(7).0,
                        &leaf,
                    )
                    .unwrap()
                );
                assert!(
                    (0..RECOVERY_STAGE_LIMIT)
                        .map(|slot| database
                            .parent()
                            .unwrap()
                            .join(format!(".tersa-wal-recovery-v1-{slot}")))
                        .all(|path| !path.exists())
                );
                return;
            }
            let store = SqlCipherMailboxStore::open(account(), &database, key(7)).unwrap();
            assert_eq!(
                schema_state(&store),
                (APPLICATION_ID, VERSION, canonical_schema())
            );
            for path in [
                database.clone(),
                sidecar_path(&database, "-wal"),
                sidecar_path(&database, "-shm"),
            ] {
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
            }
            assert!(
                (0..RECOVERY_STAGE_LIMIT)
                    .map(|slot| {
                        database
                            .parent()
                            .unwrap()
                            .join(format!(".tersa-wal-recovery-v1-{slot}"))
                    })
                    .all(|path| !path.exists())
            );
        }

        #[test]
        #[ignore = "subprocess helper for process-global umask coverage"]
        fn restrictive_umask_store_child() {
            use std::os::unix::fs::MetadataExt;

            let Some(database) = std::env::var_os("TERSA_STORE_UMASK_DATABASE") else {
                return;
            };
            let database = PathBuf::from(database);
            let mut injected = false;
            let first = SqlCipherMailboxStore::open_inner_with_writer_hook(
                account(),
                &database,
                key(7),
                &mut |point, _path| {
                    if point == WriterHook::AfterFreshWalNormalization {
                        injected = true;
                        return Err(OpenFailure::Storage);
                    }
                    Ok(())
                },
            );
            assert!(injected);
            assert!(matches!(first, Err(MailboxStoreError::Storage)));
            assert!(
                fs::read_dir(database.parent().unwrap())
                    .unwrap()
                    .all(|entry| !entry.unwrap().path().is_file())
            );

            let store = SqlCipherMailboxStore::open(account(), &database, key(7)).unwrap();
            let wal = sidecar_path(&database, "-wal");
            let shm = sidecar_path(&database, "-shm");
            for path in [&database, &wal, &shm] {
                assert!(
                    path.exists(),
                    "expected live SQLite leaf {}",
                    path.display()
                );
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
            }
            drop(store);
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
        fn reconcile_rejects_a_null_primary_key_without_mutating_the_database() {
            let (_database, store) = open("null-primary-key");
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO messages (message_id, thread_id, sender, subject, preview, received_at, unread, content) VALUES (NULL, 'thread', 'sender', 'subject', 'preview', 50, 0, NULL)",
                    [],
                )
                .unwrap();

            assert_eq!(
                run(store.reconcile_recent_envelopes(
                    &account(),
                    &[envelope("new", "thread", 100)],
                    StoreLimit::new(1).unwrap(),
                )),
                Err(MailboxStoreError::Corrupted)
            );
            let (row_count, inserted_count): (i64, i64) = store
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*), COUNT(CASE WHEN message_id = 'new' THEN 1 END) FROM messages",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(row_count, 1);
            assert_eq!(inserted_count, 0);
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
        fn persistent_writer_supports_a_clean_standalone_metadata_reader() {
            let (database, store) = open("standalone-reader");
            let values = [envelope("new", "thread", 20), envelope("old", "thread", 10)];
            run(store.upsert_envelopes(&account(), &values)).unwrap();
            let mut persistent_wal = -1;
            persistent_wal_control(&store.connection.lock().unwrap(), &mut persistent_wal).unwrap();
            assert_eq!(persistent_wal, 1);
            drop(store);
            assert!(wal_path(&database).is_file());
            assert!(shm_path(&database).is_file());

            let files_before = database.files();
            let identities_before = ReadOnlyFileIdentities {
                main: file_identity(database.path()).unwrap(),
                wal: file_identity(&wal_path(&database)).unwrap(),
                shm: file_identity(&shm_path(&database)).unwrap(),
            };
            let main_before = fs::read(database.path()).unwrap();
            let wal_before = fs::read(wal_path(&database)).unwrap();
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            accepts_reader(&reader);
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["new", "old"]
            );
            assert_eq!(
                run(reader.thread_envelopes(
                    &account(),
                    values[0].thread_id(),
                    StoreLimit::new(10).unwrap(),
                ))
                .unwrap()
                .len(),
                2
            );
            assert_eq!(
                reader
                    .connection
                    .lock()
                    .unwrap()
                    .query_row("PRAGMA journal_size_limit", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                -1
            );
            assert!(
                reader
                    .connection
                    .lock()
                    .unwrap()
                    .db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)
                    .unwrap()
            );
            let foreign_account = AccountId::new("foreign-account").unwrap();
            assert_eq!(
                run(reader.list_envelopes(&foreign_account, StoreLimit::new(10).unwrap(),)),
                Err(MailboxStoreError::Storage)
            );
            assert!(!format!("{reader:?}").contains("account"));
            drop(reader);
            assert_eq!(database.files(), files_before);
            assert_eq!(
                ReadOnlyFileIdentities {
                    main: file_identity(database.path()).unwrap(),
                    wal: file_identity(&wal_path(&database)).unwrap(),
                    shm: file_identity(&shm_path(&database)).unwrap(),
                },
                identities_before
            );
            assert_eq!(fs::read(database.path()).unwrap(), main_before);
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
        }

        #[test]
        fn read_only_reader_coexists_with_wal_resident_writer_commits() {
            let (database, store) = open("live-reader");
            let first = envelope("first", "thread", 10);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&first))).unwrap();
            let wal_before = fs::read(wal_path(&database)).unwrap();
            let second = envelope("second", "thread", 20);
            run(store.upsert_envelopes(&account(), std::slice::from_ref(&second))).unwrap();
            let wal_after = fs::read(wal_path(&database)).unwrap();
            assert!(wal_after.len() > wal_before.len());

            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap()))
                    .unwrap()
                    .iter()
                    .map(|value| value.message_id().as_str())
                    .collect::<Vec<_>>(),
                ["second", "first"]
            );
            assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_after);
            drop(reader);
            drop(store);
            assert!(wal_path(&database).exists());
            assert!(shm_path(&database).exists());
        }

        #[test]
        fn read_only_open_requires_nonempty_main_and_both_existing_sidecars() {
            let absent = TestDatabase::new("reader-absent");
            let absent_before = absent.files();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), absent.path(), key(7)),
                Err(MailboxStoreError::Storage)
            ));
            assert_eq!(absent.files(), absent_before);

            let fresh = TestDatabase::new("reader-fresh");
            fs::File::create(fresh.path()).unwrap();
            fs::write(wal_path(&fresh), b"existing-wal").unwrap();
            fs::write(shm_path(&fresh), b"existing-shm").unwrap();
            let before = fresh.files();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), fresh.path(), key(7)),
                Err(MailboxStoreError::Storage)
            ));
            assert_eq!(fresh.files(), before);
            assert_eq!(fs::read(wal_path(&fresh)).unwrap(), b"existing-wal");
            assert_eq!(fs::read(shm_path(&fresh)).unwrap(), b"existing-shm");

            for suffix in ["-wal", "-shm"] {
                let (database, store) = open(&format!("reader-missing{suffix}"));
                run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
                drop(store);
                fs::remove_file(sidecar_path(database.path(), suffix)).unwrap();
                let files_before = database.files();
                let main_before = fs::read(database.path()).unwrap();
                assert!(matches!(
                    SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)),
                    Err(MailboxStoreError::Storage)
                ));
                assert_eq!(database.files(), files_before);
                assert_eq!(fs::read(database.path()).unwrap(), main_before);
            }
        }

        #[test]
        fn read_only_open_rejects_rollback_journal_and_nonregular_sidecars_unchanged() {
            let (journal_database, journal_store) = open("reader-journal");
            drop(journal_store);
            fs::write(journal_path(&journal_database), b"foreign-journal").unwrap();
            let journal_files = journal_database.files();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), journal_database.path(), key(7),),
                Err(MailboxStoreError::Storage)
            ));
            assert_eq!(journal_database.files(), journal_files);
            assert_eq!(
                fs::read(journal_path(&journal_database)).unwrap(),
                b"foreign-journal"
            );

            let (symlink_database, symlink_store) = open("reader-symlink-wal");
            drop(symlink_store);
            let original_wal = symlink_database.directory.join("original-wal");
            fs::rename(wal_path(&symlink_database), &original_wal).unwrap();
            std::os::unix::fs::symlink(&original_wal, wal_path(&symlink_database)).unwrap();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), symlink_database.path(), key(7),),
                Err(MailboxStoreError::Storage)
            ));
            assert!(
                fs::symlink_metadata(wal_path(&symlink_database))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert!(original_wal.is_file());

            let (directory_database, directory_store) = open("reader-directory-shm");
            drop(directory_store);
            fs::remove_file(shm_path(&directory_database)).unwrap();
            fs::create_dir(shm_path(&directory_database)).unwrap();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(
                    account(),
                    directory_database.path(),
                    key(7),
                ),
                Err(MailboxStoreError::Storage)
            ));
            assert!(shm_path(&directory_database).is_dir());
        }

        #[test]
        fn read_only_open_requires_owner_only_modes_for_every_fixed_file() {
            for index in [0, 2, 3] {
                let (database, store) = open(&format!("reader-mode-{index}"));
                drop(store);
                let target = fixed_leaf_path(&database, index);
                let files_before = database.files();
                let main_before = fs::read(database.path()).unwrap();
                let wal_before = fs::read(wal_path(&database)).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();

                assert!(matches!(
                    SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7),),
                    Err(MailboxStoreError::Storage)
                ));
                assert_eq!(database.files(), files_before);
                assert_eq!(fs::read(database.path()).unwrap(), main_before);
                assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
                assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o640);
            }
        }

        #[test]
        fn writer_requires_owner_only_modes_for_main_wal_and_shm() {
            for index in [0, 2, 3] {
                let (database, store) = open(&format!("writer-mode-{index}"));
                drop(store);
                let target = fixed_leaf_path(&database, index);
                let files_before = database.files();
                let main_before = fs::read(database.path()).unwrap();
                let wal_before = fs::read(wal_path(&database)).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();

                assert!(matches!(
                    SqlCipherMailboxStore::open(account(), database.path(), key(7)),
                    Err(MailboxStoreError::Storage)
                ));
                assert_eq!(database.files(), files_before);
                assert_eq!(fs::read(database.path()).unwrap(), main_before);
                assert_eq!(fs::read(wal_path(&database)).unwrap(), wal_before);
                assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o640);
            }
        }

        #[test]
        fn writer_leaf_mode_race_after_open_fails_closed() {
            for index in [0, 2, 3] {
                let (database, store) = open(&format!("writer-mode-race-{index}"));
                drop(store);
                let target = fixed_leaf_path(&database, index);
                let identity_before = file_identity(&target).unwrap();
                let mut raced = false;
                let result = SqlCipherMailboxStore::open_inner_with_writer_hook(
                    account(),
                    database.path(),
                    key(7),
                    &mut |point, _path| {
                        if point == WriterHook::AfterOpen {
                            fs::set_permissions(&target, fs::Permissions::from_mode(0o640))
                                .unwrap();
                            raced = true;
                        }
                        Ok(())
                    },
                );
                assert!(raced);
                assert!(matches!(result, Err(MailboxStoreError::Storage)));
                let identity_after = file_identity(&target).unwrap();
                assert_eq!(identity_after.device, identity_before.device);
                assert_eq!(identity_after.inode, identity_before.inode);
                assert_eq!(identity_after.mode, 0o640);
            }
        }

        #[test]
        fn read_only_open_rejects_wrong_key_owner_schema_and_invalid_rows_redacted() {
            let (database, store) = open("reader-validation");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            drop(store);
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(8)),
                Err(MailboxStoreError::Corrupted)
            ));
            let foreign = AccountId::new("foreign-account").unwrap();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(foreign, database.path(), key(7)),
                Err(MailboxStoreError::Corrupted)
            ));

            let (integrity_database, integrity_store) = open("reader-integrity");
            run(integrity_store.upsert_envelopes(
                &account(),
                &[envelope("integrity", "thread", 1)],
            ))
            .unwrap();
            integrity_store
                .connection
                .lock()
                .unwrap()
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
            drop(integrity_store);
            let mut corrupted_bytes = fs::read(integrity_database.path()).unwrap();
            assert!(corrupted_bytes.len() > 100);
            corrupted_bytes[100] ^= 0x80;
            fs::write(integrity_database.path(), corrupted_bytes).unwrap();
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(
                    account(),
                    integrity_database.path(),
                    key(7),
                ),
                Err(MailboxStoreError::Corrupted)
            ));

            let writer = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            writer
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE messages SET subject = ?1",
                    params!["x".repeat(1_025)],
                )
                .unwrap();
            drop(writer);
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            let error =
                run(reader.list_envelopes(&account(), StoreLimit::new(10).unwrap())).unwrap_err();
            assert_eq!(error, MailboxStoreError::Corrupted);
            assert!(!error.to_string().contains("account"));
            drop(reader);

            let writer = SqlCipherMailboxStore::open(account(), database.path(), key(7)).unwrap();
            writer
                .connection
                .lock()
                .unwrap()
                .execute("UPDATE messages SET subject = 'valid'", [])
                .unwrap();
            writer
                .connection
                .lock()
                .unwrap()
                .execute("CREATE TABLE unexpected(value INTEGER)", [])
                .unwrap();
            drop(writer);
            assert!(matches!(
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)),
                Err(MailboxStoreError::Corrupted)
            ));
        }

        #[test]
        fn read_only_open_detects_observable_sidecar_replacement() {
            let (database, store) = open("reader-sidecar-replacement");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            drop(store);
            let replacement = database.directory.join("replacement-shm");
            fs::copy(shm_path(&database), &replacement).unwrap();
            let original = database.directory.join("original-shm");
            let result = SqlCipherMailboxReader::open_read_only_with_hooks(
                account(),
                database.path(),
                key(7),
                |_path| {
                    fs::rename(shm_path(&database), &original).unwrap();
                    fs::rename(&replacement, shm_path(&database)).unwrap();
                },
                |_path| {},
                |_path| {},
            );
            assert!(matches!(result, Err(MailboxStoreError::Storage)));

            let (main_database, main_store) = open("reader-main-replacement");
            drop(main_store);
            let (foreign_database, foreign_store) = open("reader-main-foreign");
            drop(foreign_store);
            let original_main = main_database.directory.join("original-main");
            let result = SqlCipherMailboxReader::open_read_only_with_hooks(
                account(),
                main_database.path(),
                key(7),
                |_path| {
                    fs::rename(main_database.path(), &original_main).unwrap();
                    fs::copy(foreign_database.path(), main_database.path()).unwrap();
                },
                |_path| {},
                |_path| {},
            );
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
        }

        #[test]
        fn read_only_sidecar_swap_in_open_swap_back_is_an_accepted_residual() {
            let (database, store) = open("reader-sidecar-race");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            drop(store);
            let replacement = database.directory.join("replacement-shm");
            fs::copy(shm_path(&database), &replacement).unwrap();
            let original = database.directory.join("original-shm");
            let reader = SqlCipherMailboxReader::open_read_only_with_hooks(
                account(),
                database.path(),
                key(7),
                |_path| {},
                |_path| {
                    fs::rename(shm_path(&database), &original).unwrap();
                    fs::rename(&replacement, shm_path(&database)).unwrap();
                },
                |_path| {
                    fs::remove_file(shm_path(&database)).unwrap();
                    fs::rename(&original, shm_path(&database)).unwrap();
                },
            )
            .unwrap();
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(1).unwrap()))
                    .unwrap()
                    .len(),
                1
            );
        }

        #[test]
        fn read_only_sidecar_delete_recreate_is_an_accepted_residual() {
            let (database, store) = open("reader-sidecar-delete-race");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            drop(store);
            let original_wal = file_identity(&wal_path(&database)).unwrap();
            let result = SqlCipherMailboxReader::open_read_only_with_hooks(
                account(),
                database.path(),
                key(7),
                |_path| {},
                |_path| fs::remove_file(wal_path(&database)).unwrap(),
                |_path| {},
            );
            assert!(matches!(result, Err(MailboxStoreError::Storage)));
            assert!(wal_path(&database).is_file());
            assert_ne!(file_identity(&wal_path(&database)).unwrap(), original_wal);
        }

        #[test]
        fn dropping_an_unpolled_reader_future_performs_no_query() {
            let (database, store) = open("reader-unpolled");
            run(store.upsert_envelopes(&account(), &[envelope("one", "thread", 1)])).unwrap();
            drop(store);
            let reader =
                SqlCipherMailboxReader::open_read_only(account(), database.path(), key(7)).unwrap();
            let local_account = account();
            let future = reader.list_envelopes(&local_account, StoreLimit::new(1).unwrap());
            drop(future);
            assert_eq!(
                run(reader.list_envelopes(&account(), StoreLimit::new(1).unwrap()))
                    .unwrap()
                    .len(),
                1
            );
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
pub use macos::{
    DatabaseKey, ReadOnlyMailboxOpenFailure, SqlCipherMailboxReader, SqlCipherMailboxStore,
};
