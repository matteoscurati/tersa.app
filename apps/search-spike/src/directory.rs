// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! SQLCipher-backed Tantivy directory used only by the M0 diagnostic.

use std::fmt;
use std::io::{self, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use tantivy::HasLen;
use tantivy::directory::error::{DeleteError, LockError, OpenReadError, OpenWriteError};
use tantivy::directory::{
    AntiCallToken, Directory, DirectoryLock, FileHandle, Lock, TerminatingWrite, WatchCallback,
    WatchCallbackList, WatchHandle, WritePtr,
};
use zeroize::Zeroizing;

pub(crate) const CHUNK_SIZE: usize = 64 * 1024;
pub(crate) const CIPHER_VERSION: &str = "4.10.0 community";
pub(crate) const SQLITE_VERSION: &str = "3.50.4";

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, BoxError>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReadMetrics {
    pub(crate) requests: usize,
    pub(crate) chunks_loaded: usize,
    pub(crate) storage_bytes_loaded: usize,
    pub(crate) bytes_returned: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct SqlCipherDirectory {
    inner: Arc<Inner>,
}

struct Inner {
    connection: Mutex<Connection>,
    metrics: Mutex<ReadMetrics>,
    watch_callbacks: WatchCallbackList,
}

impl fmt::Debug for Inner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Inner")
            .field("connection", &"SQLCipher connection")
            .field("metrics", &self.metrics)
            .finish_non_exhaustive()
    }
}

impl SqlCipherDirectory {
    pub(crate) fn create(database: &Path, key: &[u8]) -> Result<Self> {
        let directory = Self::open_connection(Connection::open(database)?, key)?;
        {
            let connection = directory.connection()?;
            connection.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA secure_delete = ON;
                 PRAGMA temp_store = MEMORY;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE file_generations (
                     generation_id INTEGER PRIMARY KEY,
                     byte_len INTEGER NOT NULL CHECK(byte_len >= 0)
                 );
                 CREATE TABLE file_chunks (
                     generation_id INTEGER NOT NULL,
                     ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                     data BLOB NOT NULL,
                     PRIMARY KEY(generation_id, ordinal),
                     FOREIGN KEY(generation_id) REFERENCES file_generations(generation_id)
                 );
                 CREATE TABLE visible_files (
                     path TEXT PRIMARY KEY,
                     generation_id INTEGER NOT NULL,
                     FOREIGN KEY(generation_id) REFERENCES file_generations(generation_id)
                 );
                 CREATE TABLE directory_locks (path TEXT PRIMARY KEY);",
            )?;
        }
        directory.verify_runtime()?;
        Ok(directory)
    }

    pub(crate) fn open_existing(database: &Path, key: &[u8]) -> Result<Self> {
        let directory = Self::open_connection(Connection::open(database)?, key)?;
        directory.verify_runtime()?;
        Ok(directory)
    }

    fn open_connection(connection: Connection, key: &[u8]) -> Result<Self> {
        apply_key(&connection, key)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA secure_delete = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA wal_autocheckpoint = 0;",
        )?;
        let _: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
        Ok(Self {
            inner: Arc::new(Inner {
                connection: Mutex::new(connection),
                metrics: Mutex::new(ReadMetrics::default()),
                watch_callbacks: WatchCallbackList::default(),
            }),
        })
    }

    pub(crate) fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.inner
            .connection
            .lock()
            .map_err(|error| format!("search store mutex poisoned: {error}").into())
    }

    pub(crate) fn verify_runtime(&self) -> Result<()> {
        let connection = self.connection()?;
        let provider: String =
            connection.query_row("PRAGMA cipher_provider", [], |row| row.get(0))?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        let sqlite_version: String =
            connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        let secure_delete: i64 =
            connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
        let temp_store: i64 = connection.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
        let fts5_enabled = connection
            .prepare("PRAGMA compile_options")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|option| option == "ENABLE_FTS5");

        if provider != "commoncrypto"
            || cipher_version != CIPHER_VERSION
            || sqlite_version != SQLITE_VERSION
            || journal_mode != "wal"
            || secure_delete != 1
            || temp_store != 2
            || !fts5_enabled
        {
            return Err("required SQLCipher search runtime is unavailable".into());
        }
        Ok(())
    }

    pub(crate) fn read_metrics(&self) -> ReadMetrics {
        self.inner
            .metrics
            .lock()
            .map_or_else(|_| ReadMetrics::default(), |metrics| *metrics)
    }

    pub(crate) fn current_index_bytes(&self) -> Result<u64> {
        let bytes: i64 = self.connection()?.query_row(
            "SELECT COALESCE(SUM(g.byte_len), 0)
             FROM visible_files AS f
             JOIN file_generations AS g USING (generation_id)",
            [],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(bytes)?)
    }

    fn publish(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        let path = path_to_string(path)?;
        let mut connection = self.connection().map_err(io::Error::other)?;
        let transaction = connection.transaction().map_err(io::Error::other)?;
        transaction
            .execute(
                "INSERT INTO file_generations (byte_len) VALUES (?1)",
                [i64::try_from(data.len()).map_err(io::Error::other)?],
            )
            .map_err(io::Error::other)?;
        let generation_id = transaction.last_insert_rowid();
        for (ordinal, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            transaction
                .execute(
                    "INSERT INTO file_chunks (generation_id, ordinal, data)
                     VALUES (?1, ?2, ?3)",
                    params![
                        generation_id,
                        i64::try_from(ordinal).map_err(io::Error::other)?,
                        chunk
                    ],
                )
                .map_err(io::Error::other)?;
        }
        transaction
            .execute(
                "INSERT INTO visible_files (path, generation_id) VALUES (?1, ?2)
                 ON CONFLICT(path) DO UPDATE SET generation_id = excluded.generation_id",
                params![path, generation_id],
            )
            .map_err(io::Error::other)?;
        transaction.commit().map_err(io::Error::other)?;
        drop(connection);
        if path == "meta.json" {
            drop(self.inner.watch_callbacks.broadcast());
        }
        Ok(())
    }

    fn reserve_empty_file(&self, path: &Path) -> io::Result<bool> {
        let path = path_to_string(path)?;
        let mut connection = self.connection().map_err(io::Error::other)?;
        let transaction = connection.transaction().map_err(io::Error::other)?;
        transaction
            .execute("INSERT INTO file_generations (byte_len) VALUES (0)", [])
            .map_err(io::Error::other)?;
        let generation_id = transaction.last_insert_rowid();
        let changed = transaction
            .execute(
                "INSERT OR IGNORE INTO visible_files (path, generation_id) VALUES (?1, ?2)",
                params![path, generation_id],
            )
            .map_err(io::Error::other)?;
        if changed == 0 {
            return Ok(false);
        }
        transaction.commit().map_err(io::Error::other)?;
        Ok(true)
    }

    fn snapshot(&self, path: &Path) -> std::result::Result<Snapshot, OpenReadError> {
        let path_string = path_to_string(path).map_err(|error| read_error(path, error))?;
        let mapping = self
            .connection()
            .map_err(|error| read_error(path, io::Error::other(error)))?
            .query_row(
                "SELECT f.generation_id, g.byte_len
                 FROM visible_files AS f
                 JOIN file_generations AS g USING (generation_id)
                 WHERE f.path = ?1",
                [path_string],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| read_error(path, io::Error::other(error)))?;
        let Some((generation_id, byte_len)) = mapping else {
            return Err(OpenReadError::FileDoesNotExist(path.to_owned()));
        };
        Ok(Snapshot {
            inner: Arc::clone(&self.inner),
            generation_id,
            byte_len: usize::try_from(byte_len)
                .map_err(|error| read_error(path, io::Error::other(error)))?,
        })
    }

    fn try_lock(&self, path: &Path) -> std::result::Result<bool, LockError> {
        let path = path_to_string(path).map_err(LockError::wrap_io_error)?;
        let changed = self
            .connection()
            .map_err(|error| LockError::wrap_io_error(io::Error::other(error)))?
            .execute(
                "INSERT OR IGNORE INTO directory_locks (path) VALUES (?1)",
                [path],
            )
            .map_err(|error| LockError::wrap_io_error(io::Error::other(error)))?;
        Ok(changed == 1)
    }
}

impl Directory for SqlCipherDirectory {
    fn get_file_handle(
        &self,
        path: &Path,
    ) -> std::result::Result<Arc<dyn FileHandle>, OpenReadError> {
        self.snapshot(path)
            .map(|snapshot| Arc::new(snapshot) as Arc<dyn FileHandle>)
    }

    fn delete(&self, path: &Path) -> std::result::Result<(), DeleteError> {
        let path_string = path_to_string(path).map_err(|error| DeleteError::IoError {
            io_error: Arc::new(error),
            filepath: path.to_owned(),
        })?;
        let changed = self
            .connection()
            .map_err(|error| DeleteError::IoError {
                io_error: Arc::new(io::Error::other(error)),
                filepath: path.to_owned(),
            })?
            .execute("DELETE FROM visible_files WHERE path = ?1", [path_string])
            .map_err(|error| DeleteError::IoError {
                io_error: Arc::new(io::Error::other(error)),
                filepath: path.to_owned(),
            })?;
        if changed == 0 {
            return Err(DeleteError::FileDoesNotExist(path.to_owned()));
        }
        Ok(())
    }

    fn exists(&self, path: &Path) -> std::result::Result<bool, OpenReadError> {
        let path_string = path_to_string(path).map_err(|error| read_error(path, error))?;
        self.connection()
            .map_err(|error| read_error(path, io::Error::other(error)))?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM visible_files WHERE path = ?1)",
                [path_string],
                |row| row.get(0),
            )
            .map_err(|error| read_error(path, io::Error::other(error)))
    }

    fn open_write(&self, path: &Path) -> std::result::Result<WritePtr, OpenWriteError> {
        if !self
            .reserve_empty_file(path)
            .map_err(|error| OpenWriteError::wrap_io_error(error, path.to_owned()))?
        {
            return Err(OpenWriteError::FileAlreadyExists(path.to_owned()));
        }
        Ok(io::BufWriter::new(Box::new(StagedWriter {
            directory: self.clone(),
            path: path.to_owned(),
            data: Vec::new(),
            position: 0,
        })))
    }

    fn atomic_read(&self, path: &Path) -> std::result::Result<Vec<u8>, OpenReadError> {
        self.open_read(path)?
            .read_bytes()
            .map(|bytes| bytes.as_slice().to_vec())
            .map_err(|error| read_error(path, error))
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        self.publish(path, data)
    }

    fn sync_directory(&self) -> io::Result<()> {
        self.connection()
            .map_err(io::Error::other)?
            .execute_batch("PRAGMA wal_checkpoint(PASSIVE)")
            .map_err(io::Error::other)
    }

    fn acquire_lock(&self, lock: &Lock) -> std::result::Result<DirectoryLock, LockError> {
        loop {
            if self.try_lock(&lock.filepath)? {
                return Ok(DirectoryLock::from(Box::new(DatabaseLockGuard {
                    directory: self.clone(),
                    path: lock.filepath.clone(),
                })));
            }
            if !lock.is_blocking {
                return Err(LockError::LockBusy);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn watch(&self, callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        Ok(self.inner.watch_callbacks.subscribe(callback))
    }
}

#[derive(Debug)]
struct Snapshot {
    inner: Arc<Inner>,
    generation_id: i64,
    byte_len: usize,
}

impl HasLen for Snapshot {
    fn len(&self) -> usize {
        self.byte_len
    }
}

impl FileHandle for Snapshot {
    fn read_bytes(&self, range: Range<usize>) -> io::Result<tantivy::directory::OwnedBytes> {
        if range.start > range.end || range.end > self.byte_len {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid range"));
        }
        if range.is_empty() {
            return Ok(tantivy::directory::OwnedBytes::new(Vec::new()));
        }
        let first = range.start / CHUNK_SIZE;
        let last = (range.end - 1) / CHUNK_SIZE;
        let connection = self
            .inner
            .connection
            .lock()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut statement = connection
            .prepare(
                "SELECT ordinal, data FROM file_chunks
                 WHERE generation_id = ?1 AND ordinal BETWEEN ?2 AND ?3
                 ORDER BY ordinal",
            )
            .map_err(io::Error::other)?;
        let chunks = statement
            .query_map(
                params![
                    self.generation_id,
                    i64::try_from(first).map_err(io::Error::other)?,
                    i64::try_from(last).map_err(io::Error::other)?
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(io::Error::other)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(io::Error::other)?;
        drop(statement);
        drop(connection);

        if chunks.len() != last - first + 1
            || chunks.iter().enumerate().any(|(offset, (ordinal, _))| {
                usize::try_from(*ordinal).ok() != Some(first + offset)
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "generation has missing chunks",
            ));
        }

        let storage_bytes_loaded = chunks.iter().map(|(_, data)| data.len()).sum::<usize>();
        let mut bytes = Vec::with_capacity(range.len());
        for (ordinal, chunk) in &chunks {
            let ordinal = usize::try_from(*ordinal).map_err(io::Error::other)?;
            let start = if ordinal == first {
                range.start % CHUNK_SIZE
            } else {
                0
            };
            let end = if ordinal == last {
                (range.end - 1) % CHUNK_SIZE + 1
            } else {
                chunk.len()
            };
            bytes.extend_from_slice(&chunk[start..end]);
        }
        if bytes.len() != range.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "range read returned the wrong byte count",
            ));
        }
        let mut metrics = self
            .inner
            .metrics
            .lock()
            .map_err(|error| io::Error::other(error.to_string()))?;
        metrics.requests += 1;
        metrics.chunks_loaded += chunks.len();
        metrics.storage_bytes_loaded += storage_bytes_loaded;
        metrics.bytes_returned += bytes.len();
        Ok(tantivy::directory::OwnedBytes::new(bytes))
    }
}

#[derive(Debug)]
struct StagedWriter {
    directory: SqlCipherDirectory,
    path: PathBuf,
    data: Vec<u8>,
    position: usize,
}

impl Write for StagedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let end = self.position.saturating_add(buffer.len());
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[self.position..end].copy_from_slice(buffer);
        self.position = end;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.directory.publish(&self.path, &self.data)
    }
}

impl Seek for StagedWriter {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => self.position as i128 + i128::from(value),
            SeekFrom::End(value) => self.data.len() as i128 + i128::from(value),
        };
        if next < 0 || next > usize::MAX as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"));
        }
        self.position = usize::try_from(next)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(self.position as u64)
    }
}

impl TerminatingWrite for StagedWriter {
    fn terminate_ref(&mut self, _: AntiCallToken) -> io::Result<()> {
        self.flush()
    }
}

#[derive(Debug)]
struct DatabaseLockGuard {
    directory: SqlCipherDirectory,
    path: PathBuf,
}

impl Drop for DatabaseLockGuard {
    fn drop(&mut self) {
        let Ok(path) = path_to_string(&self.path) else {
            return;
        };
        if let Ok(connection) = self.directory.connection() {
            let _ = connection.execute("DELETE FROM directory_locks WHERE path = ?1", [path]);
        }
    }
}

fn apply_key(connection: &Connection, key: &[u8]) -> Result<()> {
    let mut literal = Zeroizing::new(String::with_capacity(key.len() * 2 + 3));
    literal.push_str("x'");
    for byte in key {
        use std::fmt::Write as _;
        write!(&mut literal, "{byte:02x}")?;
    }
    literal.push('\'');
    connection.pragma_update(None, "key", literal.as_str())?;
    Ok(())
}

fn path_to_string(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))
}

fn read_error(path: &Path, error: io::Error) -> OpenReadError {
    OpenReadError::IoError {
        io_error: Arc::new(error),
        filepath: path.to_owned(),
    }
}
