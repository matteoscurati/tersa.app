// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! macOS Data Protection Keychain root-key and fixed App Group capabilities.
//!
//! The production constructors use only the signing-time application-group
//! value. They deliberately offer no runtime configuration or fallback.

#![deny(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", test))]
use std::sync::Mutex;
#[cfg(target_os = "macos")]
use std::sync::OnceLock;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(any(target_os = "macos", test))]
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use tersa_platform::secure_storage::{
    AccountId, AccountProfileLocator, InstallationRootKeyProvisioner, KeyStorageError,
    ProfileStorageError, ProvisionOutcome,
};
use zeroize::{Zeroize, Zeroizing};

/// Trusted read-only mailbox read compositions for the fixed default profile.
#[cfg(target_os = "macos")]
pub mod mailbox_read;

/// Closed, redacted failure returned by the trusted read-only composition.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ReadOnlyMailboxOpenError {
    /// The existing Keychain root could not be retrieved or validated.
    KeyAccess,
    /// The fixed profile location or its storage is unavailable.
    ProfileUnavailable,
    /// The encrypted mailbox failed strict validation.
    MailboxCorrupted,
}

/// Closed result of the product-only fixed-profile bootstrap operation.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(i32)]
pub enum ProductBootstrapStatus {
    /// The validated fixed account profile is ready for use.
    Ready = 0,
    /// Opaque account bytes were not a canonical account identifier.
    InvalidAccountIdentifier = 1,
    /// The bridge called the synchronous operation from an invalid context.
    InvalidExecutionContext = 2,
    /// The bounded process or global lock could not be acquired.
    BusyOrUnavailable = 3,
    /// The Keychain root is absent while profile state already exists.
    RootMissingWithExistingProfile = 4,
    /// A Keychain, filesystem, or store invariant failed.
    Unavailable = 5,
}

impl fmt::Debug for ProductBootstrapStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductBootstrapStatus([REDACTED])")
    }
}

impl fmt::Debug for ReadOnlyMailboxOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadOnlyMailboxOpenError([REDACTED])")
    }
}

impl fmt::Display for ReadOnlyMailboxOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("read-only mailbox opening failed")
    }
}

impl std::error::Error for ReadOnlyMailboxOpenError {}

// Rust guideline compliant 1.0.

#[cfg(target_os = "macos")]
const SERVICE: &str = "app.tersa.mac.storage-root.v1";
#[cfg(target_os = "macos")]
const ACCOUNT: &str = "default";
#[cfg(any(target_os = "macos", test))]
const ROOT_SALT: &[u8] = b"tersa.app/macos/root-key/v1";
#[cfg(any(target_os = "macos", test))]
const HKDF_PREFIX: &[u8] = b"tersa.app/macos/hkdf-sha256/v1";
#[cfg(any(target_os = "macos", test))]
const DATABASE_PURPOSE: &[u8] = b"sqlcipher/account-database/v1";
const PROFILE_PREFIX: &[&str] = &["profiles", "default", "accounts"];
#[cfg(target_os = "macos")]
const BOOTSTRAP_LOCK: &str = ".tersa-profile-bootstrap-v1.lock";
#[cfg(target_os = "macos")]
const DIRECTORY_CREATION_JOURNAL_MAGIC: &str = "tersa-profile-directory-v2";
#[cfg(target_os = "macos")]
const DIRECTORY_CREATION_JOURNAL_LIMIT: usize = 192;
#[cfg(target_os = "macos")]
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_os = "macos")]
const BOOTSTRAP_BACKOFF: Duration = Duration::from_millis(10);

#[cfg_attr(test, derive(Eq, PartialEq))]
struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    #[cfg(test)]
    fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[cfg(any(target_os = "macos", test))]
    fn zeroed() -> Self {
        Self(Zeroizing::new([0; 32]))
    }

    #[cfg(any(target_os = "macos", test))]
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(any(target_os = "macos", test))]
    fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    fn zeroize_now(&mut self) {
        self.0.zeroize();
    }

    #[cfg(target_os = "macos")]
    fn into_database_key(mut self) -> tersa_store_sqlcipher_macos::DatabaseKey {
        let protected = std::mem::replace(&mut self.0, Zeroizing::new([0; 32]));
        tersa_store_sqlcipher_macos::DatabaseKey::from_zeroizing(protected)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Provisions only the fixed installation root key.
pub struct DataProtectionRootKeyProvisioner {
    backend: ProductionBackend,
}

impl fmt::Debug for DataProtectionRootKeyProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataProtectionRootKeyProvisioner([REDACTED])")
    }
}

/// Locates only the fixed default profile in the configured App Group.
pub struct AppGroupProfileLocator {
    locator: ProductionContainerLocator,
}

impl fmt::Debug for AppGroupProfileLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AppGroupProfileLocator([REDACTED])")
    }
}

impl DataProtectionRootKeyProvisioner {
    /// Creates the fixed production provisioner.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the signing-time App Group is absent.
    pub fn new() -> Result<Self, KeyStorageError> {
        Ok(Self {
            backend: ProductionBackend::new()?,
        })
    }
}

impl AppGroupProfileLocator {
    /// Creates the fixed production profile locator.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the signing-time App Group is absent.
    pub fn new() -> Result<Self, ProfileStorageError> {
        Ok(Self {
            locator: ProductionContainerLocator::new()?,
        })
    }
}

impl InstallationRootKeyProvisioner for DataProtectionRootKeyProvisioner {
    fn provision_installation_root_key(&self) -> Result<ProvisionOutcome, KeyStorageError> {
        provision_installation_root_key(&self.backend)
    }
}

fn provision_installation_root_key(
    backend: &impl RootKeyBackend,
) -> Result<ProvisionOutcome, KeyStorageError> {
    if backend.copy()?.is_some() {
        return Ok(ProvisionOutcome::Existing);
    }

    let mut candidate = backend.random_key()?;
    match backend.add(&candidate)? {
        AddResult::Added => {
            candidate.zeroize_now();
            backend.candidate_zeroized_before_reread(&candidate);
            backend.copy()?.ok_or(KeyStorageError::Invalid)?;
            Ok(ProvisionOutcome::Created)
        }
        AddResult::Duplicate => {
            candidate.zeroize_now();
            backend.candidate_zeroized_before_reread(&candidate);
            backend.copy()?.ok_or(KeyStorageError::Invalid)?;
            Ok(ProvisionOutcome::Existing)
        }
    }
}

impl AccountProfileLocator for AppGroupProfileLocator {
    fn account_database_path(
        &self,
        account_id: &AccountId,
    ) -> Result<PathBuf, ProfileStorageError> {
        account_database_path(&self.locator, account_id)
    }
}

fn account_database_path(
    locator: &impl ContainerLocator,
    account_id: &AccountId,
) -> Result<PathBuf, ProfileStorageError> {
    let container = locator.container()?;
    if !container.is_dir() || !is_readable_directory(&container) {
        return Err(ProfileStorageError::Unavailable);
    }
    let digest = hex_digest(account_id);
    Ok(PROFILE_PREFIX
        .iter()
        .fold(container, |path, part| path.join(part))
        .join(digest)
        .join("mail.sqlite3"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(target_os = "macos", test))]
enum AccountKeyPurpose {
    SqlCipherAccountDatabaseV1,
}

#[cfg(any(target_os = "macos", test))]
fn derive_account_key(
    root: &SecretKey,
    account_id: &AccountId,
    purpose: AccountKeyPurpose,
) -> Result<SecretKey, KeyStorageError> {
    let purpose = match purpose {
        AccountKeyPurpose::SqlCipherAccountDatabaseV1 => DATABASE_PURPOSE,
    };
    let info = framed_info(account_id, purpose)?;
    let hkdf = Hkdf::<Sha256>::new(Some(ROOT_SALT), root.as_bytes());
    let mut output = SecretKey::zeroed();
    hkdf.expand(&info, output.as_mut_bytes())
        .map_err(|_invalid_length| KeyStorageError::Invalid)?;
    Ok(output)
}

#[cfg(any(target_os = "macos", test))]
fn framed_info(account: &AccountId, purpose: &[u8]) -> Result<Vec<u8>, KeyStorageError> {
    let account = account.as_str().as_bytes();
    let account_len = u16::try_from(account.len()).map_err(|_too_long| KeyStorageError::Invalid)?;
    let purpose_len = u16::try_from(purpose.len()).map_err(|_too_long| KeyStorageError::Invalid)?;
    let mut result = Vec::with_capacity(HKDF_PREFIX.len() + 4 + account.len() + purpose.len());
    result.extend_from_slice(HKDF_PREFIX);
    result.extend_from_slice(&account_len.to_be_bytes());
    result.extend_from_slice(account);
    result.extend_from_slice(&purpose_len.to_be_bytes());
    result.extend_from_slice(purpose);
    Ok(result)
}

fn hex_digest(account: &AccountId) -> String {
    let digest = Sha256::digest(account.as_str().as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn is_readable_directory(path: &Path) -> bool {
    std::fs::read_dir(path).is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    all(not(target_os = "macos"), not(test)),
    expect(
        dead_code,
        reason = "Non-macOS builds retain the portable capability shape but fail before constructing a Keychain add result."
    )
)]
enum AddResult {
    Added,
    Duplicate,
}

trait RootKeyRetriever: Send + Sync {
    fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError>;
}

trait RootKeyBackend: RootKeyRetriever {
    fn random_key(&self) -> Result<SecretKey, KeyStorageError>;
    fn add(&self, candidate: &SecretKey) -> Result<AddResult, KeyStorageError>;

    fn candidate_zeroized_before_reread(&self, _candidate: &SecretKey) {}
}

trait ContainerLocator: Send + Sync {
    fn container(&self) -> Result<PathBuf, ProfileStorageError>;
}

/// Internal fixed production Keychain implementation.
#[derive(Debug)]
struct ProductionBackend {
    group: &'static str,
}

impl ProductionBackend {
    fn new() -> Result<Self, KeyStorageError> {
        Ok(Self {
            group: configured_group(option_env!("TERSA_MACOS_APP_GROUP"))?,
        })
    }
}

impl RootKeyRetriever for ProductionBackend {
    fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError> {
        macos_keychain::copy(self.group)
    }
}

impl RootKeyBackend for ProductionBackend {
    fn random_key(&self) -> Result<SecretKey, KeyStorageError> {
        macos_keychain::random()
    }
    fn add(&self, candidate: &SecretKey) -> Result<AddResult, KeyStorageError> {
        macos_keychain::add(self.group, candidate)
    }
}

/// Opens the one fixed account mailbox with retrieval-only Keychain access.
///
/// This is the only production composition that consumes the derived key. It
/// accepts no profile, Keychain, purpose, or database-path override.
///
/// # Errors
///
/// Returns a closed redacted error when Keychain retrieval, fixed-profile
/// resolution, or strict mailbox validation fails.
#[cfg(target_os = "macos")]
pub fn open_default_read_only_mailbox(
    account: &AccountId,
) -> Result<tersa_store_sqlcipher_macos::SqlCipherMailboxReader, ReadOnlyMailboxOpenError> {
    let backend = ProductionBackend::new().map_err(|_error| ReadOnlyMailboxOpenError::KeyAccess)?;
    let locator = ProductionContainerLocator::new()
        .map_err(|_error| ReadOnlyMailboxOpenError::ProfileUnavailable)?;
    open_read_only_mailbox(&backend, &locator, account)
}

#[cfg(target_os = "macos")]
fn open_read_only_mailbox(
    retriever: &impl RootKeyRetriever,
    locator: &impl ContainerLocator,
    account: &AccountId,
) -> Result<tersa_store_sqlcipher_macos::SqlCipherMailboxReader, ReadOnlyMailboxOpenError> {
    let root = retriever
        .copy()
        .map_err(|_error| ReadOnlyMailboxOpenError::KeyAccess)?
        .ok_or(ReadOnlyMailboxOpenError::KeyAccess)?;
    let key = derive_account_key(
        &root,
        account,
        AccountKeyPurpose::SqlCipherAccountDatabaseV1,
    )
    .map_err(|_error| ReadOnlyMailboxOpenError::KeyAccess)?;
    drop(root);
    let path = account_database_path(locator, account)
        .map_err(|_error| ReadOnlyMailboxOpenError::ProfileUnavailable)?;
    tersa_store_sqlcipher_macos::SqlCipherMailboxReader::open_read_only_classified(
        account.clone(),
        path,
        key.into_database_key(),
    )
    .map_err(|failure| match failure {
        tersa_store_sqlcipher_macos::ReadOnlyMailboxOpenFailure::Storage => {
            ReadOnlyMailboxOpenError::ProfileUnavailable
        }
        tersa_store_sqlcipher_macos::ReadOnlyMailboxOpenFailure::Corrupted => {
            ReadOnlyMailboxOpenError::MailboxCorrupted
        }
    })
}

/// Validates opaque bytes and establishes the one fixed product profile.
///
/// This is intentionally the sole public product-bootstrap entry. Validation
/// completes before construction of Keychain or filesystem capabilities.
#[cfg(target_os = "macos")]
#[must_use]
pub fn bootstrap_default_account_bytes(account_bytes: &[u8]) -> ProductBootstrapStatus {
    let account = match validate_bootstrap_account_bytes(
        objc2_foundation::NSThread::isMainThread_class(),
        account_bytes,
    ) {
        Ok(account) => account,
        Err(status) => return status,
    };
    bootstrap_default_account(&account)
}

#[cfg(any(target_os = "macos", test))]
fn validate_bootstrap_account_bytes(
    is_main_thread: bool,
    account_bytes: &[u8],
) -> Result<AccountId, ProductBootstrapStatus> {
    if is_main_thread {
        return Err(ProductBootstrapStatus::InvalidExecutionContext);
    }
    let account_text = std::str::from_utf8(account_bytes)
        .map_err(|_error| ProductBootstrapStatus::InvalidAccountIdentifier)?;
    AccountId::new(account_text.to_owned())
        .map_err(|_error| ProductBootstrapStatus::InvalidAccountIdentifier)
}

#[cfg(target_os = "macos")]
fn bootstrap_default_account(account: &AccountId) -> ProductBootstrapStatus {
    let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
    let process_guard = match acquire_process_lock(deadline) {
        Ok(guard) => guard,
        Err(ProcessLockFailure::TimedOut) => return ProductBootstrapStatus::BusyOrUnavailable,
        Err(ProcessLockFailure::Poisoned) => return ProductBootstrapStatus::Unavailable,
    };
    let _process_guard = process_guard;
    let Ok(locator) = ProductionContainerLocator::new() else {
        return ProductBootstrapStatus::Unavailable;
    };
    let Ok(backend) = ProductionBackend::new() else {
        return ProductBootstrapStatus::Unavailable;
    };
    bootstrap_default_account_with_dependencies(
        account,
        &backend,
        &locator,
        deadline,
        |account, path, key| {
            tersa_store_sqlcipher_macos::SqlCipherMailboxStore::open(account, path, key)
                .map(|_store| ())
                .map_err(|_error| ())
        },
    )
}

/// Executes the fixed bootstrap state machine through injected trusted capabilities.
///
/// This internal seam is deliberately capability-based: tests can exercise every
/// status without exporting a root key or adding a configurable production path.
#[cfg(target_os = "macos")]
fn bootstrap_default_account_with_dependencies(
    account: &AccountId,
    backend: &impl RootKeyBackend,
    locator: &impl ContainerLocator,
    deadline: Instant,
    open_store: impl FnOnce(
        AccountId,
        PathBuf,
        tersa_store_sqlcipher_macos::DatabaseKey,
    ) -> Result<(), ()>,
) -> ProductBootstrapStatus {
    let Ok(container) = locator.container() else {
        return ProductBootstrapStatus::Unavailable;
    };
    let lock = match acquire_global_lock(&container, deadline) {
        Ok(lock) => lock,
        // Only a bounded wait for another holder is a busy condition.  A
        // malformed lock entry, an unsafe container, or any other I/O failure
        // is an invariant failure and must not be presented as contention.
        Err(error) if error == rustix::io::Errno::TIMEDOUT => {
            return ProductBootstrapStatus::BusyOrUnavailable;
        }
        Err(_error) => return ProductBootstrapStatus::Unavailable,
    };
    // The journal belongs to the fixed profile bootstrap rather than to the
    // requested account. Recover any complete fixed-lineage record before the
    // requested account starts its own traversal.
    if recover_pending_directory_creation(&lock).is_err() {
        return ProductBootstrapStatus::Unavailable;
    }
    let root = match backend.copy() {
        Ok(Some(root)) => root,
        Ok(None) => {
            match is_empty_profile_skeleton(lock.container_fd()) {
                Ok(true) => {}
                Ok(false) => return ProductBootstrapStatus::RootMissingWithExistingProfile,
                Err(_error) => return ProductBootstrapStatus::Unavailable,
            }
            if provision_installation_root_key(backend).is_err() {
                return ProductBootstrapStatus::Unavailable;
            }
            match backend.copy() {
                Ok(Some(root)) => root,
                _ => return ProductBootstrapStatus::Unavailable,
            }
        }
        Err(_error) => return ProductBootstrapStatus::Unavailable,
    };
    let Ok(key) = derive_account_key(
        &root,
        account,
        AccountKeyPurpose::SqlCipherAccountDatabaseV1,
    ) else {
        return ProductBootstrapStatus::Unavailable;
    };
    drop(root);
    let digest = hex_digest(account);
    let Ok(mut directories) = establish_account_directory(&lock, &container, &digest) else {
        return ProductBootstrapStatus::Unavailable;
    };
    if directories.revalidate().is_err() {
        directories.cleanup_before_store_open();
        return ProductBootstrapStatus::Unavailable;
    }
    let result = open_store(
        account.clone(),
        directories.path().join("mail.sqlite3"),
        key.into_database_key(),
    );
    // Once store opening begins, directory cleanup is forbidden.
    if directories.revalidate().is_err() {
        return ProductBootstrapStatus::Unavailable;
    }
    match result {
        Ok(()) => ProductBootstrapStatus::Ready,
        Err(()) => ProductBootstrapStatus::Unavailable,
    }
}

#[cfg(target_os = "macos")]
fn process_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(target_os = "macos")]
#[derive(Debug, Eq, PartialEq)]
enum ProcessLockFailure {
    TimedOut,
    Poisoned,
}

#[cfg(target_os = "macos")]
fn acquire_process_lock(
    deadline: Instant,
) -> Result<std::sync::MutexGuard<'static, ()>, ProcessLockFailure> {
    acquire_mutex_until(process_lock(), deadline)
}

#[cfg(target_os = "macos")]
fn acquire_mutex_until(
    mutex: &Mutex<()>,
    deadline: Instant,
) -> Result<std::sync::MutexGuard<'_, ()>, ProcessLockFailure> {
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_error)) => {
                return Err(ProcessLockFailure::Poisoned);
            }
            Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(
                    BOOTSTRAP_BACKOFF.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(std::sync::TryLockError::WouldBlock) => return Err(ProcessLockFailure::TimedOut),
        }
    }
}

#[cfg(target_os = "macos")]
struct BootstrapLock {
    container: rustix::fd::OwnedFd,
    lock: rustix::fd::OwnedFd,
}

#[cfg(target_os = "macos")]
impl BootstrapLock {
    fn container_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.container.as_fd()
    }

    fn journal_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.lock.as_fd()
    }
}

#[cfg(target_os = "macos")]
fn acquire_global_lock(container: &Path, deadline: Instant) -> rustix::io::Result<BootstrapLock> {
    acquire_global_lock_with_hook(container, deadline, &mut |_point| Ok(()))
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GlobalLockHook {
    AfterCreate,
    AfterExistingOpen,
}

#[cfg(target_os = "macos")]
fn acquire_global_lock_with_hook(
    container: &Path,
    deadline: Instant,
    hook: &mut dyn FnMut(GlobalLockHook) -> rustix::io::Result<()>,
) -> rustix::io::Result<BootstrapLock> {
    use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags};
    use std::os::fd::AsFd;

    let directory = fs::openat(
        fs::CWD,
        container,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    validate_directory(&fs::fstat(&directory)?, None)?;
    require_deadline(deadline)?;
    let lock = match fs::openat(
        directory.as_fd(),
        BOOTSTRAP_LOCK,
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(lock) => {
            fs::fchmod(&lock, Mode::from_raw_mode(0o600))?;
            validate_lock(&fs::fstat(&lock)?, None, true)?;
            // A newly linked journal must survive a crash before it can
            // authorize any directory creation or recovery.
            fs::fsync(&lock)?;
            fs::fsync(&directory)?;
            hook(GlobalLockHook::AfterCreate)?;
            lock
        }
        Err(error) if error == rustix::io::Errno::EXIST => {
            require_deadline(deadline)?;
            let expected =
                fs::statat(directory.as_fd(), BOOTSTRAP_LOCK, AtFlags::SYMLINK_NOFOLLOW)?;
            validate_lock(&expected, None, false)?;
            let mode = Mode::from_raw_mode(expected.st_mode).as_raw_mode();
            // A 0000/0200/0400 legacy lock cannot be opened even by its owner on
            // Darwin.  `chmodat(..., NOFOLLOW)` is the only recovery path;
            // bind it to the preceding and following identity checks so a
            // replacement is rejected before flocking.
            if mode != 0o600 {
                fs::chmodat(
                    directory.as_fd(),
                    BOOTSTRAP_LOCK,
                    Mode::from_raw_mode(0o600),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?;
            }
            require_deadline(deadline)?;
            let lock = fs::openat(
                directory.as_fd(),
                BOOTSTRAP_LOCK,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?;
            hook(GlobalLockHook::AfterExistingOpen)?;
            validate_lock(&fs::fstat(&lock)?, Some(&expected), true)?;
            lock
        }
        Err(error) => return Err(error),
    };
    retry_transient_until(deadline, || {
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
    })?;
    Ok(BootstrapLock {
        container: directory,
        lock,
    })
}

#[cfg(target_os = "macos")]
fn retry_transient_until<T>(
    deadline: Instant,
    mut operation: impl FnMut() -> rustix::io::Result<T>,
) -> rustix::io::Result<T> {
    loop {
        require_deadline(deadline)?;
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::INTR => {
                std::thread::sleep(
                    BOOTSTRAP_BACKOFF.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "macos")]
fn validate_lock(
    stat: &rustix::fs::Stat,
    expected: Option<&rustix::fs::Stat>,
    exact_mode: bool,
) -> rustix::io::Result<()> {
    use rustix::fs::{FileType, Mode};
    let mode = Mode::from_raw_mode(stat.st_mode).as_raw_mode();
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || if exact_mode {
            mode != 0o600
        } else {
            mode & !0o600 != 0
        }
        || expected.is_some_and(|old| old.st_dev != stat.st_dev || old.st_ino != stat.st_ino)
    {
        return Err(rustix::io::Errno::PERM);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_deadline(deadline: Instant) -> rustix::io::Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(rustix::io::Errno::TIMEDOUT)
    }
}

#[cfg(target_os = "macos")]
fn is_empty_profile_skeleton(container: std::os::fd::BorrowedFd<'_>) -> rustix::io::Result<bool> {
    is_empty_profile_skeleton_with_probe(container, &mut || Ok(()))
}

#[cfg(target_os = "macos")]
fn is_empty_profile_skeleton_with_probe(
    container: std::os::fd::BorrowedFd<'_>,
    probe: &mut dyn FnMut() -> rustix::io::Result<()>,
) -> rustix::io::Result<bool> {
    use std::os::fd::AsFd;
    probe()?;
    let profiles = match open_optional_directory(container, "profiles") {
        Ok(Some(profiles)) => profiles,
        Ok(None) => return Ok(true),
        Err(error) => return Err(error),
    };
    if !directory_has_only(profiles.as_fd(), Some("default"))? {
        return Ok(false);
    }
    let default = match open_optional_directory(profiles.as_fd(), "default") {
        Ok(Some(default)) => default,
        Ok(None) => return Ok(true),
        Err(error) => return Err(error),
    };
    if !directory_has_only(default.as_fd(), Some("accounts"))? {
        return Ok(false);
    }
    match open_optional_directory(default.as_fd(), "accounts") {
        Ok(Some(accounts)) => directory_has_only(accounts.as_fd(), None),
        Ok(None) => Ok(true),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "macos")]
fn open_optional_directory(
    parent: std::os::fd::BorrowedFd<'_>,
    name: &str,
) -> rustix::io::Result<Option<rustix::fd::OwnedFd>> {
    use rustix::fs::{self, Mode, OFlags};
    match fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(directory) => {
            let stat = fs::fstat(&directory)?;
            validate_directory(&stat, None)?;
            if Mode::from_raw_mode(stat.st_mode).as_raw_mode() != 0o700 {
                return Err(rustix::io::Errno::PERM);
            }
            Ok(Some(directory))
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "macos")]
fn directory_has_only(
    directory: std::os::fd::BorrowedFd<'_>,
    allowed: Option<&str>,
) -> rustix::io::Result<bool> {
    let entries = rustix::fs::Dir::read_from(directory)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if allowed.is_none_or(|allowed| name != allowed.as_bytes()) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
struct DirectorySnapshot {
    parent: rustix::fd::OwnedFd,
    name: String,
    expected: rustix::fs::Stat,
    created: bool,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingDirectoryCreation {
    parent_device: i64,
    parent_inode: u64,
    component: String,
    phase: DirectoryCreationPhase,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
enum DirectoryCreationPhase {
    Intent,
    Created { child_device: i64, child_inode: u64 },
}

#[cfg(target_os = "macos")]
impl PendingDirectoryCreation {
    fn new(parent: &rustix::fs::Stat, component: &str) -> Self {
        Self {
            parent_device: i64::from(parent.st_dev),
            parent_inode: parent.st_ino,
            component: component.to_owned(),
            phase: DirectoryCreationPhase::Intent,
        }
    }

    fn created(&self, child: &rustix::fs::Stat) -> Self {
        Self {
            parent_device: self.parent_device,
            parent_inode: self.parent_inode,
            component: self.component.clone(),
            phase: DirectoryCreationPhase::Created {
                child_device: i64::from(child.st_dev),
                child_inode: child.st_ino,
            },
        }
    }

    fn matches(&self, parent: &rustix::fs::Stat, component: &str) -> bool {
        self.parent_device == i64::from(parent.st_dev)
            && self.parent_inode == parent.st_ino
            && self.component == component
    }

    fn encode(&self) -> String {
        match self.phase {
            DirectoryCreationPhase::Intent => format!(
                "{DIRECTORY_CREATION_JOURNAL_MAGIC}\nintent\n{}\n{}\n{}\n",
                self.parent_device, self.parent_inode, self.component
            ),
            DirectoryCreationPhase::Created {
                child_device,
                child_inode,
            } => format!(
                "{DIRECTORY_CREATION_JOURNAL_MAGIC}\ncreated\n{}\n{}\n{}\n{}\n{}\n",
                self.parent_device, self.parent_inode, self.component, child_device, child_inode
            ),
        }
    }

    fn decode(bytes: &[u8]) -> rustix::io::Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_error| rustix::io::Errno::INVAL)?;
        let Some(text) = text.strip_suffix('\n') else {
            return Err(rustix::io::Errno::INVAL);
        };
        let mut fields = text.split('\n');
        if fields.next() != Some(DIRECTORY_CREATION_JOURNAL_MAGIC) {
            return Err(rustix::io::Errno::INVAL);
        }
        let phase = fields.next().ok_or(rustix::io::Errno::INVAL)?;
        let parent_device = fields
            .next()
            .ok_or(rustix::io::Errno::INVAL)?
            .parse()
            .map_err(|_error| rustix::io::Errno::INVAL)?;
        let parent_inode = fields
            .next()
            .ok_or(rustix::io::Errno::INVAL)?
            .parse()
            .map_err(|_error| rustix::io::Errno::INVAL)?;
        let component = fields.next().ok_or(rustix::io::Errno::INVAL)?;
        if !is_fixed_lineage_component(component) {
            return Err(rustix::io::Errno::INVAL);
        }
        let phase = match phase {
            "intent" if fields.next().is_none() => DirectoryCreationPhase::Intent,
            "created" => {
                let child_device = fields
                    .next()
                    .ok_or(rustix::io::Errno::INVAL)?
                    .parse()
                    .map_err(|_error| rustix::io::Errno::INVAL)?;
                let child_inode = fields
                    .next()
                    .ok_or(rustix::io::Errno::INVAL)?
                    .parse()
                    .map_err(|_error| rustix::io::Errno::INVAL)?;
                if fields.next().is_some() {
                    return Err(rustix::io::Errno::INVAL);
                }
                DirectoryCreationPhase::Created {
                    child_device,
                    child_inode,
                }
            }
            _ => return Err(rustix::io::Errno::INVAL),
        };
        Ok(Self {
            parent_device,
            parent_inode,
            component: component.to_owned(),
            phase,
        })
    }
}

#[cfg(target_os = "macos")]
fn is_fixed_lineage_component(component: &str) -> bool {
    fixed_lineage_boundary(component).is_some()
}

#[cfg(target_os = "macos")]
fn fixed_lineage_boundary(component: &str) -> Option<usize> {
    match component {
        "profiles" => Some(0),
        "default" => Some(1),
        "accounts" => Some(2),
        component if is_canonical_account_leaf(component) => Some(3),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn is_canonical_account_leaf(component: &str) -> bool {
    component.len() == 64
        && component
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(target_os = "macos")]
fn read_directory_creation_journal(
    journal: std::os::fd::BorrowedFd<'_>,
) -> rustix::io::Result<Option<PendingDirectoryCreation>> {
    let stat = rustix::fs::fstat(journal)?;
    validate_lock(&stat, None, true)?;
    let length = usize::try_from(stat.st_size).map_err(|_error| rustix::io::Errno::FBIG)?;
    if length == 0 {
        return Ok(None);
    }
    if length > DIRECTORY_CREATION_JOURNAL_LIMIT {
        return Err(rustix::io::Errno::FBIG);
    }
    let mut bytes = vec![0_u8; length];
    let read = rustix::io::pread(journal, &mut bytes[..], 0)?;
    if read != length {
        return Err(rustix::io::Errno::IO);
    }
    PendingDirectoryCreation::decode(&bytes).map(Some)
}

#[cfg(target_os = "macos")]
fn write_directory_creation_journal(
    journal: std::os::fd::BorrowedFd<'_>,
    pending: &PendingDirectoryCreation,
) -> rustix::io::Result<()> {
    if read_directory_creation_journal(journal)?.is_some() {
        return Err(rustix::io::Errno::BUSY);
    }
    let bytes = pending.encode();
    if bytes.len() > DIRECTORY_CREATION_JOURNAL_LIMIT {
        return Err(rustix::io::Errno::FBIG);
    }
    rustix::fs::ftruncate(journal, 0)?;
    let mut written = 0;
    while written < bytes.len() {
        let count = rustix::io::pwrite(journal, &bytes.as_bytes()[written..], written as u64)?;
        if count == 0 {
            return Err(rustix::io::Errno::IO);
        }
        written += count;
    }
    rustix::fs::fsync(journal)
}

#[cfg(target_os = "macos")]
fn advance_directory_creation_journal(
    journal: std::os::fd::BorrowedFd<'_>,
    pending: &PendingDirectoryCreation,
) -> rustix::io::Result<()> {
    let current = read_directory_creation_journal(journal)?.ok_or(rustix::io::Errno::INVAL)?;
    if current.parent_device != pending.parent_device
        || current.parent_inode != pending.parent_inode
        || current.component != pending.component
        || !matches!(current.phase, DirectoryCreationPhase::Intent)
        || !matches!(pending.phase, DirectoryCreationPhase::Created { .. })
    {
        return Err(rustix::io::Errno::PERM);
    }
    let bytes = pending.encode();
    if bytes.len() > DIRECTORY_CREATION_JOURNAL_LIMIT || bytes.len() <= current.encode().len() {
        return Err(rustix::io::Errno::FBIG);
    }
    // Created records are longer than intent records. Overwrite in place so a
    // crash can leave only the old intent, a malformed nonempty record, or the
    // complete created phase; it can never manufacture an empty/no-journal
    // state while the new child already exists.
    let mut written = 0;
    while written < bytes.len() {
        let count = rustix::io::pwrite(journal, &bytes.as_bytes()[written..], written as u64)?;
        if count == 0 {
            return Err(rustix::io::Errno::IO);
        }
        written += count;
    }
    rustix::fs::fsync(journal)
}

#[cfg(target_os = "macos")]
fn clear_directory_creation_journal(
    journal: std::os::fd::BorrowedFd<'_>,
) -> rustix::io::Result<()> {
    rustix::fs::ftruncate(journal, 0)?;
    rustix::fs::fsync(journal)
}

#[cfg(target_os = "macos")]
fn authorize_existing_directory(
    pending: Option<&PendingDirectoryCreation>,
    existing: &rustix::fs::Stat,
) -> rustix::io::Result<bool> {
    match pending.map(|pending| &pending.phase) {
        Some(DirectoryCreationPhase::Intent) => {
            // Intent proves only that a creation was planned. It never
            // authorizes a child that appeared before a durable identity.
            Err(rustix::io::Errno::PERM)
        }
        Some(DirectoryCreationPhase::Created {
            child_device,
            child_inode,
        }) if *child_device == i64::from(existing.st_dev) && *child_inode == existing.st_ino => {
            Ok(true)
        }
        Some(DirectoryCreationPhase::Created { .. }) => Err(rustix::io::Errno::PERM),
        None => Ok(false),
    }
}

/// Recovers any complete fixed-lineage journal before account-specific
/// bootstrap begins.
#[cfg(target_os = "macos")]
fn recover_pending_directory_creation(lock: &BootstrapLock) -> rustix::io::Result<()> {
    use rustix::fs::{self, AtFlags, Mode, OFlags};
    use std::os::fd::AsFd;

    let Some(pending) = read_directory_creation_journal(lock.journal_fd())? else {
        return Ok(());
    };
    let target_boundary =
        fixed_lineage_boundary(&pending.component).ok_or(rustix::io::Errno::PERM)?;

    let mut parent = fs::openat(
        lock.container_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    validate_directory(&fs::fstat(&parent)?, None)?;
    for component in PROFILE_PREFIX.iter().take(target_boundary) {
        let child = fs::openat(
            parent.as_fd(),
            *component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let child_stat = fs::fstat(&child)?;
        validate_directory(&child_stat, None)?;
        if Mode::from_raw_mode(child_stat.st_mode).as_raw_mode() != 0o700 {
            return Err(rustix::io::Errno::PERM);
        }
        parent = child;
    }

    let parent_stat = fs::fstat(&parent)?;
    validate_directory(&parent_stat, None)?;
    if !pending.matches(&parent_stat, &pending.component) {
        return Err(rustix::io::Errno::PERM);
    }
    let child_before = recover_pending_directory_target(lock, parent.as_fd(), &pending)?;

    // Bind normalization and clearing to the identity recorded in Created.
    fs::chmodat(
        parent.as_fd(),
        &pending.component,
        Mode::from_raw_mode(0o700),
        AtFlags::SYMLINK_NOFOLLOW,
    )?;
    let child = fs::openat(
        parent.as_fd(),
        &pending.component,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let child_after = fs::fstat(&child)?;
    validate_directory(&child_after, Some(&child_before))?;
    if Mode::from_raw_mode(child_after.st_mode).as_raw_mode() != 0o700 {
        return Err(rustix::io::Errno::PERM);
    }
    fs::fsync(&child)?;
    fs::fsync(&parent)?;
    clear_directory_creation_journal(lock.journal_fd())
}

#[cfg(target_os = "macos")]
fn recover_pending_directory_target(
    lock: &BootstrapLock,
    parent: std::os::fd::BorrowedFd<'_>,
    pending: &PendingDirectoryCreation,
) -> rustix::io::Result<rustix::fs::Stat> {
    use rustix::fs::{self, AtFlags, Mode};

    match fs::statat(parent, &pending.component, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(existing) => {
            validate_directory(&existing, None)?;
            if !authorize_existing_directory(Some(pending), &existing)? {
                return Err(rustix::io::Errno::PERM);
            }
            Ok(existing)
        }
        Err(error) if error == rustix::io::Errno::NOENT => {
            if !matches!(pending.phase, DirectoryCreationPhase::Intent) {
                return Err(rustix::io::Errno::PERM);
            }
            if let Err(error) = fs::mkdirat(parent, &pending.component, Mode::from_raw_mode(0o700))
            {
                if fs::statat(parent, &pending.component, AtFlags::SYMLINK_NOFOLLOW)
                    .is_err_and(|probe_error| probe_error == rustix::io::Errno::NOENT)
                {
                    clear_directory_creation_journal(lock.journal_fd())?;
                }
                return Err(error);
            }
            let created = fs::statat(parent, &pending.component, AtFlags::SYMLINK_NOFOLLOW)?;
            validate_directory(&created, None)?;
            advance_directory_creation_journal(lock.journal_fd(), &pending.created(&created))?;
            Ok(created)
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "macos")]
struct EstablishedDirectories {
    path: PathBuf,
    snapshots: Vec<DirectorySnapshot>,
}

#[cfg(target_os = "macos")]
impl EstablishedDirectories {
    fn path(&self) -> &Path {
        &self.path
    }

    fn revalidate(&self) -> rustix::io::Result<()> {
        use rustix::fs::{self, AtFlags, Mode, OFlags};
        for snapshot in &self.snapshots {
            let actual = fs::statat(&snapshot.parent, &snapshot.name, AtFlags::SYMLINK_NOFOLLOW)?;
            validate_established_directory(&actual, &snapshot.expected)?;
            let reopened = fs::openat(
                &snapshot.parent,
                &snapshot.name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?;
            validate_established_directory(&fs::fstat(&reopened)?, &snapshot.expected)?;
        }
        Ok(())
    }

    fn cleanup_before_store_open(&mut self) {
        while let Some(snapshot) = self.snapshots.pop() {
            if snapshot.created
                && rustix::fs::statat(
                    &snapshot.parent,
                    &snapshot.name,
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .is_ok_and(|actual| validate_directory(&actual, Some(&snapshot.expected)).is_ok())
            {
                let _ = rustix::fs::unlinkat(
                    &snapshot.parent,
                    &snapshot.name,
                    rustix::fs::AtFlags::REMOVEDIR,
                );
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn establish_account_directory(
    lock: &BootstrapLock,
    container_path: &Path,
    digest: &str,
) -> rustix::io::Result<EstablishedDirectories> {
    establish_account_directory_with_hooks(
        lock,
        container_path,
        digest,
        |_boundary| Ok(()),
        |_boundary| Ok(()),
        |_boundary| Ok(()),
        |_boundary| Ok(()),
    )
}

#[cfg(target_os = "macos")]
fn establish_account_directory_with_hooks(
    lock: &BootstrapLock,
    container_path: &Path,
    digest: &str,
    before_journal_write: impl FnMut(usize) -> rustix::io::Result<()>,
    before_mkdir: impl FnMut(usize) -> rustix::io::Result<()>,
    after_mkdir: impl FnMut(usize) -> rustix::io::Result<()>,
    mut after_boundary: impl FnMut(usize) -> rustix::io::Result<()>,
) -> rustix::io::Result<EstablishedDirectories> {
    use rustix::fs::{self, Mode, OFlags};
    use std::os::fd::AsFd;
    let mut parent = fs::openat(
        lock.container_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    validate_directory(&fs::fstat(&parent)?, None)?;
    let mut established = EstablishedDirectories {
        path: container_path.to_path_buf(),
        snapshots: Vec::new(),
    };
    let mut component_hooks = (before_journal_write, before_mkdir, after_mkdir);
    let mut retain_created_lineage = false;
    let result = (|| {
        for (boundary, component) in ["profiles", "default", "accounts", digest]
            .into_iter()
            .enumerate()
        {
            let (child, stat, created) = establish_account_component(
                lock,
                parent.as_fd(),
                boundary,
                component,
                digest,
                &mut component_hooks,
                &mut retain_created_lineage,
            )?;
            established.snapshots.push(DirectorySnapshot {
                parent: rustix::io::fcntl_dupfd_cloexec(parent.as_fd(), 0)?,
                name: component.to_owned(),
                expected: stat,
                created,
            });
            parent = child;
            established.path.push(component);
            after_boundary(boundary)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        // A live journal names a parent by identity. Removing that parent (or
        // any ancestor that makes it reachable) would make crash recovery
        // irrecoverable. The residual is deliberately retained unless the
        // component was proven absent and the journal clear was durable.
        if !retain_created_lineage {
            established.cleanup_before_store_open();
        }
        return Err(error);
    }
    Ok(established)
}

#[cfg(target_os = "macos")]
fn establish_account_component(
    lock: &BootstrapLock,
    parent: std::os::fd::BorrowedFd<'_>,
    boundary: usize,
    component: &str,
    digest: &str,
    hooks: &mut (
        impl FnMut(usize) -> rustix::io::Result<()>,
        impl FnMut(usize) -> rustix::io::Result<()>,
        impl FnMut(usize) -> rustix::io::Result<()>,
    ),
    retain_created_lineage: &mut bool,
) -> rustix::io::Result<(rustix::fd::OwnedFd, rustix::fs::Stat, bool)> {
    use rustix::fs::{self, AtFlags, Mode, OFlags};

    let parent_stat = fs::fstat(parent)?;
    validate_directory(&parent_stat, None)?;
    let pending = read_directory_creation_journal(lock.journal_fd())?;
    *retain_created_lineage = pending.is_some();
    let pending_matches = pending
        .as_ref()
        .is_some_and(|pending| pending.matches(&parent_stat, component));
    let existing = match fs::statat(parent, component, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Some(stat),
        Err(error) if error == rustix::io::Errno::NOENT => None,
        Err(error) => return Err(error),
    };
    let (created, before, authorization) = if let Some(existing) = existing {
        let authorization = existing_directory_authorization(
            pending.as_ref(),
            pending_matches,
            boundary,
            digest,
            &existing,
        )?;
        (false, existing, authorization)
    } else {
        if pending.is_some() && !pending_matches {
            return Err(rustix::io::Errno::PERM);
        }
        let intent = if let Some(pending) = pending.as_ref() {
            match &pending.phase {
                DirectoryCreationPhase::Intent => pending.clone(),
                DirectoryCreationPhase::Created { .. } => return Err(rustix::io::Errno::PERM),
            }
        } else {
            let intent = PendingDirectoryCreation::new(&parent_stat, component);
            *retain_created_lineage = true;
            (hooks.0)(boundary)?;
            write_directory_creation_journal(lock.journal_fd(), &intent)?;
            intent
        };
        let mkdir_result = (hooks.1)(boundary)
            .and_then(|()| fs::mkdirat(parent, component, Mode::from_raw_mode(0o700)));
        if let Err(error) = mkdir_result {
            // The failing mkdir did not prove that the name is absent. Only a
            // descriptor-relative no-follow absence check can revoke its
            // intent. Otherwise the journaled parent and all of its newly
            // created ancestors must survive for a fail-closed retry.
            match fs::statat(parent, component, AtFlags::SYMLINK_NOFOLLOW) {
                Err(probe_error) if probe_error == rustix::io::Errno::NOENT => {
                    clear_directory_creation_journal(lock.journal_fd())?;
                    *retain_created_lineage = false;
                }
                Ok(_) | Err(_) => {}
            }
            return Err(error);
        }
        let child = fs::statat(parent, component, AtFlags::SYMLINK_NOFOLLOW)?;
        validate_directory(&child, None)?;
        let created = intent.created(&child);
        advance_directory_creation_journal(lock.journal_fd(), &created)?;
        (hooks.2)(boundary)?;
        (true, child, true)
    };
    validate_directory(&before, None)?;
    let mode = Mode::from_raw_mode(before.st_mode).as_raw_mode();
    let recoverable = !created && mode != 0o700;
    if recoverable && !authorization {
        return Err(rustix::io::Errno::PERM);
    }
    let created_identity = if created || recoverable {
        // The durable journal authorizes only this parent/name pair. The
        // no-follow stat/chmod/open/fstat sequence binds normalization to one
        // identity. A same-user swap-and-restore between checks remains outside
        // the local filesystem threat model; an observable replacement fails.
        fs::chmodat(
            parent,
            component,
            Mode::from_raw_mode(0o700),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        Some(before)
    } else if authorization {
        Some(before)
    } else {
        None
    };
    let child = fs::openat(
        parent,
        component,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    if created {
        fs::fchmod(&child, Mode::from_raw_mode(0o700))?;
    }
    let stat = fs::fstat(&child)?;
    validate_directory(&stat, created_identity.as_ref())?;
    if (created || recoverable) && Mode::from_raw_mode(stat.st_mode).as_raw_mode() != 0o700 {
        return Err(rustix::io::Errno::PERM);
    }
    if authorization || created {
        // The created phase binds recovery to this exact child. Make the
        // child metadata and its containing entry durable before revoking the
        // only authorization for recovery.
        rustix::fs::fsync(&child)?;
        rustix::fs::fsync(parent)?;
        clear_directory_creation_journal(lock.journal_fd())?;
        *retain_created_lineage = false;
    }
    Ok((child, stat, created || recoverable || authorization))
}

#[cfg(target_os = "macos")]
fn existing_directory_authorization(
    pending: Option<&PendingDirectoryCreation>,
    pending_matches: bool,
    boundary: usize,
    digest: &str,
    existing: &rustix::fs::Stat,
) -> rustix::io::Result<bool> {
    // A pending record may be carried across an existing fixed-lineage
    // ancestor, but it cannot authorize that ancestor. Validate it before
    // continuing so recovery never turns the journal into a general
    // traversal capability.
    validate_directory(existing, None)?;
    if pending_matches {
        return authorize_existing_directory(pending, existing);
    }
    if pending.is_some_and(|pending| {
        !pending_targets_later_fixed_component(boundary, &pending.component, digest)
    }) {
        return Err(rustix::io::Errno::PERM);
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
fn pending_targets_later_fixed_component(
    boundary: usize,
    pending_component: &str,
    digest: &str,
) -> bool {
    let target_boundary = match pending_component {
        "profiles" => Some(0),
        "default" => Some(1),
        "accounts" => Some(2),
        component if component == digest => Some(3),
        _ => None,
    };
    target_boundary.is_some_and(|target_boundary| target_boundary > boundary)
}

#[cfg(target_os = "macos")]
fn validate_directory(
    stat: &rustix::fs::Stat,
    expected: Option<&rustix::fs::Stat>,
) -> rustix::io::Result<()> {
    use rustix::fs::{FileType, Mode};
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).as_raw_mode() & 0o7077 != 0
        || expected.is_some_and(|old| !same_identity(old, stat))
    {
        return Err(rustix::io::Errno::PERM);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_established_directory(
    stat: &rustix::fs::Stat,
    expected: &rustix::fs::Stat,
) -> rustix::io::Result<()> {
    use rustix::fs::Mode;

    validate_directory(stat, Some(expected))?;
    if Mode::from_raw_mode(stat.st_mode).as_raw_mode() != 0o700 {
        return Err(rustix::io::Errno::PERM);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn same_identity(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

/// Internal fixed production App Group container implementation.
#[derive(Debug)]
struct ProductionContainerLocator {
    group: &'static str,
}
impl ProductionContainerLocator {
    fn new() -> Result<Self, ProfileStorageError> {
        Ok(Self {
            group: configured_profile_group(option_env!("TERSA_MACOS_APP_GROUP"))?,
        })
    }
}

fn configured_group(group: Option<&'static str>) -> Result<&'static str, KeyStorageError> {
    group
        .filter(|value| !value.is_empty())
        .ok_or(KeyStorageError::Unavailable)
}

fn configured_profile_group(
    group: Option<&'static str>,
) -> Result<&'static str, ProfileStorageError> {
    group
        .filter(|value| !value.is_empty())
        .ok_or(ProfileStorageError::Unavailable)
}
impl ContainerLocator for ProductionContainerLocator {
    fn container(&self) -> Result<PathBuf, ProfileStorageError> {
        macos_container::lookup(self.group)
    }
}

#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    clippy::borrow_as_ptr,
    reason = "Security.framework and Core Foundation expose this add-only Keychain contract only through audited C FFI."
)]
mod macos_keychain {
    use super::{AddResult, KeyStorageError, SecretKey};
    use core_foundation::array::CFArray;
    use core_foundation::base::{
        CFEqual, CFIndexConvertible, CFRange, CFType, CFTypeRef, TCFType, kCFAllocatorDefault,
        kCFAllocatorNull,
    };
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::{CFData, CFDataCreateWithBytesNoCopy, CFDataGetBytes};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework_sys::{access_control, base, item, keychain_item, random};
    use std::ffi::c_void;

    // security-framework-sys 2.17.0 omits only this stable dictionary-key
    // symbol. All other Security constants come from the audited sys crate.
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecAttrAccessible: CFStringRef;
    }

    macro_rules! security_string {
        ($symbol:path) => {
            // SAFETY: Every accepted symbol is an immutable process-lifetime
            // Security.framework CFString constant.
            static_string(unsafe { $symbol })
        };
    }

    pub(super) fn copy(group: &str) -> Result<Option<SecretKey>, KeyStorageError> {
        let query = record_dictionary(group, None, true);
        let mut raw: CFTypeRef = std::ptr::null();
        // SAFETY: The retained query dictionary is valid for the synchronous
        // call and `raw` is a writable out-parameter initialized to null.
        let status =
            unsafe { keychain_item::SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw) };
        if status == base::errSecItemNotFound {
            return Ok(None);
        }
        if status != base::errSecSuccess || raw.is_null() {
            return Err(KeyStorageError::OperationFailed);
        }
        // SAFETY: A successful SecItemCopyMatching result follows the Core
        // Foundation create rule and is non-null as checked above.
        let result = unsafe { CFType::wrap_under_create_rule(raw) };
        decode_copy_result(result, group).map(Some)
    }
    pub(super) fn random() -> Result<SecretKey, KeyStorageError> {
        let mut key = SecretKey::zeroed();
        // SAFETY: The secret output owns exactly 32 writable bytes for the
        // duration of the synchronous Security.framework call.
        let status = unsafe {
            random::SecRandomCopyBytes(
                random::kSecRandomDefault,
                key.as_bytes().len(),
                key.as_mut_bytes().as_mut_ptr().cast::<c_void>(),
            )
        };
        if status == 0 {
            Ok(key)
        } else {
            Err(KeyStorageError::OperationFailed)
        }
    }
    pub(super) fn add(group: &str, candidate: &SecretKey) -> Result<AddResult, KeyStorageError> {
        let status = add_no_copy(group, candidate)?;
        match status {
            base::errSecSuccess => Ok(AddResult::Added),
            base::errSecDuplicateItem => Ok(AddResult::Duplicate),
            _ => Err(KeyStorageError::OperationFailed),
        }
    }

    fn record_dictionary(
        group: &str,
        data: Option<&CFData>,
        returning: bool,
    ) -> CFDictionary<CFType, CFType> {
        record_dictionary_with_optional_attributes(
            group,
            data,
            returning,
            Some(security_string!(item::kSecClassGenericPassword)),
            None,
        )
    }

    fn add_no_copy(group: &str, candidate: &SecretKey) -> Result<i32, KeyStorageError> {
        // SAFETY: This function constructs the borrowing CFData and dictionary,
        // performs the synchronous SecItemAdd call, and drops both before its
        // borrow of `candidate` can end. No object containing the no-copy
        // pointer is returned. kCFAllocatorNull never frees Rust-owned bytes.
        let data_ref = unsafe {
            CFDataCreateWithBytesNoCopy(
                kCFAllocatorDefault,
                candidate.as_bytes().as_ptr(),
                candidate.as_bytes().len().to_CFIndex(),
                kCFAllocatorNull,
            )
        };
        if data_ref.is_null() {
            return Err(KeyStorageError::OperationFailed);
        }
        // SAFETY: CFDataCreateWithBytesNoCopy returned a non-null +1 object.
        let data = unsafe { CFData::wrap_under_create_rule(data_ref) };
        let attributes = record_dictionary(group, Some(&data), false);
        // SAFETY: `attributes`, `data`, and `candidate` are live throughout
        // this synchronous call. The no-copy values are dropped before this
        // function returns, so the raw pointer cannot escape this scope.
        Ok(unsafe {
            keychain_item::SecItemAdd(attributes.as_concrete_TypeRef(), std::ptr::null_mut())
        })
    }

    fn record_dictionary_with_optional_attributes(
        group: &str,
        data: Option<&CFData>,
        returning: bool,
        class: Option<CFType>,
        synchronizable: Option<CFType>,
    ) -> CFDictionary<CFType, CFType> {
        let service = CFString::new(super::SERVICE);
        let account = CFString::new(super::ACCOUNT);
        let group = CFString::new(group);
        let accessible_key = security_string!(kSecAttrAccessible);
        let accessible =
            security_string!(access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
        let data_protection_key = security_string!(item::kSecUseDataProtectionKeychain);
        let pairs = vec![
            (security_string!(item::kSecAttrService), service.as_CFType()),
            (security_string!(item::kSecAttrAccount), account.as_CFType()),
            (
                security_string!(item::kSecAttrAccessGroup),
                group.as_CFType(),
            ),
            (accessible_key, accessible.as_CFType()),
            (data_protection_key, CFBoolean::true_value().as_CFType()),
        ];
        let mut pairs = pairs;
        if let Some(class) = class {
            pairs.push((security_string!(item::kSecClass), class));
        }
        if let Some(synchronizable) = synchronizable {
            pairs.push((
                security_string!(item::kSecAttrSynchronizable),
                synchronizable,
            ));
        }
        if returning {
            pairs.extend([
                (
                    security_string!(item::kSecReturnData),
                    CFBoolean::true_value().as_CFType(),
                ),
                (
                    security_string!(item::kSecReturnAttributes),
                    CFBoolean::true_value().as_CFType(),
                ),
                (
                    security_string!(item::kSecMatchLimit),
                    CFNumber::from(2).as_CFType(),
                ),
            ]);
        }
        if let Some(data) = data {
            pairs.push((security_string!(item::kSecValueData), data.as_CFType()));
        }
        CFDictionary::from_CFType_pairs(&pairs)
    }

    fn static_string(raw: CFStringRef) -> CFType {
        // SAFETY: Callers pass immutable process-lifetime Core Foundation
        // string constants, so wrapping under the get rule is correct.
        unsafe { CFString::wrap_under_get_rule(raw).into_CFType() }
    }

    fn decode_copy_result(result: CFType, group: &str) -> Result<SecretKey, KeyStorageError> {
        let array = result
            .downcast_into::<CFArray>()
            .ok_or(KeyStorageError::Invalid)?;
        if array.len() != 1 {
            return Err(KeyStorageError::Invalid);
        }
        let raw = array.get_all_values()[0];
        // SAFETY: `raw` is retained by `array` for the duration of this decode.
        let dictionary = unsafe { CFType::wrap_under_get_rule(raw) }
            .downcast_into::<CFDictionary>()
            .ok_or(KeyStorageError::Invalid)?;
        decode_record(&dictionary, group)
    }

    fn decode_record(dictionary: &CFDictionary, group: &str) -> Result<SecretKey, KeyStorageError> {
        let service = CFString::new(super::SERVICE);
        let account = CFString::new(super::ACCOUNT);
        let group = CFString::new(group);
        let required = [
            (security_string!(item::kSecAttrService), service.as_CFType()),
            (security_string!(item::kSecAttrAccount), account.as_CFType()),
            (
                security_string!(item::kSecAttrAccessGroup),
                group.as_CFType(),
            ),
            (
                security_string!(kSecAttrAccessible),
                security_string!(access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            ),
        ];
        for (key, value) in required {
            let actual = dictionary
                .find(key.as_CFTypeRef())
                .ok_or(KeyStorageError::Invalid)?;
            // SAFETY: Both arguments are live Core Foundation objects.
            if unsafe { CFEqual(*actual, value.as_CFTypeRef()) } == 0 {
                return Err(KeyStorageError::Invalid);
            }
        }
        validate_optional_attribute(
            dictionary,
            &security_string!(item::kSecClass),
            &security_string!(item::kSecClassGenericPassword),
        )?;
        validate_optional_attribute(
            dictionary,
            &security_string!(item::kSecAttrSynchronizable),
            &CFBoolean::false_value().as_CFType(),
        )?;
        let data = dictionary
            .find(security_string!(item::kSecValueData).as_CFTypeRef())
            .ok_or(KeyStorageError::Invalid)?;
        // SAFETY: The dictionary retains its non-null values while borrowed.
        let data = unsafe { data.as_ref() };
        let data = data.ok_or(KeyStorageError::Invalid)?;
        // SAFETY: The value remains retained by `dictionary` during decode.
        let data = unsafe { CFType::wrap_under_get_rule(data) }
            .downcast_into::<CFData>()
            .ok_or(KeyStorageError::Invalid)?;
        if data.len() != 32 {
            return Err(KeyStorageError::Invalid);
        }
        let mut bytes = SecretKey::zeroed();
        // SAFETY: The validated source range is exactly 32 bytes and `bytes`
        // owns exactly 32 writable bytes. CFDataGetBytes performs the sole
        // copy directly into the zeroizing destination.
        unsafe {
            CFDataGetBytes(
                data.as_concrete_TypeRef(),
                CFRange::init(0, 32),
                bytes.as_mut_bytes().as_mut_ptr(),
            );
        }
        Ok(bytes)
    }

    fn validate_optional_attribute(
        dictionary: &CFDictionary,
        key: &CFType,
        expected: &CFType,
    ) -> Result<(), KeyStorageError> {
        let Some(actual) = dictionary.find(key.as_CFTypeRef()) else {
            return Ok(());
        };
        // SAFETY: Both arguments are live Core Foundation objects.
        if unsafe { CFEqual(*actual, expected.as_CFTypeRef()) } == 0 {
            return Err(KeyStorageError::Invalid);
        }
        Ok(())
    }

    #[cfg(test)]
    #[expect(
        clippy::unwrap_used,
        reason = "Focused Core Foundation boundary tests fail immediately when a required fixture value is absent."
    )]
    mod tests {
        use super::*;

        fn assert_dictionary_value(
            dictionary: &CFDictionary<CFType, CFType>,
            key: &CFType,
            expected: &CFType,
        ) {
            let actual = dictionary.find(key.as_CFTypeRef()).unwrap();
            // SAFETY: The dictionary value and expected fixture are live Core
            // Foundation objects for the duration of this assertion.
            let equal = unsafe { CFEqual(actual.as_CFTypeRef(), expected.as_CFTypeRef()) };
            assert_ne!(equal, 0);
        }

        fn fixture_record(
            group: &str,
            data: Option<&[u8]>,
            class: Option<CFType>,
            synchronizable: Option<CFType>,
        ) -> CFDictionary<CFType, CFType> {
            let data = data.map(CFData::from_buffer);
            record_dictionary_with_optional_attributes(
                group,
                data.as_ref(),
                false,
                class,
                synchronizable,
            )
        }

        fn exact_fixture_record(group: &str, data: Option<&[u8]>) -> CFDictionary<CFType, CFType> {
            fixture_record(
                group,
                data,
                Some(security_string!(item::kSecClassGenericPassword)),
                Some(CFBoolean::false_value().as_CFType()),
            )
        }

        #[test]
        fn copy_query_omits_synchronizable_and_fixes_data_protection_group_and_limit() {
            let group = "TEAM.app.tersa.shared";
            let query = record_dictionary(group, None, true);
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecAttrAccessGroup),
                &CFString::new(group).as_CFType(),
            );
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecUseDataProtectionKeychain),
                &CFBoolean::true_value().as_CFType(),
            );
            assert!(
                query
                    .find(security_string!(item::kSecAttrSynchronizable).as_CFTypeRef())
                    .is_none()
            );
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecMatchLimit),
                &CFNumber::from(2).as_CFType(),
            );
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecReturnData),
                &CFBoolean::true_value().as_CFType(),
            );
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecReturnAttributes),
                &CFBoolean::true_value().as_CFType(),
            );
        }

        #[test]
        fn add_dictionary_omits_synchronizable_and_uses_data_protection_keychain() {
            let data = CFData::from_buffer(&[7; 32]);
            let dictionary = record_dictionary("TEAM.app.tersa.shared", Some(&data), false);
            assert!(
                dictionary
                    .find(security_string!(item::kSecAttrSynchronizable).as_CFTypeRef())
                    .is_none()
            );
            assert_dictionary_value(
                &dictionary,
                &security_string!(item::kSecUseDataProtectionKeychain),
                &CFBoolean::true_value().as_CFType(),
            );
            assert_dictionary_value(
                &dictionary,
                &security_string!(item::kSecValueData),
                &CFData::from_buffer(&[7; 32]).as_CFType(),
            );
        }

        #[test]
        fn copy_decoder_accepts_one_exact_record_and_rejects_ambiguous_or_malformed_results() {
            let group = "TEAM.app.tersa.shared";
            let record = exact_fixture_record(group, Some(&[7; 32]));
            let one = CFArray::from_CFTypes(&[record.as_CFType()]);
            assert_eq!(
                *decode_copy_result(one.as_CFType(), group)
                    .unwrap()
                    .as_bytes(),
                [7; 32]
            );

            let first = exact_fixture_record(group, Some(&[7; 32]));
            let second = exact_fixture_record(group, Some(&[8; 32]));
            let duplicate = CFArray::from_CFTypes(&[first.as_CFType(), second.as_CFType()]);
            assert_eq!(
                decode_copy_result(duplicate.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );
            assert_eq!(
                decode_copy_result(CFString::new("not-an-array").as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );
        }

        #[test]
        fn copy_decoder_rejects_wrong_attributes_and_secret_lengths() {
            let group = "TEAM.app.tersa.shared";
            let wrong_group = exact_fixture_record("OTHER.app.tersa.shared", Some(&[7; 32]));
            let wrong_group = CFArray::from_CFTypes(&[wrong_group.as_CFType()]);
            assert_eq!(
                decode_copy_result(wrong_group.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );

            let short = exact_fixture_record(group, Some(&[7; 31]));
            let short = CFArray::from_CFTypes(&[short.as_CFType()]);
            assert_eq!(
                decode_copy_result(short.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );

            let missing_data = exact_fixture_record(group, None);
            let missing_data = CFArray::from_CFTypes(&[missing_data.as_CFType()]);
            assert_eq!(
                decode_copy_result(missing_data.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );
        }

        #[test]
        fn copy_decoder_allows_omitted_class_and_synchronizable_but_rejects_mismatch() {
            let group = "TEAM.app.tersa.shared";
            let omitted = fixture_record(group, Some(&[7; 32]), None, None);
            let omitted = CFArray::from_CFTypes(&[omitted.as_CFType()]);
            assert_eq!(
                *decode_copy_result(omitted.as_CFType(), group)
                    .unwrap()
                    .as_bytes(),
                [7; 32]
            );

            let wrong_class = fixture_record(
                group,
                Some(&[7; 32]),
                Some(CFString::new("wrong-class").as_CFType()),
                None,
            );
            let wrong_class = CFArray::from_CFTypes(&[wrong_class.as_CFType()]);
            assert_eq!(
                decode_copy_result(wrong_class.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );

            let wrong_sync = fixture_record(
                group,
                Some(&[7; 32]),
                None,
                Some(CFBoolean::true_value().as_CFType()),
            );
            let wrong_sync = CFArray::from_CFTypes(&[wrong_sync.as_CFType()]);
            assert_eq!(
                decode_copy_result(wrong_sync.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );
        }
    }
}
#[cfg(not(target_os = "macos"))]
mod macos_keychain {
    use super::{AddResult, KeyStorageError, SecretKey};
    pub(super) fn copy(_: &str) -> Result<Option<SecretKey>, KeyStorageError> {
        Err(KeyStorageError::Unavailable)
    }
    pub(super) fn random() -> Result<SecretKey, KeyStorageError> {
        Err(KeyStorageError::Unavailable)
    }
    pub(super) fn add(_: &str, _: &SecretKey) -> Result<AddResult, KeyStorageError> {
        Err(KeyStorageError::Unavailable)
    }
}
#[cfg(target_os = "macos")]
mod macos_container {
    use super::ProfileStorageError;
    use objc2_foundation::{NSFileManager, NSString};
    use std::path::PathBuf;
    pub(super) fn lookup(group: &str) -> Result<PathBuf, ProfileStorageError> {
        let group = NSString::from_str(group);
        let url = NSFileManager::defaultManager()
            .containerURLForSecurityApplicationGroupIdentifier(&group)
            .ok_or(ProfileStorageError::Unavailable)?;
        if !url.isFileURL() {
            return Err(ProfileStorageError::Unavailable);
        }
        let path = url.path().ok_or(ProfileStorageError::Unavailable)?;
        Ok(PathBuf::from(path.to_string()))
    }
}
#[cfg(not(target_os = "macos"))]
mod macos_container {
    use super::ProfileStorageError;
    use std::path::PathBuf;
    pub(super) fn lookup(_: &str) -> Result<PathBuf, ProfileStorageError> {
        Err(ProfileStorageError::Unavailable)
    }
}

#[cfg(test)]
#[expect(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    reason = "Test fixtures use bounded indices and fail immediately on poisoned locks or unexpected results."
)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use std::process::{Command, Stdio};
    #[cfg(target_os = "macos")]
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    #[cfg(target_os = "macos")]
    use std::thread;

    #[cfg(target_os = "macos")]
    static PROFILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn account_id() -> AccountId {
        AccountId::new("acct-test-1").unwrap()
    }

    struct FakeLocator(Result<PathBuf, ProfileStorageError>);
    impl ContainerLocator for FakeLocator {
        fn container(&self) -> Result<PathBuf, ProfileStorageError> {
            self.0.clone()
        }
    }

    #[cfg(target_os = "macos")]
    struct RetrievalOnlyFake {
        result: Result<Option<[u8; 32]>, KeyStorageError>,
        copies: AtomicUsize,
    }

    #[cfg(target_os = "macos")]
    impl RootKeyRetriever for RetrievalOnlyFake {
        fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError> {
            self.copies.fetch_add(1, Ordering::SeqCst);
            self.result.map(|value| value.map(SecretKey::new))
        }
    }

    #[cfg(target_os = "macos")]
    struct TestProfile {
        container: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl TestProfile {
        fn new(name: &str) -> Self {
            let sequence = PROFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let container = std::env::temp_dir().join(format!(
                "tersa-keychain-composition-{name}-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir_all(&container).unwrap();
            Self { container }
        }

        fn locator(&self) -> FakeLocator {
            FakeLocator(Ok(self.container.clone()))
        }

        fn database_path(&self, account: &AccountId) -> PathBuf {
            let path = account_database_path(&self.locator(), account).unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            path
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for TestProfile {
        fn drop(&mut self) {
            let _ignored = std::fs::remove_dir_all(&self.container);
        }
    }

    #[cfg(target_os = "macos")]
    struct BootstrapFixture {
        path: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl BootstrapFixture {
        fn new(name: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;

            let sequence = PROFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "tersa-keychain-bootstrap-{name}-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        fn open(&self) -> rustix::fd::OwnedFd {
            rustix::fs::openat(
                rustix::fs::CWD,
                &self.path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .unwrap()
        }

        fn create_directory(&self, relative: &str) {
            use std::os::unix::fs::PermissionsExt;

            let path = self.path.join(relative);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for BootstrapFixture {
        fn drop(&mut self) {
            let _ignored = std::fs::remove_dir_all(&self.path);
        }
    }

    #[derive(Default)]
    struct Fake {
        item: Mutex<Option<[u8; 32]>>,
        random: Mutex<[u8; 32]>,
        calls: Mutex<Vec<&'static str>>,
        duplicate_on_add: bool,
        zeroized_before_reread: Mutex<bool>,
    }
    impl RootKeyRetriever for Fake {
        fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError> {
            self.calls.lock().unwrap().push("copy");
            Ok(self.item.lock().unwrap().map(SecretKey::new))
        }
    }

    impl RootKeyBackend for Fake {
        fn random_key(&self) -> Result<SecretKey, KeyStorageError> {
            self.calls.lock().unwrap().push("random");
            Ok(SecretKey::new(*self.random.lock().unwrap()))
        }
        fn add(&self, c: &SecretKey) -> Result<AddResult, KeyStorageError> {
            self.calls.lock().unwrap().push("add");
            let mut item = self.item.lock().unwrap();
            if self.duplicate_on_add {
                *item = Some([9; 32]);
                Ok(AddResult::Duplicate)
            } else if item.is_some() {
                Ok(AddResult::Duplicate)
            } else {
                *item = Some(*c.as_bytes());
                Ok(AddResult::Added)
            }
        }
        fn candidate_zeroized_before_reread(&self, candidate: &SecretKey) {
            assert_eq!(candidate.as_bytes(), &[0; 32]);
            *self.zeroized_before_reread.lock().unwrap() = true;
            self.calls.lock().unwrap().push("zeroized");
        }
    }

    #[cfg(target_os = "macos")]
    struct SharedFileBackend {
        path: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl SharedFileBackend {
        fn new(container: &Path) -> Self {
            Self {
                path: container.join("test-installation-root"),
            }
        }
    }

    #[cfg(target_os = "macos")]
    impl RootKeyRetriever for SharedFileBackend {
        fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError> {
            match std::fs::read(&self.path) {
                Ok(bytes) => {
                    let key: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_bytes| KeyStorageError::Invalid)?;
                    Ok(Some(SecretKey::new(key)))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(_error) => Err(KeyStorageError::OperationFailed),
            }
        }
    }

    #[cfg(target_os = "macos")]
    impl RootKeyBackend for SharedFileBackend {
        fn random_key(&self) -> Result<SecretKey, KeyStorageError> {
            Ok(SecretKey::new([7; 32]))
        }

        fn add(&self, candidate: &SecretKey) -> Result<AddResult, KeyStorageError> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&self.path)
            {
                Ok(mut file) => {
                    file.write_all(candidate.as_bytes())
                        .and_then(|()| file.sync_all())
                        .map_err(|_error| KeyStorageError::OperationFailed)?;
                    Ok(AddResult::Added)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    Ok(AddResult::Duplicate)
                }
                Err(_error) => Err(KeyStorageError::OperationFailed),
            }
        }
    }

    #[cfg(target_os = "macos")]
    struct ProvisionFailureBackend;

    #[cfg(target_os = "macos")]
    impl RootKeyRetriever for ProvisionFailureBackend {
        fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError> {
            Ok(None)
        }
    }

    #[cfg(target_os = "macos")]
    impl RootKeyBackend for ProvisionFailureBackend {
        fn random_key(&self) -> Result<SecretKey, KeyStorageError> {
            Err(KeyStorageError::OperationFailed)
        }

        fn add(&self, _candidate: &SecretKey) -> Result<AddResult, KeyStorageError> {
            Err(KeyStorageError::OperationFailed)
        }
    }

    #[derive(Clone)]
    struct ConcurrentFake {
        item: Arc<Mutex<Option<[u8; 32]>>>,
        first_copy: Arc<AtomicBool>,
        initial_copy_barrier: Arc<Barrier>,
        candidate: [u8; 32],
    }

    impl RootKeyRetriever for ConcurrentFake {
        fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError> {
            if !self.first_copy.swap(true, Ordering::SeqCst) {
                let snapshot = *self.item.lock().unwrap();
                self.initial_copy_barrier.wait();
                return Ok(snapshot.map(SecretKey::new));
            }
            Ok(self.item.lock().unwrap().map(SecretKey::new))
        }
    }

    impl RootKeyBackend for ConcurrentFake {
        fn random_key(&self) -> Result<SecretKey, KeyStorageError> {
            Ok(SecretKey::new(self.candidate))
        }

        fn add(&self, candidate: &SecretKey) -> Result<AddResult, KeyStorageError> {
            let mut item = self.item.lock().unwrap();
            if item.is_some() {
                Ok(AddResult::Duplicate)
            } else {
                *item = Some(*candidate.as_bytes());
                Ok(AddResult::Added)
            }
        }
    }

    #[test]
    fn bootstrap_input_validation_is_closed_and_state_free() {
        assert_eq!(
            validate_bootstrap_account_bytes(true, b"valid-account"),
            Err(ProductBootstrapStatus::InvalidExecutionContext)
        );
        for invalid in [b"".as_slice(), b"has space".as_slice(), &[0xff][..]] {
            assert_eq!(
                validate_bootstrap_account_bytes(false, invalid),
                Err(ProductBootstrapStatus::InvalidAccountIdentifier)
            );
        }
        assert_eq!(
            validate_bootstrap_account_bytes(false, b"valid-account")
                .unwrap()
                .as_str(),
            "valid-account"
        );
        assert_eq!(
            format!("{:?}", ProductBootstrapStatus::Unavailable),
            "ProductBootstrapStatus([REDACTED])"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bootstrap_orchestration_provisions_and_orders_store_open() {
        let account = account_id();
        let ready = BootstrapFixture::new("orchestration-ready");
        let existing = Fake::default();
        *existing.item.lock().unwrap() = Some([7; 32]);
        let opened_path = Arc::new(Mutex::new(None));
        let opened_path_for_call = Arc::clone(&opened_path);
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account,
                &existing,
                &FakeLocator(Ok(ready.path.clone())),
                Instant::now() + Duration::from_secs(1),
                move |_account, path, _key| {
                    assert!(path.parent().unwrap().is_dir());
                    *opened_path_for_call.lock().unwrap() = Some(path);
                    Ok(())
                },
            ),
            ProductBootstrapStatus::Ready
        );
        assert_eq!(*existing.calls.lock().unwrap(), vec!["copy"]);
        assert_eq!(
            opened_path
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .file_name()
                .unwrap(),
            "mail.sqlite3"
        );

        let provisioned = BootstrapFixture::new("orchestration-provisioned");
        let backend = Fake::default();
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account,
                &backend,
                &FakeLocator(Ok(provisioned.path.clone())),
                Instant::now() + Duration::from_secs(1),
                |_account, _path, _key| Ok(()),
            ),
            ProductBootstrapStatus::Ready
        );
        assert_eq!(
            *backend.calls.lock().unwrap(),
            vec!["copy", "copy", "random", "add", "zeroized", "copy", "copy"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bootstrap_orchestration_fails_closed_at_each_boundary() {
        use std::os::unix::fs::PermissionsExt;

        let account = account_id();
        let occupied = BootstrapFixture::new("orchestration-occupied");
        for directory in [
            "profiles",
            "profiles/default",
            "profiles/default/accounts",
            "profiles/default/accounts/existing",
        ] {
            occupied.create_directory(directory);
        }
        let database = occupied
            .path
            .join("profiles/default/accounts/existing/mail.sqlite3");
        std::fs::write(&database, b"encrypted-state").unwrap();
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account,
                &Fake::default(),
                &FakeLocator(Ok(occupied.path.clone())),
                Instant::now() + Duration::from_secs(1),
                |_account, _path, _key| panic!("store must not open without the root key"),
            ),
            ProductBootstrapStatus::RootMissingWithExistingProfile
        );

        let failed_provision = BootstrapFixture::new("orchestration-provision-failure");
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account,
                &ProvisionFailureBackend,
                &FakeLocator(Ok(failed_provision.path.clone())),
                Instant::now() + Duration::from_secs(1),
                |_account, _path, _key| panic!("store must not open after provision failure"),
            ),
            ProductBootstrapStatus::Unavailable
        );

        let store_failure = BootstrapFixture::new("orchestration-store-failure");
        let backend = Fake::default();
        *backend.item.lock().unwrap() = Some([7; 32]);
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account,
                &backend,
                &FakeLocator(Ok(store_failure.path.clone())),
                Instant::now() + Duration::from_secs(1),
                |_account, _path, _key| Err(()),
            ),
            ProductBootstrapStatus::Unavailable
        );

        let malformed = BootstrapFixture::new("orchestration-malformed");
        std::fs::write(malformed.path.join("profiles"), b"not-a-directory").unwrap();
        let backend = Fake::default();
        *backend.item.lock().unwrap() = Some([7; 32]);
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account,
                &backend,
                &FakeLocator(Ok(malformed.path.clone())),
                Instant::now() + Duration::from_secs(1),
                |_account, _path, _key| panic!("store must not open for malformed layout"),
            ),
            ProductBootstrapStatus::Unavailable
        );

        let unsafe_lock = BootstrapFixture::new("orchestration-unsafe-lock");
        let lock_path = unsafe_lock.path.join(BOOTSTRAP_LOCK);
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account,
                &Fake::default(),
                &FakeLocator(Ok(unsafe_lock.path.clone())),
                Instant::now() + Duration::from_secs(1),
                |_account, _path, _key| panic!("store must not open with an unsafe lock"),
            ),
            ProductBootstrapStatus::Unavailable
        );

        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account,
                &Fake::default(),
                &FakeLocator(Err(ProfileStorageError::Unavailable)),
                Instant::now() + Duration::from_secs(1),
                |_account, _path, _key| panic!("store must not open without a container"),
            ),
            ProductBootstrapStatus::Unavailable
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bootstrap_rejects_directory_mode_drift_after_store_open() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let fixture = BootstrapFixture::new("orchestration-directory-mode-drift");
        let backend = Fake::default();
        *backend.item.lock().unwrap() = Some([7; 32]);
        let store_reached = Arc::new(AtomicBool::new(false));
        let store_reached_for_call = Arc::clone(&store_reached);

        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account_id(),
                &backend,
                &FakeLocator(Ok(fixture.path.clone())),
                Instant::now() + Duration::from_secs(1),
                move |_account, path, _key| {
                    store_reached_for_call.store(true, Ordering::SeqCst);
                    let account_directory = path.parent().unwrap();
                    assert_eq!(
                        std::fs::metadata(account_directory).unwrap().mode() & 0o777,
                        0o700
                    );
                    std::fs::set_permissions(
                        account_directory,
                        std::fs::Permissions::from_mode(0o500),
                    )
                    .unwrap();
                    Ok(())
                },
            ),
            ProductBootstrapStatus::Unavailable
        );
        assert!(store_reached.load(Ordering::SeqCst));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unsafe_empty_skeleton_never_provisions_the_root_key() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = BootstrapFixture::new("orchestration-unsafe-empty-skeleton");
        fixture.create_directory("profiles");
        std::fs::set_permissions(
            fixture.path.join("profiles"),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        let backend = Fake::default();
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account_id(),
                &backend,
                &FakeLocator(Ok(fixture.path.clone())),
                Instant::now() + Duration::from_secs(1),
                |_account, _path, _key| panic!("store must not open for an unsafe skeleton"),
            ),
            ProductBootstrapStatus::Unavailable
        );
        assert_eq!(*backend.calls.lock().unwrap(), vec!["copy"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn profile_preflight_accepts_only_absent_or_empty_fixed_skeletons() {
        use std::os::fd::AsFd;

        let fixture = BootstrapFixture::new("preflight");
        let root = fixture.open();
        assert!(is_empty_profile_skeleton(root.as_fd()).unwrap());
        fixture.create_directory("profiles");
        assert!(is_empty_profile_skeleton(root.as_fd()).unwrap());
        fixture.create_directory("profiles/default");
        assert!(is_empty_profile_skeleton(root.as_fd()).unwrap());
        fixture.create_directory("profiles/default/accounts");
        assert!(is_empty_profile_skeleton(root.as_fd()).unwrap());

        fixture.create_directory("profiles/default/accounts/existing-account");
        // Any account child is existing profile state, even when the directory
        // is empty. Missing-root bootstrap never receives recovery authority.
        assert!(!is_empty_profile_skeleton(root.as_fd()).unwrap());
        std::fs::write(
            fixture
                .path
                .join("profiles/default/accounts/existing-account/mail.sqlite3-wal"),
            b"state",
        )
        .unwrap();
        assert!(!is_empty_profile_skeleton(root.as_fd()).unwrap());
        std::fs::remove_file(
            fixture
                .path
                .join("profiles/default/accounts/existing-account/mail.sqlite3-wal"),
        )
        .unwrap();
        std::fs::write(fixture.path.join("profiles/unexpected"), b"state").unwrap();
        assert!(!is_empty_profile_skeleton(root.as_fd()).unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn profile_preflight_probe_error_is_not_existing_profile_state() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::PermissionsExt;

        let fixture = BootstrapFixture::new("preflight-probe-error");
        let root = fixture.open();
        assert_eq!(
            is_empty_profile_skeleton_with_probe(root.as_fd(), &mut || {
                Err(rustix::io::Errno::IO)
            }),
            Err(rustix::io::Errno::IO)
        );

        fixture.create_directory("profiles");
        std::fs::set_permissions(
            fixture.path.join("profiles"),
            std::fs::Permissions::from_mode(0o2700),
        )
        .unwrap();
        assert_eq!(
            is_empty_profile_skeleton(root.as_fd()),
            Err(rustix::io::Errno::PERM)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn global_lock_normalizes_only_recoverable_modes_and_releases() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        for mode in [0o000, 0o200, 0o400, 0o600] {
            let fixture = BootstrapFixture::new(&format!("lock-{mode:o}"));
            let path = fixture.path.join(BOOTSTRAP_LOCK);
            std::fs::write(&path, b"").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let lock = acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1))
                .unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
            drop(lock);
            assert!(
                acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1)).is_ok()
            );
        }

        let invalid = BootstrapFixture::new("lock-invalid-mode");
        let path = invalid.path.join(BOOTSTRAP_LOCK);
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            acquire_global_lock(&invalid.path, Instant::now() + Duration::from_secs(1)).is_err()
        );
        assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o700);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn existing_global_lock_mode_race_fails_after_descriptor_binding() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let fixture = BootstrapFixture::new("lock-mode-race");
        let path = fixture.path.join(BOOTSTRAP_LOCK);
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let mut raced = false;

        let result = acquire_global_lock_with_hook(
            &fixture.path,
            Instant::now() + Duration::from_secs(1),
            &mut |point| {
                if point == GlobalLockHook::AfterExistingOpen {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
                        .unwrap();
                    raced = true;
                }
                Ok(())
            },
        );

        assert!(raced);
        assert!(matches!(result, Err(error) if error == rustix::io::Errno::PERM));
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(after.dev(), before.dev());
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.mode() & 0o777, 0o400);
    }

    #[cfg(target_os = "macos")]
    fn wait_for_child_checkpoint(child: &mut std::process::Child, checkpoint: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !checkpoint.exists() && Instant::now() < deadline {
            assert!(
                child.try_wait().unwrap().is_none(),
                "helper exited before checkpoint"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(checkpoint.exists(), "helper did not reach checkpoint");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn global_lock_serializes_processes_and_releases_after_kill() {
        let fixture = BootstrapFixture::new("cross-process-lock");
        let checkpoint = fixture.path.join("child-ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::global_lock_holder_child",
                "--ignored",
                "--nocapture",
            ])
            .env("TERSA_BOOTSTRAP_LOCK_CONTAINER", &fixture.path)
            .env("TERSA_BOOTSTRAP_LOCK_READY", &checkpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_child_checkpoint(&mut child, &checkpoint);

        assert!(matches!(
            acquire_global_lock(
                &fixture.path,
                Instant::now() + Duration::from_millis(40)
            ),
            Err(error) if error == rustix::io::Errno::TIMEDOUT
        ));
        let backend = Fake::default();
        *backend.item.lock().unwrap() = Some([7; 32]);
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account_id(),
                &backend,
                &FakeLocator(Ok(fixture.path.clone())),
                Instant::now() + Duration::from_millis(40),
                |_account, _path, _key| Ok(()),
            ),
            ProductBootstrapStatus::BusyOrUnavailable
        );

        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        drop(acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1)).unwrap());
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account_id(),
                &backend,
                &FakeLocator(Ok(fixture.path.clone())),
                Instant::now() + Duration::from_secs(1),
                |_account, _path, _key| Ok(()),
            ),
            ProductBootstrapStatus::Ready
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn complete_injected_bootstrap_serializes_processes_and_preserves_second_state() {
        let fixture = BootstrapFixture::new("cross-process-bootstrap");
        let first_entered = fixture.path.join("first-entered");
        let first_release = fixture.path.join("first-release");
        let second_entered = fixture.path.join("second-entered");
        let executable = std::env::current_exe().unwrap();
        let mut first = Command::new(&executable)
            .args([
                "--exact",
                "tests::injected_bootstrap_child",
                "--ignored",
                "--nocapture",
            ])
            .env("TERSA_BOOTSTRAP_CHILD_CONTAINER", &fixture.path)
            .env("TERSA_BOOTSTRAP_CHILD_ENTERED", &first_entered)
            .env("TERSA_BOOTSTRAP_CHILD_RELEASE", &first_release)
            .env("TERSA_BOOTSTRAP_CHILD_FAIL", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_child_checkpoint(&mut first, &first_entered);
        let mut second = Command::new(&executable)
            .args([
                "--exact",
                "tests::injected_bootstrap_child",
                "--ignored",
                "--nocapture",
            ])
            .env("TERSA_BOOTSTRAP_CHILD_CONTAINER", &fixture.path)
            .env("TERSA_BOOTSTRAP_CHILD_ENTERED", &second_entered)
            .env("TERSA_BOOTSTRAP_CHILD_RELEASE", &first_release)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        assert!(
            !second_entered.exists(),
            "second entered a post-lock stage early"
        );
        std::fs::write(&first_release, b"release").unwrap();
        assert!(first.wait().unwrap().success());
        wait_for_child_checkpoint(&mut second, &second_entered);
        assert!(second.wait().unwrap().success());
        assert!(second_entered.exists());
        assert_eq!(
            std::fs::read(fixture.path.join("test-installation-root")).unwrap(),
            [7; 32]
        );
        let database = fixture
            .path
            .join("profiles/default/accounts")
            .join(hex_digest(&account_id()))
            .join("mail.sqlite3");
        assert!(std::fs::metadata(database).unwrap().len() >= 512);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn concurrent_legacy_lock_normalization_serializes_two_processes() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = BootstrapFixture::new("concurrent-lock-normalization");
        let lock_path = fixture.path.join(BOOTSTRAP_LOCK);
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let checkpoints = [
            fixture.path.join("first-ready"),
            fixture.path.join("second-ready"),
        ];
        let mut children = checkpoints.each_ref().map(|checkpoint| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::global_lock_holder_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_BOOTSTRAP_LOCK_CONTAINER", &fixture.path)
                .env("TERSA_BOOTSTRAP_LOCK_READY", checkpoint)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let first = loop {
            if let Some(index) = checkpoints.iter().position(|path| path.exists()) {
                break index;
            }
            assert!(Instant::now() < deadline, "neither lock contender acquired");
            for child in &mut children {
                assert!(child.try_wait().unwrap().is_none());
            }
            thread::sleep(Duration::from_millis(10));
        };
        let second = 1 - first;
        children[first].kill().unwrap();
        assert!(!children[first].wait().unwrap().success());
        wait_for_child_checkpoint(&mut children[second], &checkpoints[second]);
        children[second].kill().unwrap();
        assert!(!children[second].wait().unwrap().success());
        drop(acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1)).unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn crash_after_lock_creation_recovers_a_zero_mode_residual() {
        use std::os::unix::fs::MetadataExt;

        let fixture = BootstrapFixture::new("lock-create-crash");
        let checkpoint = fixture.path.join("created-after-durable-sync");
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 0777; exec \"$@\"")
            .arg("tersa-lock-crash")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::global_lock_creation_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("TERSA_BOOTSTRAP_LOCK_CONTAINER", &fixture.path)
            .env("TERSA_BOOTSTRAP_LOCK_READY", &checkpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_child_checkpoint(&mut child, &checkpoint);
        let lock_path = fixture.path.join(BOOTSTRAP_LOCK);
        assert_eq!(std::fs::metadata(&lock_path).unwrap().mode() & 0o777, 0o600);
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        drop(acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1)).unwrap());
        assert_eq!(std::fs::metadata(lock_path).unwrap().mode() & 0o777, 0o600);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn restrictive_umasks_normalize_every_created_directory() {
        use std::os::unix::fs::MetadataExt;

        let executable = std::env::current_exe().unwrap();
        for (label, mask) in [("zero", "0777"), ("write", "0577"), ("read", "0377")] {
            let fixture = BootstrapFixture::new(&format!("umask-{label}"));
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; shift; exec \"$@\"")
                .arg("tersa-umask")
                .arg(mask)
                .arg(&executable)
                .args([
                    "--exact",
                    "tests::restrictive_umask_directory_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERSA_BOOTSTRAP_UMASK_CONTAINER", &fixture.path)
                .stdin(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "directory helper failed for umask {mask}");
            let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
            for relative in [
                "profiles",
                "profiles/default",
                "profiles/default/accounts",
                &format!("profiles/default/accounts/{digest}"),
            ] {
                assert_eq!(
                    std::fs::metadata(fixture.path.join(relative))
                        .unwrap()
                        .mode()
                        & 0o777,
                    0o700,
                    "wrong mode for {relative} under umask {mask}"
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn crash_after_directory_mkdir_recovers_only_the_journaled_identity() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let components = [
            "profiles".to_owned(),
            "default".to_owned(),
            "accounts".to_owned(),
            digest.to_owned(),
        ];
        for boundary in 0..=3 {
            crash_and_recover_directory_boundary(boundary, digest, &components);
        }

        let arbitrary = BootstrapFixture::new("arbitrary-zero-mode-directory");
        std::fs::create_dir(arbitrary.path.join("profiles")).unwrap();
        std::fs::set_permissions(
            arbitrary.path.join("profiles"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let arbitrary_lock =
            acquire_global_lock(&arbitrary.path, Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(establish_account_directory(&arbitrary_lock, &arbitrary.path, digest).is_err());
        assert_eq!(
            std::fs::metadata(arbitrary.path.join("profiles"))
                .unwrap()
                .mode()
                & 0o777,
            0o000
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cross_account_leaf_crash_recovery_finishes_before_requested_bootstrap() {
        use std::os::unix::fs::MetadataExt;

        let account_a = AccountId::new("acct-crashed-a").unwrap();
        let account_b = AccountId::new("acct-requested-b").unwrap();
        let digest_a = hex_digest(&account_a);
        let digest_b = hex_digest(&account_b);
        let fixture = BootstrapFixture::new("cross-account-directory-crash");
        std::fs::write(fixture.path.join("test-installation-root"), [7_u8; 32]).unwrap();
        let checkpoint = fixture
            .path
            .join("cross-account-created-before-normalization");
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 0777; exec \"$@\"")
            .arg("tersa-cross-account-directory-crash")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::directory_creation_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("TERSA_BOOTSTRAP_DIRECTORY_CONTAINER", &fixture.path)
            .env("TERSA_BOOTSTRAP_DIRECTORY_READY", &checkpoint)
            .env("TERSA_BOOTSTRAP_DIRECTORY_BOUNDARY", "3")
            .env("TERSA_BOOTSTRAP_DIRECTORY_DIGEST", &digest_a)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_child_checkpoint(&mut child, &checkpoint);
        let crashed_leaf = fixture
            .path
            .join("profiles/default/accounts")
            .join(&digest_a);
        assert_eq!(
            std::fs::metadata(&crashed_leaf).unwrap().mode() & 0o777,
            0o000
        );
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());

        let opened = Arc::new(Mutex::new(Vec::new()));
        let opened_for_call = Arc::clone(&opened);
        let expected_account_b = account_b.clone();
        assert_eq!(
            bootstrap_default_account_with_dependencies(
                &account_b,
                &SharedFileBackend::new(&fixture.path),
                &FakeLocator(Ok(fixture.path.clone())),
                Instant::now() + Duration::from_secs(1),
                move |account, path, _key| {
                    assert_eq!(account, expected_account_b);
                    opened_for_call.lock().unwrap().push(path);
                    Ok(())
                },
            ),
            ProductBootstrapStatus::Ready
        );
        assert_eq!(
            *opened.lock().unwrap(),
            vec![
                fixture
                    .path
                    .join("profiles/default/accounts")
                    .join(&digest_b)
                    .join("mail.sqlite3")
            ]
        );
        for leaf in [&digest_a, &digest_b] {
            assert_eq!(
                std::fs::metadata(fixture.path.join("profiles/default/accounts").join(leaf))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert_eq!(
            std::fs::metadata(fixture.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len(),
            0
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cross_account_leaf_intent_recovery_creates_only_the_journaled_target() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::MetadataExt;

        let account_a = AccountId::new("acct-intent-a").unwrap();
        let account_b = AccountId::new("acct-intent-b").unwrap();
        let digest_a = hex_digest(&account_a);
        let digest_b = hex_digest(&account_b);
        let fixture = BootstrapFixture::new("cross-account-directory-intent");
        fixture.create_directory("profiles");
        fixture.create_directory("profiles/default");
        fixture.create_directory("profiles/default/accounts");
        std::fs::write(fixture.path.join("test-installation-root"), [7_u8; 32]).unwrap();

        let lock =
            acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let accounts = rustix::fs::openat(
            rustix::fs::CWD,
            fixture.path.join("profiles/default/accounts"),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let intent =
            PendingDirectoryCreation::new(&rustix::fs::fstat(accounts.as_fd()).unwrap(), &digest_a);
        write_directory_creation_journal(lock.journal_fd(), &intent).unwrap();
        drop(lock);

        let expected_database = fixture
            .path
            .join("profiles/default/accounts")
            .join(&digest_b)
            .join("mail.sqlite3");
        let expected_account_b = account_b.clone();
        let mut opened = 0;
        let status = bootstrap_default_account_with_dependencies(
            &account_b,
            &SharedFileBackend::new(&fixture.path),
            &FakeLocator(Ok(fixture.path.clone())),
            Instant::now() + Duration::from_secs(1),
            |account, path, _key| {
                opened += 1;
                assert_eq!(account, expected_account_b);
                assert_eq!(path, expected_database);
                Ok(())
            },
        );
        assert_eq!(status, ProductBootstrapStatus::Ready);
        assert_eq!(opened, 1);
        for leaf in [&digest_a, &digest_b] {
            assert_eq!(
                std::fs::metadata(fixture.path.join("profiles/default/accounts").join(leaf))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert_eq!(
            std::fs::metadata(fixture.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len(),
            0
        );
    }

    #[cfg(target_os = "macos")]
    fn crash_and_recover_directory_boundary(
        boundary: usize,
        digest: &str,
        components: &[String; 4],
    ) {
        use std::os::unix::fs::MetadataExt;

        let fixture = BootstrapFixture::new(&format!("directory-create-crash-{boundary}"));
        std::fs::write(fixture.path.join("test-installation-root"), [7_u8; 32]).unwrap();
        let checkpoint = fixture
            .path
            .join(format!("created-before-directory-normalization-{boundary}"));
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 0777; exec \"$@\"")
            .arg("tersa-directory-crash")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::directory_creation_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("TERSA_BOOTSTRAP_DIRECTORY_CONTAINER", &fixture.path)
            .env("TERSA_BOOTSTRAP_DIRECTORY_READY", &checkpoint)
            .env("TERSA_BOOTSTRAP_DIRECTORY_BOUNDARY", boundary.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_child_checkpoint(&mut child, &checkpoint);
        let crashed_component = components[..=boundary]
            .iter()
            .fold(fixture.path.clone(), |path, component| path.join(component));
        assert_eq!(
            std::fs::metadata(&crashed_component).unwrap().mode() & 0o777,
            0o000,
            "boundary {boundary} did not reach its requested mkdir checkpoint"
        );
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());

        let status = bootstrap_default_account_with_dependencies(
            &account_id(),
            &SharedFileBackend::new(&fixture.path),
            &FakeLocator(Ok(fixture.path.clone())),
            Instant::now() + Duration::from_secs(1),
            |_account, database, _key| {
                assert_eq!(
                    database,
                    fixture
                        .path
                        .join("profiles/default/accounts")
                        .join(digest)
                        .join("mail.sqlite3")
                );
                Ok(())
            },
        );
        assert_eq!(
            status,
            ProductBootstrapStatus::Ready,
            "boundary {boundary} did not recover"
        );
        for component_boundary in 0..=3 {
            let directory = components[..=component_boundary]
                .iter()
                .fold(fixture.path.clone(), |path, component| path.join(component));
            assert_eq!(
                std::fs::metadata(directory).unwrap().mode() & 0o777,
                0o700,
                "boundary {boundary} left fixed lineage component {component_boundary} unnormalized"
            );
        }
        assert_eq!(
            std::fs::metadata(fixture.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len(),
            0
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "subprocess helper for the real global bootstrap lock"]
    fn global_lock_holder_child() {
        let Some(container) = std::env::var_os("TERSA_BOOTSTRAP_LOCK_CONTAINER") else {
            return;
        };
        let Some(checkpoint) = std::env::var_os("TERSA_BOOTSTRAP_LOCK_READY") else {
            return;
        };
        let _lock = acquire_global_lock(
            Path::new(&container),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        std::fs::write(checkpoint, b"ready").unwrap();
        loop {
            thread::park();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "subprocess helper for complete injected bootstrap serialization"]
    fn injected_bootstrap_child() {
        let Some(container) = std::env::var_os("TERSA_BOOTSTRAP_CHILD_CONTAINER") else {
            return;
        };
        let Some(entered) = std::env::var_os("TERSA_BOOTSTRAP_CHILD_ENTERED") else {
            return;
        };
        let Some(release) = std::env::var_os("TERSA_BOOTSTRAP_CHILD_RELEASE") else {
            return;
        };
        let fail = std::env::var_os("TERSA_BOOTSTRAP_CHILD_FAIL").is_some();
        let container = PathBuf::from(container);
        let backend = SharedFileBackend::new(&container);
        let status = bootstrap_default_account_with_dependencies(
            &account_id(),
            &backend,
            &FakeLocator(Ok(container)),
            Instant::now() + Duration::from_secs(5),
            |account, path, key| {
                let store =
                    tersa_store_sqlcipher_macos::SqlCipherMailboxStore::open(account, path, key)
                        .map_err(|_error| ())?;
                std::fs::write(&entered, b"entered").unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !Path::new(&release).exists() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(10));
                }
                drop(store);
                if fail { Err(()) } else { Ok(()) }
            },
        );
        assert_eq!(
            status,
            if fail {
                ProductBootstrapStatus::Unavailable
            } else {
                ProductBootstrapStatus::Ready
            }
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "subprocess helper for a crash before lock mode normalization"]
    fn global_lock_creation_crash_child() {
        let Some(container) = std::env::var_os("TERSA_BOOTSTRAP_LOCK_CONTAINER") else {
            return;
        };
        let Some(checkpoint) = std::env::var_os("TERSA_BOOTSTRAP_LOCK_READY") else {
            return;
        };
        let _result = acquire_global_lock_with_hook(
            Path::new(&container),
            Instant::now() + Duration::from_secs(5),
            &mut |point| {
                assert_eq!(point, GlobalLockHook::AfterCreate);
                std::fs::write(&checkpoint, b"created").unwrap();
                loop {
                    thread::park();
                }
            },
        );
        panic!("crash helper must be killed at the checkpoint");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "subprocess helper for process-global umask coverage"]
    fn restrictive_umask_directory_child() {
        let Some(container) = std::env::var_os("TERSA_BOOTSTRAP_UMASK_CONTAINER") else {
            return;
        };
        let container = PathBuf::from(container);
        let lock =
            acquire_global_lock(&container, Instant::now() + Duration::from_secs(5)).unwrap();
        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let established = establish_account_directory(&lock, &container, digest).unwrap();
        established.revalidate().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "subprocess helper for a crash before directory mode normalization"]
    fn directory_creation_crash_child() {
        let Some(container) = std::env::var_os("TERSA_BOOTSTRAP_DIRECTORY_CONTAINER") else {
            return;
        };
        let Some(checkpoint) = std::env::var_os("TERSA_BOOTSTRAP_DIRECTORY_READY") else {
            return;
        };
        let boundary = std::env::var("TERSA_BOOTSTRAP_DIRECTORY_BOUNDARY")
            .ok()
            .and_then(|boundary| boundary.parse::<usize>().ok())
            .filter(|boundary| *boundary <= 3)
            .expect("subprocess crash boundary must be 0 through 3");
        let container = PathBuf::from(container);
        let lock =
            acquire_global_lock(&container, Instant::now() + Duration::from_secs(5)).unwrap();
        let digest = std::env::var("TERSA_BOOTSTRAP_DIRECTORY_DIGEST").unwrap_or_else(|_error| {
            "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47".to_owned()
        });
        let _result = establish_account_directory_with_hooks(
            &lock,
            &container,
            &digest,
            |_boundary| Ok(()),
            |_boundary| Ok(()),
            |observed_boundary| {
                if observed_boundary != boundary {
                    return Ok(());
                }
                std::fs::write(&checkpoint, boundary.to_string()).unwrap();
                loop {
                    thread::park();
                }
            },
            |_boundary| Ok(()),
        );
        panic!("crash helper must be killed at the checkpoint");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bounded_lock_retries_eintr_and_process_mutex_timeout() {
        let mut attempts = 0;
        let result = retry_transient_until(Instant::now() + Duration::from_secs(1), || {
            attempts += 1;
            match attempts {
                1 => Err(rustix::io::Errno::INTR),
                2 => Err(rustix::io::Errno::AGAIN),
                _ => Ok(7),
            }
        });
        assert_eq!(result, Ok(7));
        assert_eq!(attempts, 3);

        let mutex = Mutex::new(());
        let guard = mutex.lock().unwrap();
        assert!(matches!(
            acquire_mutex_until(&mutex, Instant::now() + Duration::from_millis(20)),
            Err(ProcessLockFailure::TimedOut)
        ));
        drop(guard);
        assert!(acquire_mutex_until(&mutex, Instant::now() + Duration::from_secs(1)).is_ok());

        let poisoned = Mutex::new(());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoned.lock().unwrap();
            panic!("poison process mutex fixture");
        }));
        assert!(matches!(
            acquire_mutex_until(&poisoned, Instant::now() + Duration::from_secs(1)),
            Err(ProcessLockFailure::Poisoned)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn directory_establishment_cleans_each_injected_boundary_and_detects_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        for failure_boundary in 0..4 {
            let fixture = BootstrapFixture::new(&format!("directory-failure-{failure_boundary}"));
            let lock = acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1))
                .unwrap();
            let result = establish_account_directory_with_hooks(
                &lock,
                &fixture.path,
                digest,
                |_boundary| Ok(()),
                |_boundary| Ok(()),
                |_boundary| Ok(()),
                |boundary| {
                    if boundary == failure_boundary {
                        Err(rustix::io::Errno::IO)
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err());
            assert!(!fixture.path.join("profiles").exists());
        }

        let fixture = BootstrapFixture::new("directory-replacement");
        let lock =
            acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let mut established = establish_account_directory(&lock, &fixture.path, digest).unwrap();
        established.revalidate().unwrap();
        for snapshot in &established.snapshots {
            assert!(
                rustix::io::fcntl_getfd(&snapshot.parent)
                    .unwrap()
                    .contains(rustix::io::FdFlags::CLOEXEC),
                "retained cleanup descriptors must never survive exec"
            );
        }
        let account = established.path().to_path_buf();
        let moved = account.with_extension("moved");
        std::fs::rename(&account, &moved).unwrap();
        std::fs::create_dir(&account).unwrap();
        std::fs::set_permissions(&account, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(established.revalidate().is_err());
        established.cleanup_before_store_open();
        assert!(account.exists());
        assert!(moved.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn deeper_mkdir_failure_clears_journal_and_retry_converges() {
        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let retry = BootstrapFixture::new("deeper-mkdir-retry");
        let retry_lock =
            acquire_global_lock(&retry.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let failure = establish_account_directory_with_hooks(
            &retry_lock,
            &retry.path,
            digest,
            |_boundary| Ok(()),
            |boundary| {
                if boundary == 2 {
                    assert!(
                        std::fs::metadata(retry.path.join(BOOTSTRAP_LOCK))
                            .unwrap()
                            .len()
                            > 0
                    );
                    Err(rustix::io::Errno::IO)
                } else {
                    Ok(())
                }
            },
            |_boundary| Ok(()),
            |_boundary| Ok(()),
        );
        assert!(matches!(failure, Err(error) if error == rustix::io::Errno::IO));
        assert_eq!(
            std::fs::metadata(retry.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len(),
            0
        );
        assert!(!retry.path.join("profiles").exists());
        let established = establish_account_directory(&retry_lock, &retry.path, digest).unwrap();
        established.revalidate().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn partial_journal_write_retains_created_lineage() {
        use std::io::Write;

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let fixture = BootstrapFixture::new("partial-directory-journal");
        let lock =
            acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let journal_path = fixture.path.join(BOOTSTRAP_LOCK);
        let failure = establish_account_directory_with_hooks(
            &lock,
            &fixture.path,
            digest,
            |boundary| {
                if boundary == 2 {
                    let mut journal = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&journal_path)
                        .unwrap();
                    journal.write_all(b"partial-directory-intent").unwrap();
                    journal.sync_all().unwrap();
                    Err(rustix::io::Errno::IO)
                } else {
                    Ok(())
                }
            },
            |_boundary| Ok(()),
            |_boundary| Ok(()),
            |_boundary| Ok(()),
        );
        assert!(matches!(failure, Err(error) if error == rustix::io::Errno::IO));
        assert_eq!(
            std::fs::read(&journal_path).unwrap(),
            b"partial-directory-intent"
        );
        assert!(fixture.path.join("profiles/default").is_dir());
        assert!(!fixture.path.join("profiles/default/accounts").exists());
        assert!(establish_account_directory(&lock, &fixture.path, digest).is_err());
        assert!(fixture.path.join("profiles/default").is_dir());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn intent_only_journal_retries_an_absent_child_but_preserves_a_later_foreign_child() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let retry = BootstrapFixture::new("intent-only-retry");
        let retry_lock =
            acquire_global_lock(&retry.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let retry_parent = retry.open();
        let retry_intent = PendingDirectoryCreation::new(
            &rustix::fs::fstat(retry_parent.as_fd()).unwrap(),
            "profiles",
        );
        write_directory_creation_journal(retry_lock.journal_fd(), &retry_intent).unwrap();
        let established = establish_account_directory(&retry_lock, &retry.path, digest).unwrap();
        established.revalidate().unwrap();
        assert_eq!(
            std::fs::metadata(retry.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len(),
            0
        );

        let foreign = BootstrapFixture::new("intent-only-foreign-child");
        let foreign_lock =
            acquire_global_lock(&foreign.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let foreign_parent = foreign.open();
        let foreign_intent = PendingDirectoryCreation::new(
            &rustix::fs::fstat(foreign_parent.as_fd()).unwrap(),
            "profiles",
        );
        write_directory_creation_journal(foreign_lock.journal_fd(), &foreign_intent).unwrap();
        let profiles = foreign.path.join("profiles");
        std::fs::create_dir(&profiles).unwrap();
        std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(establish_account_directory(&foreign_lock, &foreign.path, digest).is_err());
        assert_eq!(std::fs::metadata(&profiles).unwrap().mode() & 0o777, 0o000);
        assert!(
            std::fs::metadata(foreign.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len()
                > 0
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pending_journal_rejects_non_lineage_and_wrong_target_after_existing_ancestor() {
        use std::os::fd::AsFd;

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        for (name, mutate) in [
            (
                "non-lineage",
                Box::new(|pending: &mut PendingDirectoryCreation| {
                    pending.component = "foreign".to_owned();
                }) as Box<dyn Fn(&mut PendingDirectoryCreation)>,
            ),
            (
                "wrong-target",
                Box::new(|pending: &mut PendingDirectoryCreation| {
                    pending.parent_inode = pending.parent_inode.saturating_add(1);
                }),
            ),
        ] {
            let fixture = BootstrapFixture::new(&format!("pending-journal-{name}"));
            fixture.create_directory("profiles");
            let lock = acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1))
                .unwrap();
            let parent = fixture.open();
            let mut pending = PendingDirectoryCreation::new(
                &rustix::fs::fstat(parent.as_fd()).unwrap(),
                "profiles",
            );
            mutate(&mut pending);
            write_directory_creation_journal(lock.journal_fd(), &pending).unwrap();

            assert!(establish_account_directory(&lock, &fixture.path, digest).is_err());
            assert!(fixture.path.join("profiles").is_dir());
            assert!(
                std::fs::metadata(fixture.path.join(BOOTSTRAP_LOCK))
                    .unwrap()
                    .len()
                    > 0
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn created_identity_phase_retries_only_the_created_child_and_clears_after_sync() {
        use std::os::unix::fs::MetadataExt;

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let fixture = BootstrapFixture::new("created-identity-retry");
        let lock =
            acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let failure = establish_account_directory_with_hooks(
            &lock,
            &fixture.path,
            digest,
            |_boundary| Ok(()),
            |_boundary| Ok(()),
            |boundary| {
                if boundary == 0 {
                    Err(rustix::io::Errno::IO)
                } else {
                    Ok(())
                }
            },
            |_boundary| Ok(()),
        );
        assert!(matches!(failure, Err(error) if error == rustix::io::Errno::IO));
        let pending = read_directory_creation_journal(lock.journal_fd())
            .unwrap()
            .unwrap();
        let profiles = fixture.path.join("profiles");
        let profile_stat = std::fs::metadata(&profiles).unwrap();
        assert!(matches!(
            pending.phase,
            DirectoryCreationPhase::Created {
                child_device,
                child_inode
            } if u64::try_from(child_device).is_ok_and(|device| device == profile_stat.dev())
                && child_inode == profile_stat.ino()
        ));
        let established = establish_account_directory(&lock, &fixture.path, digest).unwrap();
        established.revalidate().unwrap();
        assert_eq!(
            std::fs::metadata(fixture.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len(),
            0
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn created_identity_phase_rejects_replacement_and_partial_transition() {
        use std::os::fd::AsFd;

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let replaced = BootstrapFixture::new("created-identity-replacement");
        let replaced_lock =
            acquire_global_lock(&replaced.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let replaced_parent = replaced.open();
        let intent = PendingDirectoryCreation::new(
            &rustix::fs::fstat(replaced_parent.as_fd()).unwrap(),
            "profiles",
        );
        write_directory_creation_journal(replaced_lock.journal_fd(), &intent).unwrap();
        let profiles = replaced.path.join("profiles");
        std::fs::create_dir(&profiles).unwrap();
        let created_stat = rustix::fs::statat(
            replaced_parent.as_fd(),
            "profiles",
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        advance_directory_creation_journal(
            replaced_lock.journal_fd(),
            &intent.created(&created_stat),
        )
        .unwrap();
        let displaced = replaced.path.join("displaced-profiles");
        std::fs::rename(&profiles, &displaced).unwrap();
        std::fs::create_dir(&profiles).unwrap();
        assert!(establish_account_directory(&replaced_lock, &replaced.path, digest).is_err());
        assert!(profiles.is_dir());
        assert!(displaced.is_dir());
        assert!(
            std::fs::metadata(replaced.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len()
                > 0
        );

        let partial = BootstrapFixture::new("partial-created-transition");
        let partial_lock =
            acquire_global_lock(&partial.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let partial_parent = partial.open();
        let intent = PendingDirectoryCreation::new(
            &rustix::fs::fstat(partial_parent.as_fd()).unwrap(),
            "profiles",
        );
        write_directory_creation_journal(partial_lock.journal_fd(), &intent).unwrap();
        let profiles = partial.path.join("profiles");
        std::fs::create_dir(&profiles).unwrap();
        let created_stat = rustix::fs::statat(
            partial_parent.as_fd(),
            "profiles",
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        let created = intent.created(&created_stat).encode();
        let interrupted = created.len() / 2;
        rustix::io::pwrite(
            partial_lock.journal_fd(),
            &created.as_bytes()[..interrupted],
            0,
        )
        .unwrap();
        rustix::fs::fsync(partial_lock.journal_fd()).unwrap();
        assert!(read_directory_creation_journal(partial_lock.journal_fd()).is_err());
        assert!(establish_account_directory(&partial_lock, &partial.path, digest).is_err());
        assert!(profiles.is_dir());
        assert!(
            std::fs::metadata(partial.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len()
                > 0
        );
    }

    #[cfg(target_os = "macos")]
    fn prepare_cross_account_recovery(name: &str) -> (BootstrapFixture, super::BootstrapLock) {
        let fixture = BootstrapFixture::new(name);
        fixture.create_directory("profiles");
        fixture.create_directory("profiles/default");
        fixture.create_directory("profiles/default/accounts");
        let lock =
            acquire_global_lock(&fixture.path, Instant::now() + Duration::from_secs(1)).unwrap();
        (fixture, lock)
    }

    #[cfg(target_os = "macos")]
    fn open_cross_account_directory(fixture: &BootstrapFixture) -> rustix::fd::OwnedFd {
        rustix::fs::openat(
            rustix::fs::CWD,
            fixture.path.join("profiles/default/accounts"),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .unwrap()
    }

    #[cfg(target_os = "macos")]
    fn write_created_cross_account_journal(
        fixture: &BootstrapFixture,
        lock: &super::BootstrapLock,
        leaf: &str,
    ) -> PathBuf {
        use std::os::fd::AsFd;

        let accounts = open_cross_account_directory(fixture);
        let intent = PendingDirectoryCreation::new(&rustix::fs::fstat(&accounts).unwrap(), leaf);
        write_directory_creation_journal(lock.journal_fd(), &intent).unwrap();
        rustix::fs::mkdirat(
            accounts.as_fd(),
            leaf,
            rustix::fs::Mode::from_raw_mode(0o700),
        )
        .unwrap();
        let created = rustix::fs::statat(
            accounts.as_fd(),
            leaf,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        advance_directory_creation_journal(lock.journal_fd(), &intent.created(&created)).unwrap();
        fixture.path.join("profiles/default/accounts").join(leaf)
    }

    #[cfg(target_os = "macos")]
    fn assert_cross_account_journal_preserved(fixture: &BootstrapFixture) {
        assert!(
            std::fs::metadata(fixture.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len()
                > 0
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cross_account_leaf_recovery_rejects_noncanonical_parent_and_intent_states() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::PermissionsExt;

        let leaf = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let (noncanonical, noncanonical_lock) =
            prepare_cross_account_recovery("cross-account-noncanonical-leaf");
        let encoded = format!(
            "{DIRECTORY_CREATION_JOURNAL_MAGIC}\ncreated\n1\n1\n{}\n1\n1\n",
            leaf.to_ascii_uppercase()
        );
        rustix::io::pwrite(noncanonical_lock.journal_fd(), encoded.as_bytes(), 0).unwrap();
        rustix::fs::fsync(noncanonical_lock.journal_fd()).unwrap();
        assert!(recover_pending_directory_creation(&noncanonical_lock).is_err());
        assert_cross_account_journal_preserved(&noncanonical);

        let (wrong_parent, wrong_parent_lock) =
            prepare_cross_account_recovery("cross-account-wrong-parent");
        let accounts = open_cross_account_directory(&wrong_parent);
        let mut pending =
            PendingDirectoryCreation::new(&rustix::fs::fstat(accounts.as_fd()).unwrap(), leaf);
        pending.parent_inode = pending.parent_inode.saturating_add(1);
        write_directory_creation_journal(wrong_parent_lock.journal_fd(), &pending).unwrap();
        assert!(recover_pending_directory_creation(&wrong_parent_lock).is_err());
        assert_cross_account_journal_preserved(&wrong_parent);

        let (intent_existing, intent_lock) =
            prepare_cross_account_recovery("cross-account-intent-existing");
        let accounts = open_cross_account_directory(&intent_existing);
        let intent =
            PendingDirectoryCreation::new(&rustix::fs::fstat(accounts.as_fd()).unwrap(), leaf);
        write_directory_creation_journal(intent_lock.journal_fd(), &intent).unwrap();
        let target = intent_existing
            .path
            .join("profiles/default/accounts")
            .join(leaf);
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(recover_pending_directory_creation(&intent_lock).is_err());
        assert_cross_account_journal_preserved(&intent_existing);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cross_account_leaf_recovery_rejects_replacement_and_wrong_mode_lineage() {
        use std::os::unix::fs::PermissionsExt;

        let leaf = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let (replaced, replaced_lock) =
            prepare_cross_account_recovery("cross-account-created-replacement");
        let target = write_created_cross_account_journal(&replaced, &replaced_lock, leaf);
        std::fs::rename(&target, target.with_extension("replaced")).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(recover_pending_directory_creation(&replaced_lock).is_err());
        assert_cross_account_journal_preserved(&replaced);

        let (wrong_mode, wrong_mode_lock) =
            prepare_cross_account_recovery("cross-account-wrong-lineage-mode");
        write_created_cross_account_journal(&wrong_mode, &wrong_mode_lock, leaf);
        std::fs::set_permissions(
            wrong_mode.path.join("profiles"),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        assert!(recover_pending_directory_creation(&wrong_mode_lock).is_err());
        assert_cross_account_journal_preserved(&wrong_mode);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mkdir_eexist_preserves_intent_and_retry_rejects_raced_object() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let raced = BootstrapFixture::new("deeper-mkdir-race");
        let raced_lock =
            acquire_global_lock(&raced.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let raced_accounts = raced.path.join("profiles/default/accounts");
        let failure = establish_account_directory_with_hooks(
            &raced_lock,
            &raced.path,
            digest,
            |_boundary| Ok(()),
            |boundary| {
                if boundary == 2 {
                    std::fs::create_dir(&raced_accounts).unwrap();
                    std::fs::set_permissions(
                        &raced_accounts,
                        std::fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                    Err(rustix::io::Errno::EXIST)
                } else {
                    Ok(())
                }
            },
            |_boundary| Ok(()),
            |_boundary| Ok(()),
        );
        assert!(failure.is_err());
        assert_eq!(
            std::fs::metadata(&raced_accounts).unwrap().mode() & 0o777,
            0o700
        );
        assert!(raced.path.join("profiles/default").exists());
        assert!(
            std::fs::metadata(raced.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len()
                > 0
        );
        assert!(establish_account_directory(&raced_lock, &raced.path, digest).is_err());
        assert_eq!(
            std::fs::metadata(&raced_accounts).unwrap().mode() & 0o777,
            0o700
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn uncertain_mkdir_failure_retains_journaled_lineage() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let uncertain = BootstrapFixture::new("deeper-mkdir-uncertain-object");
        let uncertain_lock =
            acquire_global_lock(&uncertain.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let uncertain_accounts = uncertain.path.join("profiles/default/accounts");
        let failure = establish_account_directory_with_hooks(
            &uncertain_lock,
            &uncertain.path,
            digest,
            |_boundary| Ok(()),
            |boundary| {
                if boundary == 2 {
                    std::fs::create_dir(&uncertain_accounts).unwrap();
                    std::fs::set_permissions(
                        &uncertain_accounts,
                        std::fs::Permissions::from_mode(0o000),
                    )
                    .unwrap();
                    Err(rustix::io::Errno::IO)
                } else {
                    Ok(())
                }
            },
            |_boundary| Ok(()),
            |_boundary| Ok(()),
        );
        assert!(failure.is_err());
        assert_eq!(
            std::fs::metadata(&uncertain_accounts).unwrap().mode() & 0o777,
            0o000
        );
        assert!(uncertain.path.join("profiles/default").exists());
        assert!(
            std::fs::metadata(uncertain.path.join(BOOTSTRAP_LOCK))
                .unwrap()
                .len()
                > 0
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn replaced_parent_is_not_normalized_or_deleted_after_mkdir_failure() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let digest = "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47";
        let replaced = BootstrapFixture::new("deeper-mkdir-parent-replacement");
        let replaced_lock =
            acquire_global_lock(&replaced.path, Instant::now() + Duration::from_secs(1)).unwrap();
        let original = replaced.path.join("profiles/default");
        let displaced = replaced.path.join("profiles/displaced");
        let failure = establish_account_directory_with_hooks(
            &replaced_lock,
            &replaced.path,
            digest,
            |_boundary| Ok(()),
            |boundary| {
                if boundary == 2 {
                    std::fs::rename(&original, &displaced).unwrap();
                    std::fs::create_dir(&original).unwrap();
                    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o711))
                        .unwrap();
                    Err(rustix::io::Errno::IO)
                } else {
                    Ok(())
                }
            },
            |_boundary| Ok(()),
            |_boundary| Ok(()),
        );
        assert!(failure.is_err());
        assert_eq!(std::fs::metadata(&original).unwrap().mode() & 0o777, 0o711);
        assert!(displaced.exists());
    }

    #[test]
    fn hkdf_known_answer_and_info() {
        let root = SecretKey::new(core::array::from_fn(|i| i as u8));
        assert_eq!(
            hex_encode(&framed_info(&account_id(), DATABASE_PURPOSE).unwrap()),
            "74657273612e6170702f6d61636f732f686b64662d7368613235362f7631000b616363742d746573742d31001d73716c6369706865722f6163636f756e742d64617461626173652f7631"
        );
        assert_eq!(
            hex_encode(
                derive_account_key(
                    &root,
                    &account_id(),
                    AccountKeyPurpose::SqlCipherAccountDatabaseV1
                )
                .unwrap()
                .as_bytes()
            ),
            "c822b72b2aaad045b983307618e4ea580ab2c1a219dcf379b229661f68f8c148"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn retrieval_only_composition_opens_a_persistent_wal_fixture() {
        let root = [7; 32];
        let account = account_id();
        let profile = TestProfile::new("success");
        let derived = derive_account_key(
            &SecretKey::new(root),
            &account,
            AccountKeyPurpose::SqlCipherAccountDatabaseV1,
        )
        .unwrap();
        let store = tersa_store_sqlcipher_macos::SqlCipherMailboxStore::open(
            account.clone(),
            profile.database_path(&account),
            derived.into_database_key(),
        )
        .unwrap();
        drop(store);
        let retriever = RetrievalOnlyFake {
            result: Ok(Some(root)),
            copies: AtomicUsize::new(0),
        };

        let reader = open_read_only_mailbox(&retriever, &profile.locator(), &account).unwrap();

        assert_eq!(retriever.copies.load(Ordering::SeqCst), 1);
        assert_eq!(format!("{reader:?}"), "SqlCipherMailboxReader([REDACTED])");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn retrieval_only_composition_maps_missing_root_without_provisioning() {
        let retriever = RetrievalOnlyFake {
            result: Ok(None),
            copies: AtomicUsize::new(0),
        };
        let profile = TestProfile::new("missing-root");

        assert!(matches!(
            open_read_only_mailbox(&retriever, &profile.locator(), &account_id()),
            Err(ReadOnlyMailboxOpenError::KeyAccess)
        ));
        assert_eq!(retriever.copies.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn retrieval_only_composition_maps_storage_and_corruption() {
        let account = account_id();
        let root = [7; 32];
        let retriever = RetrievalOnlyFake {
            result: Ok(Some(root)),
            copies: AtomicUsize::new(0),
        };
        let absent = TestProfile::new("absent");
        assert!(matches!(
            open_read_only_mailbox(&retriever, &absent.locator(), &account),
            Err(ReadOnlyMailboxOpenError::ProfileUnavailable)
        ));

        let profile = TestProfile::new("wrong-root");
        let derived = derive_account_key(
            &SecretKey::new(root),
            &account,
            AccountKeyPurpose::SqlCipherAccountDatabaseV1,
        )
        .unwrap();
        let store = tersa_store_sqlcipher_macos::SqlCipherMailboxStore::open(
            account.clone(),
            profile.database_path(&account),
            derived.into_database_key(),
        )
        .unwrap();
        drop(store);
        let wrong = RetrievalOnlyFake {
            result: Ok(Some([8; 32])),
            copies: AtomicUsize::new(0),
        };
        assert!(matches!(
            open_read_only_mailbox(&wrong, &profile.locator(), &account),
            Err(ReadOnlyMailboxOpenError::MailboxCorrupted)
        ));
    }
    #[test]
    fn existing_item_skips_rng_and_add() {
        let fake = Fake::default();
        *fake.item.lock().unwrap() = Some([7; 32]);
        assert_eq!(
            provision_installation_root_key(&fake),
            Ok(ProvisionOutcome::Existing)
        );
        assert_eq!(*fake.calls.lock().unwrap(), vec!["copy"]);
    }
    #[test]
    fn success_rereads_after_add() {
        let fake = Fake::default();
        assert_eq!(
            provision_installation_root_key(&fake),
            Ok(ProvisionOutcome::Created)
        );
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec!["copy", "random", "add", "zeroized", "copy"]
        );
    }
    #[test]
    fn duplicate_loser_zeroizes_before_reread() {
        let fake = Fake {
            duplicate_on_add: true,
            ..Fake::default()
        };
        assert_eq!(
            provision_installation_root_key(&fake),
            Ok(ProvisionOutcome::Existing)
        );
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec!["copy", "random", "add", "zeroized", "copy"]
        );
        assert!(*fake.zeroized_before_reread.lock().unwrap());
    }

    #[test]
    fn simultaneous_provisioners_converge_on_one_stored_winner() {
        let item = Arc::new(Mutex::new(None));
        let barrier = Arc::new(Barrier::new(2));
        let first = ConcurrentFake {
            item: Arc::clone(&item),
            first_copy: Arc::new(AtomicBool::new(false)),
            initial_copy_barrier: Arc::clone(&barrier),
            candidate: [1; 32],
        };
        let second = ConcurrentFake {
            item: Arc::clone(&item),
            first_copy: Arc::new(AtomicBool::new(false)),
            initial_copy_barrier: barrier,
            candidate: [2; 32],
        };

        let first = std::thread::spawn(move || provision_installation_root_key(&first));
        let second = std::thread::spawn(move || provision_installation_root_key(&second));
        let mut outcomes = [
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        ];
        outcomes.sort_by_key(|outcome| match outcome {
            ProvisionOutcome::Created => 0,
            ProvisionOutcome::Existing => 1,
        });

        assert_eq!(
            outcomes,
            [ProvisionOutcome::Created, ProvisionOutcome::Existing]
        );
        let winner = *item.lock().unwrap();
        assert!(winner == Some([1; 32]) || winner == Some([2; 32]));
    }
    #[test]
    fn digest_is_fixed() {
        assert_eq!(
            hex_digest(&account_id()),
            "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47"
        );
    }
    #[test]
    fn fixed_profile_layout_requires_an_existing_readable_directory() {
        let directory = std::env::temp_dir();
        let locator = FakeLocator(Ok(directory.clone()));
        assert_eq!(
            account_database_path(&locator, &account_id()).unwrap(),
            directory.join("profiles/default/accounts/1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47/mail.sqlite3")
        );
        let missing = FakeLocator(Ok(directory.join("tersa-missing-container")));
        assert_eq!(
            account_database_path(&missing, &account_id()),
            Err(ProfileStorageError::Unavailable)
        );
        let no_config = FakeLocator(Err(ProfileStorageError::Unavailable));
        assert_eq!(
            account_database_path(&no_config, &account_id()),
            Err(ProfileStorageError::Unavailable)
        );
    }

    #[test]
    fn profile_locator_rejects_non_directories_without_fallback() {
        let path = std::env::temp_dir().join(format!(
            "tersa-keychain-profile-file-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"not a container").unwrap();
        let locator = FakeLocator(Ok(path.clone()));
        assert_eq!(
            account_database_path(&locator, &account_id()),
            Err(ProfileStorageError::Unavailable)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn profile_locator_rejects_unreadable_directories() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "tersa-keychain-unreadable-container-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let locator = FakeLocator(Ok(path.clone()));
        assert_eq!(
            account_database_path(&locator, &account_id()),
            Err(ProfileStorageError::Unavailable)
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir(path).unwrap();
    }

    #[test]
    fn production_group_configuration_fails_closed() {
        assert_eq!(configured_group(None), Err(KeyStorageError::Unavailable));
        assert_eq!(
            configured_group(Some("")),
            Err(KeyStorageError::Unavailable)
        );
        assert_eq!(
            configured_group(Some("TEAM.app.tersa.shared")),
            Ok("TEAM.app.tersa.shared")
        );
        assert_eq!(
            configured_profile_group(None),
            Err(ProfileStorageError::Unavailable)
        );
        assert_eq!(
            configured_profile_group(Some("TEAM.app.tersa.shared")),
            Ok("TEAM.app.tersa.shared")
        );
    }
    #[test]
    fn framing_rejects_oversized_purpose_and_separates_segments() {
        assert_eq!(
            framed_info(&account_id(), &vec![0; usize::from(u16::MAX) + 1]),
            Err(KeyStorageError::Invalid)
        );
        let account_ab = AccountId::new("ab").unwrap();
        let account_a = AccountId::new("a").unwrap();
        assert_ne!(
            framed_info(&account_ab, b"c").unwrap(),
            framed_info(&account_a, b"bc").unwrap()
        );
    }
    #[test]
    fn errors_and_capabilities_are_redacted() {
        assert_eq!(
            format!("{:?}", KeyStorageError::Invalid),
            "KeyStorageError([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", ProfileStorageError::Invalid),
            "ProfileStorageError([REDACTED])"
        );
        for error in [
            ReadOnlyMailboxOpenError::KeyAccess,
            ReadOnlyMailboxOpenError::ProfileUnavailable,
            ReadOnlyMailboxOpenError::MailboxCorrupted,
        ] {
            assert_eq!(format!("{error:?}"), "ReadOnlyMailboxOpenError([REDACTED])");
            assert_eq!(error.to_string(), "read-only mailbox opening failed");
        }
        let secret = SecretKey::new([0xAB; 32]);
        let formatted = format!("{secret:?}");
        assert_eq!(formatted, "SecretKey([REDACTED])");
        assert!(!formatted.contains("171"));
        assert!(!formatted.contains("AB"));
        assert!(!formatted.contains("ab"));
    }
}
