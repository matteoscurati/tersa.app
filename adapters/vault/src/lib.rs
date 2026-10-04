// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Root-key vault (ADR 0031).
//!
//! The installation root key lives in exactly one slot:
//!
//! - the OS keyring (macOS login Keychain, Linux Secret Service), holding
//!   either the plain key or, when a passphrase is set, the wrapped key; or
//! - an owner-only file under the data directory, which only ever holds the
//!   passphrase-wrapped key. It is the fallback when no keyring is reachable,
//!   for example on a headless Linux machine.
//!
//! Slot contents are tagged: `P` followed by the 32-byte key, or `W`
//! followed by a [`tersa_keys::wrap_root_key`] blob.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use keyring_core::api::CredentialStore;
use keyring_core::{Entry, Error as KeyringError};
use tersa_keys::{
    KEY_LEN, KdfParams, KeyError, RootKey, WRAPPED_LEN, unwrap_root_key, wrap_root_key,
};
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "tersa";
const KEYRING_USER: &str = "installation-root-key-v1";
const FILE_NAME: &str = "root-key.wrapped";
const TAG_PLAIN: u8 = b'P';
const TAG_WRAPPED: u8 = b'W';
const SLOT_LIMIT: u64 = 4096;

/// Vault failures. Variants carry no secret material.
#[derive(Debug)]
#[non_exhaustive]
pub enum VaultError {
    /// No keyring is reachable and the file fallback was not selected.
    KeyringUnavailable,
    /// The keyring refused access (locked, denied, or a platform failure).
    Keyring,
    /// Reading or writing the key file failed.
    File(io::ErrorKind),
    /// The key file is not an owner-only regular file.
    UnsafeFile,
    /// The slot content is not a recognized format.
    Malformed,
    /// The slot is wrapped and no passphrase was supplied.
    PassphraseRequired,
    /// The passphrase is wrong or the stored key was altered.
    WrongPassphrase,
    /// The file slot only accepts a passphrase-wrapped key.
    PassphraseMandatory,
    /// A root key already exists; refusing to overwrite it.
    AlreadyInitialized,
    /// No root key exists yet.
    NotInitialized,
    /// Key generation or wrapping failed.
    Key(KeyError),
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyringUnavailable => formatter.write_str("no system keyring is available"),
            Self::Keyring => formatter.write_str("the system keyring refused access"),
            Self::File(kind) => write!(formatter, "the key file could not be accessed ({kind})"),
            Self::UnsafeFile => {
                formatter.write_str("the key file must be an owner-only regular file")
            }
            Self::Malformed => formatter.write_str("the stored key is malformed"),
            Self::PassphraseRequired => formatter.write_str("a passphrase is required"),
            Self::WrongPassphrase => formatter.write_str("wrong passphrase or altered key"),
            Self::PassphraseMandatory => {
                formatter.write_str("a passphrase is required when no keyring is available")
            }
            Self::AlreadyInitialized => formatter.write_str("a root key already exists"),
            Self::NotInitialized => formatter.write_str("no root key exists yet"),
            Self::Key(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<KeyError> for VaultError {
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::WrongPassphraseOrTampered => Self::WrongPassphrase,
            KeyError::Malformed => Self::Malformed,
            other => Self::Key(other),
        }
    }
}

/// Where the root key is kept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotKind {
    /// The OS keyring.
    Keyring,
    /// The passphrase-only key file.
    File,
}

/// Which slot to use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BackendChoice {
    /// The keyring when reachable, otherwise the key file.
    #[default]
    Auto,
    /// Only the keyring.
    Keyring,
    /// Only the key file.
    File,
}

/// What the vault currently holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultState {
    /// No root key exists.
    Empty,
    /// The root key opens without a passphrase.
    Unprotected,
    /// The root key needs a passphrase.
    PassphraseProtected,
}

/// One opaque secret slot.
pub trait SecretSlot: fmt::Debug + Send + Sync {
    /// Reads the slot, or `None` when it is empty.
    ///
    /// # Errors
    ///
    /// Returns a [`VaultError`] when the backend fails.
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError>;
    /// Replaces the slot content.
    ///
    /// # Errors
    ///
    /// Returns a [`VaultError`] when the backend fails.
    fn write(&self, content: &[u8]) -> Result<(), VaultError>;
    /// Removes the slot content; succeeds when already empty.
    ///
    /// # Errors
    ///
    /// Returns a [`VaultError`] when the backend fails.
    fn erase(&self) -> Result<(), VaultError>;
}

/// The root-key vault.
#[derive(Debug)]
pub struct Vault {
    slot: Box<dyn SecretSlot>,
    kind: SlotKind,
    params: KdfParams,
}

impl Vault {
    /// Opens the vault for `data_dir` according to `choice`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::KeyringUnavailable`] when `choice` is
    /// [`BackendChoice::Keyring`] and no keyring is reachable.
    pub fn open(data_dir: &Path, choice: BackendChoice) -> Result<Self, VaultError> {
        let keyring = || system_store().map(|store| KeyringSlot { store });
        let file = || FileSlot {
            path: data_dir.join(FILE_NAME),
        };
        let (slot, kind): (Box<dyn SecretSlot>, SlotKind) = match choice {
            BackendChoice::Keyring => (Box::new(keyring()?), SlotKind::Keyring),
            BackendChoice::File => (Box::new(file()), SlotKind::File),
            BackendChoice::Auto => match keyring() {
                Ok(slot) => (Box::new(slot), SlotKind::Keyring),
                Err(_unavailable) => (Box::new(file()), SlotKind::File),
            },
        };
        Ok(Self::with_slot(slot, kind, KdfParams::DEFAULT))
    }

    /// Builds a vault over an explicit slot.
    #[must_use]
    pub fn with_slot(slot: Box<dyn SecretSlot>, kind: SlotKind, params: KdfParams) -> Self {
        Self { slot, kind, params }
    }

    /// The slot this vault uses.
    #[must_use]
    pub fn kind(&self) -> SlotKind {
        self.kind
    }

    /// Reports what the vault holds without needing a passphrase.
    ///
    /// # Errors
    ///
    /// Returns a [`VaultError`] when the slot cannot be read or is malformed.
    pub fn state(&self) -> Result<VaultState, VaultError> {
        match self.slot.read()? {
            None => Ok(VaultState::Empty),
            Some(content) => match content.first() {
                Some(&TAG_PLAIN) if content.len() == 1 + KEY_LEN => Ok(VaultState::Unprotected),
                Some(&TAG_WRAPPED) if content.len() == 1 + WRAPPED_LEN => {
                    Ok(VaultState::PassphraseProtected)
                }
                _ => Err(VaultError::Malformed),
            },
        }
    }

    /// Creates and stores a new root key.
    ///
    /// With a passphrase the key is stored wrapped; the file slot requires
    /// one. Refuses to replace an existing key.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::AlreadyInitialized`],
    /// [`VaultError::PassphraseMandatory`], or a backend error.
    pub fn create(&self, passphrase: Option<&[u8]>) -> Result<RootKey, VaultError> {
        if self.state()? != VaultState::Empty {
            return Err(VaultError::AlreadyInitialized);
        }
        if self.kind == SlotKind::File && passphrase.is_none() {
            return Err(VaultError::PassphraseMandatory);
        }
        let root = RootKey::generate()?;
        self.slot.write(&self.encode(&root, passphrase)?)?;
        // Read back so a backend that silently dropped the write is caught now.
        let reopened = self.unlock(passphrase)?;
        if reopened.expose_for_storage() != root.expose_for_storage() {
            return Err(VaultError::Malformed);
        }
        Ok(root)
    }

    /// Returns the stored root key.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::NotInitialized`],
    /// [`VaultError::PassphraseRequired`], [`VaultError::WrongPassphrase`],
    /// or a backend error.
    pub fn unlock(&self, passphrase: Option<&[u8]>) -> Result<RootKey, VaultError> {
        let content = self.slot.read()?.ok_or(VaultError::NotInitialized)?;
        match (content.split_first(), passphrase) {
            (Some((&TAG_PLAIN, key)), _) if key.len() == KEY_LEN => {
                let mut bytes = Zeroizing::new([0_u8; KEY_LEN]);
                bytes.copy_from_slice(key);
                Ok(RootKey::from_bytes(bytes))
            }
            (Some((&TAG_WRAPPED, _wrapped)), None) => Err(VaultError::PassphraseRequired),
            (Some((&TAG_WRAPPED, wrapped)), Some(passphrase)) => {
                Ok(unwrap_root_key(wrapped, passphrase)?)
            }
            _ => Err(VaultError::Malformed),
        }
    }

    /// Re-stores `root` with a new protection, after confirming it matches
    /// the stored key. `None` removes the passphrase (keyring slot only).
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::PassphraseMandatory`] when removing the
    /// passphrase from the file slot, or a backend error.
    pub fn reprotect(&self, root: &RootKey, passphrase: Option<&[u8]>) -> Result<(), VaultError> {
        if self.kind == SlotKind::File && passphrase.is_none() {
            return Err(VaultError::PassphraseMandatory);
        }
        self.slot.write(&self.encode(root, passphrase)?)
    }

    /// Removes the root key. Every encrypted database becomes unreadable.
    ///
    /// # Errors
    ///
    /// Returns a backend error.
    pub fn destroy(&self) -> Result<(), VaultError> {
        self.slot.erase()
    }

    fn encode(
        &self,
        root: &RootKey,
        passphrase: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut content = Zeroizing::new(Vec::with_capacity(1 + WRAPPED_LEN));
        if let Some(passphrase) = passphrase {
            content.push(TAG_WRAPPED);
            content.extend_from_slice(&wrap_root_key(root, passphrase, self.params)?);
        } else {
            content.push(TAG_PLAIN);
            content.extend_from_slice(root.expose_for_storage());
        }
        Ok(content)
    }
}

#[cfg(target_os = "macos")]
fn system_store() -> Result<Arc<CredentialStore>, VaultError> {
    let store: Arc<CredentialStore> = apple_native_keyring_store::keychain::Store::new()
        .map_err(|_error| VaultError::KeyringUnavailable)?;
    Ok(store)
}

#[cfg(target_os = "linux")]
fn system_store() -> Result<Arc<CredentialStore>, VaultError> {
    let store: Arc<CredentialStore> = zbus_secret_service_keyring_store::Store::new()
        .map_err(|_error| VaultError::KeyringUnavailable)?;
    Ok(store)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn system_store() -> Result<Arc<CredentialStore>, VaultError> {
    Err(VaultError::KeyringUnavailable)
}

/// The OS keyring slot.
struct KeyringSlot {
    store: Arc<CredentialStore>,
}

impl fmt::Debug for KeyringSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyringSlot")
    }
}

impl KeyringSlot {
    fn entry(&self) -> Result<Entry, VaultError> {
        self.store
            .build(KEYRING_SERVICE, KEYRING_USER, None)
            .map_err(|_error| VaultError::Keyring)
    }
}

impl SecretSlot for KeyringSlot {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        match self.entry()?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(KeyringError::NoStorageAccess(_)) => Err(VaultError::KeyringUnavailable),
            Err(_error) => Err(VaultError::Keyring),
        }
    }

    fn write(&self, content: &[u8]) -> Result<(), VaultError> {
        self.entry()?
            .set_secret(content)
            .map_err(|_error| VaultError::Keyring)
    }

    fn erase(&self) -> Result<(), VaultError> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(_error) => Err(VaultError::Keyring),
        }
    }
}

/// The owner-only key file slot.
#[derive(Debug)]
pub struct FileSlot {
    path: PathBuf,
}

impl FileSlot {
    /// A file slot at `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn temporary_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".tmp");
        PathBuf::from(name)
    }
}

fn file_error(error: &io::Error) -> VaultError {
    VaultError::File(error.kind())
}

fn require_owner_only(metadata: &fs::Metadata) -> Result<(), VaultError> {
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(VaultError::UnsafeFile);
    }
    Ok(())
}

impl SecretSlot for FileSlot {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(file_error(&error)),
        };
        require_owner_only(&file.metadata().map_err(|error| file_error(&error))?)?;
        let mut content = Zeroizing::new(Vec::new());
        file.take(SLOT_LIMIT)
            .read_to_end(&mut content)
            .map_err(|error| file_error(&error))?;
        Ok(Some(content))
    }

    fn write(&self, content: &[u8]) -> Result<(), VaultError> {
        let content = content.to_vec();
        if content.first() != Some(&TAG_WRAPPED) {
            return Err(VaultError::PassphraseMandatory);
        }
        let parent = self
            .path
            .parent()
            .ok_or(VaultError::File(io::ErrorKind::NotFound))?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| file_error(&error))?;

        let temporary = self.temporary_path();
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(file_error(&error)),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
            .open(&temporary)
            .map_err(|error| file_error(&error))?;
        file.write_all(&content)
            .map_err(|error| file_error(&error))?;
        file.sync_all().map_err(|error| file_error(&error))?;
        drop(file);
        fs::rename(&temporary, &self.path).map_err(|error| file_error(&error))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| file_error(&error))
    }

    fn erase(&self) -> Result<(), VaultError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(file_error(&error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use tersa_keys::KdfParams;
    use zeroize::Zeroizing;

    use super::{FileSlot, SecretSlot, SlotKind, Vault, VaultError, VaultState};

    const TEST_PARAMS: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    #[derive(Debug, Default)]
    struct MemorySlot(Mutex<Option<Vec<u8>>>);

    impl SecretSlot for MemorySlot {
        fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
            Ok(self.0.lock().expect("lock").clone().map(Zeroizing::new))
        }
        fn write(&self, content: &[u8]) -> Result<(), VaultError> {
            *self.0.lock().expect("lock") = Some(content.to_vec());
            Ok(())
        }
        fn erase(&self) -> Result<(), VaultError> {
            *self.0.lock().expect("lock") = None;
            Ok(())
        }
    }

    fn memory_vault() -> Vault {
        Vault::with_slot(Box::<MemorySlot>::default(), SlotKind::Keyring, TEST_PARAMS)
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tersa-vault-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn file_vault(dir: &std::path::Path) -> Vault {
        Vault::with_slot(
            Box::new(FileSlot::new(dir.join("keys").join("root-key.wrapped"))),
            SlotKind::File,
            TEST_PARAMS,
        )
    }

    #[test]
    fn keyring_slot_round_trips_without_passphrase() {
        let vault = memory_vault();
        assert_eq!(vault.state().expect("state"), VaultState::Empty);
        let root = vault.create(None).expect("create");
        assert_eq!(vault.state().expect("state"), VaultState::Unprotected);
        assert_eq!(
            vault.unlock(None).expect("unlock").expose_for_storage(),
            root.expose_for_storage()
        );
        assert!(matches!(
            vault.create(None),
            Err(VaultError::AlreadyInitialized)
        ));
    }

    #[test]
    fn passphrase_protection_requires_the_passphrase() {
        let vault = memory_vault();
        let root = vault.create(Some(b"secret")).expect("create");
        assert_eq!(
            vault.state().expect("state"),
            VaultState::PassphraseProtected
        );
        assert!(matches!(
            vault.unlock(None),
            Err(VaultError::PassphraseRequired)
        ));
        assert!(matches!(
            vault.unlock(Some(b"nope")),
            Err(VaultError::WrongPassphrase)
        ));
        assert_eq!(
            vault
                .unlock(Some(b"secret"))
                .expect("unlock")
                .expose_for_storage(),
            root.expose_for_storage()
        );

        vault.reprotect(&root, None).expect("remove passphrase");
        assert_eq!(vault.state().expect("state"), VaultState::Unprotected);
    }

    #[test]
    fn file_slot_requires_a_passphrase_and_is_owner_only() {
        let dir = temp_dir("file");
        let vault = file_vault(&dir);
        assert!(matches!(
            vault.create(None),
            Err(VaultError::PassphraseMandatory)
        ));
        let root = vault.create(Some(b"secret")).expect("create");
        let path = dir.join("keys").join("root-key.wrapped");
        assert_eq!(
            fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(dir.join("keys"))
                .expect("meta")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(matches!(
            vault.reprotect(&root, None),
            Err(VaultError::PassphraseMandatory)
        ));
        assert_eq!(
            vault
                .unlock(Some(b"secret"))
                .expect("unlock")
                .expose_for_storage(),
            root.expose_for_storage()
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(vault.state(), Err(VaultError::UnsafeFile)));

        vault.destroy().expect("destroy");
        assert!(!path.exists());
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn file_slot_refuses_symlinks() {
        let dir = temp_dir("symlink");
        let target = dir.join("elsewhere");
        fs::write(&target, b"x").expect("write");
        fs::create_dir_all(dir.join("keys")).expect("dir");
        std::os::unix::fs::symlink(&target, dir.join("keys").join("root-key.wrapped"))
            .expect("symlink");
        assert!(matches!(file_vault(&dir).state(), Err(VaultError::File(_))));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn malformed_slots_are_rejected() {
        let vault = memory_vault();
        vault.slot.write(b"Pshort").expect("write");
        assert!(matches!(vault.state(), Err(VaultError::Malformed)));
        assert!(matches!(vault.unlock(None), Err(VaultError::Malformed)));
    }

    /// Exercises the real OS keyring. Run manually: it may show a system
    /// prompt and writes a test item under a separate user name.
    #[test]
    #[ignore = "touches the real OS keyring"]
    fn system_keyring_round_trip() {
        let store = super::system_store().expect("keyring available");
        let entry = store
            .build("tersa-test", "vault-round-trip", None)
            .expect("entry");
        entry.set_secret(b"probe").expect("set");
        assert_eq!(entry.get_secret().expect("get"), b"probe");
        entry.delete_credential().expect("delete");
    }
}
