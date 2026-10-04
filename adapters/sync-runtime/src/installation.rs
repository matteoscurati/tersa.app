// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One unlocked installation: the data directory, the root key, the account
//! registry, and the per-account encrypted stores.
//!
//! Layout under the data directory (all directories `0700`):
//!
//! ```text
//! registry.sqlite3                      (AccountId + dedup tag only)
//! accounts/<sha256(AccountId)>/mail.sqlite3
//! ```

use core::fmt;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tersa_application::identity::{AccountIdentityHasher, HasherError, IdentityHash};
use tersa_application::mailbox::{AccountId, MailboxStoreError};
use tersa_keys::{
    AccountKeyPurpose, InstallationKeyPurpose, KeyError, RootKey, account_identity_hash,
    derive_account_key, derive_installation_key, registry_dedup_tag,
};
use tersa_store_sqlcipher::registry::{MAX_ACCOUNTS, RegistryError, SqlCipherRegistry};
use tersa_store_sqlcipher::{DatabaseKey, SqlCipherMailboxStore};
use tersa_token_broker_core::{RefreshTokenStore, RefreshTokenStoreError, ValidatedSubject};
use zeroize::Zeroizing;

const REGISTRY_FILE: &str = "registry.sqlite3";
const ACCOUNTS_DIR: &str = "accounts";
const MAIL_FILE: &str = "mail.sqlite3";

/// Installation failures. Variants carry no account data.
#[derive(Debug)]
#[non_exhaustive]
pub enum InstallationError {
    /// A data directory could not be created or is not owner-only.
    Directory,
    /// The registry failed.
    Registry(RegistryError),
    /// An account store failed.
    Store(MailboxStoreError),
    /// Key derivation failed.
    Key(KeyError),
    /// The account is not registered.
    UnknownAccount,
}

impl fmt::Display for InstallationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory => formatter.write_str("the data directory is unusable"),
            Self::Registry(error) => write!(formatter, "{error}"),
            Self::Store(_) => formatter.write_str("the account database failed"),
            Self::Key(error) => write!(formatter, "{error}"),
            Self::UnknownAccount => formatter.write_str("no such account"),
        }
    }
}

impl std::error::Error for InstallationError {}

impl From<RegistryError> for InstallationError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<MailboxStoreError> for InstallationError {
    fn from(error: MailboxStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<KeyError> for InstallationError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

/// An unlocked installation.
pub struct Installation {
    data_dir: PathBuf,
    root: RootKey,
    registry: SqlCipherRegistry,
    allocation: Mutex<()>,
}

impl fmt::Debug for Installation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Installation([REDACTED])")
    }
}

impl Installation {
    /// Opens the installation under `data_dir` with the unlocked `root` key,
    /// creating the owner-only directories and the registry on first use.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::Directory`] for an unusable directory, or
    /// a registry or key error.
    pub fn open(data_dir: &Path, root: RootKey) -> Result<Self, InstallationError> {
        ensure_private_dir(data_dir)?;
        ensure_private_dir(&data_dir.join(ACCOUNTS_DIR))?;
        let key = derive_installation_key(&root, InstallationKeyPurpose::RegistryDatabaseV1)?
            .into_bytes();
        let registry = SqlCipherRegistry::open(&data_dir.join(REGISTRY_FILE), &key)?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            root,
            registry,
            allocation: Mutex::new(()),
        })
    }

    /// Registered accounts in display order.
    ///
    /// # Errors
    ///
    /// Returns a registry error.
    pub fn accounts(&self) -> Result<Vec<AccountId>, InstallationError> {
        Ok(self.registry.accounts()?)
    }

    /// Whether another account can be added.
    ///
    /// # Errors
    ///
    /// Returns a registry error.
    pub fn has_capacity(&self) -> Result<bool, InstallationError> {
        Ok(self.registry.accounts()?.len() < MAX_ACCOUNTS)
    }

    /// The registered account for an OAuth subject, if any.
    ///
    /// # Errors
    ///
    /// Returns a registry or key error.
    pub fn account_for_subject(
        &self,
        subject: &str,
    ) -> Result<Option<AccountId>, InstallationError> {
        let tag = registry_dedup_tag(&self.root, subject.as_bytes())?;
        Ok(self.registry.find_by_tag(&tag)?)
    }

    /// Opens a registered account's encrypted store.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::UnknownAccount`] for an unregistered
    /// account, or a directory, key, or store error.
    pub fn open_store(
        &self,
        account: &AccountId,
    ) -> Result<SqlCipherMailboxStore, InstallationError> {
        if !self.registry.accounts()?.contains(account) {
            return Err(InstallationError::UnknownAccount);
        }
        self.open_store_unchecked(account)
    }

    /// Removes an account's registry entry and deletes its local data.
    ///
    /// Provider revocation is the caller's job and must happen first.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::UnknownAccount`] or a storage error.
    pub fn remove_account(&self, account: &AccountId) -> Result<(), InstallationError> {
        let _guard = self
            .allocation
            .lock()
            .map_err(|_poison| InstallationError::Directory)?;
        if !self.registry.remove(account)? {
            return Err(InstallationError::UnknownAccount);
        }
        let directory = self.account_dir(account);
        match fs::remove_dir_all(&directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_error) => Err(InstallationError::Directory),
        }
    }

    fn account_dir(&self, account: &AccountId) -> PathBuf {
        let digest = Sha256::digest(account.as_str().as_bytes());
        self.data_dir.join(ACCOUNTS_DIR).join(hex(&digest))
    }

    fn open_store_unchecked(
        &self,
        account: &AccountId,
    ) -> Result<SqlCipherMailboxStore, InstallationError> {
        let directory = self.account_dir(account);
        ensure_private_dir(&directory)?;
        let key = derive_account_key(&self.root, account, AccountKeyPurpose::SqlCipherDatabaseV1)?;
        Ok(SqlCipherMailboxStore::open(
            account.clone(),
            directory.join(MAIL_FILE),
            DatabaseKey::from_zeroizing(key.into_bytes()),
        )?)
    }

    /// Returns the account for `subject`, registering a new one when absent.
    fn account_for_subject_or_register(
        &self,
        subject: &ValidatedSubject,
    ) -> Result<AccountId, InstallationError> {
        let _guard = self
            .allocation
            .lock()
            .map_err(|_poison| InstallationError::Directory)?;
        let tag = registry_dedup_tag(&self.root, subject.as_str().as_bytes())?;
        if let Some(account) = self.registry.find_by_tag(&tag)? {
            return Ok(account);
        }
        if !self.has_capacity()? {
            return Err(InstallationError::Registry(RegistryError::Full));
        }
        let account = new_account_id()?;
        // Create the store and bind its subject before registering, so a crash
        // leaves at worst an unregistered directory, never a registered
        // account without a database.
        let store = self.open_store_unchecked(&account)?;
        store.store_broker_subject(&account, subject.as_str())?;
        drop(store);
        self.registry.register(&account, &tag)?;
        Ok(account)
    }

    fn identity_hash(
        &self,
        account: &AccountId,
        normalized_subject: &[u8],
    ) -> Result<[u8; 32], KeyError> {
        account_identity_hash(&self.root, account, normalized_subject)
    }
}

fn new_account_id() -> Result<AccountId, InstallationError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_error| InstallationError::Key(KeyError::Entropy))?;
    AccountId::new(format!("acct_{}", hex(&bytes))).map_err(|_error| InstallationError::Directory)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn ensure_private_dir(path: &Path) -> Result<(), InstallationError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|_error| InstallationError::Directory)?;
    let metadata = fs::symlink_metadata(path).map_err(|_error| InstallationError::Directory)?;
    if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(InstallationError::Directory);
    }
    if metadata.mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_error| InstallationError::Directory)?;
    }
    Ok(())
}

/// The token service's refresh-token store, backed by account databases.
///
/// Storing a token for an unknown subject registers a new account.
#[derive(Clone, Debug)]
pub struct InstallationTokens(pub Arc<Installation>);

impl RefreshTokenStore for InstallationTokens {
    fn store(
        &self,
        subject: &ValidatedSubject,
        token: &Zeroizing<String>,
    ) -> Result<(), RefreshTokenStoreError> {
        let account = self
            .0
            .account_for_subject_or_register(subject)
            .map_err(|_error| RefreshTokenStoreError::Unavailable)?;
        self.0
            .open_store_unchecked(&account)
            .and_then(|store| Ok(store.store_refresh_token(&account, token)?))
            .map_err(|_error| RefreshTokenStoreError::Unavailable)
    }

    fn load(
        &self,
        subject: &ValidatedSubject,
    ) -> Result<Option<Zeroizing<String>>, RefreshTokenStoreError> {
        let Some(account) = self
            .0
            .account_for_subject(subject.as_str())
            .map_err(|_error| RefreshTokenStoreError::Unavailable)?
        else {
            return Ok(None);
        };
        let store = self
            .0
            .open_store_unchecked(&account)
            .map_err(|_error| RefreshTokenStoreError::Unavailable)?;
        store
            .load_refresh_token(&account)
            .map_err(|error| match error {
                MailboxStoreError::Corrupted => RefreshTokenStoreError::Invalid,
                _ => RefreshTokenStoreError::Unavailable,
            })
    }

    fn delete(&self, subject: &ValidatedSubject) -> Result<(), RefreshTokenStoreError> {
        let Some(account) = self
            .0
            .account_for_subject(subject.as_str())
            .map_err(|_error| RefreshTokenStoreError::Unavailable)?
        else {
            return Ok(());
        };
        self.0
            .open_store_unchecked(&account)
            .and_then(|store| Ok(store.clear_refresh_token(&account)?))
            .map_err(|_error| RefreshTokenStoreError::Unavailable)
    }
}

/// The identity-gate hasher, keyed by the installation root key.
#[derive(Clone, Debug)]
pub struct InstallationHasher(pub Arc<Installation>);

impl AccountIdentityHasher for InstallationHasher {
    fn hash(
        &self,
        account: &AccountId,
        normalized: &Zeroizing<String>,
    ) -> Result<IdentityHash, HasherError> {
        self.0
            .identity_hash(account, normalized.as_bytes())
            .map(IdentityHash::from_bytes)
            .map_err(|_error| HasherError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;

    use tersa_keys::RootKey;
    use tersa_store_sqlcipher::registry::MAX_ACCOUNTS;
    use tersa_token_broker_core::{RefreshTokenStore, RefreshTokenStoreError, ValidatedSubject};
    use zeroize::Zeroizing;

    use super::{Installation, InstallationError, InstallationTokens};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            Self(std::env::temp_dir().join(format!(
                "tersa-installation-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn root() -> RootKey {
        RootKey::from_bytes(Zeroizing::new([7; 32]))
    }

    fn subject(value: &str) -> ValidatedSubject {
        ValidatedSubject::new(value).expect("subject")
    }

    #[test]
    fn storing_a_token_registers_the_account_once() {
        let dir = TempDir::new("register");
        let installation = Arc::new(Installation::open(&dir.0, root()).expect("open"));
        let tokens = InstallationTokens(Arc::clone(&installation));

        assert_eq!(tokens.load(&subject("sub-1")).expect("load"), None);
        tokens
            .store(&subject("sub-1"), &Zeroizing::new("token-a".to_owned()))
            .expect("store");
        tokens
            .store(&subject("sub-1"), &Zeroizing::new("token-b".to_owned()))
            .expect("rotate");
        assert_eq!(installation.accounts().expect("list").len(), 1);
        assert_eq!(
            tokens
                .load(&subject("sub-1"))
                .expect("load")
                .map(|token| token.to_string()),
            Some("token-b".to_owned())
        );

        let account = installation
            .account_for_subject("sub-1")
            .expect("find")
            .expect("registered");
        assert!(account.as_str().starts_with("acct_"));
        assert_eq!(
            installation
                .open_store(&account)
                .expect("store")
                .load_broker_subject(&account)
                .expect("subject")
                .map(|value| value.to_string()),
            Some("sub-1".to_owned())
        );

        tokens.delete(&subject("sub-1")).expect("delete");
        assert_eq!(tokens.load(&subject("sub-1")).expect("load"), None);
        tokens.delete(&subject("unknown")).expect("idempotent");
    }

    #[test]
    fn directories_are_owner_only_and_reopen_keeps_accounts() {
        let dir = TempDir::new("reopen");
        let installation = Arc::new(Installation::open(&dir.0, root()).expect("open"));
        InstallationTokens(Arc::clone(&installation))
            .store(&subject("sub-1"), &Zeroizing::new("token".to_owned()))
            .expect("store");
        drop(installation);
        assert_eq!(
            fs::metadata(&dir.0).expect("meta").permissions().mode() & 0o777,
            0o700
        );
        let reopened = Installation::open(&dir.0, root()).expect("reopen");
        assert_eq!(reopened.accounts().expect("list").len(), 1);
        assert!(Installation::open(&dir.0, RootKey::from_bytes(Zeroizing::new([8; 32]))).is_err());
    }

    #[test]
    fn the_account_cap_rejects_new_subjects_and_removal_frees_a_slot() {
        let dir = TempDir::new("cap");
        let installation = Arc::new(Installation::open(&dir.0, root()).expect("open"));
        let tokens = InstallationTokens(Arc::clone(&installation));
        for index in 0..MAX_ACCOUNTS {
            tokens
                .store(
                    &subject(&format!("sub-{index}")),
                    &Zeroizing::new("t".to_owned()),
                )
                .expect("store");
        }
        assert_eq!(
            tokens.store(&subject("one-too-many"), &Zeroizing::new("t".to_owned())),
            Err(RefreshTokenStoreError::Unavailable)
        );
        let first = installation.accounts().expect("list")[0].clone();
        installation.remove_account(&first).expect("remove");
        assert!(matches!(
            installation.remove_account(&first),
            Err(InstallationError::UnknownAccount)
        ));
        assert!(installation.has_capacity().expect("capacity"));
    }
}
