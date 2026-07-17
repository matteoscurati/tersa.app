// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Narrow ports for fixed-profile, account-scoped secure storage.

use std::fmt;
use std::path::PathBuf;

#[doc(inline)]
pub use tersa_domain::mailbox::AccountId;

// Rust guideline compliant 1.0.

/// Whether root-key provisioning created the item or found a prior winner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisionOutcome {
    /// This caller added the root key.
    Created,
    /// Another caller had already added the root key.
    Existing,
}

/// A redacted key-storage failure.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyStorageError {
    /// The requested secure-storage capability is unavailable.
    Unavailable,
    /// A persisted value or platform response did not satisfy the contract.
    Invalid,
    /// The requested value is absent.
    NotFound,
    /// A platform operation failed without exposing platform details inward.
    OperationFailed,
}

impl fmt::Debug for KeyStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyStorageError([REDACTED])")
    }
}

impl fmt::Display for KeyStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secure storage operation failed")
    }
}

impl std::error::Error for KeyStorageError {}

/// A redacted fixed-profile location failure.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileStorageError {
    /// The signed application-group container is unavailable or unusable.
    Unavailable,
    /// The account identifier does not satisfy the fixed-profile contract.
    Invalid,
}

impl fmt::Debug for ProfileStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProfileStorageError([REDACTED])")
    }
}

impl fmt::Display for ProfileStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("profile storage operation failed")
    }
}

impl std::error::Error for ProfileStorageError {}

/// Provisions the fixed installation root key, without exporting it.
pub trait InstallationRootKeyProvisioner {
    /// Ensures the fixed root key exists.
    ///
    /// # Errors
    ///
    /// Returns a redacted error if the platform cannot safely retrieve, create,
    /// or validate the fixed root-key record.
    fn provision_installation_root_key(&self) -> Result<ProvisionOutcome, KeyStorageError>;
}

/// Resolves the one fixed local profile path for an account.
pub trait AccountProfileLocator {
    /// Resolves the existing fixed database path without creating anything.
    ///
    /// The canonical [`AccountId`] boundary prevents unvalidated raw text from
    /// reaching account hashing or profile derivation:
    ///
    /// ```compile_fail
    /// use tersa_platform::secure_storage::AccountProfileLocator;
    ///
    /// fn locate(locator: &impl AccountProfileLocator) {
    ///     let _ = locator.account_database_path("raw-account-id");
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a redacted error if the configured shared container is absent or
    /// unusable, or if the account identifier cannot be represented safely.
    fn account_database_path(&self, account_id: &AccountId)
    -> Result<PathBuf, ProfileStorageError>;
}
