// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Account-identity gate: decides preserve-vs-clear before a bounded sync write.
//!
//! Phase 1 keeps a single fixed local account slot, so two different Google
//! accounts must never share one encrypted store. Before every sync write the
//! composition compares a salted, account-bound hash of the connected account's
//! own address against the hash recorded for the slot: no prior hash records it
//! (first connect); an equal hash preserves the cached mailbox; a different hash
//! clears it before the new sync writes.
//!
//! This module owns only the PORTS and the pure decision. The salt and HMAC live
//! behind `AccountIdentityHasher` (the macOS Keychain, deriving from the
//! installation root key — the key never enters this crate); the address fetch
//! lives behind `AccountProfile` (a `gmail.readonly` GET); the transactional
//! clear lives in the SQLCipher store. The composition owns the DECISION, never
//! the crypto key or the SQL.

use core::fmt;

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::mailbox::{AccountId, BoxFuture, MailboxStoreError};

/// The connected account's own email address, fetched under `gmail.readonly`.
///
/// Held only in zeroizing memory; never logged, never persisted, never crossed
/// over the C ABI.
pub struct ProfileAddress(Zeroizing<String>);

impl ProfileAddress {
    /// Wraps a fetched address.
    #[must_use]
    pub fn new(address: Zeroizing<String>) -> Self {
        Self(address)
    }

    /// Returns the address without transferring ownership.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProfileAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProfileAddress([REDACTED])")
    }
}

/// A salted, account-bound HMAC of the connected address (32 bytes).
///
/// Opaque: it reveals no address (the salt is a Keychain-confined subkey of the
/// installation root key) and is compared only in constant time.
#[derive(Clone)]
pub struct IdentityHash([u8; 32]);

impl IdentityHash {
    /// Wraps a computed hash.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the hash bytes for transactional storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for IdentityHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }
}

impl Eq for IdentityHash {}

impl fmt::Debug for IdentityHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityHash([REDACTED])")
    }
}

/// Reports a profile-fetch failure without provider data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileError {
    /// The profile endpoint could not be reached.
    Transport,
    /// The profile response did not parse into a complete address.
    InvalidResponse,
    /// The access token lost validity; re-connect is required.
    ConsentRevoked,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Transport => "the profile endpoint could not be reached",
            Self::InvalidResponse => "the profile response was incomplete",
            Self::ConsentRevoked => "the profile access was revoked",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProfileError {}

/// Reports an identity-hash derivation failure without exposing key material.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum HasherError {
    /// The salt could not be derived (e.g. the installation root key is absent).
    Unavailable,
}

impl fmt::Display for HasherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the account-identity hasher is unavailable")
    }
}

impl fmt::Debug for HasherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HasherError([REDACTED])")
    }
}

impl std::error::Error for HasherError {}

/// Reports why the account-identity gate blocked, without provider data.
///
/// Every variant is a fail-closed stop: the caller must never proceed to a sync
/// write after any of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GateError {
    /// The profile fetch failed.
    Profile(ProfileError),
    /// The identity hasher was unavailable.
    Hasher(HasherError),
    /// The identity store read or write failed.
    Store(MailboxStoreError),
}

impl fmt::Display for GateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(error) => write!(formatter, "identity gate: {error}"),
            Self::Hasher(error) => write!(formatter, "identity gate: {error}"),
            Self::Store(_) => formatter.write_str("identity gate: the identity store failed"),
        }
    }
}

impl std::error::Error for GateError {}

/// Fetches the connected account's own address under `gmail.readonly`.
///
/// A GET on a dedicated port (not the GET-only mailbox surface), driven with the
/// SAME access token as the sync so the identity cannot change between the check
/// and the write.
pub trait AccountProfile: Send + Sync {
    /// Fetches the bound account's own email address.
    ///
    /// # Errors
    ///
    /// Resolves to a typed [`ProfileError`] without provider data.
    fn email_address<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<ProfileAddress, ProfileError>>;
}

/// Derives the salted, account-bound identity hash from the connected address.
///
/// The salt is a purpose-separated HKDF subkey of the installation root key and
/// never enters this crate: the composition passes the normalized address in and
/// gets an opaque [`IdentityHash`] back.
pub trait AccountIdentityHasher: Send + Sync {
    /// Hashes the normalized address for `account`.
    ///
    /// # Errors
    ///
    /// Returns [`HasherError::Unavailable`] when the salt cannot be derived.
    fn hash(
        &self,
        account: &AccountId,
        normalized: &Zeroizing<String>,
    ) -> Result<IdentityHash, HasherError>;
}

/// The clear-vs-record action a decision resolves to for the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityReconcile {
    /// Record the fresh hash without touching the cached mailbox (first connect).
    RecordOnly,
    /// Clear the cached mailbox AND record the fresh hash in ONE transaction.
    ClearMailboxAndRecord,
}

/// Persists and atomically reconciles the account-identity hash.
///
/// The store owns the transaction: a [`IdentityReconcile::ClearMailboxAndRecord`]
/// deletes every cached message AND records `fresh` in a single transaction, so a
/// crash cannot leave a cleared mailbox with a stale or absent hash. The identity
/// row lives outside the message table, so the clear never wipes the fresh hash.
pub trait AccountIdentityStore: Send + Sync {
    /// Loads the recorded identity hash for the account slot, if any.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxStoreError`] on storage failure or an unreadable or
    /// version-incompatible row — never a silent `None`, so the caller cannot
    /// mistake an unreadable identity for a first connect.
    fn load_identity<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<Option<IdentityHash>, MailboxStoreError>>;

    /// Applies `action` for `account` in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxStoreError`]; on failure the transaction rolls back and
    /// neither the mailbox nor the recorded hash changes.
    fn reconcile_identity<'a>(
        &'a self,
        account: &'a AccountId,
        fresh: &'a IdentityHash,
        action: IdentityReconcile,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;
}

/// The gate's preserve-vs-clear decision for the fixed local account slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityDecision {
    /// No prior identity — record the fresh hash (first connect).
    FirstRecord,
    /// The same account — preserve the cached mailbox.
    Match,
    /// A different account — clear the cached mailbox before the new sync writes.
    ClearAndRecord,
}

/// Decides preserve-vs-clear from the stored hash and the freshly computed one.
///
/// Pure and total: the caller fails closed on any upstream error (a failed
/// profile fetch or hasher) BEFORE reaching this decision, so a failure never
/// falls through to preserve-and-write.
#[must_use]
pub fn decide(stored: Option<&IdentityHash>, fresh: &IdentityHash) -> IdentityDecision {
    match stored {
        None => IdentityDecision::FirstRecord,
        Some(stored) if stored == fresh => IdentityDecision::Match,
        Some(_) => IdentityDecision::ClearAndRecord,
    }
}

/// Normalizes a fetched address before hashing.
///
/// Minimal and stable by design: the value is only ever compared against a prior
/// fetch of the same `emailAddress` field for the same account, so aggressive
/// canonicalization would risk a spurious clear. Only surrounding whitespace is
/// trimmed and the address is ASCII-lowercased — nothing more.
#[must_use]
pub fn normalize_address(address: &ProfileAddress) -> Zeroizing<String> {
    Zeroizing::new(address.as_str().trim().to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{IdentityDecision, IdentityHash, ProfileAddress, decide, normalize_address};

    fn hash(byte: u8) -> IdentityHash {
        IdentityHash::from_bytes([byte; 32])
    }

    #[test]
    fn first_connect_records_the_fresh_hash() {
        assert_eq!(decide(None, &hash(1)), IdentityDecision::FirstRecord);
    }

    #[test]
    fn the_same_account_preserves_the_store() {
        assert_eq!(decide(Some(&hash(7)), &hash(7)), IdentityDecision::Match);
    }

    #[test]
    fn a_different_account_clears_before_writing() {
        assert_eq!(
            decide(Some(&hash(7)), &hash(8)),
            IdentityDecision::ClearAndRecord
        );
    }

    #[test]
    fn a_single_bit_difference_is_a_mismatch() {
        let mut other = [7_u8; 32];
        other[31] ^= 0b0000_0001;
        assert_ne!(hash(7), IdentityHash::from_bytes(other));
        assert_eq!(hash(7), hash(7));
    }

    #[test]
    fn normalization_trims_and_lowercases_only() {
        let address = ProfileAddress::new(Zeroizing::new("  User.Name@Example.COM \n".to_owned()));
        assert_eq!(&*normalize_address(&address), "user.name@example.com");
    }

    #[test]
    fn secret_and_hash_debug_are_redacted() {
        let address = ProfileAddress::new(Zeroizing::new("secret@example.test".to_owned()));
        assert_eq!(format!("{address:?}"), "ProfileAddress([REDACTED])");
        assert!(!format!("{address:?}").contains("secret@example.test"));
        assert_eq!(format!("{:?}", hash(9)), "IdentityHash([REDACTED])");
    }
}
