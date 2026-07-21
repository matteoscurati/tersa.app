// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Account-identity gate: decides preserve-vs-clear before a bounded sync write.
//!
//! Phase 1 keeps a single fixed local account slot, so two different Google
//! accounts must never share one encrypted store. Before every sync write the
//! composition compares a salted, account-bound hash of the connected account's
//! immutable OIDC subject against the hash recorded for the slot: no prior hash
//! records it (first connect); an equal hash preserves the cached mailbox; a
//! different hash clears it before the new sync writes.
//!
//! This module owns only the PORTS and the pure decision. The salt and HMAC live
//! behind `AccountIdentityHasher` (the macOS Keychain, deriving from the
//! installation root key — the key never enters this crate); the subject is
//! supplied by `AccountProfile` (the connected session, holding the validated
//! `sub`); the transactional clear lives in the SQLCipher store. The composition
//! owns the DECISION, never the crypto key or the SQL.

use core::fmt;

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::mailbox::{AccountId, BoxFuture, MailboxStoreError};
use crate::token::AccountSubject;

/// A salted, account-bound HMAC of the connected subject (32 bytes).
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
    /// The identity hasher was unavailable.
    Hasher(HasherError),
    /// The identity store read or write failed.
    Store(MailboxStoreError),
}

impl fmt::Display for GateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hasher(error) => write!(formatter, "identity gate: {error}"),
            Self::Store(_) => formatter.write_str("identity gate: the identity store failed"),
        }
    }
}

impl std::error::Error for GateError {}

/// Supplies the connected account's validated OIDC subject.
///
/// The subject is in-hand from the `id_token` (no network fetch), so this is
/// synchronous and infallible: the concrete session validated the subject and its
/// freshness at construction. The port surfaces the typed [`AccountSubject`],
/// whose constructor is crate-private, so a caller cannot feed the gate a
/// hand-minted, unvalidated identity.
pub trait AccountProfile: Send + Sync {
    /// Returns the connected account's validated subject.
    fn subject(&self) -> &AccountSubject;
}

/// Derives the salted, account-bound identity hash from the connected subject.
///
/// The salt is a purpose-separated HKDF subkey of the installation root key and
/// never enters this crate: the composition passes the normalized subject in and
/// gets an opaque [`IdentityHash`] back.
pub trait AccountIdentityHasher: Send + Sync {
    /// Hashes the normalized subject for `account`.
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

    /// Applies `action` for `account` in one transaction, as a compare-and-set
    /// against the identity the caller observed.
    ///
    /// `expected` is the recorded identity [`decide`] saw (`None` for a first
    /// connect). The store re-reads the recorded identity **inside** the write
    /// transaction and proceeds only if it still equals `expected`; otherwise a
    /// concurrent cycle won the race and it returns
    /// [`MailboxStoreError::IdentityRaced`] without mutating anything, so the
    /// caller must re-read, re-[`decide`], and retry rather than blindly applying
    /// a stale clear-or-preserve decision. This closes the gate's read-decide-
    /// record window even cross-process, where the whole-cycle permit cannot.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxStoreError::IdentityRaced`] on a lost race, or another
    /// [`MailboxStoreError`] on storage failure; on any error the transaction
    /// rolls back and neither the mailbox nor the recorded hash changes.
    fn reconcile_identity<'a>(
        &'a self,
        account: &'a AccountId,
        fresh: &'a IdentityHash,
        action: IdentityReconcile,
        expected: Option<&'a IdentityHash>,
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
/// hasher or store read) BEFORE reaching this decision, so a failure never
/// falls through to preserve-and-write.
#[must_use]
pub fn decide(stored: Option<&IdentityHash>, fresh: &IdentityHash) -> IdentityDecision {
    match stored {
        None => IdentityDecision::FirstRecord,
        Some(stored) if stored == fresh => IdentityDecision::Match,
        Some(_) => IdentityDecision::ClearAndRecord,
    }
}

/// Normalizes a validated subject before hashing.
///
/// Trim-only: a `sub` is an opaque, CASE-SENSITIVE identifier (unlike an email
/// address), so lowercasing it would be wrong and could merge distinct accounts.
/// The token layer already trims the subject; this idempotent step keeps the gate
/// self-contained. Over-normalizing is a two-way hazard here — under-normalizing
/// at worst causes a fail-safe spurious clear, but merging two subjects would not
/// be safe, so nothing beyond trimming is applied.
#[must_use]
pub fn normalize_subject(subject: &AccountSubject) -> Zeroizing<String> {
    Zeroizing::new(subject.as_str().trim().to_owned())
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use crate::token::AccountSubject;

    use super::{IdentityDecision, IdentityHash, decide, normalize_subject};

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
    fn normalization_trims_only_and_preserves_case() {
        let subject =
            AccountSubject::from_raw_for_test(Zeroizing::new("  Sub-XYZ-123  ".to_owned()));
        // Trim only: a `sub` is case-sensitive, so casing must be preserved.
        assert_eq!(&*normalize_subject(&subject), "Sub-XYZ-123");
    }

    #[test]
    fn subject_and_hash_debug_are_redacted() {
        let subject =
            AccountSubject::from_raw_for_test(Zeroizing::new("secret-sub-000".to_owned()));
        assert_eq!(format!("{subject:?}"), "AccountSubject([REDACTED])");
        assert!(!format!("{subject:?}").contains("secret-sub-000"));
        assert_eq!(format!("{:?}", hash(9)), "IdentityHash([REDACTED])");
    }
}
