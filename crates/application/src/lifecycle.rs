// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

//! Privacy-safe, durable per-account lifecycle metadata.
//!
//! This port stores no OAuth token, provider identifier, mailbox content, or
//! identity hash. Its single-row state is deliberately bounded: it records only
//! an incomplete local disconnect, an unconfirmed provider revoke, and the Unix
//! millisecond of the last fully successful mailbox sync.

use core::fmt;

use crate::mailbox::{AccountId, BoxFuture, MailboxStoreError};

/// A recovery state that must survive an interrupted disconnect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectRecoveryState {
    /// Destructive local teardown started but has not been confirmed complete.
    IncompleteTeardown,
    /// Local teardown completed, but the provider revoke was not confirmed.
    RevokeUnconfirmed,
}

/// A content-free projection of persisted lifecycle state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccountLifecycleMetadata {
    recovery: Option<DisconnectRecoveryState>,
    last_successful_sync_unix_millis: Option<i64>,
}

impl AccountLifecycleMetadata {
    /// Creates a metadata projection, rejecting a pre-Unix-epoch timestamp.
    #[must_use]
    pub const fn new(
        recovery: Option<DisconnectRecoveryState>,
        last_successful_sync_unix_millis: Option<i64>,
    ) -> Option<Self> {
        if matches!(last_successful_sync_unix_millis, Some(value) if value < 0) {
            return None;
        }
        Some(Self {
            recovery,
            last_successful_sync_unix_millis,
        })
    }

    /// Returns the durable disconnect recovery state, if any.
    #[must_use]
    pub const fn recovery(self) -> Option<DisconnectRecoveryState> {
        self.recovery
    }

    /// Returns the Unix-millisecond timestamp of the last fully successful sync.
    #[must_use]
    pub const fn last_successful_sync_unix_millis(self) -> Option<i64> {
        self.last_successful_sync_unix_millis
    }
}

/// Persists and retrieves bounded lifecycle metadata for one account.
///
/// Implementations must make every transition atomic. `mark_disconnect_started`
/// is written before a destructive teardown when a persistent store is available;
/// it remains on every local teardown failure. A successful, unconfirmed revoke
/// replaces it with `RevokeUnconfirmed`; only confirmed/reconciled completion
/// clears it. A sync timestamp is written only after the entire gated sync
/// succeeds, and account purge clears that timestamp. A later successful sync
/// proves a newly consented credential after `RevokeUnconfirmed`, so its
/// completion clears stale recovery advice before recording freshness.
pub trait AccountLifecycleStore: Send + Sync {
    /// Reads the bounded lifecycle projection.
    fn lifecycle_metadata<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<AccountLifecycleMetadata, MailboxStoreError>>;

    /// Records the durable pre-teardown marker.
    fn mark_disconnect_started<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;

    /// Records local teardown completion with an unconfirmed provider revoke.
    fn mark_revoke_unconfirmed<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;

    /// Clears a recovery marker only after confirmed completion or reconciliation.
    fn clear_disconnect_recovery<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;

    /// Records a fully successful gated-sync completion time.
    fn record_successful_sync<'a>(
        &'a self,
        account: &'a AccountId,
        unix_millis: i64,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;
}

impl<T: AccountLifecycleStore + ?Sized> AccountLifecycleStore for &T {
    fn lifecycle_metadata<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<AccountLifecycleMetadata, MailboxStoreError>> {
        (**self).lifecycle_metadata(account)
    }
    fn mark_disconnect_started<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
        (**self).mark_disconnect_started(account)
    }
    fn mark_revoke_unconfirmed<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
        (**self).mark_revoke_unconfirmed(account)
    }
    fn clear_disconnect_recovery<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
        (**self).clear_disconnect_recovery(account)
    }
    fn record_successful_sync<'a>(
        &'a self,
        account: &'a AccountId,
        unix_millis: i64,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
        (**self).record_successful_sync(account, unix_millis)
    }
}

impl fmt::Display for DisconnectRecoveryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IncompleteTeardown => "incomplete teardown",
            Self::RevokeUnconfirmed => "revoke unconfirmed",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_projection_rejects_negative_freshness() {
        assert!(AccountLifecycleMetadata::new(None, Some(-1)).is_none());
        assert_eq!(
            AccountLifecycleMetadata::new(None, Some(0))
                .and_then(AccountLifecycleMetadata::last_successful_sync_unix_millis),
            Some(0)
        );
    }
}
