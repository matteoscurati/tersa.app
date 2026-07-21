// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Trusted macOS OAuth token-lifecycle and bounded Gmail sync composition.
//!
//! This crate is the sole executor of Step 3's network-and-write composition:
//! it forwards the validated OAuth grant into the token exchange, refreshes the
//! access token proactively, gates account identity, and drives the bounded
//! recent sync into the encrypted store. It loads the refresh token from the
//! `tersa-keychain-macos` store, drives the `tersa-gmail-rest-macos` token
//! transport and read adapter, and reconciles through the validated
//! `SQLCipher` write path — all on a pinned current-thread `tokio` runtime.
//!
//! It is the only macOS crate besides the Gmail adapter that reaches the
//! network (reqwest, transitively through `tersa-gmail-rest-macos`); the
//! retrieval-only CLI never depends on it, so the CLI stays network-free.
//!
//! 3d-2 lands the account-identity gate and the gated bounded sync over the
//! inward ports ([`gated_sync`]). The concrete macOS token-lifecycle wiring
//! (grant-forward exchange, proactive refresh, and the bridge entry points on
//! the `tokio` runtime) lands in 3d-3.

#![forbid(unsafe_code)]

use core::fmt;

use tersa_application::identity::{
    AccountIdentityHasher, AccountIdentityStore, AccountProfile, GateError, IdentityDecision,
    IdentityReconcile, decide, normalize_address,
};
use tersa_application::mailbox::{AccountId, MailboxStore, RemoteMailbox};
use tersa_application::sync::{SyncCoordinator, SyncFailure, SyncPolicy, SyncReport};

/// Reports why a gated sync stopped before or during the bounded sync.
#[derive(Debug)]
#[non_exhaustive]
pub enum GatedSyncError {
    /// The account-identity gate blocked the sync; no envelope was ever written.
    Gate(GateError),
    /// The gate passed but the bounded sync itself failed.
    Sync(SyncFailure),
}

impl fmt::Display for GatedSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gate(_) => formatter.write_str("the account-identity gate blocked the sync"),
            Self::Sync(_) => formatter.write_str("the bounded sync failed"),
        }
    }
}

impl std::error::Error for GatedSyncError {}

/// Resolves the account-identity gate before any sync write.
///
/// Fetches the connected account's own address, hashes it against the
/// installation-derived salt, compares it with the recorded hash for the fixed
/// account slot, and either records it (first connect), preserves the cached
/// mailbox (same account), or clears the cached mailbox and records the new hash
/// in one transaction (different account).
///
/// Fails closed: a profile-fetch, hasher, or store-read failure returns a
/// [`GateError`] and the caller must not proceed to any sync write. A read
/// failure is never mistaken for a first connect, so an unavailable identity can
/// never re-baseline the store to whoever happens to be connected.
async fn run_identity_gate<P, H, St>(
    account: &AccountId,
    profile: &P,
    hasher: &H,
    store: &St,
) -> Result<(), GateError>
where
    P: AccountProfile,
    H: AccountIdentityHasher,
    St: AccountIdentityStore,
{
    let address = profile
        .email_address(account)
        .await
        .map_err(GateError::Profile)?;
    let normalized = normalize_address(&address);
    drop(address);
    let fresh = hasher
        .hash(account, &normalized)
        .map_err(GateError::Hasher)?;
    drop(normalized);
    let stored = store
        .load_identity(account)
        .await
        .map_err(GateError::Store)?;
    let action = match decide(stored.as_ref(), &fresh) {
        // The same account: preserve the cached mailbox, write nothing.
        IdentityDecision::Match => return Ok(()),
        IdentityDecision::FirstRecord => IdentityReconcile::RecordOnly,
        IdentityDecision::ClearAndRecord => IdentityReconcile::ClearMailboxAndRecord,
    };
    store
        .reconcile_identity(account, &fresh, action)
        .await
        .map_err(GateError::Store)
}

/// Runs the account-identity gate, then the bounded recent sync — over one
/// account session.
///
/// `session` exposes BOTH the profile-fetch surface (`AccountProfile`) and the
/// mailbox-read surface (`RemoteMailbox`), so a single credential necessarily
/// backs the identity check and the sync it guards. This makes the gate's core
/// invariant — the account whose identity is checked is the account whose mail is
/// written — a type-level guarantee, not a caller contract: a caller cannot check
/// one Google user's identity and then sync a different user's mail, because there
/// is only one session (hence one access token) to build both surfaces from. The
/// concrete macOS session (3d-3) must therefore hold a single access token and
/// derive both surfaces from it.
///
/// The gate borrows the session and completes first; only then is the session
/// moved into a [`SyncCoordinator`] as the remote and the sync driven. Because
/// the gate runs to a successful completion before the coordinator exists, a
/// blocked gate means `sync_recent` — and therefore every mailbox write — never
/// runs.
///
/// The identity hash is recorded (or the mailbox cleared and the hash recorded)
/// inside the gate, committed BEFORE any message is synced. So a "messages present
/// but identity absent" state — which the missing-row-is-first-connect branch
/// would misread — is unreachable without tampering with the encrypted store
/// itself, which already requires the database key.
///
/// # Concurrency
///
/// This function requires external per-account serialization across the WHOLE
/// gate-to-write cycle and MUST NOT be called concurrently for the same account
/// slot. The gate's load/decide/record and the sync it guards are distinct steps
/// (each call builds its own [`SyncCoordinator`], whose single-flight set is
/// per-call, not shared), so two overlapping cycles could interleave a stale
/// record over a committed one and let two accounts' mail coexist. Enforcement is
/// NOT provided here: it belongs to the 3d-3 Rust-owned sync worker (the sole
/// production caller, holding one whole-cycle permit per slot) plus an
/// in-transaction identity fence that re-checks the recorded hash inside every
/// mailbox-write transaction. Callers without that discipline break the invariant.
///
/// # Errors
///
/// Returns [`GatedSyncError::Gate`] when the identity gate blocks the sync (no
/// write occurred) and [`GatedSyncError::Sync`] when the bounded sync fails.
pub async fn gated_sync<S, St, H>(
    account: &AccountId,
    session: S,
    hasher: &H,
    store: St,
    policy: SyncPolicy,
) -> Result<SyncReport, GatedSyncError>
where
    S: AccountProfile + RemoteMailbox,
    St: MailboxStore + AccountIdentityStore,
    H: AccountIdentityHasher,
{
    run_identity_gate(account, &session, hasher, &store)
        .await
        .map_err(GatedSyncError::Gate)?;
    let coordinator = SyncCoordinator::new(session, store);
    coordinator
        .sync_recent(account, policy)
        .await
        .map_err(GatedSyncError::Sync)
}

/// Builds the pinned current-thread `tokio` runtime that will drive the
/// connect-time token exchange and the bounded sync worker.
///
/// A dedicated current-thread runtime keeps the composition's async network
/// work off the main thread and out of every other crate; the retrieval-only
/// CLI never constructs it.
///
/// # Errors
///
/// Returns the `tokio` build error when the runtime cannot be created.
#[cfg(target_os = "macos")]
pub fn build_sync_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

// Rust guideline compliant 1.0.

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use tersa_application::identity::{
        AccountIdentityHasher, AccountIdentityStore, AccountProfile, GateError, HasherError,
        IdentityHash, IdentityReconcile, ProfileAddress, ProfileError,
    };
    use tersa_application::mailbox::{
        AccountId, BoxFuture, MailboxReader, MailboxStore, MailboxStoreError, Message,
        MessageEnvelope, MessageId, Page, PageSize, PageToken, RemoteMailbox, RemoteMailboxError,
        StoreLimit, ThreadId,
    };
    use tersa_application::sync::SyncPolicy;
    use zeroize::Zeroizing;

    use super::{GatedSyncError, gated_sync, run_identity_gate};

    fn account() -> AccountId {
        AccountId::new("account-a").unwrap()
    }

    fn drive<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("composition future must complete synchronously"),
        }
    }

    struct FakeProfile(Result<String, ProfileError>);

    impl AccountProfile for FakeProfile {
        fn email_address<'a>(
            &'a self,
            _account: &'a AccountId,
        ) -> BoxFuture<'a, Result<ProfileAddress, ProfileError>> {
            let result = self
                .0
                .as_ref()
                .map(|address| ProfileAddress::new(Zeroizing::new(address.clone())))
                .map_err(|error| *error);
            Box::pin(async move { result })
        }
    }

    struct FakeHasher {
        output: Result<[u8; 32], HasherError>,
        seen: Mutex<Vec<String>>,
    }

    impl FakeHasher {
        fn ok(bytes: [u8; 32]) -> Self {
            Self {
                output: Ok(bytes),
                seen: Mutex::new(Vec::new()),
            }
        }
        fn failing() -> Self {
            Self {
                output: Err(HasherError::Unavailable),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl AccountIdentityHasher for FakeHasher {
        fn hash(
            &self,
            _account: &AccountId,
            normalized: &Zeroizing<String>,
        ) -> Result<IdentityHash, HasherError> {
            self.seen
                .lock()
                .unwrap()
                .push(normalized.as_str().to_owned());
            self.output.map(IdentityHash::from_bytes)
        }
    }

    #[derive(Default)]
    struct FakeStore {
        stored: Mutex<Option<[u8; 32]>>,
        load_error: bool,
        reconcile_error: bool,
        identity_reconciles: Mutex<Vec<([u8; 32], IdentityReconcile)>>,
        sync_reconciles: Arc<AtomicUsize>,
    }

    impl FakeStore {
        fn with_stored(bytes: [u8; 32]) -> Self {
            Self {
                stored: Mutex::new(Some(bytes)),
                ..Self::default()
            }
        }
        fn identity_reconciles(&self) -> Vec<([u8; 32], IdentityReconcile)> {
            self.identity_reconciles.lock().unwrap().clone()
        }
        /// A shared handle to the sync-write counter, kept after the store is
        /// moved into `gated_sync`, so a test can prove the write did or did not run.
        fn sync_probe(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.sync_reconciles)
        }
    }

    impl AccountIdentityStore for FakeStore {
        fn load_identity<'a>(
            &'a self,
            _account: &'a AccountId,
        ) -> BoxFuture<'a, Result<Option<IdentityHash>, MailboxStoreError>> {
            Box::pin(async move {
                if self.load_error {
                    return Err(MailboxStoreError::Storage);
                }
                Ok(self.stored.lock().unwrap().map(IdentityHash::from_bytes))
            })
        }

        fn reconcile_identity<'a>(
            &'a self,
            _account: &'a AccountId,
            fresh: &'a IdentityHash,
            action: IdentityReconcile,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async move {
                self.identity_reconciles
                    .lock()
                    .unwrap()
                    .push((*fresh.as_bytes(), action));
                if self.reconcile_error {
                    return Err(MailboxStoreError::Storage);
                }
                *self.stored.lock().unwrap() = Some(*fresh.as_bytes());
                Ok(())
            })
        }
    }

    impl MailboxReader for FakeStore {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    impl MailboxStore for FakeStore {
        fn upsert_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _envelopes: &'a [MessageEnvelope],
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn put_message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message: &'a Message,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn reconcile_recent_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _envelopes: &'a [MessageEnvelope],
            _keep_limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
            self.sync_reconciles.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(Vec::new()) })
        }
        fn cache_message_if_present<'a>(
            &'a self,
            _account: &'a AccountId,
            _message: &'a Message,
        ) -> BoxFuture<'a, Result<bool, MailboxStoreError>> {
            Box::pin(async { Ok(false) })
        }
        fn message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async { Ok(None) })
        }
    }

    // One session object exposes both the profile and the mailbox surface, so a
    // test cannot accidentally pair one account's profile with another's mail —
    // the same constraint `gated_sync` now imposes on production callers.
    impl RemoteMailbox for FakeProfile {
        fn list_recent_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _size: PageSize,
            _page_token: Option<&'a PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            Box::pin(async { Ok(Page::new(Vec::new(), None)) })
        }
        fn fetch_message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            Box::pin(async { Err(RemoteMailboxError::NotFound) })
        }
    }

    fn run_gate(
        profile: &FakeProfile,
        hasher: &FakeHasher,
        store: &FakeStore,
    ) -> Result<(), GateError> {
        drive(run_identity_gate(&account(), profile, hasher, store))
    }

    #[test]
    fn first_connect_records_only() {
        let store = FakeStore::default();
        run_gate(
            &FakeProfile(Ok("user@example.test".to_owned())),
            &FakeHasher::ok([5; 32]),
            &store,
        )
        .unwrap();
        assert_eq!(
            store.identity_reconciles(),
            vec![([5; 32], IdentityReconcile::RecordOnly)]
        );
    }

    #[test]
    fn same_account_preserves_the_store() {
        let store = FakeStore::with_stored([5; 32]);
        run_gate(
            &FakeProfile(Ok("user@example.test".to_owned())),
            &FakeHasher::ok([5; 32]),
            &store,
        )
        .unwrap();
        // A match writes nothing.
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn different_account_clears_and_records() {
        let store = FakeStore::with_stored([5; 32]);
        run_gate(
            &FakeProfile(Ok("other@example.test".to_owned())),
            &FakeHasher::ok([9; 32]),
            &store,
        )
        .unwrap();
        assert_eq!(
            store.identity_reconciles(),
            vec![([9; 32], IdentityReconcile::ClearMailboxAndRecord)]
        );
    }

    #[test]
    fn address_is_normalized_before_hashing() {
        let store = FakeStore::default();
        let hasher = FakeHasher::ok([5; 32]);
        drive(run_identity_gate(
            &account(),
            &FakeProfile(Ok("  User@Example.TEST \n".to_owned())),
            &hasher,
            &store,
        ))
        .unwrap();
        assert_eq!(
            hasher.seen.lock().unwrap().as_slice(),
            ["user@example.test"]
        );
    }

    #[test]
    fn a_profile_failure_fails_closed() {
        let store = FakeStore::with_stored([5; 32]);
        let result = run_gate(
            &FakeProfile(Err(ProfileError::Transport)),
            &FakeHasher::ok([9; 32]),
            &store,
        );
        assert_eq!(result, Err(GateError::Profile(ProfileError::Transport)));
        // No write ever reached the store.
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn a_hasher_failure_fails_closed() {
        let store = FakeStore::with_stored([5; 32]);
        let result = run_gate(
            &FakeProfile(Ok("user@example.test".to_owned())),
            &FakeHasher::failing(),
            &store,
        );
        assert_eq!(result, Err(GateError::Hasher(HasherError::Unavailable)));
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn a_load_failure_fails_closed_and_never_rebaselines() {
        let store = FakeStore {
            stored: Mutex::new(Some([5; 32])),
            load_error: true,
            ..FakeStore::default()
        };
        let result = run_gate(
            &FakeProfile(Ok("user@example.test".to_owned())),
            &FakeHasher::ok([9; 32]),
            &store,
        );
        assert_eq!(result, Err(GateError::Store(MailboxStoreError::Storage)));
        // An unreadable identity must never be treated as a first connect.
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn a_reconcile_failure_surfaces_as_a_store_error() {
        let store = FakeStore {
            reconcile_error: true,
            ..FakeStore::default()
        };
        let result = run_gate(
            &FakeProfile(Ok("user@example.test".to_owned())),
            &FakeHasher::ok([9; 32]),
            &store,
        );
        assert_eq!(result, Err(GateError::Store(MailboxStoreError::Storage)));
    }

    fn policy() -> SyncPolicy {
        SyncPolicy::new(
            PageSize::new(10).unwrap(),
            1,
            StoreLimit::new(10).unwrap(),
            StoreLimit::new(1).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn a_blocked_gate_never_reaches_the_sync_write() {
        let store = FakeStore::with_stored([5; 32]);
        let sync_writes = store.sync_probe();
        let error = drive(gated_sync(
            &account(),
            FakeProfile(Err(ProfileError::Transport)),
            &FakeHasher::ok([9; 32]),
            store,
            policy(),
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            GatedSyncError::Gate(GateError::Profile(ProfileError::Transport))
        ));
        // The gate blocked before the coordinator existed: no sync write ran.
        assert_eq!(sync_writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_passing_gate_runs_the_bounded_sync() {
        let store = FakeStore::default();
        let sync_writes = store.sync_probe();
        let report = drive(gated_sync(
            &account(),
            FakeProfile(Ok("user@example.test".to_owned())),
            &FakeHasher::ok([5; 32]),
            store,
            policy(),
        ));
        assert!(report.is_ok());
        // The gate passed, so the bounded sync ran exactly once.
        assert_eq!(sync_writes.load(Ordering::SeqCst), 1);
    }
}
