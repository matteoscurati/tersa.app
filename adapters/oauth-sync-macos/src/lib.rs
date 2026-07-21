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
#[cfg(target_os = "macos")]
use tersa_application::oauth::{AuthorizationGrant, MonotonicClock};
use tersa_application::sync::{SyncCoordinator, SyncFailure, SyncPolicy, SyncReport};
#[cfg(target_os = "macos")]
use tersa_application::token::{
    AccessToken, AccountSubject, TokenClientConfig, TokenError, TokenTransport, exchange_grant,
    refresh_access_token,
};
#[cfg(target_os = "macos")]
use tersa_keychain_macos::oauth_token::{RefreshTokenError, RefreshTokenStore};

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

/// A connected account's short-lived access token and validated OIDC subject.
///
/// Produced by [`connect_account`] and [`refresh_account`] from a SINGLE token
/// response, so the access token and the identity-gate `subject` always share an
/// origin (the same principal). 3d-3 builds the sync session from both, feeding
/// the subject to the gate and the access token to the mailbox surface.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct ConnectedAccount {
    access_token: AccessToken,
    subject: AccountSubject,
}

#[cfg(target_os = "macos")]
impl ConnectedAccount {
    /// Returns the short-lived access token with its monotonic expiry.
    #[must_use]
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    /// Returns the validated subject of the connected account.
    #[must_use]
    pub fn subject(&self) -> &AccountSubject {
        &self.subject
    }

    /// Splits the connected account into the access token and the subject.
    #[must_use]
    pub fn into_parts(self) -> (AccessToken, AccountSubject) {
        (self.access_token, self.subject)
    }
}

/// Reports why a token-lifecycle step failed.
#[cfg(target_os = "macos")]
#[derive(Debug)]
#[non_exhaustive]
pub enum TokenLifecycleError {
    /// The token exchange or refresh failed. Includes
    /// [`TokenError::IdentityUnverified`], which is non-destructive — the stored
    /// refresh token is left intact for a retry.
    Token(TokenError),
    /// The refresh-token store rejected a read or write.
    Store(RefreshTokenError),
    /// A refresh was requested but no refresh token is stored; re-connect needed.
    NoStoredToken,
    /// The exchange returned no refresh token, so offline refresh is impossible.
    MissingRefreshToken,
}

#[cfg(target_os = "macos")]
impl core::fmt::Display for TokenLifecycleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Token(_) => "the token exchange or refresh failed",
            Self::Store(_) => "the refresh-token store failed",
            Self::NoStoredToken => "no refresh token is stored; re-connect is required",
            Self::MissingRefreshToken => "the token exchange returned no refresh token",
        };
        formatter.write_str(message)
    }
}

#[cfg(target_os = "macos")]
impl std::error::Error for TokenLifecycleError {}

/// Exchanges a forwarded authorization grant and persists the refresh token.
///
/// Forwards `grant` into the token exchange, requires a validated `subject` (a
/// subject-less response fails, so a connected account's identity is always
/// verified), persists the granted refresh token to `refresh_store`, and returns
/// the short-lived access token with that subject. The grant is dropped (wiped)
/// as soon as the exchange consumes it.
///
/// # Errors
///
/// Returns [`TokenLifecycleError::Token`] when the exchange fails (including a
/// missing/invalid identity), [`TokenLifecycleError::MissingRefreshToken`] when
/// the exchange returns no refresh token, and [`TokenLifecycleError::Store`] when
/// the Keychain rejects the write.
#[cfg(target_os = "macos")]
pub async fn connect_account<T, S, C>(
    account: &AccountId,
    grant: AuthorizationGrant,
    config: &TokenClientConfig,
    transport: &T,
    refresh_store: &S,
    clock: &C,
) -> Result<ConnectedAccount, TokenLifecycleError>
where
    T: TokenTransport,
    S: RefreshTokenStore,
    C: MonotonicClock,
{
    let success = exchange_grant(&grant, config, transport, clock)
        .await
        .map_err(TokenLifecycleError::Token)?;
    drop(grant);
    let (access_token, rotated_refresh, subject) = success.into_parts();
    let refresh = rotated_refresh.ok_or(TokenLifecycleError::MissingRefreshToken)?;
    refresh_store
        .store(account, &refresh)
        .map_err(TokenLifecycleError::Store)?;
    Ok(ConnectedAccount {
        access_token,
        subject,
    })
}

/// Refreshes the access token from the stored refresh token.
///
/// Loads the stored refresh token, refreshes, persists a rotated refresh token
/// when the provider returns one, and returns the fresh access token with the
/// re-verified subject. A subject-less refresh fails (fail-closed identity),
/// leaving the stored token intact for a retry.
///
/// # Errors
///
/// Returns [`TokenLifecycleError::NoStoredToken`] when nothing is stored,
/// [`TokenLifecycleError::Token`] when the refresh fails (including a
/// missing/invalid identity), and [`TokenLifecycleError::Store`] on a Keychain
/// read or write failure.
#[cfg(target_os = "macos")]
pub async fn refresh_account<T, S, C>(
    account: &AccountId,
    config: &TokenClientConfig,
    transport: &T,
    refresh_store: &S,
    clock: &C,
) -> Result<ConnectedAccount, TokenLifecycleError>
where
    T: TokenTransport,
    S: RefreshTokenStore,
    C: MonotonicClock,
{
    let stored = refresh_store
        .load(account)
        .map_err(TokenLifecycleError::Store)?
        .ok_or(TokenLifecycleError::NoStoredToken)?;
    let success = refresh_access_token(&stored, config, transport, clock)
        .await
        .map_err(TokenLifecycleError::Token)?;
    drop(stored);
    let (access_token, rotated_refresh, subject) = success.into_parts();
    if let Some(refresh) = rotated_refresh {
        refresh_store
            .store(account, &refresh)
            .map_err(TokenLifecycleError::Store)?;
    }
    Ok(ConnectedAccount {
        access_token,
        subject,
    })
}

/// Proactively refreshes only when the access token is within `skew_margin` of
/// expiry, so a sync never begins on a token that could expire mid-flight.
///
/// Returns `Ok(None)` when the current token is still fresh (no refresh
/// performed), or `Ok(Some(..))` with the refreshed account.
///
/// # Errors
///
/// Propagates [`refresh_account`]'s errors when a refresh is due and fails.
#[cfg(target_os = "macos")]
pub async fn refresh_if_due<T, S, C>(
    account: &AccountId,
    access_token: &AccessToken,
    skew_margin: core::time::Duration,
    config: &TokenClientConfig,
    transport: &T,
    refresh_store: &S,
    clock: &C,
) -> Result<Option<ConnectedAccount>, TokenLifecycleError>
where
    T: TokenTransport,
    S: RefreshTokenStore,
    C: MonotonicClock,
{
    if access_token.needs_refresh(clock, skew_margin) {
        let refreshed = refresh_account(account, config, transport, refresh_store, clock).await?;
        Ok(Some(refreshed))
    } else {
        Ok(None)
    }
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

#[cfg(test)]
#[cfg(target_os = "macos")]
mod token_lifecycle_tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use tersa_application::mailbox::{AccountId, BoxFuture};
    use tersa_application::oauth::{
        AuthorizationConfig, AuthorizationGrant, MonotonicClock, prepare_authorization,
    };
    use tersa_application::token::{
        ExchangeRequest, IdTokenClaims, RefreshRequest, TokenClientConfig, TokenError,
        TokenResponse, TokenTransport, TokenTransportError,
    };
    use tersa_keychain_macos::oauth_token::{RefreshTokenError, RefreshTokenStore};
    use url::Url;
    use zeroize::Zeroizing;

    use super::{TokenLifecycleError, connect_account, refresh_account, refresh_if_due};

    const CLIENT_ID: &str = "public-test-client";
    const TEST_SUBJECT: &str = "sub-000123";

    fn account() -> AccountId {
        AccountId::new("account-a").unwrap()
    }

    fn redirect() -> Url {
        Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap()
    }

    fn config() -> TokenClientConfig {
        TokenClientConfig::new(CLIENT_ID, redirect(), None).unwrap()
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

    fn make_grant() -> AuthorizationGrant {
        let authorization_config =
            AuthorizationConfig::new(CLIENT_ID, redirect(), Duration::from_secs(60)).unwrap();
        let prepared = prepare_authorization(authorization_config, TestClock::at(0)).unwrap();
        let state = prepared
            .authorization_url()
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        let mut callback = redirect();
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", "test-code");
        let (_config, mut session) = prepared.into_parts();
        session.finish(&callback).unwrap()
    }

    fn valid_claims() -> IdTokenClaims {
        IdTokenClaims::new(
            Zeroizing::new(TEST_SUBJECT.to_owned()),
            vec![CLIENT_ID.to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
        )
    }

    #[derive(Clone, Debug)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn at(seconds: u64) -> Self {
            Self(Arc::new(AtomicU64::new(seconds)))
        }
        fn set(&self, seconds: u64) {
            self.0.store(seconds, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for TestClock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Debug)]
    struct FakeTransport {
        rotated_refresh_token: Option<Zeroizing<String>>,
        claims: Option<IdTokenClaims>,
    }

    impl FakeTransport {
        fn success(rotated: Option<&str>) -> Self {
            Self {
                rotated_refresh_token: rotated.map(|token| Zeroizing::new(token.to_owned())),
                claims: Some(valid_claims()),
            }
        }
        fn without_id_token() -> Self {
            Self {
                rotated_refresh_token: Some(Zeroizing::new("refresh".to_owned())),
                claims: None,
            }
        }
        fn response(&self) -> TokenResponse {
            TokenResponse::new(
                Zeroizing::new("fake-access-token".to_owned()),
                Duration::from_secs(3_600),
                self.rotated_refresh_token.clone(),
                self.claims.clone(),
            )
        }
    }

    impl TokenTransport for FakeTransport {
        fn exchange(
            &self,
            _request: ExchangeRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            let response = self.response();
            Box::pin(async move { Ok(response) })
        }
        fn refresh(
            &self,
            _request: RefreshRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            let response = self.response();
            Box::pin(async move { Ok(response) })
        }
    }

    struct FakeRefreshStore {
        stored: Mutex<Option<Zeroizing<String>>>,
        fail: bool,
    }

    impl FakeRefreshStore {
        fn empty() -> Self {
            Self {
                stored: Mutex::new(None),
                fail: false,
            }
        }
        fn with_token(token: &str) -> Self {
            Self {
                stored: Mutex::new(Some(Zeroizing::new(token.to_owned()))),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                stored: Mutex::new(None),
                fail: true,
            }
        }
        fn stored(&self) -> Option<String> {
            self.stored
                .lock()
                .unwrap()
                .as_ref()
                .map(|token| token.as_str().to_owned())
        }
    }

    impl RefreshTokenStore for FakeRefreshStore {
        fn store(
            &self,
            _account: &AccountId,
            token: &Zeroizing<String>,
        ) -> Result<(), RefreshTokenError> {
            if self.fail {
                return Err(RefreshTokenError::OperationFailed);
            }
            *self.stored.lock().unwrap() = Some(token.clone());
            Ok(())
        }
        fn load(
            &self,
            _account: &AccountId,
        ) -> Result<Option<Zeroizing<String>>, RefreshTokenError> {
            if self.fail {
                return Err(RefreshTokenError::OperationFailed);
            }
            Ok(self.stored.lock().unwrap().clone())
        }
        fn delete(&self, _account: &AccountId) -> Result<(), RefreshTokenError> {
            *self.stored.lock().unwrap() = None;
            Ok(())
        }
    }

    #[test]
    fn connect_persists_the_refresh_token_and_returns_the_subject() {
        let store = FakeRefreshStore::empty();
        let connected = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &FakeTransport::success(Some("granted-refresh")),
            &store,
            &TestClock::at(0),
        ))
        .unwrap();
        assert_eq!(connected.subject().as_str(), TEST_SUBJECT);
        assert_eq!(store.stored().as_deref(), Some("granted-refresh"));
    }

    #[test]
    fn connect_without_a_refresh_token_fails() {
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &FakeTransport::success(None),
            &FakeRefreshStore::empty(),
            &TestClock::at(0),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::MissingRefreshToken));
    }

    #[test]
    fn connect_propagates_a_missing_identity_without_deleting_the_credential() {
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &FakeTransport::without_id_token(),
            &FakeRefreshStore::empty(),
            &TestClock::at(0),
        ))
        .unwrap_err();
        // IdentityUnverified is non-destructive — never ConsentRevoked.
        assert!(matches!(
            error,
            TokenLifecycleError::Token(TokenError::IdentityUnverified)
        ));
    }

    #[test]
    fn refresh_loads_refreshes_and_persists_a_rotated_token() {
        let store = FakeRefreshStore::with_token("old-refresh");
        let connected = drive(refresh_account(
            &account(),
            &config(),
            &FakeTransport::success(Some("rotated-refresh")),
            &store,
            &TestClock::at(0),
        ))
        .unwrap();
        assert_eq!(connected.subject().as_str(), TEST_SUBJECT);
        assert_eq!(store.stored().as_deref(), Some("rotated-refresh"));
    }

    #[test]
    fn refresh_keeps_the_stored_token_when_not_rotated() {
        let store = FakeRefreshStore::with_token("kept-refresh");
        drive(refresh_account(
            &account(),
            &config(),
            &FakeTransport::success(None),
            &store,
            &TestClock::at(0),
        ))
        .unwrap();
        assert_eq!(store.stored().as_deref(), Some("kept-refresh"));
    }

    #[test]
    fn refresh_without_a_stored_token_fails() {
        let error = drive(refresh_account(
            &account(),
            &config(),
            &FakeTransport::success(Some("refresh")),
            &FakeRefreshStore::empty(),
            &TestClock::at(0),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::NoStoredToken));
    }

    #[test]
    fn refresh_surfaces_a_store_failure() {
        let error = drive(refresh_account(
            &account(),
            &config(),
            &FakeTransport::success(Some("refresh")),
            &FakeRefreshStore::failing(),
            &TestClock::at(0),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Store(_)));
    }

    #[test]
    fn refresh_if_due_skips_a_fresh_token_and_refreshes_a_stale_one() {
        let clock = TestClock::at(0);
        let store = FakeRefreshStore::empty();
        // Connect at t=0: the access token expires at t=3600.
        let connected = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &FakeTransport::success(Some("granted-refresh")),
            &store,
            &clock,
        ))
        .unwrap();
        let (access_token, _subject) = connected.into_parts();

        // Still fresh at t=0 with a 60s skew: no refresh runs.
        let outcome = drive(refresh_if_due(
            &account(),
            &access_token,
            Duration::from_secs(60),
            &config(),
            &FakeTransport::success(Some("rotated")),
            &store,
            &clock,
        ))
        .unwrap();
        assert!(outcome.is_none());

        // Within the skew of expiry at t=3560: a refresh runs and rotates.
        clock.set(3_560);
        let outcome = drive(refresh_if_due(
            &account(),
            &access_token,
            Duration::from_secs(60),
            &config(),
            &FakeTransport::success(Some("rotated")),
            &store,
            &clock,
        ))
        .unwrap();
        assert!(outcome.is_some());
        assert_eq!(store.stored().as_deref(), Some("rotated"));
    }
}
