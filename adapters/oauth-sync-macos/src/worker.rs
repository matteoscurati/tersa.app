// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Rust-owned bounded-sync worker.
// Rust guideline compliant 1.0.
//!
//! One background thread drives one whole gate-to-write cycle ([`crate::gated_sync`])
//! on a private current-thread runtime, while holding the per-slot whole-cycle
//! `permit`. The permit is claimed BEFORE the thread is spawned, so a busy slot
//! never spawns a second worker; it is released at thread exit, before the terminal
//! status is published, so "poll observed terminal" always implies the slot is
//! immediately re-claimable.
//!
//! Progress is a single closed status integer (below) — never a count, address, or
//! subject. A disconnect (a later slice) flips the cancel flag; the worker observes
//! it within `CANCEL_POLL_INTERVAL` and drops the in-flight sync future, which is
//! drop-cancellation-safe (each mailbox write is its own committed-or-rolled-back
//! transaction, and the coordinator releases its inner single-flight on drop).

use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use tersa_application::identity::{AccountIdentityHasher, AccountIdentityStore};
use tersa_application::mailbox::{AccountId, MailboxStore, PageSize, StoreLimit};
use tersa_application::oauth::{SystemMonotonicClock, SystemWallClock};
use tersa_application::sync::{SyncPolicy, SyncReport};
use tersa_application::token::{TokenClientConfig, TokenError};
use tersa_gmail_rest_macos::GmailTokenTransport;
use tersa_keychain_macos::oauth_token::DataProtectionRefreshTokenStore;
use tersa_keychain_macos::{DataProtectionAccountIdentityHasher, open_default_mailbox_store};

use crate::permit::{self, WholeCyclePermit};
use crate::{
    GatedSyncError, GmailSession, TokenLifecycleError, build_sync_runtime, gated_sync,
    refresh_account,
};

/// The worker thread is live and its cycle is in flight.
pub const STATUS_RUNNING: i32 = 0;
/// The gate passed and the bounded sync completed.
pub const STATUS_SUCCEEDED: i32 = 1;
/// A disconnect was observed and the in-flight sync future was dropped.
pub const STATUS_CANCELLED: i32 = -2;
/// The account-identity gate blocked the sync. All gate sub-reasons collapse to
/// this one code: which gate step failed (hasher, store, a lost identity race)
/// would otherwise be an identity/presence oracle.
pub const STATUS_GATE_BLOCKED: i32 = -3;
/// The bounded sync failed. All sync sub-reasons collapse to this one code,
/// including an identity-fence trip — distinguishing them would leak that a
/// concurrent identity change occurred.
pub const STATUS_SYNC_FAILED: i32 = -4;
/// The worker could not build its runtime, or hit an internal anomaly.
pub const STATUS_INTERNAL: i32 = -5;
/// No refresh token is stored for the account: it must be reconnected (re-consent)
/// rather than retried. Distinct so the caller can prompt instead of looping; not
/// an oracle — there is one fixed slot and the caller syncs its own account.
pub const STATUS_NEEDS_RECONNECT: i32 = -6;

/// How often a running cycle re-checks the cancel flag. Cancel latency is at most
/// this past the current await suspension — tens of milliseconds against a
/// seconds-long sync, versus full-sync latency if the flag were checked only
/// between cycles.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Live handles onto a spawned worker. The FFI layer (a later slice) reads the
/// status on poll and requests cancellation on disconnect; neither carries mailbox
/// content. The atomics are private so the terminal/reclaim and one-way
/// cancellation protocols cannot be violated from outside — a caller can only read
/// the status and request (never clear) a cancel.
#[derive(Debug)]
pub struct WorkerHandles {
    status: Arc<AtomicI32>,
    cancel: Arc<AtomicBool>,
}

impl WorkerHandles {
    /// Reads the current status: [`STATUS_RUNNING`] while the cycle is in flight, or
    /// a terminal code once it finished. Read with `Acquire`, paired with the
    /// worker's `Release` publish.
    #[must_use]
    pub fn status(&self) -> i32 {
        self.status.load(Ordering::Acquire)
    }

    /// Requests cancellation of the in-flight cycle. One-way: a requested cancel is
    /// never cleared, so no later caller can un-cancel a cycle. The worker observes
    /// it within `CANCEL_POLL_INTERVAL` and drops the in-flight sync future.
    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
}

/// The result of asking to begin a cycle for an account slot.
#[derive(Debug)]
pub enum BeginOutcome {
    /// The slot already has a whole cycle in flight; no worker was spawned.
    Busy,
    /// A worker was spawned; poll `status` and cancel via these handles.
    Started(WorkerHandles),
}

/// Maps a finished cycle to its closed status code without inspecting the success
/// payload or the specific failure — only the coarse Ok / gate / sync distinction.
fn status_for_result<R>(result: &Result<R, GatedSyncError>) -> i32 {
    match result {
        Ok(_) => STATUS_SUCCEEDED,
        Err(GatedSyncError::Gate(_)) => STATUS_GATE_BLOCKED,
        Err(GatedSyncError::Sync(_)) => STATUS_SYNC_FAILED,
    }
}

/// Drives one cycle to completion or cancellation, re-checking the cancel flag every
/// [`CANCEL_POLL_INTERVAL`]. On cancel it returns [`STATUS_CANCELLED`], dropping the
/// still-pending cycle future.
///
/// The op yields its own already-mapped closed status code, so this core stays
/// agnostic to which composition it drives (a bare `gated_sync`, or the
/// refresh-then-sync default-account cycle) and to their distinct error types.
async fn run_cycle<F, Fut>(op: F, cancel: &AtomicBool) -> i32
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = i32>,
{
    let mut cycle = pin!(op());
    loop {
        if cancel.load(Ordering::Acquire) {
            return STATUS_CANCELLED;
        }
        // `timeout` polls the SAME future each interval (it borrows, never restarts
        // it); an elapsed interval just yields control back to re-check the flag.
        match tokio::time::timeout(CANCEL_POLL_INTERVAL, cycle.as_mut()).await {
            Ok(status) => return status,
            Err(_elapsed) => {}
        }
    }
}

/// Publishes a worker's terminal status exactly once, and — if the cycle unwound
/// without publishing (a panic deep in `gated_sync`) — falls back to
/// [`STATUS_INTERNAL`] on drop, so a poller never sees a worker stranded at
/// [`STATUS_RUNNING`] forever.
struct StatusOnDrop {
    status: Arc<AtomicI32>,
    published: bool,
}

impl StatusOnDrop {
    fn new(status: Arc<AtomicI32>) -> Self {
        Self {
            status,
            published: false,
        }
    }
    fn publish(&mut self, code: i32) {
        self.status.store(code, Ordering::Release);
        self.published = true;
    }
}

impl Drop for StatusOnDrop {
    fn drop(&mut self) {
        if !self.published {
            self.status.store(STATUS_INTERNAL, Ordering::Release);
        }
    }
}

/// Spawns a worker thread that holds `permit` for the whole cycle, drives `op` on a
/// private current-thread runtime, then releases the permit BEFORE publishing the
/// terminal status. `op` is the only value crossing the thread boundary, so its
/// future need not be `Send` — it is built and awaited entirely on the worker thread.
fn spawn_cycle<F, Fut>(permit: WholeCyclePermit, op: F) -> WorkerHandles
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = i32>,
{
    let status = Arc::new(AtomicI32::new(STATUS_RUNNING));
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_status = Arc::clone(&status);
    let worker_cancel = Arc::clone(&cancel);
    std::thread::spawn(move || {
        // `terminal` is declared BEFORE `permit` so that, on a panic unwind, locals
        // drop in reverse order — `permit` releasing the slot first, then `terminal`
        // publishing STATUS_INTERNAL — preserving release-before-publish even when the
        // cycle panics.
        let mut terminal = StatusOnDrop::new(worker_status);
        let permit = permit;
        let outcome = match build_sync_runtime() {
            Ok(runtime) => runtime.block_on(run_cycle(op, &worker_cancel)),
            Err(_error) => STATUS_INTERNAL,
        };
        // Release the slot BEFORE publishing terminal status, so a poll that sees a
        // terminal code can immediately re-claim the slot without a spurious busy.
        drop(permit);
        terminal.publish(outcome);
    });
    WorkerHandles { status, cancel }
}

/// Claims the account slot and, only if free, spawns a worker for `op`. A busy slot
/// returns [`BeginOutcome::Busy`] without spawning. Generic over the operation so
/// the concurrency machinery is testable with a fake cycle.
fn begin_with<F, Fut>(account: &AccountId, op: F) -> BeginOutcome
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = i32>,
{
    let Some(permit) = permit::try_acquire(account) else {
        return BeginOutcome::Busy;
    };
    BeginOutcome::Started(spawn_cycle(permit, op))
}

/// Begins a bounded sync for `account` on a background worker over an
/// already-connected `session`, holding the slot's whole-cycle permit for the
/// entire gate-to-write cycle. Returns [`BeginOutcome::Busy`] without spawning if a
/// cycle is already in flight for the slot.
#[must_use]
pub fn begin_sync<St, H>(
    account: AccountId,
    session: GmailSession,
    hasher: H,
    store: St,
    policy: SyncPolicy,
) -> BeginOutcome
where
    St: MailboxStore + AccountIdentityStore + Send + 'static,
    H: AccountIdentityHasher + Send + 'static,
{
    // The permit is keyed by a clone; the account itself moves into the cycle so it
    // can be borrowed by `gated_sync` on the worker thread. The op maps the cycle's
    // outcome to a closed status code for the shared, error-agnostic core.
    let slot = account.clone();
    begin_with(&slot, move || async move {
        status_for_result(&gated_sync(&account, session, &hasher, store, policy).await)
    })
}

/// A failure at some stage of the default-account cycle. Kept internal:
/// [`status_for_cycle`] collapses it to a closed status code so no stage or
/// identity detail leaves the worker.
enum CycleError {
    /// A Keychain-backed or policy setup step failed (hasher, store, transport,
    /// refresh store, or the sync policy could not be built).
    Setup,
    /// The stored refresh token could not be exchanged for an access token.
    Refresh(TokenLifecycleError),
    /// The refreshed credential failed session-freshness validation. Its specific
    /// reason is deliberately not carried — it always collapses to one status.
    Session,
    /// The bounded sync itself failed (gate or sync).
    Gated(GatedSyncError),
}

/// Maps a finished default-account cycle to its closed status code, leaking no stage
/// or identity detail. Generic over the success payload, which is discarded.
fn status_for_cycle<R>(result: &Result<R, CycleError>) -> i32 {
    match result {
        Ok(_) => STATUS_SUCCEEDED,
        // The two reconnect-recoverable outcomes, kept distinct so the caller
        // re-consents instead of retrying forever: no token is stored, OR the stored
        // token's consent was revoked / it expired. The latter is the COMMON trigger
        // (the owner revoked access in their account settings, long inactivity, a
        // password change) — mapping it to the retry code would silently never-sync.
        Err(CycleError::Refresh(
            TokenLifecycleError::NoStoredToken
            | TokenLifecycleError::Token(TokenError::ConsentRevoked),
        )) => STATUS_NEEDS_RECONNECT,
        // The bounded sync's own identity-gate fail-closed keeps its distinct code.
        Err(CycleError::Gated(GatedSyncError::Gate(_))) => STATUS_GATE_BLOCKED,
        // Setup, other (retryable, non-destructive) refresh failures, session-
        // freshness, and the bounded sync's own failures all collapse to the opaque
        // "this cycle produced no sync" — none is an identity/presence block.
        Err(
            CycleError::Setup
            | CycleError::Refresh(_)
            | CycleError::Session
            | CycleError::Gated(GatedSyncError::Sync(_)),
        ) => STATUS_SYNC_FAILED,
    }
}

/// The bounded recent-snapshot tuning for a default-account sync, owned by this
/// trusted composition rather than supplied by the caller. The constants are valid
/// by construction, so this never fails in practice.
fn default_sync_policy() -> Option<SyncPolicy> {
    let page_size = PageSize::new(25).ok()?;
    let keep_limit = StoreLimit::new(100).ok()?;
    let full_body_limit = StoreLimit::new(25).ok()?;
    SyncPolicy::new(page_size, 4, keep_limit, full_body_limit).ok()
}

/// Builds the whole gate-to-write cycle for `account` from its stored credential:
/// refresh the access token, validate freshness, then run the bounded sync. Every
/// Keychain/network object is constructed HERE, on the worker thread, so nothing but
/// `account` and `config` crosses the thread boundary and a busy slot builds none of
/// them. The permit the worker holds covers the refresh, so a rotated refresh token
/// is persisted without a parallel-cycle race.
async fn run_default_account_cycle(
    account: &AccountId,
    config: &TokenClientConfig,
) -> Result<SyncReport, CycleError> {
    let hasher = DataProtectionAccountIdentityHasher::new().map_err(|_error| CycleError::Setup)?;
    let store = open_default_mailbox_store(account).map_err(|_error| CycleError::Setup)?;
    let refresh_store =
        DataProtectionRefreshTokenStore::new().map_err(|_error| CycleError::Setup)?;
    let transport = GmailTokenTransport::new().map_err(|_error| CycleError::Setup)?;
    let monotonic = SystemMonotonicClock::new();
    let wall_clock = SystemWallClock;
    let policy = default_sync_policy().ok_or(CycleError::Setup)?;

    // A cancel that fires between the provider rotating the refresh token and
    // `refresh_account` persisting it drops this future and loses that rotation,
    // leaving the now-invalid old token stored. This is benign: the sole canceller
    // is disconnect (3d-3d), which deletes the refresh token regardless, and even
    // absent that, the next cycle's refresh returns `ConsentRevoked`, which maps to
    // `STATUS_NEEDS_RECONNECT` (a re-consent prompt), never a silent retry loop.
    let connected = refresh_account(account, config, &transport, &refresh_store, &monotonic)
        .await
        .map_err(CycleError::Refresh)?;
    let session = GmailSession::new(account.clone(), connected, &wall_clock)
        .map_err(|_error| CycleError::Session)?;
    gated_sync(account, session, &hasher, store, policy)
        .await
        .map_err(CycleError::Gated)
}

/// Begins a bounded sync for an already-connected `account` on a background worker,
/// refreshing its stored credential inside the whole-cycle permit. Returns
/// [`BeginOutcome::Busy`] — without touching the Keychain or network — if a cycle is
/// already in flight for the slot. `config` is the validated token-client config the
/// caller supplies; the composition owns everything else.
#[must_use]
pub fn begin_default_account_sync(account: AccountId, config: TokenClientConfig) -> BeginOutcome {
    let slot = account.clone();
    begin_with(&slot, move || async move {
        status_for_cycle(&run_default_account_cycle(&account, &config).await)
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests build a known-good runtime and assert on it"
    )]

    use std::future::pending;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use tersa_application::identity::{GateError, HasherError};
    use tersa_application::mailbox::AccountId;
    use tersa_application::sync::{SyncFailure, SyncFailureSource, SyncProtocolError};
    use tersa_application::token::{TokenClientConfig, TokenError};
    use url::Url;

    use super::{
        BeginOutcome, CycleError, GatedSyncError, STATUS_CANCELLED, STATUS_GATE_BLOCKED,
        STATUS_NEEDS_RECONNECT, STATUS_RUNNING, STATUS_SUCCEEDED, STATUS_SYNC_FAILED,
        TokenLifecycleError, begin_default_account_sync, begin_with, run_cycle, status_for_cycle,
        status_for_result,
    };

    fn account(id: &str) -> AccountId {
        AccountId::new(id).unwrap()
    }

    fn config() -> TokenClientConfig {
        TokenClientConfig::new(
            "test-client-id",
            Url::parse("http://127.0.0.1/").unwrap(),
            None,
        )
        .unwrap()
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn drive_run_cycle<F, Fut>(op: F, cancel: &AtomicBool) -> i32
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = i32>,
    {
        test_runtime().block_on(run_cycle(op, cancel))
    }

    #[test]
    fn status_for_result_maps_the_bare_gated_outcome() {
        assert_eq!(
            status_for_result(&Ok::<(), GatedSyncError>(())),
            STATUS_SUCCEEDED
        );
        assert_eq!(
            status_for_result(&Err::<(), _>(GatedSyncError::Gate(GateError::Hasher(
                HasherError::Unavailable
            )))),
            STATUS_GATE_BLOCKED
        );
        // A lost identity race collapses into the SAME gate-blocked code — no oracle.
        assert_eq!(
            status_for_result(&Err::<(), _>(GatedSyncError::Gate(GateError::Store(
                tersa_application::mailbox::MailboxStoreError::IdentityRaced
            )))),
            STATUS_GATE_BLOCKED
        );
        // A sync failure — including a fence trip — collapses into sync-failed.
        assert_eq!(
            status_for_result(&Err::<(), _>(GatedSyncError::Sync(
                SyncFailure::from_source_for_test(SyncFailureSource::IdentityFenced)
            ))),
            STATUS_SYNC_FAILED
        );
    }

    #[test]
    fn status_for_cycle_maps_every_stage_without_leaking() {
        assert_eq!(
            status_for_cycle(&Ok::<(), CycleError>(())),
            STATUS_SUCCEEDED
        );
        // Both reconnect-recoverable outcomes are distinct: no stored token, and the
        // common revoked/expired-consent case.
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Refresh(
                TokenLifecycleError::NoStoredToken
            ))),
            STATUS_NEEDS_RECONNECT
        );
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Refresh(
                TokenLifecycleError::Token(TokenError::ConsentRevoked)
            ))),
            STATUS_NEEDS_RECONNECT
        );
        // A non-destructive/retryable token error stays on the retry code.
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Refresh(
                TokenLifecycleError::Token(TokenError::IdentityUnverified)
            ))),
            STATUS_SYNC_FAILED
        );
        // Setup, any other refresh failure, and session-freshness all collapse to
        // one opaque "no sync" code.
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Setup)),
            STATUS_SYNC_FAILED
        );
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Refresh(
                TokenLifecycleError::MissingRefreshToken
            ))),
            STATUS_SYNC_FAILED
        );
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Session)),
            STATUS_SYNC_FAILED
        );
        // The bounded sync's own gate/sync distinction is preserved.
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Gated(GatedSyncError::Gate(
                GateError::Hasher(HasherError::Unavailable)
            )))),
            STATUS_GATE_BLOCKED
        );
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Gated(GatedSyncError::Sync(
                SyncFailure::from_source_for_test(SyncFailureSource::Protocol(
                    SyncProtocolError::OversizedPage
                ))
            )))),
            STATUS_SYNC_FAILED
        );
    }

    #[test]
    fn run_cycle_returns_the_ops_status_verbatim() {
        let cancel = AtomicBool::new(false);
        assert_eq!(
            drive_run_cycle(|| async { STATUS_NEEDS_RECONNECT }, &cancel),
            STATUS_NEEDS_RECONNECT
        );
    }

    #[test]
    fn a_preset_cancel_stops_before_running_the_cycle() {
        let cancel = AtomicBool::new(true);
        // The op would hang forever; a cancel already set returns immediately.
        assert_eq!(drive_run_cycle(pending::<i32>, &cancel), STATUS_CANCELLED);
    }

    #[test]
    fn cancel_is_observed_promptly_and_drops_the_in_flight_future() {
        use std::sync::Arc;
        // A future that never completes but records, on Drop, that it was dropped
        // mid-flight (i.e. cancelled rather than run to completion).
        struct DropFlag(Arc<AtomicBool>);
        impl Future for DropFlag {
            type Output = i32;
            fn poll(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                std::task::Poll::Pending
            }
        }
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let started = Instant::now();

        // A separate thread requests cancellation shortly after the cycle starts.
        let flip_cancel = Arc::clone(&cancel);
        let flipper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            flip_cancel.store(true, Ordering::Release);
        });

        let drop_probe = Arc::clone(&dropped);
        let status = test_runtime().block_on(run_cycle(move || DropFlag(drop_probe), &cancel));
        flipper.join().unwrap();

        assert_eq!(status, STATUS_CANCELLED);
        assert!(
            dropped.load(Ordering::Acquire),
            "the in-flight future must be dropped on cancel"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cancel must be observed promptly, not after a long delay"
        );
    }

    fn poll_until_terminal(handles: &super::WorkerHandles) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let value = handles.status();
            if value != STATUS_RUNNING {
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "worker did not reach a terminal status"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_busy_slot_does_not_spawn_a_second_worker() {
        use std::sync::Arc;
        let slot = account("worker-busy-slot");
        let go = Arc::new(AtomicBool::new(false));

        // The first begin acquires the slot permit synchronously and moves it onto
        // the worker thread, whose op holds it until `go` is set — so the slot is
        // provably held across the second begin below (no timing race).
        let release = Arc::clone(&go);
        let BeginOutcome::Started(handles) = begin_with(&slot, move || async move {
            while !release.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            STATUS_SUCCEEDED
        }) else {
            panic!("the first begin on a free slot must start a worker");
        };

        // The Busy outcome IS the proof that no second worker spawned: only the
        // Started path calls into the spawn machinery.
        match begin_with(&slot, || async { STATUS_SUCCEEDED }) {
            BeginOutcome::Busy => {}
            BeginOutcome::Started(_) => panic!("a busy slot must not start a second worker"),
        }

        go.store(true, Ordering::Release);
        assert_eq!(poll_until_terminal(&handles), STATUS_SUCCEEDED);
        // The permit is released before the terminal status is published, so a
        // finished slot is immediately claimable again.
        match begin_with(&slot, || async { STATUS_SUCCEEDED }) {
            BeginOutcome::Started(again) => {
                assert_eq!(poll_until_terminal(&again), STATUS_SUCCEEDED);
            }
            BeginOutcome::Busy => panic!("a finished slot must be claimable again"),
        }
    }

    #[test]
    fn a_cancelled_worker_releases_its_slot() {
        let slot = account("worker-cancel-release");
        // The op never completes on its own; only cancellation ends this cycle.
        let BeginOutcome::Started(handles) = begin_with(&slot, pending::<i32>) else {
            panic!("the first begin on a free slot must start a worker");
        };
        handles.request_cancel();
        assert_eq!(poll_until_terminal(&handles), STATUS_CANCELLED);
        // A cancelled worker releases its permit, so the slot is claimable again.
        match begin_with(&slot, || async { STATUS_SUCCEEDED }) {
            BeginOutcome::Started(again) => {
                assert_eq!(poll_until_terminal(&again), STATUS_SUCCEEDED);
            }
            BeginOutcome::Busy => panic!("a cancelled-and-released slot must be claimable again"),
        }
    }

    #[test]
    fn distinct_slots_run_concurrently() {
        let entered = std::sync::Arc::new(AtomicUsize::new(0));
        let go = std::sync::Arc::new(AtomicBool::new(false));

        let start_one = |slot: &str| -> super::WorkerHandles {
            let counter = std::sync::Arc::clone(&entered);
            let release = std::sync::Arc::clone(&go);
            match begin_with(&account(slot), move || async move {
                counter.fetch_add(1, Ordering::SeqCst);
                while !release.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                STATUS_SUCCEEDED
            }) {
                BeginOutcome::Started(handles) => handles,
                BeginOutcome::Busy => panic!("a distinct free slot must start"),
            }
        };

        let a = start_one("worker-concurrent-a");
        let b = start_one("worker-concurrent-b");

        // Both workers enter their op before either is allowed to finish: they are
        // not serialized against each other.
        let deadline = Instant::now() + Duration::from_secs(5);
        while entered.load(Ordering::Acquire) < 2 {
            assert!(
                Instant::now() < deadline,
                "distinct slots must run concurrently"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        go.store(true, Ordering::Release);
        assert_eq!(poll_until_terminal(&a), STATUS_SUCCEEDED);
        assert_eq!(poll_until_terminal(&b), STATUS_SUCCEEDED);
    }

    #[test]
    fn begin_default_account_sync_on_a_busy_slot_is_busy_and_builds_nothing() {
        use std::sync::Arc;
        let slot = account("default-sync-busy");
        let go = Arc::new(AtomicBool::new(false));
        // Hold the slot with a fake op so the real entry finds it busy.
        let release = Arc::clone(&go);
        let BeginOutcome::Started(holder) = begin_with(&slot, move || async move {
            while !release.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            STATUS_SUCCEEDED
        }) else {
            panic!("the holder must start");
        };
        // The real entry returns Busy WITHOUT constructing any Keychain/network
        // object or spawning a worker. This is structural: every such object is built
        // inside the op (`run_default_account_cycle`), which `begin_with` provably
        // never calls on a busy slot. It is also self-guarding — this test runs on
        // CI without a provisioned Keychain, so any regression that hoisted the
        // real constructors ahead of `begin_with` would fail here rather than pass.
        match begin_default_account_sync(slot.clone(), config()) {
            BeginOutcome::Busy => {}
            BeginOutcome::Started(_) => panic!("a busy slot must not start a default-account sync"),
        }
        go.store(true, Ordering::Release);
        assert_eq!(poll_until_terminal(&holder), STATUS_SUCCEEDED);
    }
}
