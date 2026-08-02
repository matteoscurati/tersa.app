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
//! subject. A disconnect (3d-3d) flips the cancel flag the SYNC begin registered
//! in the permit slot (a connect begin registers none and is never signaled);
//! the worker observes it within `CANCEL_POLL_INTERVAL` and drops the in-flight
//! sync future, which is drop-cancellation-safe (each mailbox write is its own
//! committed-or-rolled-back transaction, and the coordinator releases its inner
//! single-flight on drop).
//!
//! The disconnect itself runs on a sibling worker ([`begin_disconnect`]) that
//! INVERTS the begin order: the FFI marks the slot disconnecting up front, the
//! worker spawns first and then blocking-acquires the gate on its plain thread —
//! serializing BEHIND the now-cancelling cycle — and only then loads the stored
//! refresh token, revokes it best-effort, deletes it, and purges the account's
//! local data. That worker is un-cancellable and clears the disconnecting flag
//! on the whole teardown SUCCESS FAMILY — a locally-complete teardown, whether
//! or not the provider /revoke could be confirmed ([`STATUS_SUCCEEDED`] or
//! [`STATUS_SUCCEEDED_REVOKE_UNCONFIRMED`]); only a teardown FAILURE leaves the
//! flag set (fail-closed).

use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use tersa_application::identity::{AccountIdentityHasher, AccountIdentityStore};
use tersa_application::mailbox::{
    AccountId, AccountPurgeStore, MailboxStore, PageSize, StoreLimit,
};
use tersa_application::oauth::{AuthorizationGrant, SystemMonotonicClock, SystemWallClock};
use tersa_application::sync::{SyncPolicy, SyncReport};
use tersa_application::token::{TokenClientConfig, TokenError, TokenTransport};
use tersa_gmail_rest_macos::GmailTokenTransport;
use tersa_keychain_macos::oauth_token::{DataProtectionRefreshTokenStore, RefreshTokenStore};
use tersa_keychain_macos::{
    DataProtectionAccountIdentityHasher, open_default_mailbox_store,
    open_default_mailbox_store_if_present,
};

use crate::permit::{self, WholeCyclePermit};
use crate::{
    ConnectSession, GatedSyncError, GmailSession, RevokeOutcome, TokenLifecycleError,
    build_sync_runtime, connect_account, gated_sync, refresh_account, revoke_best_effort,
};

/// The worker thread is live and its cycle is in flight.
pub const STATUS_RUNNING: i32 = 0;
/// The gate passed and the bounded sync completed.
pub const STATUS_SUCCEEDED: i32 = 1;
/// The disconnect teardown completed locally — the stored token was deleted and
/// the account's mailbox and identity were purged — but the provider /revoke
/// could NOT be confirmed: both revoke attempts failed (e.g. offline), the
/// token load failed so a token's liveness is unknown, or the token transport
/// could not be constructed so no revoke was attempted. The account IS
/// disconnected; 3e renders "Disconnected — also revoke access in your Google
/// Account settings." Positive, alongside [`STATUS_SUCCEEDED`]: the two form
/// the disconnect SUCCESS FAMILY the `disconnecting` fence clears on, distinct
/// from the FFI's positive begin-refusal code (`STATUS_SYNC_BUSY = 2`), which
/// is never a poll terminal.
pub const STATUS_SUCCEEDED_REVOKE_UNCONFIRMED: i32 = 3;
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
/// The provider explicitly omitted Gmail read access from the granted scopes.
/// Distinct so the UI can explain which consent must be allowed on retry.
pub const STATUS_INSUFFICIENT_SCOPE: i32 = -9;

/// How often a running cycle re-checks the cancel flag. Cancel latency is at most
/// this past the current await suspension — tens of milliseconds against a
/// seconds-long sync, versus full-sync latency if the flag were checked only
/// between cycles.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Live handles onto a spawned worker. The FFI layer reads the status on poll;
/// disconnect signals cancellation through the SAME flag these handles carry,
/// but reaches it via the permit slot's registration, never through this type.
/// Neither carries mailbox content. The atomics are private so the
/// terminal/reclaim and one-way cancellation protocols cannot be violated from
/// outside — a caller can only read the status and request (never clear) a
/// cancel.
#[derive(Debug)]
pub struct WorkerHandles {
    status: Arc<AtomicI32>,
    // Read only by the test-only `request_cancel`: PRODUCTION cancels a sync via
    // the permit slot's registration (a `Weak` to this same flag), never through
    // the handle. Kept on the handle as the cancellation-authority the atomic
    // protocol is defined over, but off the production API so no holder of a
    // CONNECT worker's handles can drop-abort its exchange.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "read only by the test-only `request_cancel`; production cancels via the permit registration, and the field is kept as the atomic cancel-authority off the production API"
        )
    )]
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
    ///
    /// DROP-CANCELLATION CONTRACT: connect cancellation flows through the OAuth
    /// tombstone/lease ONLY — this flag must NEVER be fired mid-connect.
    /// Disconnect (3d-3d), the sole canceller, signals the SYNC cycle's copy of
    /// this flag through the permit slot's registration and serializes on the
    /// whole-cycle permit, so it cannot overlap — or signal — a connect holding
    /// the slot. The bridge lease makes an accidental mid-connect drop
    /// fail-safe (the tombstone stays pinned) but does not un-store a token.
    ///
    /// `#[cfg(test)]`: handle-based cancellation is a TEST affordance only. No
    /// production caller exists — a disconnect cancels an in-flight SYNC through
    /// the permit slot's registration (a `Weak` to a sync's cancel flag), never
    /// through a handle. Keeping this off the production build makes the "connect
    /// is never cancel-signaled" guarantee structural: no holder of a CONNECT
    /// worker's handles can even name a method to drop-abort its exchange.
    #[cfg(test)]
    pub(crate) fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    /// Builds handles wrapping a fixed status and an inert, unset cancel flag, for
    /// tests in other crates that drive a session registry (the mailbox-sync FFI)
    /// without spawning a real worker thread. No worker observes the cancel flag.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn from_status_for_test(status: i32) -> Self {
        Self {
            status: Arc::new(AtomicI32::new(status)),
            cancel: Arc::new(AtomicBool::new(false)),
        }
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

/// Builds handles for a cycle that could not start: the status Arc is already
/// terminal at [`STATUS_INTERNAL`] and the cancel flag is inert (unset), so a
/// session registered with these handles polls terminal immediately and reaps.
fn terminal_internal_handles() -> WorkerHandles {
    WorkerHandles {
        status: Arc::new(AtomicI32::new(STATUS_INTERNAL)),
        cancel: Arc::new(AtomicBool::new(false)),
    }
}

/// Spawns a worker thread that holds `permit` for the whole cycle, drives `op` on a
/// private current-thread runtime, then releases the permit BEFORE publishing the
/// terminal status. `op` is the only value crossing the thread boundary, so its
/// future need not be `Send` — it is built and awaited entirely on the worker thread.
/// `status` and `cancel` are the caller-built handle atomics: the SAME `cancel` a
/// sync begin registered in the permit slot, so a disconnect signal reaches this
/// worker's poll loop.
///
/// # Failure mapping
///
/// Thread creation is fallible, so this goes through [`std::thread::Builder`] and
/// its `io::Result` rather than the panicking `std::thread::spawn` — a panic here,
/// on the FFI caller thread, would abort the whole process under the release
/// profile's `panic = "abort"`. If the OS refuses the thread, the un-spawned
/// closure drops with `permit` inside it (releasing the slot, and deregistering
/// any registered cancel flag) and the returned handles are already terminal at
/// [`STATUS_INTERNAL`]: the caller registers a session the first poll reaps,
/// which is exactly the ABI's internal-anomaly code.
fn spawn_cycle<F, Fut>(
    permit: WholeCyclePermit,
    status: Arc<AtomicI32>,
    cancel: Arc<AtomicBool>,
    op: F,
) -> WorkerHandles
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = i32>,
{
    let worker_status = Arc::clone(&status);
    let worker_cancel = Arc::clone(&cancel);
    let spawned = std::thread::Builder::new()
        .name("tersa-sync".to_owned())
        .spawn(move || {
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
    match spawned {
        // Dropping the join handle detaches the worker, as before.
        Ok(_worker) => WorkerHandles { status, cancel },
        // The un-spawned closure (owning `permit`) was dropped with the error, so
        // the slot is already released; surface the internal-anomaly terminal code.
        Err(_error) => terminal_internal_handles(),
    }
}

/// Claims the account slot and, only if free, spawns a worker for `op`, building
/// the handle atomics and registering the cancel flag in the permit slot iff
/// `registers_cancel`. A busy OR disconnecting slot returns
/// [`BeginOutcome::Busy`] without spawning — the two refusals are deliberately
/// indistinguishable to the caller. Generic over the operation so the
/// concurrency machinery is testable with a fake cycle.
fn begin_inner<F, Fut>(account: &AccountId, registers_cancel: bool, op: F) -> BeginOutcome
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = i32>,
{
    let status = Arc::new(AtomicI32::new(STATUS_RUNNING));
    let cancel = Arc::new(AtomicBool::new(false));
    // The registration is STRUCTURAL: only a sync begin registers its cancel
    // flag in the slot, so a disconnect can never signal a connect.
    let registered = registers_cancel.then(|| Arc::clone(&cancel));
    let Some(permit) = permit::try_acquire(account, registered) else {
        return BeginOutcome::Busy;
    };
    BeginOutcome::Started(spawn_cycle(permit, status, cancel, op))
}

/// Begins a SYNC cycle for `op`: the worker's cancel flag is registered in the
/// permit slot, so a disconnect prompt-cancels the in-flight sync and takes the
/// gate without waiting out a whole bounded sync.
fn begin_with<F, Fut>(account: &AccountId, op: F) -> BeginOutcome
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = i32>,
{
    begin_inner(account, true, op)
}

/// Begins a CONNECT cycle for `op`: the worker's cancel flag is NEVER
/// registered in the permit slot. The connect runs through the same
/// [`CANCEL_POLL_INTERVAL`] cancel poll as a sync, so a disconnect that could
/// signal it would drop-abort the token exchange mid-flight and orphan a
/// minted token — connect cancellation flows through the OAuth tombstone/lease
/// only, and the sync-only registration is what makes a signaled connect
/// impossible.
fn begin_connect_with<F, Fut>(account: &AccountId, op: F) -> BeginOutcome
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = i32>,
{
    begin_inner(account, false, op)
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

/// A failure at some stage of the default-account or connect-account cycle. Kept
/// internal: [`status_for_cycle`] collapses it to a closed status code so no stage
/// or identity detail leaves the worker.
enum CycleError {
    /// A Keychain-backed or policy setup step failed (hasher, store, transport,
    /// refresh store, or the sync policy could not be built).
    Setup,
    /// The OAuth grant could not be claimed: the session is unknown, expired, or
    /// already claimed — the login window elapsed before the worker started. A
    /// claim-miss whose session was CANCELLED is not this variant but
    /// `Connect(TokenLifecycleError::Cancelled)`, reported as a cancel rather
    /// than a re-consent prompt.
    ClaimMissing,
    /// The initial grant exchange, the connect cancel fence, or the
    /// refresh-token store failed (the newly-connected account path).
    Connect(TokenLifecycleError),
    /// The stored refresh token could not be exchanged for an access token.
    Refresh(TokenLifecycleError),
    /// The refreshed credential failed session-freshness validation. Its specific
    /// reason is deliberately not carried — it always collapses to one status.
    Session,
    /// The bounded sync itself failed (gate or sync).
    Gated(GatedSyncError),
}

/// Maps a finished default-account or connect-account cycle to its closed status
/// code, leaking no stage or identity detail. Generic over the success payload,
/// which is discarded.
fn status_for_cycle<R>(result: &Result<R, CycleError>) -> i32 {
    match result {
        Ok(_) => STATUS_SUCCEEDED,
        // The reconnect-recoverable outcomes, kept distinct so the caller
        // re-consents instead of retrying forever: no token is stored, OR the stored
        // token's consent was revoked / it expired. The latter is the COMMON trigger
        // (the owner revoked access in their account settings, long inactivity, a
        // password change) — mapping it to the retry code would silently never-sync.
        // On the connect path the same code covers an unclaimable grant (the login
        // window elapsed) and an `invalid_grant` at the initial exchange, which the
        // token layer surfaces as `ConsentRevoked`.
        Err(
            CycleError::ClaimMissing
            | CycleError::Connect(TokenLifecycleError::Token(TokenError::ConsentRevoked))
            | CycleError::Refresh(
                TokenLifecycleError::NoStoredToken
                | TokenLifecycleError::Token(TokenError::ConsentRevoked),
            ),
        ) => STATUS_NEEDS_RECONNECT,
        Err(
            CycleError::Connect(TokenLifecycleError::Token(TokenError::InsufficientScope))
            | CycleError::Refresh(TokenLifecycleError::Token(TokenError::InsufficientScope)),
        ) => STATUS_INSUFFICIENT_SCOPE,
        // The bounded sync's own identity-gate fail-closed keeps its distinct code.
        Err(CycleError::Gated(GatedSyncError::Gate(_))) => STATUS_GATE_BLOCKED,
        // A cancel observed at a connect fence whose local cleanup COMPLETED:
        // this connect created no NEW connection (no token minted, nothing
        // stored, the just-stored token deleted, or the prior credential
        // restored), so it reports the SAME closed cancel code a mid-sync
        // cancel yields. This does NOT mean the account is disconnected: a
        // cancelled RE-connect restores the prior credential and the
        // pre-existing connection survives — 3e must not render this code as
        // "disconnected". Distinct from the reconnect code (nothing needs
        // re-consent) and from sync-failed (this is not a retryable failure).
        Err(CycleError::Connect(TokenLifecycleError::Cancelled)) => STATUS_CANCELLED,
        // A cancel whose post-store cleanup write failed persistently is NOT a
        // clean cancel: a usable token may still sit in the Keychain, so it
        // surfaces as the internal code — 3e presents "cancelled — please
        // disconnect to be sure" — never the clean cancel code.
        Err(CycleError::Connect(TokenLifecycleError::CancelledCleanupIncomplete)) => {
            STATUS_INTERNAL
        }
        // Setup, other (retryable, non-destructive) exchange/refresh failures,
        // session-freshness, and the bounded sync's own failures all collapse to
        // the opaque "this cycle produced no sync" — none is an identity/presence
        // block.
        Err(
            CycleError::Setup
            | CycleError::Connect(_)
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

/// Builds the whole gate-to-write cycle for a newly-connected `account`: claim the
/// just-finished OAuth grant together with its token-client config, then drive
/// the claimed scope ([`run_claimed_connect_cycle`]: setup, the initial grant
/// exchange, refresh-token persistence, freshness validation, and the bounded
/// sync), releasing the session's in-flight lease EXACTLY ONCE on every outcome
/// via [`complete_after`]. The claim runs FIRST, before any Keychain/network
/// setup, so a claim-miss costs nothing, never touches the Keychain — and takes
/// NO lease, so it must NOT complete.
///
/// The config arrives WITH the claim — built by the session's implementation
/// from the client id and the REAL redirect the grant was issued against (required
/// for the `authorization_code` exchange) — because this composition's direct dependency set
/// is closed and deliberately excludes `url`: the caller owns the redirect type,
/// exactly as it supplies the config to [`begin_default_account_sync`].
/// `session` is the ONE [`ConnectSession`] the claim and all of
/// [`crate::connect_account`]'s cancel fences are served from, so a user who
/// cancelled mid-exchange never ends up connected — and a claim-miss that is
/// actually a cancel (the tombstone made the grant unclaimable between
/// grant-store and claim) reports [`TokenLifecycleError::Cancelled`], not the
/// re-consent code.
async fn run_connect_account_cycle<St: ConnectSession>(
    account: &AccountId,
    session: &St,
) -> Result<SyncReport, CycleError> {
    let (grant, config) = session.claim().ok_or_else(|| {
        if session.is_cancelled() {
            CycleError::Connect(TokenLifecycleError::Cancelled)
        } else {
            CycleError::ClaimMissing
        }
    })?;
    // The successful claim took the session's in-flight lease: it is released
    // EXACTLY ONCE after the WHOLE claimed scope — a setup failure, a connect
    // error, and success alike — never on the claim-miss above (no lease was
    // taken), and never from `Drop` (a mid-connect future drop must keep the
    // tombstone pinned, fail-safe).
    complete_after(session, || {
        run_claimed_connect_cycle(account, grant, &config, session)
    })
    .await
}

/// Drives the post-claim scope of a connect cycle (`op`: setup, connect,
/// session build, and the bounded sync) and releases the claimed session's
/// in-flight lease EXACTLY ONCE — on success and on every error — before the
/// outcome is mapped to a status.
///
/// This is the ONLY lease-release site, and it is deliberately NOT `Drop`: a
/// mid-connect future drop must NOT retire the cancel tombstone (that would
/// reopen the store-without-fence bypass the tombstone closes). The release
/// only lets a resident tombstone resume TTL reaping; it never un-stores a
/// token. Generic over the operation and its success payload so the
/// exactly-once release is testable with a fake cycle.
async fn complete_after<R, St, F, Fut>(session: &St, op: F) -> Result<R, CycleError>
where
    St: ConnectSession,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<R, CycleError>>,
{
    let outcome = op().await;
    session.complete();
    outcome
}

/// The post-claim scope of a connect cycle: every Keychain/network object is
/// constructed HERE, on the worker thread (a busy slot builds none of them),
/// then the claimed grant is exchanged (the initial exchange, not a refresh),
/// the refresh token persisted, freshness validated, and the bounded sync run.
/// This runs with the session's in-flight lease held — [`complete_after`]
/// releases it on every outcome, INCLUDING a setup failure before the connect
/// begins (a leaked lease would pin the cancel tombstone forever). The held
/// permit covers the exchange, so the persisted refresh token cannot race a
/// parallel cycle.
async fn run_claimed_connect_cycle<St: ConnectSession>(
    account: &AccountId,
    grant: AuthorizationGrant,
    config: &TokenClientConfig,
    session: &St,
) -> Result<SyncReport, CycleError> {
    let hasher = DataProtectionAccountIdentityHasher::new().map_err(|_error| CycleError::Setup)?;
    let store = open_default_mailbox_store(account).map_err(|_error| CycleError::Setup)?;
    let refresh_store =
        DataProtectionRefreshTokenStore::new().map_err(|_error| CycleError::Setup)?;
    let transport = GmailTokenTransport::new().map_err(|_error| CycleError::Setup)?;
    let monotonic = SystemMonotonicClock::new();
    let wall_clock = SystemWallClock;
    let policy = default_sync_policy().ok_or(CycleError::Setup)?;

    // `connect_account` drops (wipes) the grant as soon as the exchange
    // consumes it and runs the fail-closed snapshot-conditional cancel fences.
    // A cancel arriving after the post-store fence is the disconnect (3d-3d)
    // backstop, which deletes any stored token regardless.
    let connected = connect_account(
        account,
        grant,
        config,
        &transport,
        &refresh_store,
        &monotonic,
        session,
    )
    .await
    .map_err(CycleError::Connect)?;
    let session = GmailSession::new(account.clone(), connected, &wall_clock)
        .map_err(|_error| CycleError::Session)?;
    gated_sync(account, session, &hasher, store, policy)
        .await
        .map_err(CycleError::Gated)
}

/// Begins a bounded sync for a newly-connected `account` on a background worker,
/// claiming the just-finished OAuth grant and exchanging it for tokens inside the
/// whole-cycle permit. Returns [`BeginOutcome::Busy`] — WITHOUT calling
/// [`ConnectSession::claim`], touching the Keychain, or spawning a worker — if a
/// cycle is already in flight for the slot: the grant is not consumed and the
/// caller may retry the same session. Only `account` and the `Send + 'static`
/// session cross the thread boundary; the grant and config are produced and
/// consumed on the worker thread, so they never need to be `Send`. The session
/// is injected as ONE [`ConnectSession`] so this crate never depends on the
/// bridge that owns the sessions, and so the claim and the cancel fences
/// provably reference the same session id. The claim yields the token-client
/// config alongside the grant because the closed dependency set keeps `url`
/// (the redirect's type) with the caller, not this composition.
#[must_use]
pub fn begin_connect_account_sync<St>(account: AccountId, session: St) -> BeginOutcome
where
    St: ConnectSession + Send + 'static,
{
    // The CONNECT begin: it never registers its cancel flag in the permit slot,
    // so a disconnect can never drop-abort the token exchange (see
    // `begin_connect_with`).
    let slot = account.clone();
    begin_connect_with(&slot, move || async move {
        status_for_cycle(&run_connect_account_cycle(&account, &session).await)
    })
}

/// A failure at some stage of the disconnect teardown. Kept internal: the
/// worker collapses every stage to [`STATUS_INTERNAL`] — which stage failed
/// would leak teardown progress, and the disconnecting flag stays set
/// regardless, so a retried disconnect converges.
enum TeardownError {
    /// A Keychain-backed setup step failed (the refresh-token store, the token
    /// transport, or the presence-checked mailbox-store open).
    Setup,
    /// The stored refresh token could not be deleted.
    TokenDelete,
    /// The mailbox + identity purge transaction failed.
    Purge,
}

/// Whether the disconnect teardown could CONFIRM the provider /revoke of the
/// stored token. Kept internal: the worker maps it onto the closed status set —
/// [`STATUS_SUCCEEDED`] for `Confirmed`/`NotNeeded`,
/// [`STATUS_SUCCEEDED_REVOKE_UNCONFIRMED`] for `Unconfirmed` — so a
/// locally-complete teardown whose revoke could not be confirmed is a DISTINCT
/// outcome the UI renders as "Disconnected — also revoke access in your Google
/// Account settings."
enum RevokeDisposition {
    /// A token was stored and the provider confirmed its revocation (on the
    /// first revoke attempt or the one retry).
    Confirmed,
    /// Nothing was stored, so there was nothing to revoke.
    NotNeeded,
    /// The revoke could not be confirmed: both revoke attempts failed, the
    /// token load failed (a token may be present but unreadable), or a token
    /// was present but the transport could not be constructed, so no revoke
    /// was attempted at all.
    Unconfirmed,
}

/// The disconnect teardown's fault-injectable core: load the stored token,
/// revoke it best-effort, delete it, then purge the local account data,
/// returning the revoke disposition on success. Runs INSIDE the held
/// disconnect gate, which is what serializes it behind any in-flight cycle.
/// `store` is `None` when the account has no database file: the purge then
/// no-ops without creating one.
async fn run_teardown_with<S, T, P, F, E>(
    account: &AccountId,
    refresh_store: &S,
    transport: Option<&T>,
    open_store: F,
) -> Result<RevokeDisposition, TeardownError>
where
    S: RefreshTokenStore,
    T: TokenTransport,
    P: AccountPurgeStore,
    F: FnOnce() -> Result<Option<P>, E>,
{
    // load-under-permit: an in-flight sync may rotate the token; only the
    // permit serializes us behind it. Loading at BEGIN instead could revoke a
    // rotated-out stale token and miss the live one.
    let token = refresh_store.load(account);
    // The revoke disposition, computed BEFORE the mandatory local teardown so
    // an unconfirmed revoke never aborts it. Ok(None) — nothing stored — has
    // nothing to revoke (`NotNeeded`). The two `Unconfirmed` arms: Err — the
    // load failed, so the token's liveness is UNKNOWN and the revoke cannot be
    // confirmed — and a `None` transport (its constructor failed) with a token
    // present, which cannot even attempt the revoke. On every arm the
    // idempotent delete and the purge still run, so the capability dies first
    // and the local teardown is never gated on a Keychain read fault or the
    // network.
    let disposition = match (&token, transport) {
        (Ok(Some(token)), Some(transport)) => {
            // revoke targets the ONE stored token; a rotated refresh token
            // abandoned unrevoked by the connect restore fence
            // (`finish_cancelled_cleanup`, restore-prior branch) is only
            // also-revoked here if Google /revoke is grant-scoped (the unverified
            // 3f assumption) — 3f now gates disconnect COMPLETENESS, not just the
            // connect fence. The revoke is BEST-EFFORT: the local delete/purge
            // below never gates on the network, so an offline consent withdrawal
            // still tears down — but whether the provider CONFIRMED the revoke is
            // now reported, not discarded.
            match revoke_best_effort(transport, token).await {
                RevokeOutcome::Confirmed => RevokeDisposition::Confirmed,
                RevokeOutcome::Failed => RevokeDisposition::Unconfirmed,
            }
        }
        (Ok(Some(_)), None) | (Err(_), _) => RevokeDisposition::Unconfirmed,
        (Ok(None), _) => RevokeDisposition::NotNeeded,
    };
    // The token capability dies BEFORE any local-store work: opening the
    // mailbox store can FAIL (corrupt DB, unavailable root key), and a
    // pre-delete open failure must never abort the mandatory token delete —
    // that would leave a usable credential behind. So delete first, then open
    // and purge, mapping an open failure to `Purge` (post-delete, retryable).
    refresh_store
        .delete(account)
        .map_err(|_error| TeardownError::TokenDelete)?;
    if let Some(store) = open_store().map_err(|_error| TeardownError::Purge)? {
        store
            .purge_account(account)
            .await
            .map_err(|_error| TeardownError::Purge)?;
    }
    Ok(disposition)
}

/// The disconnect teardown's production composition: every Keychain/network
/// object is constructed HERE, on the worker thread, so nothing but `account`
/// crosses the thread boundary. The mailbox-store open is presence-checked: a
/// never-connected account has no database file, and the purge must no-op
/// WITHOUT creating one (disconnect never creates artifacts). On success the
/// revoke disposition is returned so the worker can report an unconfirmed
/// /revoke as its own closed status.
async fn run_disconnect_teardown(account: &AccountId) -> Result<RevokeDisposition, TeardownError> {
    // The refresh store is the ONLY genuinely-fatal prerequisite: without it the
    // mandatory token delete cannot run.
    let refresh_store =
        DataProtectionRefreshTokenStore::new().map_err(|_error| TeardownError::Setup)?;
    // The transport is needed only for the BEST-EFFORT revoke: a construction
    // failure (TLS/reqwest builder) becomes a SKIPPED revoke, exactly like a
    // failed token load — it must never gate the mandatory local teardown.
    let transport = GmailTokenTransport::new().ok();
    // The mailbox store is opened LAZILY, AFTER the token delete inside
    // `run_teardown_with`, so a store-open failure can never precede — and thus
    // abort — the credential delete.
    run_teardown_with(account, &refresh_store, transport.as_ref(), || {
        open_default_mailbox_store_if_present(account)
    })
    .await
}

/// Spawns the disconnect worker for `account`: a plain thread that
/// blocking-acquires the slot's gate — serializing BEHIND any in-flight sync
/// or connect — then loads the stored refresh token, revokes it best-effort,
/// deletes it, and purges the account's local mailbox and identity in one
/// transaction.
///
/// Claims the slot's single-worker disconnect lease + sets the `disconnecting`
/// fence SYNCHRONOUSLY on the caller thread (via `permit::begin_disconnect`)
/// BEFORE spawning, so "`disconnect_begin` returned STARTED ⇒ no new sync can
/// begin" holds. Returns [`BeginOutcome::Busy`] WITHOUT spawning when a
/// disconnect worker is already active on the slot: a concurrent request
/// coalesces onto the running teardown rather than starting a second one that
/// could clear the fence early or tear down a freshly re-connected account.
/// That is NOT refusing withdrawal — the running worker owns it. A RETRY after
/// a FAILED teardown (fence still set, lease released) IS admitted and
/// converges.
///
/// This worker clears the fence via `permit::clear_disconnecting` on the whole
/// disconnect SUCCESS FAMILY — [`STATUS_SUCCEEDED`] (the revoke was confirmed,
/// or nothing was stored) and [`STATUS_SUCCEEDED_REVOKE_UNCONFIRMED`] (the
/// local teardown completed but the provider /revoke could NOT be confirmed)
/// alike; only a teardown FAILURE leaves it set (fail-closed), and the
/// idempotent teardown converges on retry. The single-worker lease is released
/// on EVERY outcome (success, failure, panic) as the `permit::DisconnectLease`
/// drops, so a panicked worker never strands the slot un-retryable.
///
/// UN-CANCELLABLE: the worker is NOT routed through `run_cycle`'s
/// `CANCEL_POLL_INTERVAL` poll, so the `cancel` flag in the returned handles
/// is inert — registered nowhere, observed nowhere. The teardown is short,
/// local, and must run to completion once started.
#[must_use = "the returned outcome is the only way to poll or coalesce the disconnect"]
pub fn begin_disconnect(account: AccountId) -> BeginOutcome {
    begin_disconnect_with(account, |account| async move {
        run_disconnect_teardown(&account).await
    })
}

/// The disconnect worker's spawn-and-run machinery, generic over the teardown
/// operation — exactly as `begin_with` is generic over the sync op — so the
/// disposition→status mapping and the fence policy are testable with a fake
/// teardown (the production [`run_disconnect_teardown`] builds Keychain- and
/// network-backed objects a test host cannot drive to a successful revoke).
///
/// `op` is HANDED a clone of the FENCED `account` (it does not choose its own),
/// so the slot that is fenced/cleared and the account that is torn down are the
/// same value by construction — a mismatch that could fence one slot while
/// purging another account is unrepresentable. The future is built and awaited
/// entirely on the worker thread, inside the held gate.
#[must_use = "the returned outcome is the only way to poll or coalesce the disconnect"]
fn begin_disconnect_with<F, Fut>(account: AccountId, op: F) -> BeginOutcome
where
    F: FnOnce(AccountId) -> Fut + Send + 'static,
    Fut: Future<Output = Result<RevokeDisposition, TeardownError>>,
{
    // Claim the single-worker lease + set the fence on THIS (caller) thread,
    // before any worker spawns. `None` ⇒ a disconnect is already active on the
    // slot ⇒ coalesce (do not spawn a second teardown).
    let Some(lease) = permit::begin_disconnect(&account) else {
        return BeginOutcome::Busy;
    };
    let status = Arc::new(AtomicI32::new(STATUS_RUNNING));
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_status = Arc::clone(&status);
    // The op tears down exactly the fenced account (a clone of it), never one of
    // its own choosing — see the fn doc.
    let op_account = account.clone();
    let spawned = std::thread::Builder::new()
        .name("tersa-disconnect".to_owned())
        .spawn(move || {
            // Declaration order = REVERSE drop order on a panic unwind: `permit`
            // releases the gate first, then `lease_guard` releases
            // `disconnect_active` (so a retry is admitted), then `terminal`
            // publishes STATUS_INTERNAL — preserving release-before-publish even
            // on a panic. The `disconnecting` fence is NOT cleared on that path
            // (fail-closed).
            let mut terminal = StatusOnDrop::new(worker_status);
            let lease_guard = lease;
            // Blocking-acquire the gate OFF any tokio runtime thread (the
            // runtime is built only below), bypassing the disconnecting check —
            // disconnect set that flag itself, so a flag-checking acquire would
            // self-deadlock.
            let permit = permit::acquire_disconnect_gate(&account);
            let outcome = match build_sync_runtime() {
                Ok(runtime) => match runtime.block_on(op(op_account)) {
                    // The local teardown COMPLETED: a confirmed revoke — or
                    // nothing stored to revoke — is the plain success; an
                    // unconfirmed revoke is the distinct "disconnected — also
                    // revoke access in your Google Account settings" code.
                    Ok(RevokeDisposition::Confirmed | RevokeDisposition::NotNeeded) => {
                        STATUS_SUCCEEDED
                    }
                    Ok(RevokeDisposition::Unconfirmed) => STATUS_SUCCEEDED_REVOKE_UNCONFIRMED,
                    // Anti-oracle preserved: which STAGE failed never leaks.
                    Err(_stage) => STATUS_INTERNAL,
                },
                Err(_error) => STATUS_INTERNAL,
            };
            // Release the gate BEFORE publishing the terminal status, mirroring
            // `spawn_cycle`: a poll that sees terminal can immediately re-claim.
            drop(permit);
            // FORK E: clear the disconnecting FENCE on the whole disconnect
            // SUCCESS FAMILY — SUCCEEDED and SUCCEEDED_REVOKE_UNCONFIRMED alike.
            // An unconfirmed revoke still tore down LOCALLY (the token is
            // deleted, the mailbox purged), so clearing only on plain SUCCEEDED
            // would leave the slot fenced FOREVER (no sync, no connect) until a
            // retried disconnect or a process restart. Only a teardown FAILURE
            // keeps the fence set (fail-closed): the teardown is idempotent, so
            // a retried disconnect converges; a restart clears the in-memory
            // flag. KNOWN GAP (not neutral): a retry after a PARTIAL teardown —
            // delete ok, purge failed, revoke unconfirmed — reports plain
            // SUCCEEDED because the token is gone (Ok(None)) by the retry. Since
            // 3e-2a, the ABSENCE of the revoke-unconfirmed signal is an
            // affirmative "revocation was fine" claim, which is FALSE here (the
            // grant may still be live at Google). The in-process fix is a sticky
            // per-slot `revoke_unconfirmed` bit OR'd into a later retry's
            // disposition (3e-2b); cross-restart durability is the deferred F6
            // marker. Bounded: the user saw the first attempt fail.
            if matches!(
                outcome,
                STATUS_SUCCEEDED | STATUS_SUCCEEDED_REVOKE_UNCONFIRMED
            ) {
                permit::clear_disconnecting(&account);
            }
            // Release the single-worker lease (clearing `disconnect_active`)
            // BEFORE publishing terminal, and AFTER clearing the fence: by the
            // time a caller can observe the terminal status and re-issue a
            // disconnect, `disconnect_active` is already clear, so it is admitted
            // (never spuriously refused). Combined with a coalescing begin never
            // touching the fence, no observable "fence cleared, lease held"
            // window can orphan the fence. On a panic this runs during unwind
            // (declaration order), keeping the fence set (fail-closed).
            drop(lease_guard);
            terminal.publish(outcome);
        });
    match spawned {
        // Dropping the join handle detaches the worker, as before.
        Ok(_worker) => BeginOutcome::Started(WorkerHandles { status, cancel }),
        // The thread never spawned, so the moved `lease` dropped with the un-run
        // closure — releasing `disconnect_active` so a retry is admitted — while
        // the `disconnecting` fence stays set (fail-closed). The returned handles
        // poll terminal immediately, like `spawn_cycle`'s refusal mapping.
        Err(_error) => BeginOutcome::Started(terminal_internal_handles()),
    }
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
    use tersa_application::oauth::{
        AuthorizationConfig, AuthorizationGrant, SystemMonotonicClock, prepare_authorization,
    };
    use tersa_application::sync::{SyncFailure, SyncFailureSource, SyncProtocolError};
    use tersa_application::token::{TokenClientConfig, TokenError};
    use url::Url;

    use super::{
        BeginOutcome, ConnectSession, CycleError, GatedSyncError, RevokeDisposition, RevokeOutcome,
        STATUS_CANCELLED, STATUS_GATE_BLOCKED, STATUS_INSUFFICIENT_SCOPE, STATUS_INTERNAL,
        STATUS_NEEDS_RECONNECT, STATUS_RUNNING, STATUS_SUCCEEDED,
        STATUS_SUCCEEDED_REVOKE_UNCONFIRMED, STATUS_SYNC_FAILED, TokenLifecycleError,
        begin_connect_account_sync, begin_connect_with, begin_default_account_sync,
        begin_disconnect, begin_disconnect_with, begin_with, complete_after, permit,
        revoke_best_effort, run_cycle, status_for_cycle, status_for_result,
    };

    /// A fake [`ConnectSession`]: `claim_missing` never produces a grant (the
    /// busy-slot and claim-miss tests); `claiming` yields a real grant and
    /// config exactly once (the setup-failure lease test). `claim_calls` and
    /// `completions` are shared counters, cloned out before the session moves
    /// onto the worker thread, so a test can prove the claim did or did not
    /// run and that the lease was released exactly once — or, on a claim-miss
    /// (which takes no lease), never.
    struct FakeConnectSession {
        cancelled: bool,
        grant: std::sync::Mutex<Option<(AuthorizationGrant, TokenClientConfig)>>,
        claim_calls: std::sync::Arc<AtomicUsize>,
        completions: std::sync::Arc<AtomicUsize>,
    }

    impl FakeConnectSession {
        fn claim_missing(cancelled: bool) -> Self {
            Self {
                cancelled,
                grant: std::sync::Mutex::new(None),
                claim_calls: std::sync::Arc::new(AtomicUsize::new(0)),
                completions: std::sync::Arc::new(AtomicUsize::new(0)),
            }
        }
        /// A session whose claim succeeds once. These tests never reach the
        /// connect itself: on this CI host (no provisioned Keychain for the
        /// unsigned test binary) the post-claim SETUP fails first — exactly
        /// the lease-release path under test.
        fn claiming(cancelled: bool) -> Self {
            Self {
                grant: std::sync::Mutex::new(Some((make_grant(), config()))),
                ..Self::claim_missing(cancelled)
            }
        }
    }

    impl ConnectSession for FakeConnectSession {
        fn claim(&self) -> Option<(AuthorizationGrant, TokenClientConfig)> {
            self.claim_calls.fetch_add(1, Ordering::SeqCst);
            self.grant.lock().unwrap().take()
        }
        fn is_cancelled(&self) -> bool {
            self.cancelled
        }
        fn complete(&self) {
            self.completions.fetch_add(1, Ordering::SeqCst);
        }
    }

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

    /// A real, finished authorization grant, as a successful
    /// [`ConnectSession::claim`] would yield it. Nothing here reaches the
    /// exchange in these tests — the post-claim setup fails first on CI — so
    /// the code and verifier only prove the claim path consumes a real grant.
    fn make_grant() -> AuthorizationGrant {
        let redirect = || Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        let authorization_config =
            AuthorizationConfig::new("test-client-id", redirect(), Duration::from_secs(60))
                .unwrap();
        let prepared =
            prepare_authorization(authorization_config, SystemMonotonicClock::new()).unwrap();
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
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Refresh(
                TokenLifecycleError::Token(TokenError::InsufficientScope)
            ))),
            STATUS_INSUFFICIENT_SCOPE
        );
        // A non-destructive/retryable token error stays on the retry code.
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Refresh(
                TokenLifecycleError::Token(TokenError::IdentityUnverified)
            ))),
            STATUS_SYNC_FAILED
        );
        // The connect path's two reconnect-recoverable outcomes: an unclaimable
        // grant (the login window elapsed), and an `invalid_grant` at the initial
        // exchange, which the token layer surfaces as ConsentRevoked.
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::ClaimMissing)),
            STATUS_NEEDS_RECONNECT
        );
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Connect(
                TokenLifecycleError::Token(TokenError::ConsentRevoked)
            ))),
            STATUS_NEEDS_RECONNECT
        );
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Connect(
                TokenLifecycleError::Token(TokenError::InsufficientScope)
            ))),
            STATUS_INSUFFICIENT_SCOPE
        );
        // Other exchange/store failures are opaque, non-reconnect, non-identity:
        // they collapse to the same retry code as every other non-gate failure.
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Connect(
                TokenLifecycleError::MissingRefreshToken
            ))),
            STATUS_SYNC_FAILED
        );
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Connect(
                TokenLifecycleError::Token(TokenError::Transport)
            ))),
            STATUS_SYNC_FAILED
        );
        // A connect aborted at the cancel fence reports the SAME closed cancel
        // code a mid-sync cancel yields — distinct from both the reconnect and
        // the retry codes.
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Connect(
                TokenLifecycleError::Cancelled
            ))),
            STATUS_CANCELLED
        );
        // A cancel whose local cleanup FAILED is NOT a clean cancel: a usable
        // token may remain in the Keychain, so it maps to the internal code
        // (3e surfaces "cancelled — please disconnect to be sure").
        assert_eq!(
            status_for_cycle(&Err::<(), _>(CycleError::Connect(
                TokenLifecycleError::CancelledCleanupIncomplete
            ))),
            STATUS_INTERNAL
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

    #[test]
    fn begin_connect_account_sync_with_a_claim_miss_needs_reconnect_without_keychain() {
        let slot = account("connect-claim-miss");
        let session = FakeConnectSession::claim_missing(false);
        let completions = std::sync::Arc::clone(&session.completions);
        let BeginOutcome::Started(handles) = begin_connect_account_sync(slot, session) else {
            panic!("a free slot must start a connect-account sync");
        };
        // The claim runs BEFORE any Keychain/network object is constructed, so on
        // this CI host (no provisioned Keychain) the cycle still reaches a terminal
        // status: a claim-miss maps to NEEDS_RECONNECT (re-consent), never to a
        // setup failure. This drives the real spawn/permit path end to end.
        assert_eq!(poll_until_terminal(&handles), STATUS_NEEDS_RECONNECT);
        // A claim-miss takes NO lease, so the worker must never complete one.
        assert_eq!(completions.load(Ordering::Acquire), 0);
    }

    #[test]
    fn a_claim_miss_on_a_cancelled_session_reports_cancelled_not_reconnect() {
        // A cancel that landed between the grant-store and the claim made the
        // grant unclaimable: the claim misses, but `is_cancelled` is true, so the
        // cycle must report the cancel code — not NEEDS_RECONNECT, which would
        // wrongly prompt the user to re-consent a flow they just cancelled.
        let slot = account("connect-claim-miss-cancelled");
        let session = FakeConnectSession::claim_missing(true);
        let completions = std::sync::Arc::clone(&session.completions);
        let BeginOutcome::Started(handles) = begin_connect_account_sync(slot, session) else {
            panic!("a free slot must start a connect-account sync");
        };
        assert_eq!(poll_until_terminal(&handles), STATUS_CANCELLED);
        // A claim-miss takes NO lease — even when the miss IS a cancel.
        assert_eq!(completions.load(Ordering::Acquire), 0);
    }

    #[test]
    fn a_setup_failure_after_a_successful_claim_releases_the_lease() {
        // A successful claim takes the session's in-flight lease; a SETUP
        // failure — before the connect begins — must still release it exactly
        // once, or the cancel tombstone stays pinned forever and `in_flight`
        // grows. On this CI host (no provisioned Keychain for the unsigned
        // test binary) the first Keychain-backed constructor fails with
        // `CycleError::Setup`, so this drives the setup-failure path end to
        // end. (The bridge's
        // `a_claimed_sessions_tombstone_is_pinned_by_the_lease_until_complete`
        // test covers the other half: once `complete_session` runs, a reap
        // past the TTL retires the tombstone.)
        let slot = account("connect-setup-failure-releases-lease");
        let session = FakeConnectSession::claiming(false);
        let completions = std::sync::Arc::clone(&session.completions);
        let BeginOutcome::Started(handles) = begin_connect_account_sync(slot, session) else {
            panic!("a free slot must start a connect-account sync");
        };
        assert_eq!(poll_until_terminal(&handles), STATUS_SYNC_FAILED);
        assert_eq!(
            completions.load(Ordering::Acquire),
            1,
            "a setup failure after a successful claim must release the lease exactly once"
        );
    }

    #[test]
    fn complete_after_releases_the_lease_exactly_once_on_success() {
        let session = FakeConnectSession::claim_missing(false);
        let outcome = test_runtime().block_on(complete_after(&session, || async {
            Ok::<_, CycleError>(())
        }));
        assert!(outcome.is_ok());
        assert_eq!(session.completions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn complete_after_releases_the_lease_exactly_once_on_error() {
        let session = FakeConnectSession::claim_missing(false);
        let outcome = test_runtime().block_on(complete_after(&session, || async {
            Err::<(), _>(CycleError::Setup)
        }));
        assert!(matches!(outcome, Err(CycleError::Setup)));
        assert_eq!(session.completions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn begin_connect_account_sync_on_a_busy_slot_is_busy_and_never_claims() {
        use std::sync::Arc;
        let slot = account("connect-sync-busy");
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
        let session = FakeConnectSession::claim_missing(false);
        let claim_calls = std::sync::Arc::clone(&session.claim_calls);
        // The Busy outcome proves no worker spawned; the counter proves the claim
        // was never called, so the grant is not consumed and the caller may retry
        // the same session. Both are structural: `begin_with` provably never runs
        // the op on a busy slot.
        match begin_connect_account_sync(slot.clone(), session) {
            BeginOutcome::Busy => {}
            BeginOutcome::Started(_) => panic!("a busy slot must not start a connect-account sync"),
        }
        assert_eq!(
            claim_calls.load(Ordering::Acquire),
            0,
            "a busy slot must not consume the grant: the claim must not run"
        );
        go.store(true, Ordering::Release);
        assert_eq!(poll_until_terminal(&holder), STATUS_SUCCEEDED);
    }

    /// Records the cross-object order of teardown steps (revoke, token delete,
    /// purge) so a test can assert the token capability dies before the cache
    /// purge.
    #[derive(Debug, Default)]
    struct OrderLog(std::sync::Mutex<Vec<&'static str>>);

    impl OrderLog {
        fn record(&self, step: &'static str) {
            self.0.lock().unwrap().push(step);
        }
        fn steps(&self) -> Vec<&'static str> {
            self.0.lock().unwrap().clone()
        }
    }

    /// A refresh-token store fake: holds one optional token, can fail the load
    /// or a leading run of deletes, and records every delete in the shared
    /// order log. Its delete is idempotent exactly like the production store.
    #[derive(Debug)]
    struct FakeRefreshStore {
        token: std::sync::Mutex<Option<zeroize::Zeroizing<String>>>,
        fail_load: bool,
        failing_deletes: AtomicUsize,
        log: std::sync::Arc<OrderLog>,
    }

    impl FakeRefreshStore {
        fn with_token(log: std::sync::Arc<OrderLog>) -> Self {
            Self {
                token: std::sync::Mutex::new(Some(zeroize::Zeroizing::new(
                    "refresh-token".to_owned(),
                ))),
                fail_load: false,
                failing_deletes: AtomicUsize::new(0),
                log,
            }
        }
        fn empty(log: std::sync::Arc<OrderLog>) -> Self {
            Self {
                token: std::sync::Mutex::new(None),
                ..Self::with_token(log)
            }
        }
        fn with_failing_load(log: std::sync::Arc<OrderLog>) -> Self {
            Self {
                fail_load: true,
                ..Self::with_token(log)
            }
        }
        fn fail_next_deletes(self, count: usize) -> Self {
            self.failing_deletes.store(count, Ordering::SeqCst);
            self
        }
        fn stored_token(&self) -> Option<String> {
            self.token
                .lock()
                .unwrap()
                .as_ref()
                .map(|token| token.as_str().to_owned())
        }
    }

    impl tersa_keychain_macos::oauth_token::RefreshTokenStore for FakeRefreshStore {
        fn store(
            &self,
            _account: &AccountId,
            token: &zeroize::Zeroizing<String>,
        ) -> Result<(), tersa_keychain_macos::oauth_token::RefreshTokenError> {
            *self.token.lock().unwrap() = Some(token.clone());
            Ok(())
        }
        fn load(
            &self,
            _account: &AccountId,
        ) -> Result<
            Option<zeroize::Zeroizing<String>>,
            tersa_keychain_macos::oauth_token::RefreshTokenError,
        > {
            if self.fail_load {
                return Err(tersa_keychain_macos::oauth_token::RefreshTokenError::OperationFailed);
            }
            Ok(self.token.lock().unwrap().clone())
        }
        fn delete(
            &self,
            _account: &AccountId,
        ) -> Result<(), tersa_keychain_macos::oauth_token::RefreshTokenError> {
            self.log.record("delete");
            let remaining = self.failing_deletes.load(Ordering::SeqCst);
            if remaining > 0 {
                self.failing_deletes.store(remaining - 1, Ordering::SeqCst);
                return Err(tersa_keychain_macos::oauth_token::RefreshTokenError::OperationFailed);
            }
            *self.token.lock().unwrap() = None;
            Ok(())
        }
    }

    /// A token transport that never exchanges or refreshes (the teardown only
    /// revokes) and records every revoked token, in order, in the shared log.
    #[derive(Debug)]
    struct RecordingTransport {
        revoked: std::sync::Mutex<Vec<String>>,
        fail_revoke: bool,
        failing_revokes: AtomicUsize,
        log: std::sync::Arc<OrderLog>,
    }

    impl RecordingTransport {
        fn new(log: std::sync::Arc<OrderLog>) -> Self {
            Self {
                revoked: std::sync::Mutex::new(Vec::new()),
                fail_revoke: false,
                failing_revokes: AtomicUsize::new(0),
                log,
            }
        }
        fn with_failing_revoke(self) -> Self {
            Self {
                fail_revoke: true,
                ..self
            }
        }
        /// Fails the next `count` revoke attempts, then succeeds — exercises the
        /// retry-once-then-confirm path (vs `with_failing_revoke`, which fails
        /// every attempt).
        fn fail_next_revokes(self, count: usize) -> Self {
            self.failing_revokes.store(count, Ordering::SeqCst);
            self
        }
        fn revoked(&self) -> Vec<String> {
            self.revoked.lock().unwrap().clone()
        }
    }

    impl tersa_application::token::TokenTransport for RecordingTransport {
        fn exchange(
            &self,
            _request: tersa_application::token::ExchangeRequest,
        ) -> tersa_application::mailbox::BoxFuture<
            '_,
            Result<
                tersa_application::token::TokenResponse,
                tersa_application::token::TokenTransportError,
            >,
        > {
            Box::pin(async { Err(tersa_application::token::TokenTransportError::Transport) })
        }
        fn refresh(
            &self,
            _request: tersa_application::token::RefreshRequest,
        ) -> tersa_application::mailbox::BoxFuture<
            '_,
            Result<
                tersa_application::token::TokenResponse,
                tersa_application::token::TokenTransportError,
            >,
        > {
            Box::pin(async { Err(tersa_application::token::TokenTransportError::Transport) })
        }
        fn revoke<'a>(
            &'a self,
            token: &'a zeroize::Zeroizing<String>,
        ) -> tersa_application::mailbox::BoxFuture<
            'a,
            Result<(), tersa_application::token::TokenTransportError>,
        > {
            // Record INSIDE the awaited future: a revoke that was constructed
            // but never polled leaves no trace, so the assertions fail rather
            // than pass vacuously.
            Box::pin(async move {
                self.log.record("revoke");
                self.revoked.lock().unwrap().push(token.as_str().to_owned());
                if self.fail_revoke {
                    return Err(tersa_application::token::TokenTransportError::Transport);
                }
                // Atomically consume one from the failure budget (no non-atomic
                // read-modify-write): `checked_sub` yields `None` at 0, so
                // `fetch_update` returns `Ok` only while a failure remains.
                if self
                    .failing_revokes
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_ok()
                {
                    return Err(tersa_application::token::TokenTransportError::Transport);
                }
                Ok(())
            })
        }
    }

    /// A purge-store fake: fails a leading run of purges and records every
    /// purge call in the shared order log.
    #[derive(Debug)]
    struct FakePurgeStore {
        purges: AtomicUsize,
        failing_purges: AtomicUsize,
        log: std::sync::Arc<OrderLog>,
    }

    impl FakePurgeStore {
        fn new(log: std::sync::Arc<OrderLog>) -> Self {
            Self {
                purges: AtomicUsize::new(0),
                failing_purges: AtomicUsize::new(0),
                log,
            }
        }
        fn fail_next_purges(self, count: usize) -> Self {
            self.failing_purges.store(count, Ordering::SeqCst);
            self
        }
        fn purge_calls(&self) -> usize {
            self.purges.load(Ordering::SeqCst)
        }
    }

    impl tersa_application::mailbox::AccountPurgeStore for FakePurgeStore {
        fn purge_account<'a>(
            &'a self,
            _account: &'a AccountId,
        ) -> tersa_application::mailbox::BoxFuture<
            'a,
            Result<(), tersa_application::mailbox::MailboxStoreError>,
        > {
            Box::pin(async move {
                self.log.record("purge");
                self.purges.fetch_add(1, Ordering::SeqCst);
                let remaining = self.failing_purges.load(Ordering::SeqCst);
                if remaining > 0 {
                    self.failing_purges.store(remaining - 1, Ordering::SeqCst);
                    return Err(tersa_application::mailbox::MailboxStoreError::Storage);
                }
                Ok(())
            })
        }
    }

    fn drive_teardown<S, T, P>(
        slot: &AccountId,
        refresh_store: &S,
        transport: &T,
        store: Option<&P>,
    ) -> Result<RevokeDisposition, super::TeardownError>
    where
        S: tersa_keychain_macos::oauth_token::RefreshTokenStore,
        T: tersa_application::token::TokenTransport,
        P: tersa_application::mailbox::AccountPurgeStore,
    {
        // Mirror the production call shape: an OPTIONAL transport (a `None`
        // skips the revoke) and a LAZY store opener invoked AFTER the delete.
        // The already-built fake is handed back by reference through the closure.
        test_runtime().block_on(super::run_teardown_with(
            slot,
            refresh_store,
            Some(transport),
            || Ok::<_, super::TeardownError>(store),
        ))
    }

    #[test]
    fn begin_disconnect_never_cancels_a_connect_holding_the_slot() {
        use std::sync::Arc;
        // FORK B (a): a connect holds the slot with NO registered cancel flag,
        // so a disconnect begin has nothing to signal — the connect is never
        // drop-aborted mid-token-exchange.
        let slot = account("disconnect-connect-never-cancelled");
        let go = Arc::new(AtomicBool::new(false));
        let release = Arc::clone(&go);
        let BeginOutcome::Started(handles) = begin_connect_with(&slot, move || async move {
            while !release.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            STATUS_SUCCEEDED
        }) else {
            panic!("a free slot must start the connect");
        };
        let _lease = permit::begin_disconnect(&slot);
        // Give any (wrongly) signaled cancel several poll intervals to land.
        std::thread::sleep(Duration::from_millis(150));
        go.store(true, Ordering::Release);
        assert_eq!(
            poll_until_terminal(&handles),
            STATUS_SUCCEEDED,
            "the connect must run to completion, never cancelled"
        );
        assert!(
            !handles.cancel.load(Ordering::Acquire),
            "a connect's cancel flag must stay unset"
        );
        // The slot IS marked disconnecting, though: new begins refuse.
        assert!(matches!(
            begin_with(&slot, || async { STATUS_SUCCEEDED }),
            BeginOutcome::Busy
        ));
        permit::clear_disconnecting(&slot);
    }

    #[test]
    fn begin_disconnect_prompt_cancels_a_sync_holding_the_slot() {
        // FORK B (b): a sync registered its cancel flag, so the disconnect
        // begin signals it; the sync observes it within its poll interval,
        // drops the in-flight future, and releases the gate.
        let slot = account("disconnect-sync-cancelled");
        let BeginOutcome::Started(handles) = begin_with(&slot, pending::<i32>) else {
            panic!("a free slot must start the sync");
        };
        let _lease = permit::begin_disconnect(&slot);
        assert_eq!(poll_until_terminal(&handles), STATUS_CANCELLED);
        // The slot still refuses new begins: disconnecting stays set until the
        // teardown succeeds.
        assert!(matches!(
            begin_with(&slot, || async { STATUS_SUCCEEDED }),
            BeginOutcome::Busy
        ));
        permit::clear_disconnecting(&slot);
    }

    #[test]
    fn begins_refuse_while_disconnecting_and_the_grant_stays_unclaimed() {
        let slot = account("disconnect-begin-refusal");
        let _lease = permit::begin_disconnect(&slot);
        // A sync begin refuses WITHOUT building any Keychain/network object:
        // the refusal happens inside the permit check, before the op is ever
        // built, exactly like the busy-slot tests prove for a held slot.
        match begin_default_account_sync(slot.clone(), config()) {
            BeginOutcome::Busy => {}
            BeginOutcome::Started(_) => panic!("a disconnecting slot must refuse a sync begin"),
        }
        // A connect begin refuses WITHOUT claiming the grant: the caller may
        // retry the same OAuth session after the teardown.
        let session = FakeConnectSession::claim_missing(false);
        let claim_calls = std::sync::Arc::clone(&session.claim_calls);
        match begin_connect_account_sync(slot.clone(), session) {
            BeginOutcome::Busy => {}
            BeginOutcome::Started(_) => panic!("a disconnecting slot must refuse a connect begin"),
        }
        assert_eq!(
            claim_calls.load(Ordering::Acquire),
            0,
            "a refused connect begin must not consume the grant"
        );
        permit::clear_disconnecting(&slot);
    }

    #[test]
    fn a_failed_disconnect_worker_leaves_the_slot_disconnecting() {
        // FORK E, setup-failure half, end to end: on this CI host (no
        // provisioned Keychain for the unsigned test binary) the teardown's
        // first Keychain-backed constructor fails, so the worker reports the
        // internal code — and the disconnecting flag STAYS set.
        let slot = account("disconnect-setup-failure");
        // `begin_disconnect` now sets the fence + claims the lease itself.
        let BeginOutcome::Started(handles) = begin_disconnect(slot.clone()) else {
            panic!("a free slot must start the disconnect worker");
        };
        assert_eq!(poll_until_terminal(&handles), STATUS_INTERNAL);
        assert!(matches!(
            begin_with(&slot, || async { STATUS_SUCCEEDED }),
            BeginOutcome::Busy
        ));
        // A retried disconnect converges on a healthy host; clear the flag as
        // a successful teardown would so this slot is reusable.
        permit::clear_disconnecting(&slot);
    }

    #[test]
    fn teardown_revokes_then_deletes_then_purges() {
        // The load-under-permit order: the ONE stored token is revoked
        // best-effort, the capability dies (delete), and only then does the
        // cache purge run.
        let slot = account("disconnect-order");
        let log = std::sync::Arc::new(OrderLog::default());
        let refresh_store = FakeRefreshStore::with_token(std::sync::Arc::clone(&log));
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log));
        let purge_store = FakePurgeStore::new(std::sync::Arc::clone(&log));
        let outcome = drive_teardown(&slot, &refresh_store, &transport, Some(&purge_store));
        assert!(matches!(outcome, Ok(RevokeDisposition::Confirmed)));
        assert_eq!(log.steps(), vec!["revoke", "delete", "purge"]);
        assert_eq!(transport.revoked(), vec!["refresh-token".to_owned()]);
        assert_eq!(refresh_store.stored_token(), None);
    }

    #[test]
    fn teardown_with_nothing_stored_skips_the_revoke_and_still_purges() {
        // Ok(None): a never-connected (or already-torn-down) account revokes
        // nothing but still deletes (idempotent) and purges.
        let slot = account("disconnect-empty-token");
        let log = std::sync::Arc::new(OrderLog::default());
        let refresh_store = FakeRefreshStore::empty(std::sync::Arc::clone(&log));
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log));
        let purge_store = FakePurgeStore::new(std::sync::Arc::clone(&log));
        let outcome = drive_teardown(&slot, &refresh_store, &transport, Some(&purge_store));
        // Nothing stored → nothing to revoke: NotNeeded (maps to plain
        // SUCCEEDED at the worker, NOT the revoke-unconfirmed code).
        assert!(matches!(outcome, Ok(RevokeDisposition::NotNeeded)));
        assert_eq!(log.steps(), vec!["delete", "purge"]);
        assert!(transport.revoked().is_empty());
    }

    #[test]
    fn teardown_with_a_failed_load_skips_the_revoke_and_still_tears_down() {
        // Err on load: whether a token lives at the provider is unknown, so
        // nothing is revoked — but the idempotent delete and the purge still
        // run, so the local teardown is never gated on a Keychain read fault.
        let slot = account("disconnect-load-failure");
        let log = std::sync::Arc::new(OrderLog::default());
        let refresh_store = FakeRefreshStore::with_failing_load(std::sync::Arc::clone(&log));
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log));
        let purge_store = FakePurgeStore::new(std::sync::Arc::clone(&log));
        let outcome = drive_teardown(&slot, &refresh_store, &transport, Some(&purge_store));
        // An unreadable token can never be confirmed revoked: Unconfirmed.
        assert!(matches!(outcome, Ok(RevokeDisposition::Unconfirmed)));
        assert_eq!(log.steps(), vec!["delete", "purge"]);
        assert!(transport.revoked().is_empty());
    }

    #[test]
    fn teardown_without_a_database_file_purges_nothing_and_succeeds() {
        // A never-connected account has no database file: the store is None
        // and the purge no-ops — the revoke and delete still run.
        let slot = account("disconnect-absent-db");
        let log = std::sync::Arc::new(OrderLog::default());
        let refresh_store = FakeRefreshStore::with_token(std::sync::Arc::clone(&log));
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log));
        let outcome = drive_teardown(&slot, &refresh_store, &transport, None::<&FakePurgeStore>);
        assert!(matches!(outcome, Ok(RevokeDisposition::Confirmed)));
        assert_eq!(log.steps(), vec!["revoke", "delete"]);
    }

    #[test]
    fn a_failed_revoke_does_not_gate_the_local_teardown() {
        // Offline withdrawal: the revoke fails (and so does its one retry),
        // but the delete and purge still run and the teardown SUCCEEDS.
        let slot = account("disconnect-offline-revoke");
        let log = std::sync::Arc::new(OrderLog::default());
        let refresh_store = FakeRefreshStore::with_token(std::sync::Arc::clone(&log));
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log)).with_failing_revoke();
        let purge_store = FakePurgeStore::new(std::sync::Arc::clone(&log));
        let outcome = drive_teardown(&slot, &refresh_store, &transport, Some(&purge_store));
        // Both revoke attempts failed, so the revoke is UNCONFIRMED — but the
        // teardown still SUCCEEDS locally (Ok, not Err).
        assert!(matches!(outcome, Ok(RevokeDisposition::Unconfirmed)));
        // Best-effort with ONE retry: exactly two revoke attempts, then the
        // local teardown proceeds.
        assert_eq!(log.steps(), vec!["revoke", "revoke", "delete", "purge"]);
        assert_eq!(transport.revoked().len(), 2);
    }

    #[test]
    fn a_failed_token_delete_aborts_before_the_purge() {
        // The capability must die before the cache purge: a failed delete
        // aborts the teardown and the purge NEVER runs while a usable token
        // may remain.
        let slot = account("disconnect-delete-failure");
        let log = std::sync::Arc::new(OrderLog::default());
        let refresh_store =
            FakeRefreshStore::with_token(std::sync::Arc::clone(&log)).fail_next_deletes(1);
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log));
        let purge_store = FakePurgeStore::new(std::sync::Arc::clone(&log));
        let outcome = drive_teardown(&slot, &refresh_store, &transport, Some(&purge_store));
        assert!(matches!(outcome, Err(super::TeardownError::TokenDelete)));
        assert_eq!(purge_store.purge_calls(), 0);
        assert_eq!(log.steps(), vec!["revoke", "delete"]);
    }

    #[test]
    fn an_unopenable_store_still_revokes_and_deletes_then_fails_at_the_purge() {
        // F1 (Opus/Sol): the mailbox-store OPEN can fail (corrupt DB, unavailable
        // root key), and it is opened LAZILY inside the teardown — AFTER the
        // token delete. So a store-open failure must NOT abort the mandatory
        // token delete (which would leave a usable credential behind); the
        // revoke and delete still run, and only then does the teardown fail at
        // the (post-delete, retryable) purge stage.
        let slot = account("disconnect-unopenable-store");
        let log = std::sync::Arc::new(OrderLog::default());
        let refresh_store = FakeRefreshStore::with_token(std::sync::Arc::clone(&log));
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log));
        let outcome = test_runtime().block_on(super::run_teardown_with(
            &slot,
            &refresh_store,
            Some(&transport),
            // The lazy opener FAILS — as a corrupt DB or unavailable root key
            // would — instead of yielding a store.
            || Err::<Option<FakePurgeStore>, _>(super::TeardownError::Purge),
        ));
        assert!(matches!(outcome, Err(super::TeardownError::Purge)));
        // The credential died FIRST, despite the store being unopenable.
        assert_eq!(log.steps(), vec!["revoke", "delete"]);
        assert_eq!(
            refresh_store.stored_token(),
            None,
            "the token is deleted even when the store cannot be opened"
        );
    }

    #[test]
    fn a_failed_teardown_converges_on_retry_and_the_flag_follows_success() {
        // FORK E, retry-convergence half: a teardown whose purge fails once
        // leaves the capability destroyed (delete ran first) and the flag set;
        // a retry with the fault cleared is idempotent and succeeds, and ONLY
        // that success clears the flag.
        let slot = account("disconnect-fork-e-retry");
        let log = std::sync::Arc::new(OrderLog::default());
        let refresh_store = FakeRefreshStore::with_token(std::sync::Arc::clone(&log));
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log));
        let purge_store = FakePurgeStore::new(std::sync::Arc::clone(&log)).fail_next_purges(1);

        // The FFI marks the slot disconnecting at BEGIN.
        let _lease = permit::begin_disconnect(&slot);
        let first = drive_teardown(&slot, &refresh_store, &transport, Some(&purge_store));
        assert!(matches!(first, Err(super::TeardownError::Purge)));
        assert_eq!(
            refresh_store.stored_token(),
            None,
            "the token capability dies before the failed purge"
        );
        // The worker clears the flag ONLY on the success family, so a failed
        // teardown leaves it set here.
        assert!(
            permit::try_acquire(&slot, None).is_none(),
            "a failed teardown leaves the slot disconnecting"
        );
        // Retry with the fault cleared: the load now finds nothing (the delete
        // already ran), so no second revoke fires; delete is an idempotent
        // no-op; the purge succeeds.
        let second = drive_teardown(&slot, &refresh_store, &transport, Some(&purge_store));
        // Nothing stored → NotNeeded: this is the accepted risk of the
        // success-family fence clear — a retry after a PARTIAL teardown (delete
        // ok, purge failed, revoke unconfirmed) reports the PLAIN success
        // because the token is gone by the retry (durable revoke-memory is the
        // deferred F6 marker, not this slice).
        assert!(matches!(second, Ok(RevokeDisposition::NotNeeded)));
        permit::clear_disconnecting(&slot);
        assert!(
            permit::try_acquire(&slot, None).is_some(),
            "a successful teardown reopens the slot"
        );
        assert_eq!(transport.revoked(), vec!["refresh-token".to_owned()]);
        assert_eq!(
            log.steps(),
            vec!["revoke", "delete", "purge", "delete", "purge"]
        );
    }

    #[test]
    fn revoke_best_effort_confirms_a_first_try_success() {
        let log = std::sync::Arc::new(OrderLog::default());
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log));
        let token = zeroize::Zeroizing::new("refresh-token".to_owned());
        let outcome = test_runtime().block_on(revoke_best_effort(&transport, &token));
        assert!(matches!(outcome, RevokeOutcome::Confirmed));
        assert_eq!(transport.revoked(), vec!["refresh-token".to_owned()]);
    }

    #[test]
    fn revoke_best_effort_confirms_when_the_one_retry_succeeds() {
        // The first attempt fails, the retry succeeds: Confirmed — and exactly
        // two attempts were made (the retry is fired ONCE, never more).
        let log = std::sync::Arc::new(OrderLog::default());
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log)).fail_next_revokes(1);
        let token = zeroize::Zeroizing::new("refresh-token".to_owned());
        let outcome = test_runtime().block_on(revoke_best_effort(&transport, &token));
        assert!(matches!(outcome, RevokeOutcome::Confirmed));
        assert_eq!(transport.revoked().len(), 2);
    }

    #[test]
    fn revoke_best_effort_fails_only_when_both_attempts_fail() {
        let log = std::sync::Arc::new(OrderLog::default());
        let transport = RecordingTransport::new(std::sync::Arc::clone(&log)).with_failing_revoke();
        let token = zeroize::Zeroizing::new("refresh-token".to_owned());
        let outcome = test_runtime().block_on(revoke_best_effort(&transport, &token));
        assert!(matches!(outcome, RevokeOutcome::Failed));
        assert_eq!(transport.revoked().len(), 2);
    }

    #[test]
    fn teardown_without_a_transport_and_a_token_present_is_unconfirmed() {
        // The transport constructor failed: a token exists but no revoke can be
        // attempted — Unconfirmed — while the delete and purge still run.
        let slot = account("disconnect-no-transport-disposition");
        let log = std::sync::Arc::new(OrderLog::default());
        let refresh_store = FakeRefreshStore::with_token(std::sync::Arc::clone(&log));
        let purge_store = FakePurgeStore::new(std::sync::Arc::clone(&log));
        let outcome = test_runtime().block_on(super::run_teardown_with(
            &slot,
            &refresh_store,
            None::<&RecordingTransport>,
            || Ok::<_, super::TeardownError>(Some(&purge_store)),
        ));
        assert!(matches!(outcome, Ok(RevokeDisposition::Unconfirmed)));
        assert_eq!(log.steps(), vec!["delete", "purge"]);
        assert_eq!(refresh_store.stored_token(), None);
    }

    /// Drives the REAL disconnect-worker machinery — the lease, fence, gate,
    /// disposition→status mapping, fence-clear policy, and terminal publish —
    /// over a fake teardown, exactly as the `begin_with` tests drive the sync
    /// machinery with a fake op. The fakes move into the worker op; their
    /// shared order log stays readable after the terminal status is published.
    fn begin_fake_disconnect(
        slot: &AccountId,
        refresh_store: FakeRefreshStore,
        transport: Option<RecordingTransport>,
        purge_store: FakePurgeStore,
    ) -> super::WorkerHandles {
        let BeginOutcome::Started(handles) =
            begin_disconnect_with(slot.clone(), move |account| async move {
                super::run_teardown_with(&account, &refresh_store, transport.as_ref(), || {
                    Ok::<_, super::TeardownError>(Some(&purge_store))
                })
                .await
            })
        else {
            panic!("a free slot must start the disconnect worker");
        };
        handles
    }

    #[test]
    fn a_successful_disconnect_with_a_confirmed_revoke_reports_succeeded_and_clears_the_fence() {
        // The confirmed-revoke happy path: plain SUCCEEDED, fence cleared.
        let slot = account("disconnect-worker-confirmed");
        let log = std::sync::Arc::new(OrderLog::default());
        let handles = begin_fake_disconnect(
            &slot,
            FakeRefreshStore::with_token(std::sync::Arc::clone(&log)),
            Some(RecordingTransport::new(std::sync::Arc::clone(&log))),
            FakePurgeStore::new(std::sync::Arc::clone(&log)),
        );
        assert_eq!(poll_until_terminal(&handles), STATUS_SUCCEEDED);
        assert!(
            permit::try_acquire(&slot, None).is_some(),
            "the fence clears on the confirmed success"
        );
        assert_eq!(log.steps(), vec!["revoke", "delete", "purge"]);
    }

    #[test]
    fn a_successful_disconnect_with_nothing_stored_reports_succeeded_not_unconfirmed() {
        // Ok(None) → NotNeeded → plain SUCCEEDED, NOT the revoke-unconfirmed
        // code: a never-connected account must not be told to revoke in its
        // Google settings.
        let slot = account("disconnect-worker-not-needed");
        let log = std::sync::Arc::new(OrderLog::default());
        let handles = begin_fake_disconnect(
            &slot,
            FakeRefreshStore::empty(std::sync::Arc::clone(&log)),
            Some(RecordingTransport::new(std::sync::Arc::clone(&log))),
            FakePurgeStore::new(std::sync::Arc::clone(&log)),
        );
        assert_eq!(poll_until_terminal(&handles), STATUS_SUCCEEDED);
        assert!(
            permit::try_acquire(&slot, None).is_some(),
            "the fence clears on the nothing-to-revoke success"
        );
        assert_eq!(log.steps(), vec!["delete", "purge"]);
    }

    #[test]
    fn a_successful_disconnect_with_an_unconfirmed_revoke_reports_3_and_clears_the_fence() {
        // ★ REQUIRED regression (Fable): teardown SUCCESS + revoke FAILED
        // (present token, both revoke attempts fail) must publish
        // STATUS_SUCCEEDED_REVOKE_UNCONFIRMED AND clear the disconnecting
        // fence. A success-only fence clear would leave the slot fenced
        // FOREVER (no sync, no connect) until a retried disconnect or a
        // restart — this is the test that would have caught that bug.
        let slot = account("disconnect-worker-revoke-unconfirmed");
        let log = std::sync::Arc::new(OrderLog::default());
        let handles = begin_fake_disconnect(
            &slot,
            FakeRefreshStore::with_token(std::sync::Arc::clone(&log)),
            Some(RecordingTransport::new(std::sync::Arc::clone(&log)).with_failing_revoke()),
            FakePurgeStore::new(std::sync::Arc::clone(&log)),
        );
        assert_eq!(
            poll_until_terminal(&handles),
            STATUS_SUCCEEDED_REVOKE_UNCONFIRMED
        );
        assert!(
            permit::try_acquire(&slot, None).is_some(),
            "the fence must clear on the unconfirmed-revoke success, or the slot stays fenced forever"
        );
        // Both revoke attempts fired before the local teardown proceeded.
        assert_eq!(log.steps(), vec!["revoke", "revoke", "delete", "purge"]);
    }

    #[test]
    fn a_disconnect_with_no_transport_reports_3_and_clears_the_fence() {
        // The transport constructor failed with a token present: no revoke
        // could be attempted → Unconfirmed → the distinct code, fence cleared.
        let slot = account("disconnect-worker-no-transport");
        let log = std::sync::Arc::new(OrderLog::default());
        let handles = begin_fake_disconnect(
            &slot,
            FakeRefreshStore::with_token(std::sync::Arc::clone(&log)),
            None,
            FakePurgeStore::new(std::sync::Arc::clone(&log)),
        );
        assert_eq!(
            poll_until_terminal(&handles),
            STATUS_SUCCEEDED_REVOKE_UNCONFIRMED
        );
        assert!(
            permit::try_acquire(&slot, None).is_some(),
            "the fence must clear on the unconfirmed (no-transport) success"
        );
        assert_eq!(log.steps(), vec!["delete", "purge"]);
    }

    #[test]
    fn a_disconnect_with_an_unreadable_token_reports_3_and_clears_the_fence() {
        // Err on the token load: a token may be present but unreadable, so the
        // revoke can never be confirmed → Unconfirmed → the distinct code,
        // fence cleared.
        let slot = account("disconnect-worker-load-err");
        let log = std::sync::Arc::new(OrderLog::default());
        let handles = begin_fake_disconnect(
            &slot,
            FakeRefreshStore::with_failing_load(std::sync::Arc::clone(&log)),
            Some(RecordingTransport::new(std::sync::Arc::clone(&log))),
            FakePurgeStore::new(std::sync::Arc::clone(&log)),
        );
        assert_eq!(
            poll_until_terminal(&handles),
            STATUS_SUCCEEDED_REVOKE_UNCONFIRMED
        );
        assert!(
            permit::try_acquire(&slot, None).is_some(),
            "the fence must clear on the unconfirmed (unreadable-token) success"
        );
        assert_eq!(log.steps(), vec!["delete", "purge"]);
    }
}
