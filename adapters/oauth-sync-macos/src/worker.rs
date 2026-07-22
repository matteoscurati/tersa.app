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
use tersa_application::mailbox::{AccountId, MailboxStore};
use tersa_application::sync::SyncPolicy;

use crate::permit::{self, WholeCyclePermit};
use crate::{GatedSyncError, GmailSession, build_sync_runtime, gated_sync};

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
/// still-pending sync future. Generic over the success payload, which is discarded,
/// so tests can drive it without constructing a `SyncReport`.
async fn run_cycle<F, Fut, R>(op: F, cancel: &AtomicBool) -> i32
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<R, GatedSyncError>>,
{
    let mut sync = pin!(op());
    loop {
        if cancel.load(Ordering::Acquire) {
            return STATUS_CANCELLED;
        }
        // `timeout` polls the SAME future each interval (it borrows, never restarts
        // it); an elapsed interval just yields control back to re-check the flag.
        match tokio::time::timeout(CANCEL_POLL_INTERVAL, sync.as_mut()).await {
            Ok(result) => return status_for_result(&result),
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
fn spawn_cycle<F, Fut, R>(permit: WholeCyclePermit, op: F) -> WorkerHandles
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<R, GatedSyncError>>,
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
fn begin_with<F, Fut, R>(account: &AccountId, op: F) -> BeginOutcome
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<R, GatedSyncError>>,
{
    let Some(permit) = permit::try_acquire(account) else {
        return BeginOutcome::Busy;
    };
    BeginOutcome::Started(spawn_cycle(permit, op))
}

/// Begins a bounded sync for `account` on a background worker, holding the slot's
/// whole-cycle permit for the entire gate-to-write cycle. Returns
/// [`BeginOutcome::Busy`] without spawning if a cycle is already in flight for the
/// slot. This is the production entry point the FFI layer (a later slice) wraps.
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
    // can be borrowed by `gated_sync` on the worker thread.
    let slot = account.clone();
    begin_with(&slot, move || async move {
        gated_sync(&account, session, &hasher, store, policy).await
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests build a known-good runtime and assert on it"
    )]

    use std::future::{pending, ready};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use tersa_application::identity::{GateError, HasherError};
    use tersa_application::mailbox::AccountId;
    use tersa_application::sync::{SyncFailure, SyncFailureSource, SyncProtocolError};

    use super::{
        BeginOutcome, GatedSyncError, STATUS_CANCELLED, STATUS_GATE_BLOCKED, STATUS_RUNNING,
        STATUS_SUCCEEDED, STATUS_SYNC_FAILED, begin_with, run_cycle,
    };

    fn account(id: &str) -> AccountId {
        AccountId::new(id).unwrap()
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn drive_run_cycle<F, Fut, R>(op: F, cancel: &AtomicBool) -> i32
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<R, GatedSyncError>>,
    {
        test_runtime().block_on(run_cycle(op, cancel))
    }

    #[test]
    fn a_completed_cycle_maps_to_its_closed_status() {
        let cancel = AtomicBool::new(false);
        assert_eq!(
            drive_run_cycle(|| ready(Ok::<(), GatedSyncError>(())), &cancel),
            STATUS_SUCCEEDED
        );
        assert_eq!(
            drive_run_cycle(
                || ready(Err::<(), _>(GatedSyncError::Gate(GateError::Hasher(
                    HasherError::Unavailable
                )))),
                &cancel
            ),
            STATUS_GATE_BLOCKED
        );
        // A lost identity race collapses into the SAME gate-blocked code — no oracle.
        assert_eq!(
            drive_run_cycle(
                || ready(Err::<(), _>(GatedSyncError::Gate(GateError::Store(
                    tersa_application::mailbox::MailboxStoreError::IdentityRaced
                )))),
                &cancel
            ),
            STATUS_GATE_BLOCKED
        );
        // A sync failure — including a fence trip — collapses into sync-failed.
        assert_eq!(
            drive_run_cycle(
                || ready(Err::<(), _>(GatedSyncError::Sync(
                    SyncFailure::from_source_for_test(SyncFailureSource::IdentityFenced)
                ))),
                &cancel
            ),
            STATUS_SYNC_FAILED
        );
        assert_eq!(
            drive_run_cycle(
                || ready(Err::<(), _>(GatedSyncError::Sync(
                    SyncFailure::from_source_for_test(SyncFailureSource::Protocol(
                        SyncProtocolError::OversizedPage
                    ))
                ))),
                &cancel
            ),
            STATUS_SYNC_FAILED
        );
    }

    #[test]
    fn a_preset_cancel_stops_before_running_the_cycle() {
        let cancel = AtomicBool::new(true);
        // The op would hang forever; a cancel already set returns immediately.
        assert_eq!(
            drive_run_cycle(pending::<Result<(), GatedSyncError>>, &cancel),
            STATUS_CANCELLED
        );
    }

    #[test]
    fn cancel_is_observed_promptly_and_drops_the_in_flight_future() {
        use std::sync::Arc;
        // A future that never completes but records, on Drop, that it was dropped
        // mid-flight (i.e. cancelled rather than run to completion).
        struct DropFlag(Arc<AtomicBool>);
        impl Future for DropFlag {
            type Output = Result<(), GatedSyncError>;
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
            Ok::<(), GatedSyncError>(())
        }) else {
            panic!("the first begin on a free slot must start a worker");
        };

        // The Busy outcome IS the proof that no second worker spawned: only the
        // Started path calls into the spawn machinery.
        match begin_with(&slot, || async { Ok::<(), GatedSyncError>(()) }) {
            BeginOutcome::Busy => {}
            BeginOutcome::Started(_) => panic!("a busy slot must not start a second worker"),
        }

        go.store(true, Ordering::Release);
        assert_eq!(poll_until_terminal(&handles), STATUS_SUCCEEDED);
        // The permit is released before the terminal status is published, so a
        // finished slot is immediately claimable again.
        match begin_with(&slot, || async { Ok::<(), GatedSyncError>(()) }) {
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
        let BeginOutcome::Started(handles) =
            begin_with(&slot, pending::<Result<(), GatedSyncError>>)
        else {
            panic!("the first begin on a free slot must start a worker");
        };
        handles.request_cancel();
        assert_eq!(poll_until_terminal(&handles), STATUS_CANCELLED);
        // A cancelled worker releases its permit, so the slot is claimable again.
        match begin_with(&slot, || async { Ok::<(), GatedSyncError>(()) }) {
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
                Ok::<(), GatedSyncError>(())
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
}
