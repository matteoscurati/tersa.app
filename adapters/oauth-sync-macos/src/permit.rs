// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Process-global, per-account-slot whole-cycle sync permit and disconnect
//! coordination.
// Rust guideline compliant 1.0.
//!
//! A single sync cycle spans the identity gate AND every mailbox write it guards
//! ([`crate::gated_sync`]); two overlapping cycles for one account slot could
//! interleave a stale identity decision over a committed one. The compare-and-set
//! identity record closes that at the store even cross-process, but in-process the
//! cheapest correct serialization is one whole-cycle permit per slot: a cycle holds
//! it from before the gate until after the last write, so a second begin for the
//! same slot cannot even start.
//!
//! The permit is a per-slot [`tokio::sync::Mutex`] rather than a `std` mutex on
//! purpose: the worker acquires it BEFORE spawning its thread (a busy slot must
//! never spawn) and then moves the guard onto that thread for the whole
//! `block_on`. Only [`tokio::sync::OwnedMutexGuard`] is `Send` (a `std` guard is
//! not) and non-poisoning, so a worker panic can never brick a slot.
//!
//! # Disconnect coordination (3d-3d)
//!
//! Each slot also carries a small `std`-mutex coordination record: a
//! `disconnecting` flag and a `Weak` to the CURRENT sync cycle's cancel flag.
//! Disconnect (OAuth consent withdrawal + local teardown) drives three entry
//! points:
//!
//! - [`begin_disconnect`] — called synchronously on the caller thread before
//!   the worker spawns. Returns `Some(DisconnectLease)` when it ADMITS a worker
//!   — setting `disconnecting` (a racing [`try_acquire`] now refuses, so no new
//!   sync or connect begins mid-teardown), claiming the single-worker
//!   `disconnect_active` lease, and signaling the registered sync cancel flag
//!   (the in-flight sync drops within its cancel-poll interval and releases the
//!   gate) — or `None` when a worker is already active, in which case it
//!   COALESCES without touching the fence. It never touches the gate itself.
//! - [`acquire_disconnect_gate`] — called by the disconnect worker on its own
//!   plain thread, OFF any `tokio` runtime: blocking-acquires the gate,
//!   serializing the teardown BEHIND the now-cancelling sync (or connect). It
//!   deliberately bypasses the `disconnecting` check — disconnect set that flag
//!   itself, so routing through a flag-checking path would self-deadlock.
//! - [`clear_disconnecting`] — clears the `disconnecting` fence, called by the
//!   worker ONLY on full teardown success, STRICTLY BEFORE it releases its lease
//!   (so no "fence cleared, lease held" state a coalescing begin could observe
//!   and orphan). On any failure the fence stays set (fail-closed; the teardown
//!   is idempotent, so a retried disconnect — fence set, lease free — converges).
//!
//! A CONNECT begin never registers a cancel flag (its `sync_cancel` argument is
//! `None`): a signaled connect would be drop-aborted by the worker's cancel
//! poll mid-token-exchange, orphaning a minted token. The registration is
//! therefore structural — only a sync begin passes `Some`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use tersa_application::mailbox::AccountId;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// One account slot's coordination state: the whole-cycle gate plus the
/// disconnect coordination record.
#[derive(Debug)]
struct AccountSlot {
    /// The whole-cycle permit gate.
    gate: Arc<AsyncMutex<()>>,
    /// The disconnect coordination record. A `std` mutex, NOT async: it is
    /// only ever held for non-blocking flag/registration work, including by
    /// [`try_acquire`] while it try-locks the gate, so no critical section
    /// ever awaits or blocks on the gate.
    coord: Mutex<SlotCoord>,
}

/// The disconnect coordination record for one slot.
#[derive(Debug)]
struct SlotCoord {
    /// Set at disconnect BEGIN, cleared only on the teardown SUCCESS FAMILY
    /// (`STATUS_SUCCEEDED` or `STATUS_SUCCEEDED_REVOKE_UNCONFIRMED` — i.e. any
    /// locally-complete teardown, revoke confirmed or not). While set, every
    /// [`try_acquire`] refuses: no new sync or connect begins mid-teardown. This
    /// is the FENCE — it persists across a FAILED teardown
    /// (fail-closed), so on its own it cannot tell "a worker is running" from
    /// "a prior teardown failed and the account is fenced pending retry"; that
    /// distinction is [`Self::disconnect_active`].
    disconnecting: bool,
    /// Set while exactly one disconnect worker is actively tearing the slot
    /// down, released (RAII, panic-safe) by [`DisconnectLease`] on the worker's
    /// exit — success, failure, OR panic. [`begin_disconnect`] admits a worker
    /// only when this is clear, so concurrent disconnects coalesce onto the
    /// running one (no premature flag clear, no second teardown of a
    /// re-connected account) while a retry AFTER a failed teardown — `disconnecting`
    /// still set, `disconnect_active` clear — is still admitted and converges.
    disconnect_active: bool,
    /// The CURRENT sync cycle's cancel flag, registered by [`try_acquire`]
    /// (sync begins only; a connect begin registers `None`) and cleared by the
    /// permit's `Drop`. A `Weak` so a finished cycle's handles never keep the
    /// registration — or the slot — alive.
    sync_cancel: Option<Weak<AtomicBool>>,
}

/// The process-global registry of per-slot permits.
///
/// Grow-only: an entry is created on first use and never removed. Removal would be
/// unsound, not merely complex — dropping a slot while a concurrent claim has
/// already cloned its `Arc` but not yet locked it would split the slot into two
/// independent locks and break the exclusivity this permit exists to provide. The
/// map is bounded by the number of distinct accounts connected in this process — a
/// handful — so growth is a non-issue.
static PERMITS: OnceLock<Mutex<HashMap<AccountId, Arc<AccountSlot>>>> = OnceLock::new();

fn permits() -> &'static Mutex<HashMap<AccountId, Arc<AccountSlot>>> {
    PERMITS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Clones (or lazily creates) the per-slot record.
///
/// The registry lock is held only for this clone — never across a `coord` or
/// gate lock — so it can never invert lock order with either. The registry
/// guards a plain map whose invariants no panic can break, so a poisoned
/// registry lock is recovered rather than propagated.
fn slot(account: &AccountId) -> Arc<AccountSlot> {
    let mut map = permits().lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(map.entry(account.clone()).or_insert_with(|| {
        Arc::new(AccountSlot {
            gate: Arc::new(AsyncMutex::new(())),
            coord: Mutex::new(SlotCoord {
                disconnecting: false,
                disconnect_active: false,
                sync_cancel: None,
            }),
        })
    }))
}

/// Locks a slot's coordination record, recovering a poisoned lock: the record
/// is two plain fields no panic can corrupt, and every critical section is
/// panic-free flag work, so recovery never observes a broken invariant.
fn lock_coord(slot: &AccountSlot) -> std::sync::MutexGuard<'_, SlotCoord> {
    slot.coord.lock().unwrap_or_else(PoisonError::into_inner)
}

/// RAII proof of exclusive ownership of one account slot's whole gate-to-write
/// cycle. Dropping it deregisters the cycle's cancel flag (if any) and releases
/// the slot. The guard is `Send`, so the worker can move it onto its background
/// thread and hold it across the entire `block_on`.
#[must_use = "dropping the permit immediately releases the account slot"]
#[derive(Debug)]
pub struct WholeCyclePermit {
    _guard: OwnedMutexGuard<()>,
    slot: Arc<AccountSlot>,
}

impl Drop for WholeCyclePermit {
    /// Deregisters the cycle's cancel flag so a later [`begin_disconnect`]
    /// never signals a finished cycle's stale flag. Unconditional and
    /// panic-safe: one permit holds the slot at a time, so the registration it
    /// clears is its own (clearing a `None` left by a connect begin is
    /// harmless). Runs before the gate guard below is released, and the gate
    /// is still held throughout, so no racing claim can observe the slot
    /// without a registration.
    fn drop(&mut self) {
        lock_coord(&self.slot).sync_cancel = None;
    }
}

/// Claims the slot without blocking.
///
/// `None` means the slot is already held (busy) OR a disconnect is in flight:
/// the caller MUST NOT start a worker for it — a second whole cycle for one
/// slot is exactly what this permit forbids, and a busy or disconnecting slot
/// must not even spawn a thread. The caller maps both refusals to its one
/// "busy" outcome, so a begin never learns which refused it.
///
/// `sync_cancel` is the new cycle's cancel flag: a SYNC begin passes `Some` and
/// a CONNECT begin passes `None` (a connect must never be cancel-signaled —
/// see the module docs). The disconnecting-check, the gate try-lock, AND the
/// registration happen in ONE `coord` critical section, so a racing
/// [`begin_disconnect`] either wins first (this acquire refuses) or observes
/// the registration (and signals it): no interleaving yields an acquired
/// permit whose cancel was never signaled. The registration happens ONLY after
/// the gate try-lock succeeds — a failed claim registers nothing.
///
/// The invariant is stated over an ACTIVE permit: [`WholeCyclePermit::drop`]
/// deregisters before releasing the gate, so a permit whose destructor has
/// begun may be gate-holding yet unregistered — but that cycle's future is
/// already finished or dropped, so there is nothing left to cancel. A
/// `begin_disconnect` that observes the momentary gap simply signals nothing,
/// which is correct for an already-terminating cycle.
#[must_use = "a None means the slot is busy or disconnecting; the caller must not spawn"]
pub(crate) fn try_acquire(
    account: &AccountId,
    sync_cancel: Option<Arc<AtomicBool>>,
) -> Option<WholeCyclePermit> {
    let slot = slot(account);
    let mut coord = lock_coord(&slot);
    if coord.disconnecting {
        return None;
    }
    // Still under the `coord` lock: a `begin_disconnect` cannot interleave
    // between the try-lock and the registration. The `?` returns BEFORE the
    // assignment, so a failed try-lock never registers.
    let guard = Arc::clone(&slot.gate).try_lock_owned().ok()?;
    coord.sync_cancel = sync_cancel.map(|cancel| Arc::downgrade(&cancel));
    drop(coord);
    Some(WholeCyclePermit {
        _guard: guard,
        slot,
    })
}

/// RAII lease proving exactly ONE disconnect worker is active on a slot.
/// Dropping it clears `disconnect_active` (success, failure, OR panic), so a
/// panicked worker never strands the slot un-retryable. It deliberately does
/// NOT clear `disconnecting`: that fence is cleared only by
/// [`clear_disconnecting`] on full teardown success. `Send`, so the worker
/// moves it onto its background thread and holds it for the whole teardown.
#[must_use = "dropping the lease frees the slot for a retried disconnect"]
#[derive(Debug)]
pub(crate) struct DisconnectLease {
    slot: Arc<AccountSlot>,
}

impl Drop for DisconnectLease {
    fn drop(&mut self) {
        lock_coord(&self.slot).disconnect_active = false;
    }
}

/// Marks the slot disconnecting, and — if no disconnect worker is already
/// active — claims the single-worker lease and signals the CURRENT sync
/// cycle's cancel flag, all in ONE `coord` critical section.
///
/// Returns `Some(lease)` when THIS call admits a worker (the caller must spawn
/// one and move the lease onto it), or `None` when a disconnect worker is
/// already active on the slot (the caller must NOT spawn — the running worker
/// owns the teardown; a concurrent request coalesces onto it).
///
/// The `disconnecting` fence is set ONLY on the admitting path — a coalescing
/// (`None`) call NEVER touches it. This is load-bearing: the admitted worker
/// clears the fence on success STRICTLY BEFORE it releases its lease, so a
/// coalescing call that raced into the post-clear, pre-release window would,
/// if it re-set the fence, leave it set with no worker left to clear it —
/// fencing the slot forever. Because a coalescing call leaves the fence
/// untouched, the admitted worker's fence is the only one that exists, and it
/// is always cleared by that same worker.
///
/// This runs SYNCHRONOUSLY on the FFI caller thread before the worker spawns,
/// so "`disconnect_begin` returned STARTED ⇒ no new sync can begin" holds. A
/// RETRY after a failed teardown (`disconnecting` still set, `disconnect_active`
/// clear) is admitted and converges. Never touches the gate — the in-flight
/// sync observes its cancel flag within its poll interval and releases the gate
/// on its own.
#[must_use = "a None means a disconnect is already active; the caller must not spawn a second worker"]
pub(crate) fn begin_disconnect(account: &AccountId) -> Option<DisconnectLease> {
    let slot = slot(account);
    let mut coord = lock_coord(&slot);
    if coord.disconnect_active {
        // A worker already owns the teardown; coalesce WITHOUT touching the
        // fence (the owning worker set it and will clear it).
        return None;
    }
    coord.disconnecting = true;
    coord.disconnect_active = true;
    if let Some(weak) = &coord.sync_cancel
        && let Some(flag) = weak.upgrade()
    {
        flag.store(true, Ordering::Release);
    }
    drop(coord);
    Some(DisconnectLease {
        slot: Arc::clone(&slot),
    })
}

/// RAII guard for the disconnect worker's hold on the gate. Dropping it
/// releases the gate. It deliberately does NOT clear `disconnecting`: the flag
/// is cleared only by [`clear_disconnecting`] on full teardown success, so a
/// failed (or panicked) teardown leaves the slot fail-closed.
#[must_use = "dropping the permit immediately releases the account slot"]
#[derive(Debug)]
pub(crate) struct DisconnectPermit {
    _guard: OwnedMutexGuard<()>,
}

/// Blocking-acquires the gate for a disconnect teardown, waiting out any
/// in-flight sync or connect.
///
/// MUST run off any `tokio` runtime thread (the disconnect worker is a plain
/// `std::thread` and calls this BEFORE building its runtime): `blocking_lock`
/// panics inside an async context. MUST bypass the `disconnecting` check —
/// disconnect set that flag itself, so a flag-checking acquire would
/// self-deadlock.
pub(crate) fn acquire_disconnect_gate(account: &AccountId) -> DisconnectPermit {
    let slot = slot(account);
    let guard = Arc::clone(&slot.gate).blocking_lock_owned();
    DisconnectPermit { _guard: guard }
}

/// Clears the slot's `disconnecting` fence. Called by the disconnect worker on
/// the teardown SUCCESS FAMILY (`STATUS_SUCCEEDED` or
/// `STATUS_SUCCEEDED_REVOKE_UNCONFIRMED` — any locally-complete teardown) —
/// never on a failure, never from a drop guard, so a failed or panicked teardown
/// leaves the slot refusing new begins (fail-closed) until a retried disconnect
/// converges. (The single-worker lease is released separately, on EVERY outcome,
/// by [`DisconnectLease`].)
pub(crate) fn clear_disconnecting(account: &AccountId) {
    let slot = slot(account);
    lock_coord(&slot).disconnecting = false;
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests assert on known-good claims")]

    use std::time::{Duration, Instant};

    use super::*;

    fn account(id: &str) -> AccountId {
        AccountId::new(id).unwrap()
    }

    fn cancel_flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    fn try_acquire_is_exclusive_per_slot_and_releases_on_drop() {
        let slot = account("permit-exclusive");
        let first = try_acquire(&slot, None).expect("free slot claims");
        assert!(try_acquire(&slot, None).is_none(), "a held slot is busy");
        drop(first);
        let _again = try_acquire(&slot, None).expect("a released slot claims again");
    }

    #[test]
    fn distinct_slots_are_independent() {
        let a = account("permit-slot-a");
        let b = account("permit-slot-b");
        let _held_a = try_acquire(&a, None).expect("slot a claims");
        // A different slot is unaffected by a held one.
        let _held_b = try_acquire(&b, None).expect("slot b claims while a is held");
        assert!(try_acquire(&a, None).is_none(), "slot a is still held");
    }

    #[test]
    fn begin_disconnect_refuses_new_begins_and_finish_reopens_the_slot() {
        let slot = account("permit-disconnecting-flag");
        let lease = begin_disconnect(&slot).expect("a fresh slot admits a disconnect worker");
        assert!(
            try_acquire(&slot, None).is_none(),
            "a disconnecting slot refuses a new begin"
        );
        drop(lease);
        clear_disconnecting(&slot);
        let _claimed = try_acquire(&slot, None).expect("a finished disconnect reopens the slot");
    }

    #[test]
    fn begin_disconnect_coalesces_while_active_and_admits_a_retry() {
        // The single-worker lease is the two-state fix (Sol P1 / Opus F2): while
        // ONE disconnect worker is active, a concurrent begin coalesces (returns
        // None) rather than spawning a second teardown that could clear the fence
        // early or tear down a re-connected account.
        let slot = account("permit-disconnect-coalesce");
        let lease = begin_disconnect(&slot).expect("the first begin admits a worker");
        assert!(
            begin_disconnect(&slot).is_none(),
            "a concurrent begin must coalesce onto the active worker"
        );
        // The active worker exits (its lease drops) but FAILED, so the fence
        // stays set: a retry is still admitted (fence set, lease free) and
        // converges — it does NOT coalesce forever behind a dead worker.
        drop(lease);
        let retry = begin_disconnect(&slot)
            .expect("a retry after a failed teardown is admitted, not coalesced");
        drop(retry);
        clear_disconnecting(&slot);
        assert!(
            try_acquire(&slot, None).is_some(),
            "a successful (cleared) disconnect reopens the slot"
        );
    }

    #[test]
    fn a_coalescing_begin_never_orphans_the_fence() {
        // M1 (Opus): the post-success window — the owning worker has cleared the
        // fence but not yet released its lease — must not let a coalescing begin
        // re-arm the fence, or it would be set with NO worker left to clear it,
        // fencing the slot forever.
        let slot = account("permit-no-orphan-fence");
        let lease = begin_disconnect(&slot).expect("the first begin admits a worker");
        // The worker succeeded: it clears the fence BEFORE releasing its lease.
        clear_disconnecting(&slot);
        // A concurrent begin races into that window: it coalesces (the lease is
        // still held) and MUST NOT re-set the fence.
        assert!(
            begin_disconnect(&slot).is_none(),
            "the racing begin coalesces onto the still-active worker"
        );
        drop(lease);
        // The fence was never re-armed, so releasing the lease leaves the slot
        // OPEN — not orphaned-fenced forever.
        assert!(
            try_acquire(&slot, None).is_some(),
            "a coalescing begin must not orphan the fence"
        );
    }

    #[test]
    fn a_panicked_worker_lease_frees_the_slot_for_a_retry() {
        // The lease releases `disconnect_active` on EVERY drop, including a panic
        // unwind, so a panicked disconnect worker never strands the slot
        // un-retryable (the fence stays set — fail-closed — but a retry is
        // admitted).
        let slot = account("permit-disconnect-panic-lease");
        let outcome = std::panic::catch_unwind(|| {
            let _lease = begin_disconnect(&slot).expect("admits a worker");
            panic!("teardown panics with the lease held");
        });
        assert!(outcome.is_err());
        // Fence still set (fail-closed), but the lease dropped on unwind:
        assert!(try_acquire(&slot, None).is_none(), "the fence stays set");
        let retry = begin_disconnect(&slot).expect("a retry is admitted after the panic");
        drop(retry);
        clear_disconnecting(&slot);
    }

    #[test]
    fn begin_disconnect_signals_the_registered_sync_cancel() {
        let slot = account("permit-signal-sync");
        let flag = cancel_flag();
        let permit = try_acquire(&slot, Some(Arc::clone(&flag))).expect("free slot claims");
        let _lease = begin_disconnect(&slot);
        assert!(
            flag.load(Ordering::Acquire),
            "the registered sync cancel must be signaled promptly"
        );
        // The signal does not release the gate: the sync finishes (and releases)
        // on its own; the slot still refuses new begins meanwhile.
        assert!(try_acquire(&slot, None).is_none());
        drop(permit);
        clear_disconnecting(&slot);
    }

    #[test]
    fn begin_disconnect_does_not_signal_a_connect_registration() {
        // FORK B (a): a connect holds the slot with NO registered cancel flag,
        // so disconnect has nothing to signal — the connect is never
        // drop-aborted mid-token-exchange. The slot still refuses new begins.
        let slot = account("permit-connect-unsignaled");
        let _connect = try_acquire(&slot, None).expect("free slot claims");
        let _lease = begin_disconnect(&slot);
        assert!(try_acquire(&slot, None).is_none());
        // No flag was registered, so there is nothing to assert unset on
        // directly; the worker-level test proves the connect's own flag stays
        // unset end to end. Clean up the flag for slot hygiene.
        clear_disconnecting(&slot);
    }

    #[test]
    fn a_failed_try_lock_registers_nothing() {
        // A busy slot's try_acquire must not overwrite the HOLDER's
        // registration: only the holder's flag is signaled by a disconnect.
        let slot = account("permit-failed-try-lock");
        let holder_flag = cancel_flag();
        let _holder = try_acquire(&slot, Some(Arc::clone(&holder_flag))).expect("free slot claims");
        let contender_flag = cancel_flag();
        assert!(try_acquire(&slot, Some(Arc::clone(&contender_flag))).is_none());
        let _lease = begin_disconnect(&slot);
        assert!(
            holder_flag.load(Ordering::Acquire),
            "the holder's registered cancel is signaled"
        );
        assert!(
            !contender_flag.load(Ordering::Acquire),
            "a failed try-lock must never have registered its flag"
        );
        clear_disconnecting(&slot);
    }

    #[test]
    fn dropping_the_permit_deregisters_the_sync_cancel() {
        // RAII deregister: after the cycle ends, a disconnect finds no stale
        // registration to signal.
        let slot = account("permit-raii-deregister");
        let flag = cancel_flag();
        let permit = try_acquire(&slot, Some(Arc::clone(&flag))).expect("free slot claims");
        drop(permit);
        let _lease = begin_disconnect(&slot);
        assert!(
            !flag.load(Ordering::Acquire),
            "a finished cycle's flag must not be signaled after deregistration"
        );
        clear_disconnecting(&slot);
    }

    #[test]
    fn acquire_disconnect_gate_bypasses_the_disconnecting_check() {
        // Disconnect set the flag itself; its gate acquire must not route
        // through the refusing check, or it would self-deadlock.
        let slot = account("permit-disconnect-bypass");
        let _lease = begin_disconnect(&slot);
        let _gate = acquire_disconnect_gate(&slot);
        clear_disconnecting(&slot);
    }

    #[test]
    fn acquire_disconnect_gate_serializes_behind_a_held_permit() {
        let slot = account("permit-disconnect-blocking");
        let holder = try_acquire(&slot, None).expect("free slot claims");
        let acquired = Arc::new(AtomicBool::new(false));
        let waiter = {
            let slot = slot.clone();
            let acquired = Arc::clone(&acquired);
            std::thread::spawn(move || {
                let _gate = acquire_disconnect_gate(&slot);
                acquired.store(true, Ordering::Release);
            })
        };
        // The blocking acquire must wait out the in-flight cycle.
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !acquired.load(Ordering::Acquire),
            "the disconnect gate must serialize behind the held permit"
        );
        drop(holder);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !acquired.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "the waiter must acquire once the gate is free"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        waiter.join().unwrap();
    }

    #[test]
    fn a_racing_begin_disconnect_either_refuses_or_signals_every_claim() {
        // FORK B (b): with the check, try-lock, and registration in ONE `coord`
        // section, a try_acquire racing a begin_disconnect has exactly two
        // outcomes, both safe. Ordering 1 — the claim wins: the disconnect
        // observes the registration and signals it.
        let first = account("permit-race-claim-first");
        let flag = cancel_flag();
        let permit = try_acquire(&first, Some(Arc::clone(&flag))).expect("free slot claims");
        let _lease = begin_disconnect(&first);
        assert!(
            flag.load(Ordering::Acquire),
            "an acquired permit's cancel must be signaled by the losing disconnect"
        );
        drop(permit);
        clear_disconnecting(&first);
        // Ordering 2 — the disconnect wins: the claim refuses.
        let second = account("permit-race-disconnect-first");
        let _lease = begin_disconnect(&second);
        assert!(
            try_acquire(&second, Some(cancel_flag())).is_none(),
            "a disconnecting slot must refuse the losing claim"
        );
        clear_disconnecting(&second);
    }
}
