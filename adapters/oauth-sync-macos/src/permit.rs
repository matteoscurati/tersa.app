// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Process-global, per-account-slot whole-cycle sync permit.
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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use tersa_application::mailbox::AccountId;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// The process-global registry of per-slot permits.
///
/// Grow-only: an entry is created on first use and never removed. Removal would be
/// unsound, not merely complex — dropping a slot mutex while a concurrent claim has
/// already cloned its `Arc` but not yet locked it would split the slot into two
/// independent locks and break the exclusivity this permit exists to provide. The
/// map is bounded by the number of distinct accounts connected in this process — a
/// handful — so growth is a non-issue.
static PERMITS: OnceLock<Mutex<HashMap<AccountId, Arc<AsyncMutex<()>>>>> = OnceLock::new();

fn permits() -> &'static Mutex<HashMap<AccountId, Arc<AsyncMutex<()>>>> {
    PERMITS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Clones (or lazily creates) the per-slot async mutex.
///
/// The registry lock is held only for this clone — never across a slot lock — so it
/// can never invert lock order with the permit itself. The registry guards a plain
/// map whose invariants no panic can break, so a poisoned registry lock is
/// recovered rather than propagated.
fn slot(account: &AccountId) -> Arc<AsyncMutex<()>> {
    let mut map = permits().lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(
        map.entry(account.clone())
            .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
    )
}

/// RAII proof of exclusive ownership of one account slot's whole gate-to-write
/// cycle. Dropping it releases the slot. The guard is `Send`, so the worker can move
/// it onto its background thread and hold it across the entire `block_on`.
#[must_use = "dropping the permit immediately releases the account slot"]
pub struct WholeCyclePermit {
    _guard: OwnedMutexGuard<()>,
}

/// Claims the slot without blocking.
///
/// `None` means the slot is already held (busy): the caller MUST NOT start a worker
/// for it — a second whole cycle for one slot is exactly what this permit forbids,
/// and a busy slot must not even spawn a thread.
pub fn try_acquire(account: &AccountId) -> Option<WholeCyclePermit> {
    slot(account)
        .try_lock_owned()
        .ok()
        .map(|guard| WholeCyclePermit { _guard: guard })
}

// A blocking-acquire variant for disconnect (which must serialize behind an
// in-flight sync) is deferred to the disconnect slice (3d-3d), where its sole
// caller lands; it MUST run off any tokio runtime thread.

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests assert on known-good claims")]

    use super::*;

    fn account(id: &str) -> AccountId {
        AccountId::new(id).unwrap()
    }

    #[test]
    fn try_acquire_is_exclusive_per_slot_and_releases_on_drop() {
        let slot = account("permit-exclusive");
        let first = try_acquire(&slot).expect("free slot claims");
        assert!(try_acquire(&slot).is_none(), "a held slot is busy");
        drop(first);
        let _again = try_acquire(&slot).expect("a released slot claims again");
    }

    #[test]
    fn distinct_slots_are_independent() {
        let a = account("permit-slot-a");
        let b = account("permit-slot-b");
        let _held_a = try_acquire(&a).expect("slot a claims");
        // A different slot is unaffected by a held one.
        let _held_b = try_acquire(&b).expect("slot b claims while a is held");
        assert!(try_acquire(&a).is_none(), "slot a is still held");
    }
}
