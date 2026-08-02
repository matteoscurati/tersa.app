// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded per-subject single-flight serialization of token mutations.
//!
//! A subject's refresh, revoke, and delete operations must never overlap:
//! they read and rewrite the same stored credential. Claiming is non-blocking
//! (a held slot answers `Busy`, never a queue), and the guard is RAII so a
//! cancelled future releases the slot on drop. No mutex guard ever crosses an
//! `.await`: the std mutex protects only the insert/remove of the slot.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use crate::error::BrokerError;

/// Caps the distinct subjects with an in-flight mutation. Permits are
/// short-lived, so reaching this bound means a burst across many accounts;
/// the caller retries rather than growing memory without limit.
const MAX_SUBJECT_PERMITS: usize = 32;

/// The set of subjects with an in-flight token mutation.
pub(crate) struct SubjectPermits {
    held: Arc<Mutex<HashSet<String>>>,
}

impl SubjectPermits {
    pub(crate) fn new() -> Self {
        Self {
            held: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Claims the single-flight permit for `subject` until the returned guard
    /// drops.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Busy`] when the subject already has a mutation
    /// in flight or the permit bound is reached, and
    /// [`BrokerError::Unavailable`] when the lock is poisoned (fail closed).
    pub(crate) fn claim(&self, subject: &str) -> Result<SubjectPermit, BrokerError> {
        let mut guard = self
            .held
            .lock()
            .map_err(|_poisoned| BrokerError::Unavailable)?;
        if guard.contains(subject) || guard.len() >= MAX_SUBJECT_PERMITS {
            return Err(BrokerError::Busy);
        }
        guard.insert(subject.to_owned());
        drop(guard);
        Ok(SubjectPermit {
            held: Arc::clone(&self.held),
            subject: subject.to_owned(),
        })
    }
}

impl fmt::Debug for SubjectPermits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubjectPermits")
            .field("held", &self.held.lock().map_or(0, |guard| guard.len()))
            .finish()
    }
}

/// Releases the subject's slot on drop, including on future cancellation.
pub(crate) struct SubjectPermit {
    held: Arc<Mutex<HashSet<String>>>,
    subject: String,
}

impl Drop for SubjectPermit {
    fn drop(&mut self) {
        // Release the slot even through a poisoned lock: the set holds no
        // secrets, and a slot abandoned after a panic would wedge the
        // subject's mutations behind `Busy` for the process lifetime.
        let mut guard = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        guard.remove(&self.subject);
    }
}

impl fmt::Debug for SubjectPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SubjectPermit([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::PoisonError;

    use super::{MAX_SUBJECT_PERMITS, SubjectPermits};
    use crate::error::BrokerError;

    #[test]
    fn the_same_subject_is_busy_while_held_and_claimable_after_drop() {
        let permits = SubjectPermits::new();
        let guard = permits.claim("subject-a").unwrap();
        assert!(matches!(permits.claim("subject-a"), Err(BrokerError::Busy)));
        drop(guard);
        // The RAII drop released the slot: the guard returned here is dropped
        // at the end of the statement and releases it again.
        assert!(permits.claim("subject-a").is_ok());
    }

    #[test]
    fn distinct_subjects_coexist_up_to_the_explicit_bound() {
        let permits = SubjectPermits::new();
        let mut guards = Vec::new();
        for index in 0..MAX_SUBJECT_PERMITS {
            guards.push(permits.claim(&format!("subject-{index}")).unwrap());
        }
        // The bound is explicit: one more distinct subject is Busy even
        // though no single subject holds two permits.
        assert!(matches!(
            permits.claim("subject-overflow"),
            Err(BrokerError::Busy)
        ));
        // Freeing one slot makes the overflow subject claimable again.
        drop(guards.pop().unwrap());
        assert!(permits.claim("subject-overflow").is_ok());
    }

    #[test]
    fn guard_debug_redacts_the_subject() {
        let permits = SubjectPermits::new();
        let guard = permits.claim("110169484474386276334").unwrap();
        let rendered = format!("{guard:?}");
        assert!(!rendered.contains("110169484474386276334"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn a_poisoned_lock_fails_claim_closed() {
        let permits = SubjectPermits::new();

        // Poison the lock. `catch_unwind` keeps the deliberate panic
        // contained to this test.
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = permits.held.lock().unwrap();
            panic!("deliberate test poison");
        }));
        assert!(poisoned.is_err());

        // Fail closed: a claim never trusts the poisoned set.
        assert!(matches!(
            permits.claim("subject-a"),
            Err(BrokerError::Unavailable)
        ));
    }

    #[test]
    fn a_guard_drop_through_a_poisoned_lock_still_releases_the_slot() {
        let permits = SubjectPermits::new();
        let permit = permits.claim("subject-a").unwrap();

        // Poison the shared lock while the guard still holds its slot.
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = permits.held.lock().unwrap();
            panic!("deliberate test poison");
        }));
        assert!(poisoned.is_err());

        // The RAII drop recovers through the poison and frees the slot, so
        // the subject is never wedged behind Busy for the process lifetime.
        drop(permit);
        let inner = permits.held.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(inner.is_empty());
        drop(inner);
        // The lock correctly remains poisoned: later claims still fail closed
        // rather than succeeding.
        assert!(matches!(
            permits.claim("subject-a"),
            Err(BrokerError::Unavailable)
        ));
    }
}
