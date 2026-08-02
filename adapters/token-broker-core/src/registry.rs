// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The bounded pending-authorization-session registry.
//!
//! Sessions are keyed by their opaque handle. The registry enforces an
//! explicit small maximum, reaps expired entries deterministically at insert
//! time (an expired session is consumed and dropped — zeroizing it — never
//! evicting a live entry), and fails closed on a poisoned lock while still
//! wiping resident sessions so no verifier or state lingers in a map the
//! broker will never trust again.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use tersa_application::oauth::{AuthorizationSession, MonotonicClock};

use crate::error::BrokerError;
use crate::handle::SessionHandle;
use crate::ports::SessionHandleEntropy;

/// The explicit maximum of concurrently pending authorization sessions.
const MAX_PENDING_SESSIONS: usize = 8;

/// The attempts to allocate a collision-free handle before failing closed.
/// With 128 random bits a collision is already cryptographically negligible;
/// the bound exists so a broken entropy source fails instead of looping.
const MAX_HANDLE_ALLOCATION_ATTEMPTS: u32 = 3;

/// The bounded pending-session set, keyed by opaque handle text.
pub(crate) struct SessionRegistry<C> {
    sessions: Mutex<HashMap<String, AuthorizationSession<C>>>,
}

impl<C> SessionRegistry<C> {
    pub(crate) fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl<C: MonotonicClock> SessionRegistry<C> {
    /// Reaps expired sessions, then inserts `session` under a freshly
    /// allocated collision-free handle.
    ///
    /// Insertion happens only AFTER a collision-free allocation: a handle is
    /// never handed out for a session that failed to register.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Busy`] when the registry is at capacity after
    /// reaping (a live entry is never evicted), [`BrokerError::Unavailable`]
    /// when the lock is poisoned, entropy fails, or no unique handle could be
    /// allocated within the attempt bound.
    pub(crate) fn insert<E: SessionHandleEntropy>(
        &self,
        session: AuthorizationSession<C>,
        entropy: &E,
    ) -> Result<SessionHandle, BrokerError> {
        let mut guard = self.lock_sessions()?;
        // Deterministic reaping: `expire` consumes and zeroizes an expired
        // session and reports `NotExpired` for a live one.
        guard.retain(|_handle, session| session.expire().is_err());
        if guard.len() >= MAX_PENDING_SESSIONS {
            return Err(BrokerError::Busy);
        }
        let mut attempts = 0_u32;
        loop {
            let handle = SessionHandle::generate(entropy)?;
            if let Entry::Vacant(entry) = guard.entry(handle.as_str().to_owned()) {
                entry.insert(session);
                return Ok(handle);
            }
            attempts += 1;
            if attempts >= MAX_HANDLE_ALLOCATION_ATTEMPTS {
                return Err(BrokerError::Unavailable);
            }
        }
    }

    /// Atomically removes and returns the session for `handle`.
    ///
    /// The removal IS the claim: the session leaves the registry before any
    /// callback validation runs, so a duplicate, wrong, or replayed callback
    /// can only ever meet [`BrokerError::SessionUnknown`].
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::SessionUnknown`] when no live session exists
    /// for the handle, and [`BrokerError::Unavailable`] on a poisoned lock.
    pub(crate) fn claim(
        &self,
        handle: &SessionHandle,
    ) -> Result<AuthorizationSession<C>, BrokerError> {
        self.lock_sessions()?
            .remove(handle.as_str())
            .ok_or(BrokerError::SessionUnknown)
    }

    /// Locks the registry, failing closed on poison.
    ///
    /// A poisoned lock means a panicking thread may have left the map
    /// inconsistent; the broker never trusts it again. The resident sessions
    /// are NOT abandoned: the map is drained (dropping a session zeroizes its
    /// state and verifier) before the error propagates.
    fn lock_sessions(
        &self,
    ) -> Result<MutexGuard<'_, HashMap<String, AuthorizationSession<C>>>, BrokerError> {
        self.sessions.lock().map_err(|poisoned| {
            poisoned.into_inner().clear();
            BrokerError::Unavailable
        })
    }
}

impl<C> fmt::Debug for SessionRegistry<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRegistry")
            .field(
                "pending",
                &self.sessions.lock().map_or(0, |guard| guard.len()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tersa_application::oauth::{
        AuthorizationConfig, AuthorizationSession, MonotonicClock, prepare_authorization,
    };
    use url::Url;

    use super::{MAX_HANDLE_ALLOCATION_ATTEMPTS, MAX_PENDING_SESSIONS, SessionRegistry};
    use crate::error::BrokerError;
    use crate::handle::{SESSION_HANDLE_BYTES, SessionHandle};
    use crate::ports::SessionHandleEntropy;

    const SESSION_TTL: Duration = Duration::from_secs(60);

    /// A deterministic, cloneable monotonic clock counting whole seconds.
    #[derive(Clone, Debug, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds, Ordering::Relaxed);
        }
    }

    impl MonotonicClock for TestClock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::Relaxed))
        }
    }

    /// Mints distinct handle bytes on every call, deterministically.
    #[derive(Debug, Default)]
    struct CounterEntropy(AtomicU64);

    impl SessionHandleEntropy for CounterEntropy {
        fn handle_bytes(&self) -> Result<[u8; SESSION_HANDLE_BYTES], BrokerError> {
            let counter = self.0.fetch_add(1, Ordering::Relaxed);
            let mut bytes = [0_u8; SESSION_HANDLE_BYTES];
            bytes[..8].copy_from_slice(&counter.to_be_bytes());
            Ok(bytes)
        }
    }

    /// Replays a fixed script of handle bytes, repeating the last entry so an
    /// always-colliding source can be modeled.
    #[derive(Debug)]
    struct ScriptedEntropy {
        script: Mutex<VecDeque<[u8; SESSION_HANDLE_BYTES]>>,
        calls: AtomicU32,
    }

    impl ScriptedEntropy {
        fn with_script(script: &[[u8; SESSION_HANDLE_BYTES]]) -> Self {
            Self {
                script: Mutex::new(script.iter().copied().collect()),
                calls: AtomicU32::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl SessionHandleEntropy for ScriptedEntropy {
        fn handle_bytes(&self) -> Result<[u8; SESSION_HANDLE_BYTES], BrokerError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut script = self
                .script
                .lock()
                .map_err(|_poisoned| BrokerError::Unavailable)?;
            let next = if script.len() > 1 {
                script.pop_front()
            } else {
                script.front().copied()
            };
            next.ok_or(BrokerError::Unavailable)
        }
    }

    /// Builds a real portable authorization session on the shared clock,
    /// distinguished by its redirect port so a claimed session can be matched
    /// to the insert that registered it.
    fn make_session(clock: &TestClock, port: u16) -> AuthorizationSession<TestClock> {
        let redirect = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let config =
            AuthorizationConfig::new("registry-test-client", redirect, SESSION_TTL).unwrap();
        let (_authorization_url, session) = prepare_authorization(config, clock.clone())
            .unwrap()
            .into_parts();
        session
    }

    fn test_port(base: u16, index: usize) -> u16 {
        base + u16::try_from(index).unwrap()
    }

    #[test]
    fn capacity_rejects_the_ninth_live_session_without_evicting_one() {
        let registry = SessionRegistry::new();
        let clock = TestClock::default();
        let entropy = CounterEntropy::default();
        let mut live = Vec::new();
        for index in 0..MAX_PENDING_SESSIONS {
            let port = test_port(10_000, index);
            let handle = registry
                .insert(make_session(&clock, port), &entropy)
                .unwrap();
            live.push((handle.as_str().to_owned(), port));
        }
        assert!(matches!(
            registry.insert(make_session(&clock, 10_999), &entropy),
            Err(BrokerError::Busy)
        ));
        // No live entry was evicted to make room: every issued handle still
        // claims exactly its own session.
        for (handle_text, port) in live {
            let handle = SessionHandle::parse(&handle_text).unwrap();
            let session = registry.claim(&handle).unwrap();
            assert_eq!(session.redirect_uri().port(), Some(port));
        }
    }

    #[test]
    fn expired_sessions_are_reaped_and_capacity_is_recovered() {
        let registry = SessionRegistry::new();
        let clock = TestClock::default();
        let entropy = CounterEntropy::default();
        let mut expired_handles = Vec::new();
        for index in 0..MAX_PENDING_SESSIONS {
            let handle = registry
                .insert(make_session(&clock, test_port(11_000, index)), &entropy)
                .unwrap();
            expired_handles.push(handle.as_str().to_owned());
        }
        clock.advance(SESSION_TTL.as_secs() + 1);

        // The next insert reaps every expired session instead of reporting
        // Busy, so a full registry of dead sessions accepts a new live one.
        registry
            .insert(make_session(&clock, 12_000), &entropy)
            .unwrap();
        for handle_text in expired_handles {
            let handle = SessionHandle::parse(&handle_text).unwrap();
            assert!(matches!(
                registry.claim(&handle),
                Err(BrokerError::SessionUnknown)
            ));
        }
        // The reclaimed capacity is real: the registry fills to the bound
        // again and only then reports Busy.
        for index in 1..MAX_PENDING_SESSIONS {
            registry
                .insert(make_session(&clock, test_port(13_000, index)), &entropy)
                .unwrap();
        }
        assert!(matches!(
            registry.insert(make_session(&clock, 13_999), &entropy),
            Err(BrokerError::Busy)
        ));
    }

    #[test]
    fn collisions_retry_and_an_exhausted_budget_fails_closed() {
        let registry = SessionRegistry::new();
        let clock = TestClock::default();

        let occupied = [0xAA; SESSION_HANDLE_BYTES];
        let first_entropy = ScriptedEntropy::with_script(&[occupied]);
        let first_handle = registry
            .insert(make_session(&clock, 15_001), &first_entropy)
            .unwrap();

        // A scripted collision is retried with the next scripted value.
        let unique = [0xBB; SESSION_HANDLE_BYTES];
        let retrying_entropy = ScriptedEntropy::with_script(&[occupied, unique]);
        let second_handle = registry
            .insert(make_session(&clock, 15_002), &retrying_entropy)
            .unwrap();
        assert_ne!(first_handle.as_str(), second_handle.as_str());
        assert_eq!(retrying_entropy.calls(), 2);

        // A source that can only collide exhausts the attempt bound and fails
        // closed; the live session under the collided handle is never
        // replaced.
        let colliding_entropy = ScriptedEntropy::with_script(&[occupied]);
        assert!(matches!(
            registry.insert(make_session(&clock, 15_003), &colliding_entropy),
            Err(BrokerError::Unavailable)
        ));
        assert_eq!(colliding_entropy.calls(), MAX_HANDLE_ALLOCATION_ATTEMPTS);

        let first_session = registry.claim(&first_handle).unwrap();
        assert_eq!(first_session.redirect_uri().port(), Some(15_001));
        let second_session = registry.claim(&second_handle).unwrap();
        assert_eq!(second_session.redirect_uri().port(), Some(15_002));
    }

    #[test]
    fn claim_is_one_shot_and_replay_is_session_unknown() {
        let registry = SessionRegistry::new();
        let clock = TestClock::default();
        let entropy = CounterEntropy::default();
        let handle = registry
            .insert(make_session(&clock, 16_000), &entropy)
            .unwrap();
        let handle_text = handle.as_str().to_owned();

        let session = registry.claim(&handle).unwrap();
        assert_eq!(session.redirect_uri().port(), Some(16_000));

        // The claim removed the session: a replay of the same handle text and
        // an unknown well-formed handle both meet SessionUnknown.
        let replay = SessionHandle::parse(&handle_text).unwrap();
        assert!(matches!(
            registry.claim(&replay),
            Err(BrokerError::SessionUnknown)
        ));
        let unknown = SessionHandle::parse("ABCDEFGHIJKLMNOPQRSTUV").unwrap();
        assert!(matches!(
            registry.claim(&unknown),
            Err(BrokerError::SessionUnknown)
        ));
    }
}
