// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One cached Gmail session per account, reused until shortly before its
//! access token expires.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use tersa_application::mailbox::AccountId;

/// The two clocks a cached token is checked against. The monotonic clock
/// stops while the machine sleeps, but Google expires tokens by wall-clock
/// time, so an entry is valid only while both say so.
pub(crate) trait CacheClock {
    fn monotonic(&self) -> Instant;
    fn wall(&self) -> SystemTime;
}

/// The system clocks.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemCacheClock;

impl CacheClock for SystemCacheClock {
    fn monotonic(&self) -> Instant {
        Instant::now()
    }

    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Where a session came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Origin {
    /// Reused from the cache.
    Cached,
    /// Refreshed for this call.
    Fresh,
}

struct Entry<T> {
    value: T,
    monotonic: Instant,
    wall: SystemTime,
}

pub(crate) struct SessionCache<T, C> {
    clock: C,
    /// How long before its expiry a token is replaced.
    margin: Duration,
    entries: Mutex<HashMap<AccountId, Entry<T>>>,
    /// One refresh at a time per account, so concurrent misses share it.
    refreshing: Mutex<HashMap<AccountId, Arc<tokio::sync::Mutex<()>>>>,
}

impl<T: Clone, C: CacheClock> SessionCache<T, C> {
    pub(crate) fn new(clock: C, margin: Duration) -> Self {
        Self {
            clock,
            margin,
            entries: Mutex::new(HashMap::new()),
            refreshing: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, account: &AccountId) -> Option<T> {
        let entries = lock(&self.entries);
        let entry = entries.get(account)?;
        (self.clock.monotonic() < entry.monotonic && self.clock.wall() < entry.wall)
            .then(|| entry.value.clone())
    }

    /// The cached value, or a new one from `refresh`, which returns it with
    /// its token's lifetime. Concurrent misses for one account wait for a
    /// single refresh; a failed refresh caches nothing.
    pub(crate) async fn get_or_refresh<E, F, Fut>(
        &self,
        account: &AccountId,
        refresh: F,
    ) -> Result<(T, Origin), E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(T, Duration), E>>,
    {
        if let Some(value) = self.get(account) {
            return Ok((value, Origin::Cached));
        }
        let gate = Arc::clone(lock(&self.refreshing).entry(account.clone()).or_default());
        let _turn = gate.lock().await;
        if let Some(value) = self.get(account) {
            return Ok((value, Origin::Cached));
        }
        // The token's lifetime starts no earlier than this request.
        let monotonic = self.clock.monotonic();
        let wall = self.clock.wall();
        let (value, lifetime) = refresh().await?;
        let lifetime = lifetime.saturating_sub(self.margin);
        lock(&self.entries).insert(
            account.clone(),
            Entry {
                value: value.clone(),
                monotonic: monotonic.checked_add(lifetime).unwrap_or(monotonic),
                wall: wall.checked_add(lifetime).unwrap_or(wall),
            },
        );
        Ok((value, Origin::Fresh))
    }

    pub(crate) fn forget(&self, account: &AccountId) {
        lock(&self.entries).remove(account);
    }
}

/// The maps hold no invariant a panic could break; recover them.
fn lock<V>(mutex: &Mutex<V>) -> MutexGuard<'_, V> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    use tersa_application::mailbox::AccountId;

    use super::{CacheClock, Origin, SessionCache};

    const HOUR: Duration = Duration::from_secs(3600);
    const MARGIN: Duration = Duration::from_secs(60);

    /// Clocks that move only when a test says so.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<(Instant, SystemTime)>>);

    impl TestClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new((Instant::now(), SystemTime::now()))))
        }

        fn advance(&self, monotonic: Duration, wall: Duration) {
            let mut now = self.0.lock().unwrap();
            now.0 += monotonic;
            now.1 += wall;
        }
    }

    impl CacheClock for TestClock {
        fn monotonic(&self) -> Instant {
            self.0.lock().unwrap().0
        }

        fn wall(&self) -> SystemTime {
            self.0.lock().unwrap().1
        }
    }

    fn account(name: &str) -> AccountId {
        AccountId::new(name).unwrap()
    }

    fn run<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// Hands out 1, 2, 3, … with a one-hour token and counts the calls.
    fn issue(count: &Cell<u32>) -> impl Future<Output = Result<(u32, Duration), ()>> {
        count.set(count.get() + 1);
        std::future::ready(Ok((count.get(), HOUR)))
    }

    #[test]
    fn a_session_is_reused_until_the_margin_before_expiry() {
        let clock = TestClock::new();
        let cache = SessionCache::new(clock.clone(), MARGIN);
        let count = Cell::new(0);
        let first = account("acct_a");
        run(async {
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((1, Origin::Fresh))
            );
            let almost = HOUR - MARGIN - Duration::from_secs(1);
            clock.advance(almost, almost);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((1, Origin::Cached))
            );
            clock.advance(Duration::from_secs(1), Duration::ZERO);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((2, Origin::Fresh))
            );
            assert_eq!(
                cache
                    .get_or_refresh(&account("acct_b"), || issue(&count))
                    .await,
                Ok((3, Origin::Fresh)),
                "accounts never share a session"
            );
        });
    }

    #[test]
    fn a_wall_clock_jump_expires_the_session() {
        // The machine slept: wall time moved, monotonic time did not.
        let clock = TestClock::new();
        let cache = SessionCache::new(clock.clone(), MARGIN);
        let count = Cell::new(0);
        let first = account("acct_a");
        run(async {
            cache
                .get_or_refresh(&first, || issue(&count))
                .await
                .unwrap();
            clock.advance(Duration::from_secs(5), 2 * HOUR);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((2, Origin::Fresh))
            );
        });
    }

    #[test]
    fn a_forgotten_session_is_refreshed() {
        let cache = SessionCache::new(TestClock::new(), MARGIN);
        let count = Cell::new(0);
        let first = account("acct_a");
        run(async {
            cache
                .get_or_refresh(&first, || issue(&count))
                .await
                .unwrap();
            cache.forget(&first);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((2, Origin::Fresh))
            );
        });
    }

    #[test]
    fn a_failed_refresh_caches_nothing() {
        let cache = SessionCache::new(TestClock::new(), MARGIN);
        let count = Cell::new(0);
        let first = account("acct_a");
        run(async {
            assert_eq!(
                cache
                    .get_or_refresh(&first, || async { Err::<(u32, Duration), _>("offline") })
                    .await,
                Err("offline")
            );
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((1, Origin::Fresh))
            );
        });
    }

    #[test]
    fn concurrent_misses_share_one_refresh() {
        let cache = Rc::new(SessionCache::new(TestClock::new(), MARGIN));
        let count = Rc::new(Cell::new(0));
        let results = run(tokio::task::LocalSet::new().run_until(async {
            let callers: Vec<_> = (0..3)
                .map(|_| {
                    let cache = Rc::clone(&cache);
                    let count = Rc::clone(&count);
                    tokio::task::spawn_local(async move {
                        cache
                            .get_or_refresh(&account("acct_a"), || async move {
                                tokio::time::sleep(Duration::from_millis(20)).await;
                                issue(&count).await
                            })
                            .await
                    })
                })
                .collect();
            let mut results = Vec::new();
            for caller in callers {
                results.push(caller.await.unwrap());
            }
            results
        }));
        assert_eq!(count.get(), 1);
        assert_eq!(
            results,
            [
                Ok((1, Origin::Fresh)),
                Ok((1, Origin::Cached)),
                Ok((1, Origin::Cached))
            ]
        );
    }
}
