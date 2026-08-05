// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exposes the Apple OAuth feasibility adapter through a narrow C ABI.
//!
//! The adapter keeps sensitive state in Rust. Swift supplies only public build
//! configuration and transports the authorization URL or callback URL.

use std::collections::{BTreeMap, BTreeSet};
use std::slice;
use std::str;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use tersa_application::oauth::{
    AuthorizationConfig, AuthorizationGrant, AuthorizationSession, OAuthError,
    SystemMonotonicClock, prepare_authorization,
};
use url::Url;
use zeroize::Zeroizing;

// Rust guideline compliant 1.0.

const IOS_CALLBACK_PATH: &str = "/oauth/callback";
const AUTHORIZATION_LIFETIME: Duration = Duration::from_secs(120);
/// How long a finished-but-unclaimed grant may sit in the registry before the
/// reaper wipes it. Distinct from [`AUTHORIZATION_LIFETIME`] (which bounds the
/// pre-callback window) so tightening one does not silently move the other; the
/// begin→claim window is therefore up to the sum of the two.
const PENDING_GRANT_LIFETIME: Duration = AUTHORIZATION_LIFETIME;
/// How long a cancel tombstone stays protective before the reaper retires it.
///
/// `finish()` and the grant store run in ONE registry critical section (see
/// [`finish_and_store`]): a store happens only in the same critical section
/// as a passing expiry check, so any reaper retirement section (which runs at
/// wall time ≥ cancel+TTL ≥ begin+[`AUTHORIZATION_LIFETIME`] = `expires_at`, a
/// cancel being possible only after its begin) runs strictly after the last
/// possible store; 120s therefore suffices with no margin. A finisher that
/// arrives after its tombstone was retired necessarily sees an elapsed
/// deadline and fails the expiry check before reaching the store. The TTL is
/// deliberately tied to [`AUTHORIZATION_LIFETIME`], NOT to the tunable
/// [`PENDING_GRANT_LIFETIME`]: shortening the grant TTL must never shorten
/// tombstone protection.
///
/// LEASE INVARIANT: a CLAIMED session's tombstone is unreapable. The TTL
/// cannot bound the claim→fence window — it spans the ~30s token-exchange
/// network request — so a claimed session's tombstone is pinned by the
/// in-flight lease ([`GrantRegistry::in_flight`]) until the connect worker
/// acknowledges completion via [`complete_session`]. The TTL bounds only
/// unclaimed and completed sessions: a completed session's tombstone is
/// re-stamped at release, and normal TTL reaping resumes from the release.
const CANCEL_TOMBSTONE_LIFETIME: Duration = AUTHORIZATION_LIFETIME;
const MAX_AUTHORIZATION_URL_BYTES: usize = 4_096;

const STATUS_OK: i32 = 0;
const STATUS_SUCCEEDED: i32 = 1;
const STATUS_INVALID_INPUT: i32 = -1;
const STATUS_CONFIGURATION_MISSING: i32 = -2;
const STATUS_BUFFER_TOO_SMALL: i32 = -3;
const STATUS_REJECTED: i32 = -4;
const STATUS_CANCELLED: i32 = -5;
const STATUS_EXPIRED: i32 = -6;
const STATUS_INTERNAL: i32 = -7;
const STATUS_INSUFFICIENT_SCOPE: i32 = -8;

type PendingSession = AuthorizationSession<SystemMonotonicClock>;

/// One finished authorization awaiting a single-use token-exchange claim,
/// kept with the redirect URI the exchange must present. Dropping an entry
/// zeroizes the grant's code and verifier.
struct PendingGrant {
    grant: AuthorizationGrant,
    redirect_uri: Url,
    /// The begin-validated public OAuth client id the token exchange
    /// authenticates as. It rides with the grant because the exchange needs it
    /// and the finished session no longer carries it; a public client id is
    /// not a secret, so it is not zeroized.
    client_id: String,
    created_at: Instant,
}

/// The pending-authorization registry: one mutex over two maps and the lease
/// set with separate lifecycles, so every state transition (store, cancel,
/// claim, complete, reap) has a single linearization point.
struct GrantRegistry {
    /// Finished grants awaiting a single-use claim. Secret-bearing, so this
    /// map is count-capped at [`MAX_PENDING_GRANTS`] (bounding secret
    /// residency) and TTL'd at [`PENDING_GRANT_LIFETIME`].
    grants: BTreeMap<u64, PendingGrant>,
    /// Tombstones for cancelled sessions, stamped at cancel time. They hold NO
    /// secret, so they are NOT count-capped; they are TTL'd at
    /// [`CANCEL_TOMBSTONE_LIFETIME`] (at least the session store window) so a
    /// live tombstone is never removed while a finisher may still store. A
    /// tombstone whose id is in `in_flight` is exempt from TTL reaping.
    cancelled: BTreeMap<u64, Instant>,
    /// Sessions whose grant was successfully claimed but whose connect worker
    /// has not yet acknowledged completion via [`complete_session`]. A cancel
    /// tombstone for an id in this set is UNREAPABLE: the claim→fence window
    /// spans the token-exchange network request, which the tombstone TTL
    /// cannot bound. Entries are removed ONLY by `complete_session`, never
    /// TTL-reaped.
    in_flight: BTreeSet<u64>,
}

impl GrantRegistry {
    fn new() -> Self {
        Self {
            grants: BTreeMap::new(),
            cancelled: BTreeMap::new(),
            in_flight: BTreeSet::new(),
        }
    }
}

/// The outcome of attempting to store a finished grant.
#[derive(Debug, Eq, PartialEq)]
enum StoreOutcome {
    /// The grant was stored and is claimable exactly once.
    Stored,
    /// A cancel tombstone holds the session: the incoming grant was dropped
    /// (wiping its code and verifier) instead of becoming claimable.
    RefusedCancelled,
}

const MAX_PENDING_GRANTS: usize = 4;

/// A begun iOS session plus the public client id it was begun with: the
/// finished session keeps only redirect/state/verifier, so the id the token
/// exchange needs rides alongside the stored session until finish stores it
/// with the grant. A public client id is not a secret, so it is not zeroized.
struct IosSessionEntry {
    session: PendingSession,
    client_id: String,
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static IOS_SESSIONS: OnceLock<Mutex<BTreeMap<u64, IosSessionEntry>>> = OnceLock::new();
static PENDING_GRANTS: OnceLock<Mutex<GrantRegistry>> = OnceLock::new();
static REAPER_STARTED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
static PENDING_GRANT_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
// Serializes registry-mutating tests AND resets the process-global registry on
// entry, so tests are order-independent; recovers a poisoned lock so one
// failing test does not cascade into the rest. NEXT_SESSION_ID is monotonic
// and shared, so only the registry maps and the lease set are reset, never
// the counter.
fn registry_test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = PENDING_GRANT_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut registry = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    registry.grants.clear();
    registry.cancelled.clear();
    registry.in_flight.clear();
    drop(registry);
    guard
}

fn ios_sessions() -> &'static Mutex<BTreeMap<u64, IosSessionEntry>> {
    IOS_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn pending_grants() -> &'static Mutex<GrantRegistry> {
    PENDING_GRANTS.get_or_init(|| Mutex::new(GrantRegistry::new()))
}

/// Starts an iOS authorization session without launching a browser.
///
/// `client_id` and `redirect_scheme` must point to readable UTF-8 bytes. The
/// output pointers must be writable for their declared sizes.
///
/// # Safety
///
/// Every non-null pointer must remain valid for the duration of this call and
/// must not alias a mutable output.
#[expect(
    unsafe_code,
    reason = "the C ABI validates and copies caller-owned byte buffers"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_oauth_ios_begin(
    client_id: *const u8,
    client_id_len: usize,
    redirect_scheme: *const u8,
    redirect_scheme_len: usize,
    output_session_id: *mut u64,
    output_url: *mut u8,
    output_url_capacity: usize,
    output_url_len: *mut usize,
) -> i32 {
    let result = (|| {
        // SAFETY: The function contract requires readable input buffers.
        let client_id = unsafe { read_utf8(client_id, client_id_len) }?;
        // SAFETY: The function contract requires readable input buffers.
        let redirect_scheme = unsafe { read_utf8(redirect_scheme, redirect_scheme_len) }?;
        let redirect_uri = ios_redirect_uri(&redirect_scheme)?;
        let (session_id, begun_session) = begin_session(&client_id, redirect_uri)?;
        let BegunSession {
            session,
            authorization_url,
            client_id,
        } = begun_session;
        let authorization_url = Zeroizing::new(String::from(authorization_url));
        // SAFETY: The function contract requires writable output buffers.
        unsafe {
            write_begin_output(
                session_id,
                &authorization_url,
                output_session_id,
                output_url,
                output_url_capacity,
                output_url_len,
            )?;
        }
        ios_sessions()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session_id, IosSessionEntry { session, client_id });
        ensure_reaper();
        Ok(())
    })();
    result.map_or_else(|status| status, |()| STATUS_OK)
}

/// Completes and consumes an iOS authorization session.
///
/// # Safety
///
/// `callback_url` must point to `callback_url_len` readable UTF-8 bytes.
#[expect(
    unsafe_code,
    reason = "the C ABI validates and copies a caller-owned callback buffer"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_oauth_ios_finish(
    session_id: u64,
    callback_url: *const u8,
    callback_url_len: usize,
) -> i32 {
    // SAFETY: The function contract requires a readable input buffer.
    let callback_bytes = match unsafe { read_utf8(callback_url, callback_url_len) } {
        Ok(value) => Zeroizing::new(value),
        Err(status) => return status,
    };
    let callback_url = match Url::parse(&callback_bytes) {
        Ok(url) => url,
        Err(_error) => return STATUS_INVALID_INPUT,
    };
    // Recover a poisoned lock rather than abandon it: failing closed on poison
    // would make every finish return STATUS_REJECTED forever and strand
    // `Zeroizing` verifiers in the map, the exact failure this teardown order
    // exists to prevent. The map holds no invariant a panic could break.
    let entry = ios_sessions()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&session_id);
    let Some(IosSessionEntry {
        mut session,
        client_id,
    }) = entry
    else {
        return STATUS_REJECTED;
    };
    // `finish()` and the grant store share ONE registry critical section
    // inside `finish_and_store`; the registry lock is already released before
    // the callback bytes are re-zeroized here.
    let status = finish_and_store(session_id, &mut session, &callback_url, &client_id);
    let _callback_bytes = Zeroizing::new(String::from(callback_url));
    status
}

/// Cancels and consumes an iOS or macOS authorization session.
///
/// # Status contract (frozen C ABI)
///
/// - `STATUS_CANCELLED` — the id passed the admission guard and a tombstone
///   was stamped: the cancellation is durable and beats any in-flight
///   finisher uniformly (displaced grant, displaced session, or a finisher
///   that has not stored yet), agreeing with the finisher's own
///   `STATUS_CANCELLED`.
/// - `STATUS_REJECTED` — admission failure only: the id is implausible
///   (zero, or at or beyond the allocation cursor, so it was never handed
///   out by this process). Nothing is stamped and nothing is displaced.
///
/// # Connectedness contract (for 3e)
///
/// This return value is authoritative ONLY over "the session can no longer
/// produce a grant". It is NOT the source of truth for whether an account is
/// connected: the CONNECT WORKER's terminal status is the sole source of that.
/// A cancel that loses the post-store race — the worker stored the refresh
/// token and passed its final cancel fence before the tombstone landed —
/// returns `STATUS_CANCELLED` here while the worker returns `STATUS_SUCCEEDED`
/// and a sync ran. UI connectedness must therefore key off the worker status
/// plus disconnect, never off this return value.
///
/// Symmetrically, a `STATUS_CANCELLED` FROM THE CONNECT WORKER means only
/// "this connect created no new connection"; it does NOT imply the account is
/// disconnected. A cancelled RE-connect restores the prior credential and
/// leaves the pre-existing connection intact, so 3e must not render the
/// worker's CANCELLED as "disconnected" — connectedness keys off the worker
/// status plus disconnect, as above. (Deferred 3e input, deliberately NOT
/// implemented in this slice: a distinct outcome — e.g.
/// `CancelledPriorPreserved` — would let the UI distinguish "re-connect
/// cancelled, existing connection unchanged" from "connect cancelled, nothing
/// connected". No new status int is added here.)
///
/// # Invariant
///
/// The `session_id` is a lookup key, NOT a capability (the same note
/// [`claim_grant`] carries): it is a sequential, Swift-visible counter, so an
/// in-process caller walking `1..NEXT_SESSION_ID` could tombstone every live
/// flow. The blast radius is bounded — in-process only, and tombstoning wipes
/// grants rather than disclosing them — but the `session_id` must only ever be
/// one the caller legitimately holds from its own begin, never accepted from
/// an untrusted source.
#[expect(
    unsafe_code,
    reason = "a stable unmangled symbol is required by the C-compatible Apple bridge"
)]
#[unsafe(no_mangle)]
pub extern "C" fn tersa_oauth_cancel(session_id: u64) -> i32 {
    // Admission guard: stamp a tombstone only for a plausibly-allocated id.
    // The bound on the tombstone map is on ADMISSION, not on eviction —
    // cap-evicting `cancelled` would reinstate the store-after-cancel race,
    // while admission bounds tombstones by the set of ids this process ever
    // handed out (each stamped at most once).
    let next = NEXT_SESSION_ID.load(Ordering::Acquire);
    let plausible = session_id != 0 && session_id < next;

    // Recover a poisoned lock rather than abandon it: cancel must never be a
    // silent no-op, and the maps hold no invariant a panic could break.
    let mut registry = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if plausible {
        // Wipe any stored grant (dropping it zeroizes its code and verifier)
        // and stamp the tombstone under the same lock the finisher's fused
        // finish→store section takes, so cancel and store serialize.
        registry.grants.remove(&session_id);
        registry.cancelled.insert(session_id, Instant::now());
    }
    drop(registry);

    // Session-map teardown runs for either admission outcome: an implausible
    // id can hold no session, so this is a no-op there. Same poison recovery:
    // abandoning a poisoned session map would strand `Zeroizing` verifiers.
    let mut sessions = ios_sessions()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(mut entry) = sessions.remove(&session_id) {
        // The session was found and removed; consuming it here is terminal
        // even if it had already reached a terminal state on its own.
        let _consumed = entry.session.cancel();
    }
    drop(sessions);

    #[cfg(target_os = "macos")]
    {
        let mut sessions = macos_sessions()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = sessions.remove(&session_id) {
            entry.cancel.store(true, Ordering::Release);
        }
    }

    // A cancel-only macOS tombstone must still be reaped: begin may never have
    // run on a path that starts the reaper for this process.
    ensure_reaper();

    if plausible {
        STATUS_CANCELLED
    } else {
        STATUS_REJECTED
    }
}

struct BegunSession {
    session: PendingSession,
    authorization_url: Url,
    /// The begin-validated public client id, carried so the value stored with
    /// the finished grant is the one begin checked (the session itself keeps
    /// only redirect/state/verifier). Not a secret, so not zeroized.
    client_id: String,
}

/// Allocates the next never-reused session id, failing closed with
/// [`STATUS_INTERNAL`] once the counter reaches `u64::MAX` instead of wrapping
/// onto an id a live session could still hold. `u64::MAX` itself is never
/// handed out: the counter stalls there and every later allocation fails.
///
/// The `AcqRel` success ordering gives the admission guard's `Acquire` load of
/// the cursor in [`tersa_oauth_cancel`] a release to pair with.
///
/// # Invariant
///
/// The tombstone-safety chain is `stamp >= alloc >= origin`: `stamp >= alloc`
/// is the admission guard in [`tersa_oauth_cancel`]; the two preconditions
/// below establish the rest and every caller must preserve them:
///
/// 1. The id is allocated strictly AFTER the session's clock origin is fixed
///    by `prepare_authorization` (`alloc >= origin`), so a cancel's tombstone
///    stamp — at wall time no earlier than this allocation — can never precede
///    the session's own begin.
/// 2. Every production session is built with [`AUTHORIZATION_LIFETIME`] as its
///    lifetime, so a tombstone TTL of [`CANCEL_TOMBSTONE_LIFETIME`]
///    (== `AUTHORIZATION_LIFETIME`) covers the whole window in which the
///    session could still reach its store (see the call sites in
///    [`begin_session`] and `tersa_oauth_macos_begin`).
fn allocate_session_id() -> Result<u64, i32> {
    NEXT_SESSION_ID
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_error| STATUS_INTERNAL)
}

fn begin_session(client_id: &str, redirect_uri: Url) -> Result<(u64, BegunSession), i32> {
    if client_id.trim().is_empty() || client_id.to_ascii_uppercase().contains("UNCONFIGURED") {
        return Err(STATUS_CONFIGURATION_MISSING);
    }
    // Invariant (see allocate_session_id): production sessions live exactly
    // AUTHORIZATION_LIFETIME, so the tombstone TTL covers the store window.
    let config = AuthorizationConfig::new(client_id, redirect_uri, AUTHORIZATION_LIFETIME)
        .map_err(status_for_error)?;
    let prepared =
        prepare_authorization(config, SystemMonotonicClock::new()).map_err(status_for_error)?;
    let (authorization_url, session) = prepared.into_parts();
    if authorization_url.as_str().len() > MAX_AUTHORIZATION_URL_BYTES {
        return Err(STATUS_INVALID_INPUT);
    }
    // Invariant (see allocate_session_id): allocate strictly AFTER
    // prepare_authorization fixed the session's clock origin.
    let session_id = allocate_session_id()?;
    Ok((
        session_id,
        BegunSession {
            session,
            authorization_url,
            client_id: client_id.to_owned(),
        },
    ))
}

fn ios_redirect_uri(scheme: &str) -> Result<Url, i32> {
    if scheme.is_empty()
        || scheme.to_ascii_uppercase().contains("UNCONFIGURED")
        || scheme.eq_ignore_ascii_case("http")
        || scheme.eq_ignore_ascii_case("https")
        || !scheme.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')))
        })
    {
        return Err(STATUS_CONFIGURATION_MISSING);
    }
    Url::parse(&format!("{scheme}:{IOS_CALLBACK_PATH}")).map_err(|_error| STATUS_INVALID_INPUT)
}

fn status_for_error(error: OAuthError) -> i32 {
    match error {
        OAuthError::Expired => STATUS_EXPIRED,
        OAuthError::EntropyUnavailable => STATUS_INTERNAL,
        OAuthError::InvalidConfiguration => STATUS_CONFIGURATION_MISSING,
        OAuthError::InsufficientScope => STATUS_INSUFFICIENT_SCOPE,
        _ => STATUS_REJECTED,
    }
}

/// Runs `session.finish()` and the grant store in ONE registry critical
/// section, so mutex serialization turns the tombstone and expiry checks into
/// a store bound: a grant becomes claimable only when its expiry check passed
/// in the same section as the store itself (see [`CANCEL_TOMBSTONE_LIFETIME`]).
///
/// `finish()` does no I/O and takes no other lock, and the caller holds no
/// other lock, so the section cannot deadlock; the finisher holds ONLY the
/// registry mutex. The lock is released BEFORE any non-registry work
/// (`ensure_reaper`, HTTP responses, buffer zeroization by the caller).
fn finish_and_store(
    session_id: u64,
    session: &mut PendingSession,
    callback_url: &Url,
    client_id: &str,
) -> i32 {
    // Recover a poisoned lock rather than abandon it: dropping the guard on
    // poison would strand every already-resident code+verifier un-zeroized for
    // the process lifetime, inverting the TTL bound. The maps hold no invariant
    // a panic could break.
    let mut registry = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let status = match session.finish(callback_url) {
        Ok(grant) => match store_grant_locked(
            &mut registry,
            session_id,
            grant,
            session.redirect_uri().clone(),
            client_id.to_owned(),
            Instant::now(),
        ) {
            StoreOutcome::Stored => STATUS_SUCCEEDED,
            StoreOutcome::RefusedCancelled => STATUS_CANCELLED,
        },
        Err(error) => status_for_error(error),
    };
    drop(registry);
    ensure_reaper();
    status
}

/// Stores a finished grant in an already-held `registry` under its OAuth
/// `session_id` for a later single-use claim by the token-exchange step.
/// Returns [`StoreOutcome::RefusedCancelled`] without storing when a cancel
/// tombstone protects the session: the refused grant drops here, wiping its
/// code and verifier. The tombstone check runs FIRST, so a refused store
/// never triggers a cap eviction and causes no collateral grant loss.
///
/// The caller must hold the registry lock across the whole finish→store
/// section (see [`finish_and_store`]) and must not call [`ensure_reaper`]
/// while holding it.
#[must_use]
fn store_grant_locked(
    registry: &mut GrantRegistry,
    session_id: u64,
    grant: AuthorizationGrant,
    redirect_uri: Url,
    client_id: String,
    created_at: Instant,
) -> StoreOutcome {
    if registry.cancelled.contains_key(&session_id) {
        // A cancel already claimed this session: the incoming grant drops here,
        // wiping its code and verifier instead of becoming claimable.
        return StoreOutcome::RefusedCancelled;
    }
    // The cap bounds secret residency, so it applies to the secret-bearing
    // grants map ONLY — never to the tombstones.
    if registry.grants.len() >= MAX_PENDING_GRANTS && !registry.grants.contains_key(&session_id) {
        evict_oldest_pending_grant(&mut registry.grants);
    }
    registry.grants.insert(
        session_id,
        PendingGrant {
            grant,
            redirect_uri,
            client_id,
            created_at,
        },
    );
    StoreOutcome::Stored
}

/// Standalone-store seam for tests: one registry critical section around
/// [`store_grant_locked`], mirroring the fused finish→store path. Production
/// stores go through [`finish_and_store`].
#[cfg(test)]
#[must_use]
fn store_grant(
    session_id: u64,
    grant: AuthorizationGrant,
    redirect_uri: Url,
    client_id: &str,
) -> StoreOutcome {
    store_grant_at(session_id, grant, redirect_uri, client_id, Instant::now())
}

#[cfg(test)]
#[must_use]
fn store_grant_at(
    session_id: u64,
    grant: AuthorizationGrant,
    redirect_uri: Url,
    client_id: &str,
    created_at: Instant,
) -> StoreOutcome {
    let mut registry = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let outcome = store_grant_locked(
        &mut registry,
        session_id,
        grant,
        redirect_uri,
        client_id.to_owned(),
        created_at,
    );
    drop(registry);
    ensure_reaper();
    outcome
}

fn evict_oldest_pending_grant(grants: &mut BTreeMap<u64, PendingGrant>) {
    let oldest = grants
        .iter()
        .min_by_key(|(_session_id, grant)| grant.created_at)
        .map(|(session_id, _grant)| *session_id);
    if let Some(session_id) = oldest {
        grants.remove(&session_id);
    }
}

/// Claims the grant stored under an OAuth `session_id` for token exchange.
///
/// Returns the grant, its redirect URI, and the client id exactly once: a
/// missing, expired, cancelled, or already-claimed id yields `None`. The
/// client id is the one begin recorded and the store kept with the grant, so
/// the exchange configuration cannot disagree with the session by construction.
///
/// A SUCCESSFUL claim also takes the session's in-flight lease in the SAME
/// critical section (`GrantRegistry::in_flight`): a cancel tombstone stamped
/// afterwards is pinned against TTL reaping until the connect worker
/// acknowledges completion via [`complete_session`]. A claim that returns
/// `None` takes no lease.
///
/// # Invariant
///
/// The `session_id` is a lookup key, NOT a capability: it is a sequential,
/// Swift-visible counter, so a caller that can supply an arbitrary `session_id`
/// could retrieve another flow's code and verifier. This function is a plain
/// in-process Rust seam with no C ABI; the `session_id` must only ever be one the
/// caller legitimately holds from its own begin/finish, never accepted from an
/// untrusted source.
#[must_use]
pub fn claim_grant(session_id: u64) -> Option<(AuthorizationGrant, Url, String)> {
    let mut registry = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    // A claim must NOT consume a tombstone: removing it here would let a
    // still-running finisher store a grant afterwards, re-arming the race the
    // tombstone closes. Only the reaper retires tombstones, once the session
    // can no longer produce a grant.
    if registry.cancelled.contains_key(&session_id) {
        // Defensive wipe: a grant and a tombstone cannot coexist today, but
        // if that ever changes the secret must be destroyed here rather than
        // linger. This drops a GRANT, never the tombstone.
        let _wiped = registry.grants.remove(&session_id);
        return None;
    }
    let entry = registry.grants.remove(&session_id)?;
    if entry.created_at.elapsed() >= PENDING_GRANT_LIFETIME {
        // The abandoned grant drops here, wiping its code and verifier. NO
        // lease is taken: the claim yielded nothing.
        None
    } else {
        // The successful claim takes the in-flight lease in the same critical
        // section as the grant removal, so a cancel racing the claim either
        // lands BEFORE it (the tombstone refuses the claim above) or AFTER it
        // (the lease is resident and pins the tombstone).
        registry.in_flight.insert(session_id);
        Some((entry.grant, entry.redirect_uri, entry.client_id))
    }
}

/// Queries whether an OAuth `session_id` was cancelled, WITHOUT consuming the
/// tombstone.
///
/// This is the connect flow's cancel-fence query: the token-exchange
/// composition checks it after the provider exchange mints tokens but before
/// the refresh token is stored, so a user who cancelled while the exchange was
/// in flight revokes the minted token and aborts instead of ending up
/// connected. The query is non-consuming — a `true` answer leaves the
/// tombstone protective against a still-running finisher; only the reaper
/// retires tombstones, once the session can no longer produce a grant — and
/// for a CLAIMED session the in-flight lease pins the tombstone until the
/// connect worker calls [`complete_session`].
///
/// # Invariant
///
/// The `session_id` is a lookup key, NOT a capability (the same note
/// [`claim_grant`] carries): it is a sequential, Swift-visible counter, so an
/// in-process caller walking `1..NEXT_SESSION_ID` could probe which flows were
/// cancelled. That discloses only cancel state, never secrets, but the
/// `session_id` must only ever be one the caller legitimately holds from its
/// own begin, never accepted from an untrusted source.
#[must_use]
pub fn is_session_cancelled(session_id: u64) -> bool {
    // Recover a poisoned lock rather than abandon the query, matching every
    // other registry access: the maps hold no invariant a panic could break.
    pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .cancelled
        .contains_key(&session_id)
}

/// Releases a claimed session's in-flight lease: the connect worker's
/// acknowledgement that its cycle finished, on success and on every error.
///
/// Removes `session_id` from `GrantRegistry::in_flight`; if a cancel
/// tombstone is resident for the session its stamp is moved to now, so normal
/// TTL reaping resumes FROM THE RELEASE rather than retroactively from the
/// original cancel time. Idempotent and infallible: completing an unclaimed or
/// already-completed session changes nothing. Same poison recovery as every
/// other registry access.
///
/// This is the ONLY lease-release site, and it is deliberately not driven by
/// `Drop` on the caller side: a mid-connect drop must leave the tombstone
/// pinned (fail-safe), never reopen the store-without-fence bypass the
/// tombstone closes.
pub fn complete_session(session_id: u64) {
    let mut registry = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    registry.in_flight.remove(&session_id);
    if let Some(stamped_at) = registry.cancelled.get_mut(&session_id) {
        *stamped_at = Instant::now();
    }
}

fn ensure_reaper() {
    // Claim the spawn slot exactly once, releasing it again if the OS refuses
    // the thread so the next ensure_reaper call retries. std::thread::spawn
    // panics on thread-creation failure, which is fatal across the C ABI with
    // panic = "abort", so build the thread explicitly and tolerate the error:
    // without a reaper, wipes are merely deferred to the next successful call
    // (claims still TTL-check at claim time), never lost.
    if REAPER_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    if std::thread::Builder::new()
        .name("tersa-oauth-reaper".into())
        .spawn(|| {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                reap_expired_ios_sessions();
                reap_expired_pending_grants(Instant::now());
            }
        })
        .is_err()
    {
        REAPER_STARTED.store(false, Ordering::Release);
    }
}

fn reap_expired_ios_sessions() {
    // Recover a poisoned lock rather than skip the sweep: abandoning the map
    // would strand `Zeroizing` verifiers for the process lifetime.
    let mut sessions = ios_sessions()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    sessions.retain(|_session_id, entry| match entry.session.expire() {
        Ok(()) => false,
        Err(OAuthError::NotExpired) => true,
        Err(_terminal_error) => false,
    });
}

/// Wipes finished grants older than [`PENDING_GRANT_LIFETIME`] and retires
/// cancel tombstones older than [`CANCEL_TOMBSTONE_LIFETIME`] as of `now`, so
/// an abandoned code and verifier are wiped within one reaper tick while a
/// tombstone stays protective for the whole window in which its session could
/// still produce a grant. A tombstone whose session holds an in-flight lease
/// is NEVER retired, and lease entries themselves are never TTL-reaped: the
/// claim→fence window spans the token-exchange network request, so the lease
/// — released only by [`complete_session`] — bounds it, not the TTL.
fn reap_expired_pending_grants(now: Instant) {
    let mut registry = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    // Destructure once so the tombstone sweep can read the lease set while the
    // maps are borrowed for retention.
    let GrantRegistry {
        grants,
        cancelled,
        in_flight,
    } = &mut *registry;
    grants
        .retain(|_session_id, grant| now.duration_since(grant.created_at) < PENDING_GRANT_LIFETIME);
    cancelled.retain(|session_id, stamped_at| {
        in_flight.contains(session_id)
            || now.duration_since(*stamped_at) < CANCEL_TOMBSTONE_LIFETIME
    });
}

#[expect(
    unsafe_code,
    reason = "raw C buffers are copied immediately into checked Rust values"
)]
unsafe fn read_utf8(pointer: *const u8, length: usize) -> Result<String, i32> {
    if pointer.is_null() || length == 0 || length > MAX_AUTHORIZATION_URL_BYTES {
        return Err(STATUS_INVALID_INPUT);
    }
    // SAFETY: The caller guarantees `length` readable bytes at `pointer`.
    let bytes = unsafe { slice::from_raw_parts(pointer, length) };
    str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_error| STATUS_INVALID_INPUT)
}

#[expect(
    unsafe_code,
    reason = "the C ABI writes fixed-size scalar and byte outputs"
)]
unsafe fn write_begin_output(
    session_id: u64,
    authorization_url: &str,
    output_session_id: *mut u64,
    output_url: *mut u8,
    output_url_capacity: usize,
    output_url_len: *mut usize,
) -> Result<(), i32> {
    if output_session_id.is_null() || output_url.is_null() || output_url_len.is_null() {
        return Err(STATUS_INVALID_INPUT);
    }
    if authorization_url.len() > output_url_capacity {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    // SAFETY: The caller guarantees writable outputs with the declared capacity.
    unsafe {
        output_url.copy_from_nonoverlapping(authorization_url.as_ptr(), authorization_url.len());
        output_session_id.write(session_id);
        output_url_len.write(authorization_url.len());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io::{self, Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        AUTHORIZATION_LIFETIME, AuthorizationConfig, PendingSession, STATUS_CANCELLED,
        STATUS_EXPIRED, STATUS_INTERNAL, STATUS_OK, STATUS_REJECTED, STATUS_SUCCEEDED,
        SystemMonotonicClock, Url, Zeroizing, finish_and_store, prepare_authorization,
        status_for_error,
    };

    const MAX_REQUEST_BYTES: usize = 8_192;
    const REQUEST_READ_LIFETIME: Duration = Duration::from_secs(2);
    const CALLBACK_PATH: &str = "/";
    const HTTP_SUCCESS_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 55\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nAuthorization received. Return to the tersa.app window.";
    const HTTP_ERROR_RESPONSE: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 55\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nAuthorization rejected. Return to the tersa.app window.";

    #[derive(Debug)]
    pub(super) struct MacSessionEntry {
        pub(super) status: Arc<AtomicI32>,
        pub(super) cancel: Arc<AtomicBool>,
    }

    #[derive(Debug, Eq, PartialEq)]
    enum LoopbackError {
        AlreadyConsumed,
        NonLoopbackPeer,
        OversizedRequest,
        InvalidMethod,
        WrongPath,
        MalformedRequest,
        ReadDeadline,
        Io,
    }

    struct AcceptedCallback {
        stream: TcpStream,
        callback: Url,
    }

    pub(super) struct LoopbackReceiver {
        listener: Option<TcpListener>,
        redirect_uri: Url,
        consumed: bool,
    }

    impl LoopbackReceiver {
        fn bind() -> io::Result<Self> {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            let port = listener.local_addr()?.port();
            let redirect_uri = Url::parse(&format!("http://127.0.0.1:{port}{CALLBACK_PATH}"))
                .map_err(io::Error::other)?;
            Ok(Self {
                listener: Some(listener),
                redirect_uri,
                consumed: false,
            })
        }

        fn redirect_uri(&self) -> &Url {
            &self.redirect_uri
        }

        fn try_accept(
            &mut self,
            authorization_deadline: Instant,
        ) -> Result<Option<AcceptedCallback>, LoopbackError> {
            if self.consumed {
                return Err(LoopbackError::AlreadyConsumed);
            }
            let listener = self
                .listener
                .as_ref()
                .ok_or(LoopbackError::AlreadyConsumed)?;
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    let request_deadline = std::cmp::min(
                        authorization_deadline,
                        Instant::now() + REQUEST_READ_LIFETIME,
                    );
                    match read_callback(&mut stream, peer, &self.redirect_uri, request_deadline) {
                        Ok(callback) => {
                            self.consumed = true;
                            self.listener.take();
                            Ok(Some(AcceptedCallback { stream, callback }))
                        }
                        Err(_rejected_connection) => {
                            write_response(&mut stream, HTTP_ERROR_RESPONSE);
                            Ok(None)
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(_) => Err(LoopbackError::Io),
            }
        }
    }

    fn read_callback(
        stream: &mut TcpStream,
        peer: SocketAddr,
        redirect_uri: &Url,
        deadline: Instant,
    ) -> Result<Url, LoopbackError> {
        stream
            .set_nonblocking(false)
            .map_err(|_error| LoopbackError::Io)?;
        let mut request = Zeroizing::new(Vec::with_capacity(1_024));
        let mut chunk = Zeroizing::new([0_u8; 1_024]);
        let mut complete = false;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(LoopbackError::ReadDeadline)?;
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_error| LoopbackError::Io)?;
            let count = match stream.read(&mut chunk[..]) {
                Ok(count) => count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(LoopbackError::ReadDeadline);
                }
                Err(_error) => return Err(LoopbackError::Io),
            };
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                complete = true;
                break;
            }
            if request.len() > MAX_REQUEST_BYTES {
                return Err(LoopbackError::OversizedRequest);
            }
        }
        if !complete {
            return Err(LoopbackError::MalformedRequest);
        }
        validate_request(peer, &request, redirect_uri)
    }

    fn write_response(stream: &mut TcpStream, response: &[u8]) {
        let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
        let _ = stream.write_all(response);
    }

    fn complete_callback(
        session_id: u64,
        mut accepted: AcceptedCallback,
        session: &mut PendingSession,
        client_id: &str,
    ) -> i32 {
        // `finish()` and the grant store share ONE registry critical section
        // inside `finish_and_store`; the HTTP response write and the callback
        // re-zeroization happen only after that lock is released, driven by
        // the computed status.
        let status = finish_and_store(session_id, session, &accepted.callback, client_id);
        let response = if status == STATUS_SUCCEEDED {
            HTTP_SUCCESS_RESPONSE
        } else {
            HTTP_ERROR_RESPONSE
        };
        write_response(&mut accepted.stream, response);
        let _callback_bytes = Zeroizing::new(String::from(accepted.callback));
        status
    }

    fn validate_request(
        peer: SocketAddr,
        request: &[u8],
        redirect_uri: &Url,
    ) -> Result<Url, LoopbackError> {
        if !peer.ip().is_loopback() {
            return Err(LoopbackError::NonLoopbackPeer);
        }
        if request.len() > MAX_REQUEST_BYTES {
            return Err(LoopbackError::OversizedRequest);
        }
        let request =
            std::str::from_utf8(request).map_err(|_error| LoopbackError::MalformedRequest)?;
        let request_line = request.split_once("\r\n").map_or(request, |(line, _)| line);
        let mut fields = request_line.split(' ');
        let method = fields.next().ok_or(LoopbackError::MalformedRequest)?;
        let target = fields.next().ok_or(LoopbackError::MalformedRequest)?;
        let version = fields.next().ok_or(LoopbackError::MalformedRequest)?;
        if fields.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
            return Err(LoopbackError::MalformedRequest);
        }
        if method != "GET" {
            return Err(LoopbackError::InvalidMethod);
        }
        if !target.starts_with(CALLBACK_PATH)
            || target
                .as_bytes()
                .get(CALLBACK_PATH.len())
                .is_some_and(|byte| *byte != b'?')
        {
            return Err(LoopbackError::WrongPath);
        }
        let callback = redirect_uri
            .join(target)
            .map_err(|_error| LoopbackError::MalformedRequest)?;
        if callback.path() != CALLBACK_PATH {
            return Err(LoopbackError::WrongPath);
        }
        Ok(callback)
    }

    pub(super) fn begin(
        client_id: &str,
    ) -> Result<(Url, PendingSession, LoopbackReceiver, String), i32> {
        let receiver = LoopbackReceiver::bind().map_err(|_error| STATUS_INTERNAL)?;
        // Invariant (see allocate_session_id): production sessions live exactly
        // AUTHORIZATION_LIFETIME, so the tombstone TTL covers the store window.
        let config = AuthorizationConfig::new(
            client_id,
            receiver.redirect_uri().clone(),
            AUTHORIZATION_LIFETIME,
        )
        .map_err(status_for_error)?;
        let prepared =
            prepare_authorization(config, SystemMonotonicClock::new()).map_err(status_for_error)?;
        let (url, session) = prepared.into_parts();
        // The validated client id rides along: the finished session keeps only
        // redirect/state/verifier, so the store needs it again at finish time.
        Ok((url, session, receiver, client_id.to_owned()))
    }

    pub(super) fn spawn(
        session_id: u64,
        mut receiver: LoopbackReceiver,
        mut session: PendingSession,
        client_id: String,
    ) -> MacSessionEntry {
        let status = Arc::new(AtomicI32::new(STATUS_OK));
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_status = Arc::clone(&status);
        let worker_cancel = Arc::clone(&cancel);
        // The client id moves with the worker thread — the entry the spawn
        // thread owns alongside the session — so the value stored with the
        // finished grant is the one begin validated.
        thread::spawn(move || {
            let deadline = Instant::now() + AUTHORIZATION_LIFETIME;
            loop {
                if worker_cancel.load(Ordering::Acquire) {
                    let _ = session.cancel();
                    worker_status.store(STATUS_CANCELLED, Ordering::Release);
                    return;
                }
                if Instant::now() >= deadline {
                    let _ = session.expire();
                    worker_status.store(STATUS_EXPIRED, Ordering::Release);
                    return;
                }
                match receiver.try_accept(deadline) {
                    Ok(Some(accepted)) => {
                        worker_status.store(
                            complete_callback(session_id, accepted, &mut session, &client_id),
                            Ordering::Release,
                        );
                        return;
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(10)),
                    Err(_) => {
                        worker_status.store(STATUS_REJECTED, Ordering::Release);
                        return;
                    }
                }
            }
        });
        MacSessionEntry { status, cancel }
    }

    #[cfg(test)]
    mod tests {
        #![expect(
            clippy::unwrap_used,
            reason = "loopback tests use static addresses and fail immediately on fixture errors"
        )]

        use std::io::{Read as _, Write as _};
        use std::net::TcpStream;
        use std::thread;
        use std::time::{Duration, Instant};

        use super::super::{
            allocate_session_id, claim_grant, registry_test_guard, tersa_oauth_cancel,
        };
        use super::{
            AcceptedCallback, CALLBACK_PATH, HTTP_ERROR_RESPONSE, HTTP_SUCCESS_RESPONSE,
            LoopbackError, LoopbackReceiver, MAX_REQUEST_BYTES, STATUS_CANCELLED, STATUS_REJECTED,
            STATUS_SUCCEEDED, SocketAddr, Url, begin, complete_callback, validate_request,
        };

        fn redirect() -> Url {
            Url::parse("http://127.0.0.1:43123").unwrap()
        }

        fn deadline() -> Instant {
            Instant::now() + Duration::from_secs(2)
        }

        fn state(authorization_url: &Url) -> String {
            authorization_url
                .query_pairs()
                .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
                .unwrap()
        }

        fn wait_for_callback(receiver: &mut LoopbackReceiver) -> AcceptedCallback {
            let authorization_deadline = deadline();
            loop {
                if let Some(accepted) = receiver.try_accept(authorization_deadline).unwrap() {
                    return accepted;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }

        #[test]
        fn binds_only_a_literal_ipv4_loopback_ephemeral_port() {
            let receiver = LoopbackReceiver::bind().unwrap();
            assert_eq!(receiver.redirect_uri().host_str(), Some("127.0.0.1"));
            assert!(receiver.redirect_uri().port().is_some_and(|port| port > 0));
        }

        #[test]
        fn authorization_uses_the_provider_documented_root_redirect() {
            let (authorization_url, _session, receiver, _client_id) =
                begin("public-test-client").unwrap();
            let redirect_parameter = authorization_url
                .query_pairs()
                .find_map(|(name, value)| (name == "redirect_uri").then(|| value.into_owned()))
                .unwrap();

            assert_eq!(receiver.redirect_uri().path(), CALLBACK_PATH);
            assert_eq!(redirect_parameter, receiver.redirect_uri().as_str());
            assert!(!redirect_parameter.contains("/oauth/callback"));
        }

        #[test]
        fn rejects_non_get_wrong_path_oversize_and_non_loopback() {
            let loopback: SocketAddr = "127.0.0.1:50000".parse().unwrap();
            let remote: SocketAddr = "192.0.2.10:50000".parse().unwrap();
            assert_eq!(
                validate_request(loopback, b"POST / HTTP/1.1\r\n\r\n", &redirect()),
                Err(LoopbackError::InvalidMethod)
            );
            assert_eq!(
                validate_request(loopback, b"GET /wrong HTTP/1.1\r\n\r\n", &redirect()),
                Err(LoopbackError::WrongPath)
            );
            assert_eq!(
                validate_request(loopback, &vec![b'a'; MAX_REQUEST_BYTES + 1], &redirect()),
                Err(LoopbackError::OversizedRequest)
            );
            assert_eq!(
                validate_request(remote, b"GET / HTTP/1.1\r\n\r\n", &redirect()),
                Err(LoopbackError::NonLoopbackPeer)
            );
        }

        #[test]
        fn a_receiver_rejects_a_second_connection_attempt() {
            let mut receiver = LoopbackReceiver::bind().unwrap();
            receiver.consumed = true;
            assert!(matches!(
                receiver.try_accept(deadline()),
                Err(LoopbackError::AlreadyConsumed)
            ));
        }

        #[test]
        fn callback_path_is_exact() {
            let loopback: SocketAddr = "127.0.0.1:50000".parse().unwrap();
            let request = format!("GET {CALLBACK_PATH}?state=test&code=test HTTP/1.1\r\n\r\n");
            let callback = validate_request(loopback, request.as_bytes(), &redirect()).unwrap();
            assert_eq!(callback.path(), CALLBACK_PATH);
            assert_eq!(callback.query(), Some("state=test&code=test"));
            assert_eq!(
                validate_request(
                    loopback,
                    b"GET /oauth/callback HTTP/1.1\r\n\r\n",
                    &redirect()
                ),
                Err(LoopbackError::WrongPath)
            );
        }

        #[test]
        fn malformed_preconnect_is_discarded_before_a_valid_callback() {
            let (authorization_url, mut session, mut receiver, client_id) =
                begin("public-test-client").unwrap();
            let address = receiver.listener.as_ref().unwrap().local_addr().unwrap();
            let preconnect = thread::spawn(move || {
                let mut stream = TcpStream::connect(address).unwrap();
                stream.write_all(b"POST / HTTP/1.1\r\n\r\n").unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).unwrap();
                response
            });
            let authorization_deadline = deadline();
            while !preconnect.is_finished() {
                assert!(
                    receiver
                        .try_accept(authorization_deadline)
                        .unwrap()
                        .is_none()
                );
                thread::sleep(Duration::from_millis(1));
            }
            let rejected_response = preconnect.join().unwrap();
            assert_eq!(rejected_response, HTTP_ERROR_RESPONSE);
            assert!(!receiver.consumed);

            let state = state(&authorization_url);
            let browser = thread::spawn(move || {
                let mut stream = TcpStream::connect(address).unwrap();
                write!(
                    stream,
                    "GET /?state={state}&code=secret-code HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                )
                .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).unwrap();
                response
            });
            let accepted = wait_for_callback(&mut receiver);
            let session_id = allocate_session_id().unwrap();
            let _registry_guard = registry_test_guard();
            assert_eq!(
                complete_callback(session_id, accepted, &mut session, &client_id),
                STATUS_SUCCEEDED
            );
            let response = browser.join().unwrap();
            assert_eq!(response, HTTP_SUCCESS_RESPONSE);
            assert!(!response.windows(6).any(|window| window == b"secret"));
            assert!(matches!(
                receiver.try_accept(deadline()),
                Err(LoopbackError::AlreadyConsumed)
            ));
            assert!(TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_err());

            let (grant, redirect_uri, claimed_client_id) = claim_grant(session_id).unwrap();
            assert_eq!(grant.code(), "secret-code");
            assert_eq!(grant.verifier().len(), 43);
            assert_eq!(&redirect_uri, receiver.redirect_uri());
            // The claim returns the client id begin recorded, carried with the grant.
            assert_eq!(claimed_client_id, "public-test-client");
            assert!(claim_grant(session_id).is_none());
        }

        #[test]
        fn a_callback_finishing_after_a_cancel_reports_cancelled_and_stores_nothing() {
            let (authorization_url, mut session, mut receiver, client_id) =
                begin("public-test-client").unwrap();
            let address = receiver.listener.as_ref().unwrap().local_addr().unwrap();
            let state = state(&authorization_url);
            let browser = thread::spawn(move || {
                let mut stream = TcpStream::connect(address).unwrap();
                write!(
                    stream,
                    "GET /?state={state}&code=raced-code HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                )
                .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).unwrap();
                response
            });
            let accepted = wait_for_callback(&mut receiver);
            let session_id = allocate_session_id().unwrap();
            let _registry_guard = registry_test_guard();
            // The cancel's tombstone is already resident, as it is when the
            // worker thread reaches complete_callback after tersa_oauth_cancel
            // returned: the raced store must lose. Admission passes (the id is
            // allocated), so the cancel reports STATUS_CANCELLED.
            assert_eq!(tersa_oauth_cancel(session_id), STATUS_CANCELLED);

            assert_eq!(
                complete_callback(session_id, accepted, &mut session, &client_id),
                STATUS_CANCELLED
            );
            let response = browser.join().unwrap();
            assert_eq!(response, HTTP_ERROR_RESPONSE);
            assert!(!response.windows(6).any(|window| window == b"raced"));
            assert!(claim_grant(session_id).is_none());
            // The raced store left no grant behind; the tombstone itself stays
            // resident (claim must not consume it) until the reaper retires it.
            let registry = super::super::pending_grants().lock().unwrap();
            assert!(!registry.grants.contains_key(&session_id));
            assert!(registry.cancelled.contains_key(&session_id));
        }

        #[test]
        fn state_mismatch_receives_a_static_error_response() {
            // complete_callback reaches the registry via finish_and_store, so
            // this test serializes and resets with every other registry test.
            let _registry_guard = registry_test_guard();
            let (_authorization_url, mut session, mut receiver, client_id) =
                begin("public-test-client").unwrap();
            let address = receiver.listener.as_ref().unwrap().local_addr().unwrap();
            let browser = thread::spawn(move || {
                let mut stream = TcpStream::connect(address).unwrap();
                stream
                    .write_all(b"GET /?state=wrong&code=secret-code HTTP/1.1\r\n\r\n")
                    .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).unwrap();
                response
            });
            let accepted = wait_for_callback(&mut receiver);
            let session_id = allocate_session_id().unwrap();
            assert_eq!(
                complete_callback(session_id, accepted, &mut session, &client_id),
                STATUS_REJECTED
            );
            let response = browser.join().unwrap();
            assert_eq!(response, HTTP_ERROR_RESPONSE);
            assert!(!response.windows(6).any(|window| window == b"secret"));
        }

        #[test]
        fn incomplete_request_has_an_absolute_deadline() {
            let mut receiver = LoopbackReceiver::bind().unwrap();
            let address = receiver.listener.as_ref().unwrap().local_addr().unwrap();
            let mut client = TcpStream::connect(address).unwrap();
            let drip = thread::spawn(move || {
                for _ in 0..20 {
                    if client.write_all(b"x").is_err() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            });
            thread::sleep(Duration::from_millis(5));
            let started = Instant::now();
            assert!(
                receiver
                    .try_accept(Instant::now() + Duration::from_millis(50))
                    .unwrap()
                    .is_none()
            );
            let elapsed = started.elapsed();
            assert!(elapsed >= Duration::from_millis(35));
            assert!(elapsed < Duration::from_millis(150));
            drip.join().unwrap();
            assert!(!receiver.consumed);
        }

        #[test]
        fn a_stored_grant_returns_the_client_id_begin_recorded() {
            // The macOS store path end to end: begin records the client id, the
            // loopback drive stores it with the grant, and the single-use claim
            // returns it.
            let _registry_guard = registry_test_guard();
            let (authorization_url, mut session, mut receiver, client_id) =
                begin("client-mac-claim").unwrap();
            let address = receiver.listener.as_ref().unwrap().local_addr().unwrap();
            let state = state(&authorization_url);
            let browser = thread::spawn(move || {
                let mut stream = TcpStream::connect(address).unwrap();
                write!(
                    stream,
                    "GET /?state={state}&code=client-id-code HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                )
                .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).unwrap();
                response
            });
            let accepted = wait_for_callback(&mut receiver);
            let session_id = allocate_session_id().unwrap();
            assert_eq!(
                complete_callback(session_id, accepted, &mut session, &client_id),
                STATUS_SUCCEEDED
            );
            assert_eq!(browser.join().unwrap(), HTTP_SUCCESS_RESPONSE);

            let (_grant, redirect_uri, claimed_client_id) = claim_grant(session_id).unwrap();
            assert_eq!(claimed_client_id, "client-mac-claim");
            assert_eq!(&redirect_uri, receiver.redirect_uri());
        }
    }
}

#[cfg(target_os = "macos")]
use macos::{MacSessionEntry, begin as begin_macos, spawn as spawn_macos};

#[cfg(target_os = "macos")]
static MACOS_SESSIONS: OnceLock<Mutex<BTreeMap<u64, MacSessionEntry>>> = OnceLock::new();

#[cfg(target_os = "macos")]
fn macos_sessions() -> &'static Mutex<BTreeMap<u64, MacSessionEntry>> {
    MACOS_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Starts a macOS loopback authorization session before browser handoff.
///
/// # Safety
///
/// Input and output pointers must satisfy the same requirements as
/// [`tersa_oauth_ios_begin`].
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "the C ABI validates and copies caller-owned byte buffers"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_oauth_macos_begin(
    client_id: *const u8,
    client_id_len: usize,
    output_session_id: *mut u64,
    output_url: *mut u8,
    output_url_capacity: usize,
    output_url_len: *mut usize,
) -> i32 {
    let result = (|| {
        // SAFETY: The function contract requires a readable input buffer.
        let client_id = unsafe { read_utf8(client_id, client_id_len) }?;
        if client_id.trim().is_empty() || client_id.to_ascii_uppercase().contains("UNCONFIGURED") {
            return Err(STATUS_CONFIGURATION_MISSING);
        }
        let (authorization_url, session, receiver, client_id) = begin_macos(&client_id)?;
        let authorization_url = Zeroizing::new(String::from(authorization_url));
        // Invariant (see allocate_session_id): allocate strictly AFTER
        // begin_macos's prepare_authorization fixed the session's clock origin.
        let session_id = allocate_session_id()?;
        // SAFETY: The function contract requires writable output buffers.
        unsafe {
            write_begin_output(
                session_id,
                &authorization_url,
                output_session_id,
                output_url,
                output_url_capacity,
                output_url_len,
            )?;
        }
        // Same poison recovery as `tersa_oauth_cancel`: the session map holds
        // no invariant a panic could break.
        macos_sessions()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                session_id,
                spawn_macos(session_id, receiver, session, client_id),
            );
        // A macOS begin→cancel flow must reap its tombstone even if no grant
        // is ever stored in this process.
        ensure_reaper();
        Ok(())
    })();
    result.map_or_else(|status| status, |()| STATUS_OK)
}

/// Polls one macOS loopback session without exposing sensitive values.
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "a stable unmangled symbol is required by the C-compatible Apple bridge"
)]
#[unsafe(no_mangle)]
pub extern "C" fn tersa_oauth_macos_poll(session_id: u64) -> i32 {
    // Recover a poisoned lock rather than fail closed: poll only reads and
    // removes entries, so no invariant a panic could break is at stake, and a
    // stuck poll would strand the worker's session entry forever.
    let mut sessions = macos_sessions()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(entry) = sessions.get(&session_id) else {
        return STATUS_REJECTED;
    };
    let status = entry.status.load(Ordering::Acquire);
    if status != STATUS_OK {
        sessions.remove(&session_id);
    }
    status
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "redirect tests use compile-time constant schemes"
    )]

    use std::time::{Duration, Instant};

    use super::{
        AUTHORIZATION_LIFETIME, AuthorizationConfig, AuthorizationGrant, CANCEL_TOMBSTONE_LIFETIME,
        IosSessionEntry, MAX_PENDING_GRANTS, NEXT_SESSION_ID, OAuthError, Ordering,
        PENDING_GRANT_LIFETIME, PoisonError, STATUS_CANCELLED, STATUS_CONFIGURATION_MISSING,
        STATUS_EXPIRED, STATUS_INSUFFICIENT_SCOPE, STATUS_OK, STATUS_REJECTED, STATUS_SUCCEEDED,
        StoreOutcome, SystemMonotonicClock, Url, allocate_session_id, claim_grant,
        complete_session, finish_and_store, ios_redirect_uri, ios_sessions, is_session_cancelled,
        pending_grants, prepare_authorization, reap_expired_ios_sessions,
        reap_expired_pending_grants, registry_test_guard, status_for_error, store_grant,
        store_grant_at, tersa_oauth_cancel, tersa_oauth_ios_begin, tersa_oauth_ios_finish,
    };

    #[test]
    fn insufficient_scope_has_a_distinct_bridge_status() {
        assert_eq!(
            status_for_error(OAuthError::InsufficientScope),
            STATUS_INSUFFICIENT_SCOPE
        );
    }

    /// Builds a live session with the given lifetime plus the well-formed
    /// callback whose state and code would finish it successfully, without
    /// consuming the session.
    fn make_session(lifetime: Duration, code: &str) -> (super::PendingSession, Url) {
        let redirect = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        let config = AuthorizationConfig::new("public-test-client", redirect, lifetime).unwrap();
        let prepared = prepare_authorization(config, SystemMonotonicClock::new()).unwrap();
        let state = prepared
            .authorization_url()
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        let mut callback = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", code);
        let (_authorization_url, session) = prepared.into_parts();
        (session, callback)
    }

    fn make_grant(code: &str) -> (AuthorizationGrant, Url) {
        let (mut session, callback) = make_session(Duration::from_secs(60), code);
        let redirect_uri = session.redirect_uri().clone();
        let grant = session.finish(&callback).unwrap();
        (grant, redirect_uri)
    }

    #[test]
    fn ios_redirect_scheme_fails_closed() {
        assert_eq!(ios_redirect_uri(""), Err(STATUS_CONFIGURATION_MISSING));
        assert_eq!(
            ios_redirect_uri("UNCONFIGURED"),
            Err(STATUS_CONFIGURATION_MISSING)
        );
        assert_eq!(ios_redirect_uri("https"), Err(STATUS_CONFIGURATION_MISSING));
        assert_eq!(
            ios_redirect_uri("app.tersa.oauth.test").unwrap().as_str(),
            "app.tersa.oauth.test:/oauth/callback"
        );
    }

    #[test]
    fn ios_pending_session_is_removed_by_its_expiry_task() {
        let config = AuthorizationConfig::new(
            "public-test-client",
            Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap(),
            Duration::from_millis(1),
        )
        .unwrap();
        let prepared = prepare_authorization(config, SystemMonotonicClock::new()).unwrap();
        let (_url, session) = prepared.into_parts();
        let session_id = u64::MAX;
        ios_sessions().lock().unwrap().insert(
            session_id,
            IosSessionEntry {
                session,
                client_id: "public-test-client".to_owned(),
            },
        );
        std::thread::sleep(Duration::from_millis(2));
        reap_expired_ios_sessions();

        assert!(!ios_sessions().lock().unwrap().contains_key(&session_id));
    }

    #[test]
    fn a_stored_grant_is_claimed_exactly_once() {
        let _registry_guard = registry_test_guard();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("claim-once-code");
        assert_eq!(
            store_grant_at(
                session_id,
                grant,
                redirect_uri.clone(),
                "public-test-client",
                Instant::now()
            ),
            StoreOutcome::Stored
        );

        let (claimed, claimed_redirect, claimed_client_id) = claim_grant(session_id).unwrap();
        assert_eq!(claimed.code(), "claim-once-code");
        assert_eq!(claimed.verifier().len(), 43);
        assert!(
            claimed
                .verifier()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert_eq!(claimed_redirect, redirect_uri);
        assert_eq!(claimed_client_id, "public-test-client");
        assert!(claim_grant(session_id).is_none());
    }

    #[expect(
        unsafe_code,
        reason = "the iOS begin/finish C ABI is unsafe to call and this test exercises its checked boundary"
    )]
    #[test]
    fn ios_finish_stores_the_client_id_begin_recorded() {
        // The iOS store path end to end through the public C ABI: begin records
        // the client id alongside the session, finish stores it with the grant,
        // and the single-use claim returns it.
        let _registry_guard = registry_test_guard();
        let client_id = b"client-ios-claim";
        let scheme = b"tersa-bridge-test";
        let mut oauth_session_id = 0_u64;
        let mut url_buffer = [0_u8; 4096];
        let mut url_len = 0_usize;
        // SAFETY: the input buffers are valid; the outputs are writable for
        // their declared sizes.
        let status = unsafe {
            tersa_oauth_ios_begin(
                client_id.as_ptr(),
                client_id.len(),
                scheme.as_ptr(),
                scheme.len(),
                &raw mut oauth_session_id,
                url_buffer.as_mut_ptr(),
                url_buffer.len(),
                &raw mut url_len,
            )
        };
        assert_eq!(status, STATUS_OK);
        let authorization_url =
            Url::parse(std::str::from_utf8(&url_buffer[..url_len]).unwrap()).unwrap();
        let state = authorization_url
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        let mut callback = Url::parse("tersa-bridge-test:/oauth/callback").unwrap();
        callback
            .query_pairs_mut()
            .append_pair("code", "ios-client-id-code")
            .append_pair("state", &state);
        let callback = callback.as_str();
        // SAFETY: the callback buffer is valid for its stated length.
        let status =
            unsafe { tersa_oauth_ios_finish(oauth_session_id, callback.as_ptr(), callback.len()) };
        assert_eq!(status, STATUS_SUCCEEDED);

        let (_grant, redirect_uri, claimed_client_id) = claim_grant(oauth_session_id).unwrap();
        assert_eq!(claimed_client_id, "client-ios-claim");
        assert_eq!(redirect_uri.as_str(), "tersa-bridge-test:/oauth/callback");
    }

    #[test]
    fn an_expired_stored_grant_is_not_claimable() {
        let _registry_guard = registry_test_guard();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("expired-code");
        let stale = Instant::now()
            .checked_sub(AUTHORIZATION_LIFETIME + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            store_grant_at(session_id, grant, redirect_uri, "public-test-client", stale),
            StoreOutcome::Stored
        );

        assert!(claim_grant(session_id).is_none());
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .grants
                .contains_key(&session_id)
        );
    }

    #[test]
    fn a_full_registry_evicts_the_oldest_pending_grant() {
        let _registry_guard = registry_test_guard();
        let base = Instant::now();
        let mut session_ids = Vec::new();
        for index in 0..MAX_PENDING_GRANTS {
            let session_id = allocate_session_id().unwrap();
            let (grant, redirect_uri) = make_grant("capped-code");
            assert_eq!(
                store_grant_at(
                    session_id,
                    grant,
                    redirect_uri,
                    "public-test-client",
                    base + Duration::from_secs(index as u64),
                ),
                StoreOutcome::Stored
            );
            session_ids.push(session_id);
        }
        let newest_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("newest-code");
        assert_eq!(
            store_grant_at(
                newest_id,
                grant,
                redirect_uri,
                "public-test-client",
                base + Duration::from_secs(1_000),
            ),
            StoreOutcome::Stored
        );

        assert!(claim_grant(session_ids[0]).is_none());
        for session_id in &session_ids[1..] {
            assert!(claim_grant(*session_id).is_some());
        }
        assert!(claim_grant(newest_id).is_some());
    }

    #[test]
    fn the_reaper_evicts_only_grants_older_than_the_authorization_lifetime() {
        let _registry_guard = registry_test_guard();
        let base = Instant::now();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("reaped-code");
        assert_eq!(
            store_grant_at(
                session_id,
                grant,
                redirect_uri,
                "public-test-client",
                base + Duration::from_secs(1),
            ),
            StoreOutcome::Stored
        );

        reap_expired_pending_grants(base + AUTHORIZATION_LIFETIME);
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .grants
                .contains_key(&session_id)
        );
        reap_expired_pending_grants(base + AUTHORIZATION_LIFETIME + Duration::from_secs(1));
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .grants
                .contains_key(&session_id)
        );
        assert!(claim_grant(session_id).is_none());
    }

    #[test]
    fn a_cancel_after_a_store_wipes_the_grant_and_blocks_claims() {
        let _registry_guard = registry_test_guard();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("cancelled-code");
        assert_eq!(
            store_grant_at(
                session_id,
                grant,
                redirect_uri,
                "public-test-client",
                Instant::now()
            ),
            StoreOutcome::Stored
        );

        // Displacing a stored grant is a real cancel: the grant drops (wiped)
        // here, the tombstone takes over, and nothing remains claimable.
        assert_eq!(tersa_oauth_cancel(session_id), STATUS_CANCELLED);
        let registry = pending_grants().lock().unwrap();
        assert!(!registry.grants.contains_key(&session_id));
        assert!(registry.cancelled.contains_key(&session_id));
        drop(registry);
        assert!(claim_grant(session_id).is_none());
    }

    #[test]
    fn a_claim_of_a_tombstone_keeps_it_protective_against_a_late_store() {
        let _registry_guard = registry_test_guard();
        let session_id = allocate_session_id().unwrap();
        // The cancel lands first and leaves its tombstone behind, as it does
        // when a callback finishes only after tersa_oauth_cancel returned.
        // Admission passes for the allocated id, so it reports STATUS_CANCELLED.
        assert_eq!(tersa_oauth_cancel(session_id), STATUS_CANCELLED);

        // A claim against the tombstone yields nothing and must NOT consume
        // it: the finisher may still be running, so the tombstone has to stay
        // resident and refuse the late store too.
        assert!(claim_grant(session_id).is_none());

        let (grant, redirect_uri) = make_grant("raced-code");
        assert_eq!(
            store_grant(session_id, grant, redirect_uri, "public-test-client"),
            StoreOutcome::RefusedCancelled
        );
        assert!(claim_grant(session_id).is_none());
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&session_id)
        );
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .grants
                .contains_key(&session_id)
        );
    }

    #[test]
    fn is_session_cancelled_reports_the_tombstone_without_consuming_it() {
        let _registry_guard = registry_test_guard();
        let cancelled_id = allocate_session_id().unwrap();
        let never_cancelled_id = allocate_session_id().unwrap();

        // A plausible id with no tombstone reports not-cancelled.
        assert!(!is_session_cancelled(never_cancelled_id));

        // The cancel stamps the tombstone; the fence query then reports it...
        assert_eq!(tersa_oauth_cancel(cancelled_id), STATUS_CANCELLED);
        assert!(is_session_cancelled(cancelled_id));
        // ...and the query is non-consuming: a second check still sees the
        // tombstone, which only the reaper retires, so a fence re-check (or a
        // late store) remains refused.
        assert!(is_session_cancelled(cancelled_id));
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&cancelled_id)
        );
        // The query touches only its own id: a sibling flow stays unaffected.
        assert!(!is_session_cancelled(never_cancelled_id));
    }

    #[test]
    fn grant_cap_pressure_never_evicts_a_cancel_tombstone() {
        let _registry_guard = registry_test_guard();
        let cancelled_id = allocate_session_id().unwrap();
        assert_eq!(tersa_oauth_cancel(cancelled_id), STATUS_CANCELLED);

        // Fill the grants map past its cap with other sessions' grants so the
        // cap eviction actually fires; the cap must never reach the tombstones.
        for index in 0..=MAX_PENDING_GRANTS {
            let other_id = allocate_session_id().unwrap();
            let (grant, redirect_uri) = make_grant("other-code");
            assert_eq!(
                store_grant_at(
                    other_id,
                    grant,
                    redirect_uri,
                    "public-test-client",
                    Instant::now() + Duration::from_secs(index as u64),
                ),
                StoreOutcome::Stored
            );
        }
        assert_eq!(
            pending_grants().lock().unwrap().grants.len(),
            MAX_PENDING_GRANTS
        );

        let (grant, redirect_uri) = make_grant("late-code");
        assert_eq!(
            store_grant(cancelled_id, grant, redirect_uri, "public-test-client"),
            StoreOutcome::RefusedCancelled
        );
        assert!(claim_grant(cancelled_id).is_none());
        // The refused store ran its tombstone check FIRST, so the cap pressure
        // caused NO collateral eviction of the resident grants.
        assert_eq!(
            pending_grants().lock().unwrap().grants.len(),
            MAX_PENDING_GRANTS
        );
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&cancelled_id)
        );
    }

    #[test]
    fn a_tombstone_outlives_the_grant_ttl_and_falls_only_to_its_own_lifetime() {
        let _registry_guard = registry_test_guard();
        let base = Instant::now();
        let grant_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("ttl-code");
        assert_eq!(
            store_grant_at(grant_id, grant, redirect_uri, "public-test-client", base),
            StoreOutcome::Stored
        );
        // The tombstone is stamped after the grant, so even with equal TTLs
        // there is a window in which the grant is stale but the tombstone is
        // not: proof the tombstone lifecycle is independent of the grant TTL.
        let cancelled_id = allocate_session_id().unwrap();
        pending_grants()
            .lock()
            .unwrap()
            .cancelled
            .insert(cancelled_id, base + Duration::from_secs(30));

        // Past the grant TTL the grant is wiped, while the tombstone survives
        // and still refuses a late store for its session.
        reap_expired_pending_grants(base + PENDING_GRANT_LIFETIME + Duration::from_secs(1));
        {
            let registry = pending_grants().lock().unwrap();
            assert!(!registry.grants.contains_key(&grant_id));
            assert!(registry.cancelled.contains_key(&cancelled_id));
        }
        let (grant, redirect_uri) = make_grant("late-code");
        assert_eq!(
            store_grant(cancelled_id, grant, redirect_uri, "public-test-client"),
            StoreOutcome::RefusedCancelled
        );

        // The tombstone is retired only once its own lifetime has fully
        // elapsed, at which point the session can no longer produce a grant.
        reap_expired_pending_grants(
            base + Duration::from_secs(30) + CANCEL_TOMBSTONE_LIFETIME + Duration::from_secs(1),
        );
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&cancelled_id)
        );
        assert!(claim_grant(cancelled_id).is_none());
    }

    #[test]
    fn a_claimed_sessions_tombstone_is_pinned_by_the_lease_until_complete() {
        let _registry_guard = registry_test_guard();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("leased-code");
        assert_eq!(
            store_grant(session_id, grant, redirect_uri, "public-test-client"),
            StoreOutcome::Stored
        );

        // A successful claim takes the in-flight lease in the same critical
        // section as the grant removal.
        assert!(claim_grant(session_id).is_some());
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .in_flight
                .contains(&session_id)
        );

        // The cancel lands mid-connect and stamps its tombstone; age the stamp
        // past the TTL so that, without the lease, the very next reap would
        // retire it.
        assert_eq!(tersa_oauth_cancel(session_id), STATUS_CANCELLED);
        let aged = Instant::now()
            .checked_sub(CANCEL_TOMBSTONE_LIFETIME + Duration::from_secs(1))
            .unwrap();
        pending_grants()
            .lock()
            .unwrap()
            .cancelled
            .insert(session_id, aged);

        // The tombstone SURVIVES a reap past its TTL: the lease pins it,
        // because the claim→fence window spans the network exchange.
        reap_expired_pending_grants(Instant::now());
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&session_id)
        );

        // The worker acknowledges completion: the lease is released and the
        // tombstone re-stamped at release, so it now survives a reap at now
        // (the aged stamp would have been retired by it)...
        complete_session(session_id);
        {
            let registry = pending_grants().lock().unwrap();
            assert!(!registry.in_flight.contains(&session_id));
            assert!(*registry.cancelled.get(&session_id).unwrap() > aged);
        }
        reap_expired_pending_grants(Instant::now());
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&session_id)
        );

        // ...and normal TTL reaping resumes FROM THE RELEASE.
        reap_expired_pending_grants(
            Instant::now() + CANCEL_TOMBSTONE_LIFETIME + Duration::from_secs(1),
        );
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&session_id)
        );
    }

    #[test]
    fn a_missed_claim_takes_no_lease() {
        let _registry_guard = registry_test_guard();
        let session_id = allocate_session_id().unwrap();
        // An unknown id: the claim misses and takes no lease.
        assert!(claim_grant(session_id).is_none());
        assert!(pending_grants().lock().unwrap().in_flight.is_empty());
        // A tombstoned id: the claim misses too and still takes no lease.
        assert_eq!(tersa_oauth_cancel(session_id), STATUS_CANCELLED);
        assert!(claim_grant(session_id).is_none());
        assert!(pending_grants().lock().unwrap().in_flight.is_empty());
    }

    #[test]
    fn complete_session_is_idempotent_and_leaves_the_lease_released() {
        let _registry_guard = registry_test_guard();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("leased-code");
        assert_eq!(
            store_grant(session_id, grant, redirect_uri, "public-test-client"),
            StoreOutcome::Stored
        );
        assert!(claim_grant(session_id).is_some());
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .in_flight
                .contains(&session_id)
        );

        // A second release changes nothing: no panic, the lease stays removed.
        complete_session(session_id);
        complete_session(session_id);
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .in_flight
                .contains(&session_id)
        );
    }

    #[test]
    fn complete_session_without_a_tombstone_is_a_noop() {
        let _registry_guard = registry_test_guard();
        // An allocated id with nothing resident — no grant, no tombstone, no
        // lease: completing it changes nothing (and must not panic).
        let session_id = allocate_session_id().unwrap();
        complete_session(session_id);
        let registry = pending_grants().lock().unwrap();
        assert!(!registry.in_flight.contains(&session_id));
        assert!(!registry.cancelled.contains_key(&session_id));
        assert!(!registry.grants.contains_key(&session_id));
    }

    #[test]
    fn cancel_reports_cancelled_for_every_allocated_id() {
        let _registry_guard = registry_test_guard();
        // Cancelling an id with a stored grant displaced it: STATUS_CANCELLED.
        let stored_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("displaced-code");
        assert_eq!(
            store_grant_at(
                stored_id,
                grant,
                redirect_uri,
                "public-test-client",
                Instant::now()
            ),
            StoreOutcome::Stored
        );
        assert_eq!(tersa_oauth_cancel(stored_id), STATUS_CANCELLED);

        // Cancelling a live iOS session displaced it too: STATUS_CANCELLED.
        let config = AuthorizationConfig::new(
            "public-test-client",
            Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap(),
            Duration::from_secs(60),
        )
        .unwrap();
        let prepared = prepare_authorization(config, SystemMonotonicClock::new()).unwrap();
        let (_url, session) = prepared.into_parts();
        let ios_id = allocate_session_id().unwrap();
        ios_sessions().lock().unwrap().insert(
            ios_id,
            IosSessionEntry {
                session,
                client_id: "public-test-client".to_owned(),
            },
        );
        assert_eq!(tersa_oauth_cancel(ios_id), STATUS_CANCELLED);
        assert!(!ios_sessions().lock().unwrap().contains_key(&ios_id));

        // An allocated-but-stateless id still passes admission: the tombstone
        // is stamped (STATUS_CANCELLED), so a late finish for it loses.
        let stateless_id = allocate_session_id().unwrap();
        assert_eq!(tersa_oauth_cancel(stateless_id), STATUS_CANCELLED);
        let (grant, redirect_uri) = make_grant("late-code");
        assert_eq!(
            store_grant(stateless_id, grant, redirect_uri, "public-test-client"),
            StoreOutcome::RefusedCancelled
        );
    }

    #[test]
    fn the_reaper_evicts_only_stale_cancel_tombstones() {
        let _registry_guard = registry_test_guard();
        let base = Instant::now();
        let session_id = allocate_session_id().unwrap();
        pending_grants()
            .lock()
            .unwrap()
            .cancelled
            .insert(session_id, base + Duration::from_secs(1));

        reap_expired_pending_grants(base + CANCEL_TOMBSTONE_LIFETIME);
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&session_id)
        );
        reap_expired_pending_grants(base + CANCEL_TOMBSTONE_LIFETIME + Duration::from_secs(1));
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&session_id)
        );
    }

    #[test]
    fn a_cancel_only_tombstone_is_reaped_after_its_lifetime_without_any_store() {
        let _registry_guard = registry_test_guard();
        // A cancel with no prior store (the macOS begin→cancel path) still has
        // its tombstone retired by the reaper once its lifetime has elapsed.
        // Admission passes for the allocated id, so it reports STATUS_CANCELLED.
        let session_id = allocate_session_id().unwrap();
        assert_eq!(tersa_oauth_cancel(session_id), STATUS_CANCELLED);
        assert!(
            pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&session_id)
        );

        reap_expired_pending_grants(
            Instant::now() + CANCEL_TOMBSTONE_LIFETIME + Duration::from_secs(1),
        );
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&session_id)
        );
    }

    #[test]
    fn a_delayed_finisher_loses_to_expiry_even_after_the_tombstone_is_retired() {
        let _registry_guard = registry_test_guard();
        let session_id = allocate_session_id().unwrap();
        // A well-formed callback on a live session: finish() would pass right
        // now. The 1ms lifetime stands in for AUTHORIZATION_LIFETIME so the
        // deadline can really elapse below without any sleep.
        let lifetime = Duration::from_millis(1);
        let (mut session, callback) = make_session(lifetime, "retired-tombstone-code");
        let began = Instant::now();

        // The cancel lands first and stamps its durable tombstone.
        assert_eq!(tersa_oauth_cancel(session_id), STATUS_CANCELLED);
        let stamped_at = pending_grants()
            .lock()
            .unwrap()
            .cancelled
            .get(&session_id)
            .copied()
            .unwrap();

        // The reaper retires the tombstone only at wall time ≥ cancel+TTL,
        // which in the real world is necessarily ≥ begin+AUTHORIZATION_LIFETIME
        // = expires_at: no live session can outlive its tombstone's
        // retirement. Drive the reaper with an injected clock...
        reap_expired_pending_grants(
            stamped_at + CANCEL_TOMBSTONE_LIFETIME + Duration::from_secs(1),
        );
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&session_id)
        );

        // ...and spin (never sleep) until the session's own deadline has
        // really elapsed — the state the fused finisher is guaranteed to
        // observe whenever its tombstone was legitimately retired.
        while began.elapsed() < lifetime {
            std::hint::spin_loop();
        }

        // The delayed finisher's store now fails on the fused section's
        // EXPIRY check (finish() sees the elapsed deadline), NOT on the
        // retired tombstone, and nothing becomes claimable.
        assert_eq!(
            finish_and_store(session_id, &mut session, &callback, "public-test-client"),
            STATUS_EXPIRED
        );
        assert!(claim_grant(session_id).is_none());
        let registry = pending_grants().lock().unwrap();
        assert!(!registry.grants.contains_key(&session_id));
        assert!(!registry.cancelled.contains_key(&session_id));
    }

    #[test]
    fn a_finisher_blocked_past_the_deadline_by_the_registry_lock_expires() {
        // The ONE test that only passes while finish() runs INSIDE the
        // registry critical section. Hold the registry lock across the session
        // deadline. FUSED: the finisher blocks BEFORE finish(), so when it
        // finally runs the deadline has elapsed -> STATUS_EXPIRED. UN-FUSED:
        // finish() would have run while the session was still live ->
        // STATUS_SUCCEEDED.
        let _registry_guard = registry_test_guard();
        let lifetime = Duration::from_millis(50);
        let (mut session, callback) = make_session(lifetime, "fused-code");
        let session_id = allocate_session_id().unwrap();
        let registry_hold = pending_grants()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let handle = std::thread::spawn(move || {
            finish_and_store(session_id, &mut session, &callback, "public-test-client")
        });
        // Spin (never sleep) until the 50ms deadline has certainly elapsed,
        // yielding so the blocked finisher had every chance to run finish()
        // early (which is exactly what an un-fused mutant would do), then
        // release the lock.
        let began = Instant::now();
        while began.elapsed() < lifetime {
            std::hint::spin_loop();
            std::thread::yield_now();
        }
        drop(registry_hold);
        assert_eq!(handle.join().unwrap(), STATUS_EXPIRED);
        // ...and nothing claimable.
        assert!(claim_grant(session_id).is_none());
    }

    #[test]
    fn a_cancel_of_an_implausible_id_stamps_nothing_and_is_rejected() {
        let _registry_guard = registry_test_guard();
        // Ids that can never have been handed out: the cursor starts at 1 and
        // allocate_session_id stalls rather than ever yielding u64::MAX.
        for implausible in [0_u64, u64::MAX] {
            assert_eq!(tersa_oauth_cancel(implausible), STATUS_REJECTED);
            assert!(
                !pending_grants()
                    .lock()
                    .unwrap()
                    .cancelled
                    .contains_key(&implausible)
            );
        }

        // An id at or beyond the allocation cursor is implausible too:
        // admission fails and nothing is stamped.
        let future_id = NEXT_SESSION_ID.load(Ordering::Acquire) + 8;
        assert_eq!(tersa_oauth_cancel(future_id), STATUS_REJECTED);
        assert!(
            !pending_grants()
                .lock()
                .unwrap()
                .cancelled
                .contains_key(&future_id)
        );

        // A later begin that legitimately allocates that id is NOT refused by
        // a phantom tombstone. Advancing the cursor proves the id becomes
        // allocatable; the refusal check itself is registry-level (the whole
        // sequence runs under the test lock, so no concurrent cancel can
        // interleave).
        let mut reached = allocate_session_id().unwrap();
        while reached < future_id {
            reached = allocate_session_id().unwrap();
        }
        let (grant, redirect_uri) = make_grant("late-legit-code");
        assert_eq!(
            store_grant_at(
                future_id,
                grant,
                redirect_uri,
                "public-test-client",
                Instant::now()
            ),
            StoreOutcome::Stored
        );
        assert!(claim_grant(future_id).is_some());
    }
}
