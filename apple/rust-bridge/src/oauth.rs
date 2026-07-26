// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exposes the Apple OAuth feasibility adapter through a narrow C ABI.
//!
//! The adapter keeps sensitive state in Rust. Swift supplies only public build
//! configuration and transports the authorization URL or callback URL.

use std::collections::BTreeMap;
use std::slice;
use std::str;
use std::sync::atomic::{AtomicU64, Ordering};
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

type PendingSession = AuthorizationSession<SystemMonotonicClock>;

/// One finished authorization awaiting a single-use token-exchange claim,
/// kept with the redirect URI the exchange must present. Dropping an entry
/// zeroizes the grant's code and verifier.
struct PendingGrant {
    grant: AuthorizationGrant,
    redirect_uri: Url,
    created_at: Instant,
}

const MAX_PENDING_GRANTS: usize = 4;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static IOS_SESSIONS: OnceLock<Mutex<BTreeMap<u64, PendingSession>>> = OnceLock::new();
static PENDING_GRANTS: OnceLock<Mutex<BTreeMap<u64, PendingGrant>>> = OnceLock::new();
static REAPER: OnceLock<()> = OnceLock::new();

#[cfg(test)]
static PENDING_GRANT_TEST_LOCK: Mutex<()> = Mutex::new(());

fn ios_sessions() -> &'static Mutex<BTreeMap<u64, PendingSession>> {
    IOS_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn pending_grants() -> &'static Mutex<BTreeMap<u64, PendingGrant>> {
    PENDING_GRANTS.get_or_init(|| Mutex::new(BTreeMap::new()))
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
            .map_err(|_error| STATUS_INTERNAL)?
            .insert(session_id, session);
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
    let session = ios_sessions()
        .lock()
        .ok()
        .and_then(|mut sessions| sessions.remove(&session_id));
    let Some(mut session) = session else {
        return STATUS_REJECTED;
    };
    let outcome = session.finish(&callback_url);
    let _callback_bytes = Zeroizing::new(String::from(callback_url));
    match outcome {
        Ok(grant) => {
            store_grant(session_id, grant, session.redirect_uri().clone());
            STATUS_SUCCEEDED
        }
        Err(error) => status_for_error(error),
    }
}

/// Cancels and consumes an iOS or macOS authorization session.
#[expect(
    unsafe_code,
    reason = "a stable unmangled symbol is required by the C-compatible Apple bridge"
)]
#[unsafe(no_mangle)]
pub extern "C" fn tersa_oauth_cancel(session_id: u64) -> i32 {
    // Best-effort eviction: dropping any stored grant zeroizes its code and
    // verifier. A callback completing concurrently on the worker thread can still
    // store a grant after this point; that cancel-versus-callback race is closed
    // under a single lock in 3c-3c-3, where the grant first becomes claimable.
    pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&session_id);

    if let Ok(mut sessions) = ios_sessions().lock()
        && let Some(mut session) = sessions.remove(&session_id)
    {
        return session
            .cancel()
            .map_or_else(status_for_error, |()| STATUS_CANCELLED);
    }

    #[cfg(target_os = "macos")]
    if let Ok(mut sessions) = macos_sessions().lock()
        && let Some(entry) = sessions.remove(&session_id)
    {
        entry.cancel.store(true, Ordering::Release);
        return STATUS_CANCELLED;
    }

    STATUS_REJECTED
}

struct BegunSession {
    session: PendingSession,
    authorization_url: Url,
}

/// Allocates the next never-reused session id, failing closed with
/// [`STATUS_INTERNAL`] once the counter reaches `u64::MAX` instead of wrapping
/// onto an id a live session could still hold. `u64::MAX` itself is never
/// handed out: the counter stalls there and every later allocation fails.
fn allocate_session_id() -> Result<u64, i32> {
    NEXT_SESSION_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_error| STATUS_INTERNAL)
}

fn begin_session(client_id: &str, redirect_uri: Url) -> Result<(u64, BegunSession), i32> {
    if client_id.trim().is_empty() || client_id.to_ascii_uppercase().contains("UNCONFIGURED") {
        return Err(STATUS_CONFIGURATION_MISSING);
    }
    let config = AuthorizationConfig::new(client_id, redirect_uri, AUTHORIZATION_LIFETIME)
        .map_err(status_for_error)?;
    let prepared =
        prepare_authorization(config, SystemMonotonicClock::new()).map_err(status_for_error)?;
    let (authorization_url, session) = prepared.into_parts();
    if authorization_url.as_str().len() > MAX_AUTHORIZATION_URL_BYTES {
        return Err(STATUS_INVALID_INPUT);
    }
    let session_id = allocate_session_id()?;
    Ok((
        session_id,
        BegunSession {
            session,
            authorization_url,
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
        _ => STATUS_REJECTED,
    }
}

/// Stores a finished grant under its OAuth `session_id` for a later
/// single-use claim by the token-exchange step.
fn store_grant(session_id: u64, grant: AuthorizationGrant, redirect_uri: Url) {
    store_grant_at(session_id, grant, redirect_uri, Instant::now());
}

fn store_grant_at(
    session_id: u64,
    grant: AuthorizationGrant,
    redirect_uri: Url,
    created_at: Instant,
) {
    // Recover a poisoned lock rather than abandon it: dropping the guard on
    // poison would strand every already-resident code+verifier un-zeroized for
    // the process lifetime, inverting the TTL bound. The map holds no invariant a
    // panic could break.
    let mut grants = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if grants.len() >= MAX_PENDING_GRANTS && !grants.contains_key(&session_id) {
        evict_oldest_pending_grant(&mut grants);
    }
    grants.insert(
        session_id,
        PendingGrant {
            grant,
            redirect_uri,
            created_at,
        },
    );
    drop(grants);
    ensure_reaper();
}

fn evict_oldest_pending_grant(grants: &mut BTreeMap<u64, PendingGrant>) {
    let oldest = grants
        .iter()
        .min_by_key(|(_session_id, entry)| entry.created_at)
        .map(|(session_id, _entry)| *session_id);
    if let Some(session_id) = oldest {
        grants.remove(&session_id);
    }
}

/// Claims the grant stored under an OAuth `session_id` for token exchange.
///
/// Returns the grant and its redirect URI exactly once: a missing, expired,
/// or already-claimed id yields `None`.
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
pub fn claim_grant(session_id: u64) -> Option<(AuthorizationGrant, Url)> {
    let mut grants = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let entry = grants.remove(&session_id)?;
    if entry.created_at.elapsed() >= PENDING_GRANT_LIFETIME {
        // The abandoned grant drops here, wiping its code and verifier.
        return None;
    }
    Some((entry.grant, entry.redirect_uri))
}

fn ensure_reaper() {
    REAPER.get_or_init(|| {
        drop(std::thread::spawn(|| {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                reap_expired_ios_sessions();
                reap_expired_pending_grants(Instant::now());
            }
        }));
    });
}

fn reap_expired_ios_sessions() {
    if let Ok(mut sessions) = ios_sessions().lock() {
        sessions.retain(|_session_id, session| match session.expire() {
            Ok(()) => false,
            Err(OAuthError::NotExpired) => true,
            Err(_terminal_error) => false,
        });
    }
}

/// Evicts every grant older than the authorization lifetime as of `now`, so
/// an abandoned code and verifier are wiped within one reaper tick.
fn reap_expired_pending_grants(now: Instant) {
    let mut grants = pending_grants()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    grants
        .retain(|_session_id, entry| now.duration_since(entry.created_at) < PENDING_GRANT_LIFETIME);
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
        SystemMonotonicClock, Url, Zeroizing, prepare_authorization, status_for_error, store_grant,
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
    ) -> i32 {
        let outcome = session.finish(&accepted.callback);
        let status = outcome.map_or_else(status_for_error, |grant| {
            store_grant(session_id, grant, session.redirect_uri().clone());
            STATUS_SUCCEEDED
        });
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

    pub(super) fn begin(client_id: &str) -> Result<(Url, PendingSession, LoopbackReceiver), i32> {
        let receiver = LoopbackReceiver::bind().map_err(|_error| STATUS_INTERNAL)?;
        let config = AuthorizationConfig::new(
            client_id,
            receiver.redirect_uri().clone(),
            AUTHORIZATION_LIFETIME,
        )
        .map_err(status_for_error)?;
        let prepared =
            prepare_authorization(config, SystemMonotonicClock::new()).map_err(status_for_error)?;
        let (url, session) = prepared.into_parts();
        Ok((url, session, receiver))
    }

    pub(super) fn spawn(
        session_id: u64,
        mut receiver: LoopbackReceiver,
        mut session: PendingSession,
    ) -> MacSessionEntry {
        let status = Arc::new(AtomicI32::new(STATUS_OK));
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_status = Arc::clone(&status);
        let worker_cancel = Arc::clone(&cancel);
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
                            complete_callback(session_id, accepted, &mut session),
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

    pub(super) fn entitlement_probe() -> i32 {
        let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
            return STATUS_INTERNAL;
        };
        if listener.set_nonblocking(true).is_err() {
            return STATUS_INTERNAL;
        }
        let Ok(address) = listener.local_addr() else {
            return STATUS_INTERNAL;
        };
        let connected = TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok();
        let deadline = Instant::now() + Duration::from_secs(2);
        let accepted = loop {
            match listener.accept() {
                Ok(connection) => break Some(connection),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break None;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break None,
            }
        };
        if accepted.is_some() && connected {
            STATUS_SUCCEEDED
        } else {
            STATUS_INTERNAL
        }
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

        use super::super::{PENDING_GRANT_TEST_LOCK, allocate_session_id, claim_grant};
        use super::{
            AcceptedCallback, CALLBACK_PATH, HTTP_ERROR_RESPONSE, HTTP_SUCCESS_RESPONSE,
            LoopbackError, LoopbackReceiver, MAX_REQUEST_BYTES, STATUS_REJECTED, STATUS_SUCCEEDED,
            SocketAddr, Url, begin, complete_callback, validate_request,
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
            let (authorization_url, _session, receiver) = begin("public-test-client").unwrap();
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
            let (authorization_url, mut session, mut receiver) =
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
            let _registry_guard = PENDING_GRANT_TEST_LOCK.lock().unwrap();
            assert_eq!(
                complete_callback(session_id, accepted, &mut session),
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

            let (grant, redirect_uri) = claim_grant(session_id).unwrap();
            assert_eq!(grant.code(), "secret-code");
            assert_eq!(grant.verifier().len(), 43);
            assert_eq!(&redirect_uri, receiver.redirect_uri());
            assert!(claim_grant(session_id).is_none());
        }

        #[test]
        fn state_mismatch_receives_a_static_error_response() {
            let (_authorization_url, mut session, mut receiver) =
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
                complete_callback(session_id, accepted, &mut session),
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
    }
}

#[cfg(target_os = "macos")]
use macos::{MacSessionEntry, begin as begin_macos, entitlement_probe, spawn as spawn_macos};

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
        let (authorization_url, session, receiver) = begin_macos(&client_id)?;
        let authorization_url = Zeroizing::new(String::from(authorization_url));
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
        macos_sessions()
            .lock()
            .map_err(|_error| STATUS_INTERNAL)?
            .insert(session_id, spawn_macos(session_id, receiver, session));
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
    let Ok(mut sessions) = macos_sessions().lock() else {
        return STATUS_INTERNAL;
    };
    let Some(entry) = sessions.get(&session_id) else {
        return STATUS_REJECTED;
    };
    let status = entry.status.load(Ordering::Acquire);
    if status != STATUS_OK {
        sessions.remove(&session_id);
    }
    status
}

/// Probes sandboxed loopback server and outbound client capabilities.
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "a stable unmangled symbol is required by the C-compatible Apple bridge"
)]
#[unsafe(no_mangle)]
pub extern "C" fn tersa_oauth_macos_entitlement_probe() -> i32 {
    entitlement_probe()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "redirect tests use compile-time constant schemes"
    )]

    use std::time::{Duration, Instant};

    use super::{
        AUTHORIZATION_LIFETIME, AuthorizationConfig, AuthorizationGrant, MAX_PENDING_GRANTS,
        PENDING_GRANT_TEST_LOCK, STATUS_CONFIGURATION_MISSING, STATUS_REJECTED,
        SystemMonotonicClock, Url, allocate_session_id, claim_grant, ios_redirect_uri,
        ios_sessions, pending_grants, prepare_authorization, reap_expired_ios_sessions,
        reap_expired_pending_grants, store_grant_at, tersa_oauth_cancel,
    };

    fn make_grant(code: &str) -> (AuthorizationGrant, Url) {
        let redirect = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        let config =
            AuthorizationConfig::new("public-test-client", redirect, Duration::from_secs(60))
                .unwrap();
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
        let (_authorization_url, mut session) = prepared.into_parts();
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
        ios_sessions().lock().unwrap().insert(session_id, session);
        std::thread::sleep(Duration::from_millis(2));
        reap_expired_ios_sessions();

        assert!(!ios_sessions().lock().unwrap().contains_key(&session_id));
    }

    #[test]
    fn a_stored_grant_is_claimed_exactly_once() {
        let _registry_guard = PENDING_GRANT_TEST_LOCK.lock().unwrap();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("claim-once-code");
        store_grant_at(session_id, grant, redirect_uri.clone(), Instant::now());

        let (claimed, claimed_redirect) = claim_grant(session_id).unwrap();
        assert_eq!(claimed.code(), "claim-once-code");
        assert_eq!(claimed.verifier().len(), 43);
        assert!(
            claimed
                .verifier()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert_eq!(claimed_redirect, redirect_uri);
        assert!(claim_grant(session_id).is_none());
    }

    #[test]
    fn an_expired_stored_grant_is_not_claimable() {
        let _registry_guard = PENDING_GRANT_TEST_LOCK.lock().unwrap();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("expired-code");
        let stale = Instant::now()
            .checked_sub(AUTHORIZATION_LIFETIME + Duration::from_secs(1))
            .unwrap();
        store_grant_at(session_id, grant, redirect_uri, stale);

        assert!(claim_grant(session_id).is_none());
        assert!(!pending_grants().lock().unwrap().contains_key(&session_id));
    }

    #[test]
    fn a_full_registry_evicts_the_oldest_pending_grant() {
        let _registry_guard = PENDING_GRANT_TEST_LOCK.lock().unwrap();
        let base = Instant::now();
        let mut session_ids = Vec::new();
        for index in 0..MAX_PENDING_GRANTS {
            let session_id = allocate_session_id().unwrap();
            let (grant, redirect_uri) = make_grant("capped-code");
            store_grant_at(
                session_id,
                grant,
                redirect_uri,
                base + Duration::from_secs(index as u64),
            );
            session_ids.push(session_id);
        }
        let newest_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("newest-code");
        store_grant_at(
            newest_id,
            grant,
            redirect_uri,
            base + Duration::from_secs(1_000),
        );

        assert!(claim_grant(session_ids[0]).is_none());
        for session_id in &session_ids[1..] {
            assert!(claim_grant(*session_id).is_some());
        }
        assert!(claim_grant(newest_id).is_some());
    }

    #[test]
    fn the_reaper_evicts_only_grants_older_than_the_authorization_lifetime() {
        let _registry_guard = PENDING_GRANT_TEST_LOCK.lock().unwrap();
        let base = Instant::now();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("reaped-code");
        store_grant_at(
            session_id,
            grant,
            redirect_uri,
            base + Duration::from_secs(1),
        );

        reap_expired_pending_grants(base + AUTHORIZATION_LIFETIME);
        assert!(pending_grants().lock().unwrap().contains_key(&session_id));
        reap_expired_pending_grants(base + AUTHORIZATION_LIFETIME + Duration::from_secs(1));
        assert!(!pending_grants().lock().unwrap().contains_key(&session_id));
        assert!(claim_grant(session_id).is_none());
    }

    #[test]
    fn cancel_evicts_a_pending_grant_without_a_live_session() {
        let _registry_guard = PENDING_GRANT_TEST_LOCK.lock().unwrap();
        let session_id = allocate_session_id().unwrap();
        let (grant, redirect_uri) = make_grant("cancelled-code");
        store_grant_at(session_id, grant, redirect_uri, Instant::now());

        assert_eq!(tersa_oauth_cancel(session_id), STATUS_REJECTED);
        assert!(claim_grant(session_id).is_none());
    }
}
