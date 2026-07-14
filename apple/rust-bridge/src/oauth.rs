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
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tersa_application::oauth::{
    AuthorizationConfig, AuthorizationSession, OAuthError, SystemMonotonicClock,
    prepare_authorization,
};
use url::Url;
use zeroize::Zeroizing;

// Rust guideline compliant 1.0.

const IOS_CALLBACK_PATH: &str = "/oauth/callback";
const AUTHORIZATION_LIFETIME: Duration = Duration::from_secs(120);
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

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static IOS_SESSIONS: OnceLock<Mutex<BTreeMap<u64, PendingSession>>> = OnceLock::new();

fn ios_sessions() -> &'static Mutex<BTreeMap<u64, PendingSession>> {
    IOS_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
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
            drop(grant);
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
    if let Ok(mut sessions) = ios_sessions().lock()
        && let Some(mut session) = sessions.remove(&session_id)
    {
        return status_for_result(session.cancel());
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
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
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

fn status_for_result(result: Result<(), OAuthError>) -> i32 {
    match result {
        Ok(()) => STATUS_OK,
        Err(error) => status_for_error(error),
    }
}

fn status_for_error(error: OAuthError) -> i32 {
    match error {
        OAuthError::Cancelled => STATUS_CANCELLED,
        OAuthError::Expired => STATUS_EXPIRED,
        OAuthError::EntropyUnavailable => STATUS_INTERNAL,
        OAuthError::InvalidConfiguration => STATUS_CONFIGURATION_MISSING,
        _ => STATUS_REJECTED,
    }
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
        SystemMonotonicClock, Url, Zeroizing, prepare_authorization, status_for_error,
    };

    const MAX_REQUEST_BYTES: usize = 8_192;
    const CALLBACK_PATH: &str = "/";
    const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 55\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nAuthorization received. Return to the tersa.app window.";

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
        Io,
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

        fn try_accept(&mut self) -> Result<Option<Url>, LoopbackError> {
            if self.consumed {
                return Err(LoopbackError::AlreadyConsumed);
            }
            let listener = self
                .listener
                .as_ref()
                .ok_or(LoopbackError::AlreadyConsumed)?;
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    self.consumed = true;
                    self.listener.take();
                    let callback = read_callback(&mut stream, peer, &self.redirect_uri);
                    let _ = stream.write_all(HTTP_RESPONSE);
                    callback.map(Some)
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
    ) -> Result<Url, LoopbackError> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|_error| LoopbackError::Io)?;
        let mut request = Zeroizing::new(Vec::with_capacity(1_024));
        let mut chunk = Zeroizing::new([0_u8; 1_024]);
        let mut complete = false;
        loop {
            let count = stream
                .read(&mut chunk[..])
                .map_err(|_error| LoopbackError::Io)?;
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
                match receiver.try_accept() {
                    Ok(Some(callback)) => {
                        let outcome = session.finish(&callback);
                        let _callback_bytes = Zeroizing::new(String::from(callback));
                        worker_status.store(
                            outcome.map_or_else(status_for_error, |grant| {
                                drop(grant);
                                STATUS_SUCCEEDED
                            }),
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
        use std::time::Duration;

        use super::{
            CALLBACK_PATH, HTTP_RESPONSE, LoopbackError, LoopbackReceiver, MAX_REQUEST_BYTES,
            SocketAddr, Url, begin, validate_request,
        };

        fn redirect() -> Url {
            Url::parse("http://127.0.0.1:43123").unwrap()
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
            assert_eq!(receiver.try_accept(), Err(LoopbackError::AlreadyConsumed));
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
        fn fake_callback_is_one_shot_and_response_never_reflects_input() {
            let mut receiver = LoopbackReceiver::bind().unwrap();
            let address = receiver.listener.as_ref().unwrap().local_addr().unwrap();
            let client = thread::spawn(move || {
                let mut stream = TcpStream::connect(address).unwrap();
                stream
                    .write_all(
                        b"GET /?state=secret-state&code=secret-code HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                    )
                    .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).unwrap();
                response
            });

            let callback = loop {
                if let Some(callback) = receiver.try_accept().unwrap() {
                    break callback;
                }
                thread::sleep(Duration::from_millis(1));
            };
            let response = client.join().unwrap();
            assert_eq!(
                callback.query(),
                Some("state=secret-state&code=secret-code")
            );
            assert_eq!(response, HTTP_RESPONSE);
            assert!(!response.windows(6).any(|window| window == b"secret"));
            assert_eq!(receiver.try_accept(), Err(LoopbackError::AlreadyConsumed));
            assert!(TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_err());
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
        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
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
            .insert(session_id, spawn_macos(receiver, session));
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

    use super::{STATUS_CONFIGURATION_MISSING, ios_redirect_uri};

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
}
