// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! IPv4 loopback listener for the OAuth redirect (RFC 8252 §7.3).
//!
//! Binds `127.0.0.1` on an ephemeral port and waits for the one request to the
//! root path whose `state` matches the pending authorization; it then hands
//! that full URL to the token service, which validates state and code again.
//! Any other request, including a guessed or forged callback from another
//! local process, gets a 404 and does not end the wait, so it cannot consume
//! the session. The listener never echoes request content back.

use core::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const MAX_REQUEST_HEAD: usize = 8 * 1024;
const MAX_CONNECTIONS: usize = 32;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const DONE_PAGE: &str = "<!doctype html><meta charset=utf-8><title>tersa</title>\
<p>Sign-in finished. You can close this tab and return to the terminal.</p>";

/// Why waiting for the callback failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoopbackError {
    /// Binding or accepting on the loopback interface failed.
    Io(io::ErrorKind),
    /// No callback arrived before the deadline.
    TimedOut,
    /// Too many unrelated connections arrived before the callback.
    TooManyConnections,
}

impl fmt::Display for LoopbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(formatter, "the local sign-in listener failed ({kind})"),
            Self::TimedOut => formatter.write_str("sign-in timed out"),
            Self::TooManyConnections => {
                formatter.write_str("too many unexpected connections to the sign-in listener")
            }
        }
    }
}

impl std::error::Error for LoopbackError {}

/// A bound loopback listener awaiting one OAuth callback.
#[derive(Debug)]
pub struct Loopback {
    listener: TcpListener,
    port: u16,
}

impl Loopback {
    /// Binds `127.0.0.1` on an ephemeral port.
    ///
    /// # Errors
    ///
    /// Returns [`LoopbackError::Io`] when binding fails.
    pub async fn bind() -> Result<Self, LoopbackError> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .map_err(|error| LoopbackError::Io(error.kind()))?;
        let port = listener
            .local_addr()
            .map_err(|error| LoopbackError::Io(error.kind()))?
            .port();
        Ok(Self { listener, port })
    }

    /// The exact redirect URI to register with the authorization request.
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    /// Waits up to `deadline` for a request to the root path carrying
    /// `expected_state` and returns its full URL.
    ///
    /// # Errors
    ///
    /// Returns [`LoopbackError::TimedOut`] after `deadline`,
    /// [`LoopbackError::TooManyConnections`] after too many stray requests, or
    /// [`LoopbackError::Io`] when accepting fails.
    pub async fn wait_for_callback(
        self,
        deadline: Duration,
        expected_state: &str,
    ) -> Result<String, LoopbackError> {
        tokio::time::timeout(deadline, self.serve(expected_state))
            .await
            .map_err(|_elapsed| LoopbackError::TimedOut)?
    }

    async fn serve(self, expected_state: &str) -> Result<String, LoopbackError> {
        for _ in 0..MAX_CONNECTIONS {
            let (mut stream, peer) = self
                .listener
                .accept()
                .await
                .map_err(|error| LoopbackError::Io(error.kind()))?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let Ok(Ok(Some(target))) =
                tokio::time::timeout(READ_TIMEOUT, read_request_target(&mut stream)).await
            else {
                let _ = stream
                    .write_all(response(400, "Bad Request", "").as_bytes())
                    .await;
                continue;
            };
            if is_matching_callback(&target, expected_state) {
                let _ = stream
                    .write_all(response(200, "OK", DONE_PAGE).as_bytes())
                    .await;
                let _ = stream.shutdown().await;
                return Ok(format!("http://127.0.0.1:{}{target}", self.port));
            }
            let _ = stream
                .write_all(response(404, "Not Found", "").as_bytes())
                .await;
        }
        Err(LoopbackError::TooManyConnections)
    }
}

/// Reads one HTTP request head and returns the target of a `GET`.
async fn read_request_target(stream: &mut tokio::net::TcpStream) -> io::Result<Option<String>> {
    let mut head = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if head.len() >= MAX_REQUEST_HEAD {
            return Ok(None);
        }
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(None);
        }
        head.extend_from_slice(&buffer[..read]);
    }
    Ok(parse_request_target(&head))
}

/// Whether `target` is the root path with exactly one `state` parameter equal
/// to `expected`.
fn is_matching_callback(target: &str, expected: &str) -> bool {
    let Some(query) = target.strip_prefix("/?") else {
        return false;
    };
    let mut states = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(name, _value)| name == "state")
        .map(|(_name, value)| value);
    matches!((states.next(), states.next()), (Some(state), None) if state == expected)
}

fn parse_request_target(head: &[u8]) -> Option<String> {
    let line_end = head.windows(2).position(|window| window == b"\r\n")?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if method != "GET" || !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return None;
    }
    if !target.starts_with('/') || !target.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return None;
    }
    Some(target.to_owned())
}

fn response(status: u16, reason: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::{Loopback, LoopbackError, is_matching_callback, parse_request_target};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    async fn request(port: u16, target: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.expect("read");
        reply
    }

    #[test]
    fn parses_only_well_formed_get_targets() {
        assert_eq!(
            parse_request_target(b"GET /?code=a&state=b HTTP/1.1\r\n\r\n"),
            Some("/?code=a&state=b".to_owned())
        );
        assert_eq!(parse_request_target(b"POST / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(
            parse_request_target(b"GET http://x/ HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(parse_request_target(b"GET /a b HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn matches_only_the_expected_state() {
        assert!(is_matching_callback("/?code=a&state=s1", "s1"));
        assert!(is_matching_callback("/?state=s%2F1&code=a", "s/1"));
        assert!(!is_matching_callback("/?code=a&state=other", "s1"));
        assert!(!is_matching_callback("/?code=a", "s1"));
        assert!(!is_matching_callback("/?state=s1&state=s1", "s1"));
        assert!(!is_matching_callback("/x?state=s1", "s1"));
        assert!(!is_matching_callback("/", "s1"));
    }

    #[test]
    fn returns_the_callback_after_ignoring_other_paths() {
        runtime().block_on(async {
            let loopback = Loopback::bind().await.expect("bind");
            let redirect = loopback.redirect_uri();
            let port: u16 = redirect
                .trim_start_matches("http://127.0.0.1:")
                .trim_end_matches('/')
                .parse()
                .expect("port");
            let waiter = tokio::spawn(async move {
                loopback
                    .wait_for_callback(Duration::from_secs(5), "xyz")
                    .await
            });

            assert!(
                request(port, "/favicon.ico")
                    .await
                    .starts_with("HTTP/1.1 404")
            );
            // A forged callback with the wrong state does not end the wait.
            assert!(
                request(port, "/?code=evil&state=guess")
                    .await
                    .starts_with("HTTP/1.1 404")
            );
            let reply = request(port, "/?code=abc&state=xyz").await;
            assert!(reply.starts_with("HTTP/1.1 200"));
            assert!(!reply.contains("abc"));

            let callback = waiter.await.expect("join").expect("callback");
            assert_eq!(
                callback,
                format!("http://127.0.0.1:{port}/?code=abc&state=xyz")
            );
        });
    }

    #[test]
    fn times_out_without_a_callback() {
        runtime().block_on(async {
            let loopback = Loopback::bind().await.expect("bind");
            assert!(matches!(
                loopback
                    .wait_for_callback(Duration::from_millis(50), "state")
                    .await,
                Err(LoopbackError::TimedOut)
            ));
        });
    }
}
