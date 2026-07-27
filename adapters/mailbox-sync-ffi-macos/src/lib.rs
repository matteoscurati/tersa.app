// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exposes the Rust-owned bounded Gmail sync worker through a narrow C ABI.
//!
//! This crate is a sibling static library to the minimal Apple bootstrap bridge,
//! kept separate so the network stack (tokio, reqwest, native-tls) the trusted
//! composition links stays out of that bridge's deliberately small trust surface.
//!
//! Swift supplies only two public strings — the OAuth client identifier and the
//! opaque account identifier — and never any URL: the Google token and revoke
//! endpoints are pinned downstream in the Gmail transport, and the registered
//! redirect for a plain sync begin is pinned here. A connect begin supplies
//! only the account identifier plus the bridge-issued id of the finished OAuth
//! session whose grant the worker claims: the grant, its registered redirect,
//! and the client identifier all arrive with the claim from the bridge's
//! session registry, never from Swift, so the exchange configuration cannot
//! disagree with the session by construction. Both begins share the one poll
//! entry point. Progress is a single closed status integer; no mailbox content,
//! address, subject, or count ever crosses this boundary.
//!
//! # Single-archive link
//!
//! The application links ONLY this crate's static archive: depending on the
//! bridge re-exports its `tersa_oauth_*` and `tersa_macos_*` C symbols from the
//! same archive, so one `.a` carries both surfaces. Verified on the release
//! build: the archive carries 14 `T _tersa_*` symbols (this crate's own 3 plus
//! the bridge's 11), and a C probe linking against this archive alone calls
//! the bridge's exported functions. Linking the bridge archive as well fails
//! loudly with duplicate symbols, so 3e wires exactly this one archive into
//! the application target.

#![deny(unsafe_code)]

// Rust guideline compliant 1.0.

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::BTreeMap;
    use std::slice;
    use std::str;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    use tersa_application::mailbox::AccountId;
    use tersa_application::oauth::AuthorizationGrant;
    use tersa_application::token::TokenClientConfig;
    use tersa_oauth_sync_macos::ConnectSession;
    use tersa_oauth_sync_macos::worker::{
        BeginOutcome, STATUS_RUNNING, WorkerHandles, begin_connect_account_sync,
        begin_default_account_sync,
    };
    use url::Url;

    /// A worker was spawned; the caller reads its written session id and polls it.
    const STATUS_STARTED: i32 = 0;
    /// The account slot already has a whole cycle in flight; no worker was spawned
    /// and no session id was written. Positive so it never aliases a poll terminal.
    const STATUS_SYNC_BUSY: i32 = 2;
    /// The session registry lock was poisoned, or the pinned configuration could not
    /// be constructed — an internal anomaly rather than caller error. Matches the
    /// worker's own internal code so the two never disagree.
    const STATUS_INTERNAL: i32 = -5;
    /// A begin input was rejected: an unreadable or non-UTF-8 buffer, an invalid
    /// account identifier, a null output pointer, or a blank client identifier.
    const STATUS_INVALID_INPUT: i32 = -7;
    /// A poll named a session that is not (or is no longer) registered.
    const STATUS_UNKNOWN_SESSION: i32 = -8;

    /// The largest client- or account-identifier buffer this ABI copies. A Google
    /// OAuth client id and an opaque account id are both well under this bound; a
    /// larger length is a caller error, not a value to allocate.
    const MAX_INPUT_BYTES: usize = 512;

    /// The registered redirect pinned into every configuration. It is a syntactically
    /// valid loopback placeholder that this worker's refresh grant never transmits;
    /// `TokenClientConfig` only requires the field to be a well-formed URL.
    const PLACEHOLDER_REDIRECT_URI: &str = "http://127.0.0.1/";

    /// Hands out monotonically increasing, never-reused session identifiers.
    static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
    /// Maps a live session id to its worker handles until a poll observes a terminal
    /// status and reaps it.
    static SYNC_SESSIONS: OnceLock<Mutex<BTreeMap<u64, WorkerHandles>>> = OnceLock::new();

    fn sync_sessions() -> &'static Mutex<BTreeMap<u64, WorkerHandles>> {
        SYNC_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
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

    /// Copies a caller-owned UTF-8 buffer into an owned `String`, rejecting a null,
    /// empty, oversized, or non-UTF-8 input with [`STATUS_INVALID_INPUT`].
    ///
    /// # Safety
    ///
    /// When `pointer` is non-null it must point to `length` readable bytes that
    /// remain valid for the duration of this call.
    #[expect(
        unsafe_code,
        reason = "raw C buffers are copied immediately into checked Rust values"
    )]
    unsafe fn read_utf8(pointer: *const u8, length: usize) -> Result<String, i32> {
        if pointer.is_null() || length == 0 || length > MAX_INPUT_BYTES {
            return Err(STATUS_INVALID_INPUT);
        }
        // SAFETY: the caller guarantees `length` readable bytes at `pointer`.
        let bytes = unsafe { slice::from_raw_parts(pointer, length) };
        str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_error| STATUS_INVALID_INPUT)
    }

    /// Builds the token-client configuration pinned to this application's public
    /// posture: the caller-supplied client id, the pinned placeholder redirect, and
    /// no client secret. A blank client id is a caller error; the placeholder redirect
    /// is a compile-time constant whose parse failure could only be an internal fault.
    fn pinned_configuration(client_id: String) -> Result<TokenClientConfig, i32> {
        let redirect = Url::parse(PLACEHOLDER_REDIRECT_URI).map_err(|_error| STATUS_INTERNAL)?;
        TokenClientConfig::new(client_id, redirect, None).map_err(|_error| STATUS_INVALID_INPUT)
    }

    /// The production [`ConnectSession`] backed by the Apple bridge's session
    /// registry: the claim, the cancel fences, and the completion acknowledgement
    /// all act on the ONE OAuth session id this value was built with. The id is
    /// private and immutable, so no code path can re-point the session at a
    /// different id after construction — the worker's claim and its three cancel
    /// fences provably reference the same session. The client identifier arrives
    /// WITH the claim from the bridge, which validated it at begin and stored it
    /// with the grant, so it cannot disagree with the session by construction.
    struct BridgeConnectSession {
        oauth_session_id: u64,
    }

    impl ConnectSession for BridgeConnectSession {
        fn claim(&self) -> Option<(AuthorizationGrant, TokenClientConfig)> {
            let (grant, redirect, client_id) =
                tersa_apple_bridge::claim_grant(self.oauth_session_id)?;
            // A public OAuth client carries no secret, exactly as
            // `pinned_configuration` pins it; the Google token and revoke
            // endpoints are pinned downstream in the Gmail transport.
            match TokenClientConfig::new(client_id, redirect, None) {
                Ok(config) => Some((grant, config)),
                Err(_error) => {
                    // The lease WAS taken by `claim_grant`, and a claim-miss
                    // takes none, so this is the one path that reports a miss
                    // AFTER taking the lease: release it here. Unreachable in
                    // practice — the bridge validated the client id at begin
                    // and builds the redirect itself, so the config build
                    // cannot fail.
                    tersa_apple_bridge::complete_session(self.oauth_session_id);
                    None
                }
            }
        }

        fn is_cancelled(&self) -> bool {
            tersa_apple_bridge::is_session_cancelled(self.oauth_session_id)
        }

        fn complete(&self) {
            tersa_apple_bridge::complete_session(self.oauth_session_id);
        }
    }

    /// Begins a bounded sync for the default account of the given OAuth client on a
    /// Rust-owned background worker, writing an opaque session id the caller polls.
    ///
    /// Returns [`STATUS_STARTED`] with `output_session_id` written when a worker was
    /// spawned, [`STATUS_SYNC_BUSY`] (nothing written) when the slot already has a
    /// cycle in flight, [`STATUS_INVALID_INPUT`] for a rejected input, or
    /// [`STATUS_INTERNAL`] for a registry, session-id allocation, or configuration
    /// fault. `output_session_id` is written only on [`STATUS_STARTED`]; the caller
    /// must not read it otherwise.
    ///
    /// # Safety
    ///
    /// `client_id` and `account_id` must each either be null or point to a readable
    /// buffer of the stated length. `output_session_id`, when non-null, must be
    /// writable for one `u64`. Every non-null pointer must remain valid for the
    /// duration of this call and must not alias a mutable output.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_mailbox_macos_sync_begin(
        client_id: *const u8,
        client_id_len: usize,
        account_id: *const u8,
        account_id_len: usize,
        output_session_id: *mut u64,
    ) -> i32 {
        let result = (|| {
            if output_session_id.is_null() {
                return Err(STATUS_INVALID_INPUT);
            }
            // SAFETY: the function contract requires a readable client-id buffer.
            let client_id = unsafe { read_utf8(client_id, client_id_len) }?;
            // SAFETY: the function contract requires a readable account-id buffer.
            let account_id = unsafe { read_utf8(account_id, account_id_len) }?;
            let account = AccountId::new(account_id).map_err(|_error| STATUS_INVALID_INPUT)?;
            let config = pinned_configuration(client_id)?;
            // Lock the registry BEFORE spawning: a poisoned registry must fail
            // without starting a worker no published session could ever track. The
            // guard is held across the spawn and insert, so registration always
            // precedes publishing the id.
            let mut sessions = sync_sessions().lock().map_err(|_error| STATUS_INTERNAL)?;
            // Allocate before spawning: id exhaustion likewise fails closed without
            // starting an untrackable worker, and the counter can never wrap onto a
            // live id.
            let session_id = allocate_session_id()?;
            match begin_default_account_sync(account, config) {
                BeginOutcome::Busy => Err(STATUS_SYNC_BUSY),
                BeginOutcome::Started(handles) => {
                    // Register before publishing the id, so a caller can never
                    // observe an id that is not yet pollable.
                    sessions.insert(session_id, handles);
                    // SAFETY: `output_session_id` was checked non-null above and the
                    // contract requires it to be writable for one `u64`.
                    unsafe {
                        *output_session_id = session_id;
                    }
                    Ok(())
                }
            }
        })();
        result.map_or_else(|status| status, |()| STATUS_STARTED)
    }

    /// Begins a bounded sync for a newly-connected account on a Rust-owned
    /// background worker, claiming the finished OAuth grant for
    /// `oauth_session_id` inside the whole-cycle permit, and writes an opaque
    /// session id the caller polls through the SAME [`tersa_mailbox_macos_sync_poll`]
    /// as a plain sync.
    ///
    /// `oauth_session_id` is the bridge-issued id of the caller's own finished
    /// authorization: a lookup key, never a capability, and never a value from
    /// an untrusted source. The grant, its registered redirect, and the client
    /// identifier are claimed from the bridge's session registry exactly once,
    /// on the worker thread.
    ///
    /// Returns [`STATUS_STARTED`] with `output_session_id` written when a worker
    /// was spawned, [`STATUS_SYNC_BUSY`] (nothing written, the grant NOT
    /// claimed — the caller may retry the same OAuth session) when the account
    /// slot already has a cycle in flight, [`STATUS_INVALID_INPUT`] for a
    /// rejected input, or [`STATUS_INTERNAL`] for a registry or session-id
    /// allocation fault. `output_session_id` is written only on
    /// [`STATUS_STARTED`]; the caller must not read it otherwise.
    ///
    /// # Safety
    ///
    /// `account_id` must either be null or point to a readable buffer of the
    /// stated length. `output_session_id`, when non-null, must be writable for
    /// one `u64`. Every non-null pointer must remain valid for the duration of
    /// this call and must not alias a mutable output.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_mailbox_macos_connect_begin(
        account_id: *const u8,
        account_id_len: usize,
        oauth_session_id: u64,
        output_session_id: *mut u64,
    ) -> i32 {
        let result = (|| {
            if output_session_id.is_null() {
                return Err(STATUS_INVALID_INPUT);
            }
            // SAFETY: the function contract requires a readable account-id buffer.
            let account_id = unsafe { read_utf8(account_id, account_id_len) }?;
            let account = AccountId::new(account_id).map_err(|_error| STATUS_INVALID_INPUT)?;
            // Lock the registry BEFORE spawning: a poisoned registry must fail
            // without starting a worker no published session could ever track. The
            // guard is held across the spawn and insert, so registration always
            // precedes publishing the id.
            let mut sessions = sync_sessions().lock().map_err(|_error| STATUS_INTERNAL)?;
            // Allocate before spawning: id exhaustion likewise fails closed without
            // starting an untrackable worker, and the counter can never wrap onto a
            // live id.
            let session_id = allocate_session_id()?;
            let session = BridgeConnectSession { oauth_session_id };
            match begin_connect_account_sync(account, session) {
                BeginOutcome::Busy => Err(STATUS_SYNC_BUSY),
                BeginOutcome::Started(handles) => {
                    // Register before publishing the id, so a caller can never
                    // observe an id that is not yet pollable.
                    sessions.insert(session_id, handles);
                    // SAFETY: `output_session_id` was checked non-null above and the
                    // contract requires it to be writable for one `u64`.
                    unsafe {
                        *output_session_id = session_id;
                    }
                    Ok(())
                }
            }
        })();
        result.map_or_else(|status| status, |()| STATUS_STARTED)
    }

    /// Polls one bounded-sync session, returning the worker's closed status integer
    /// and reaping the session once it reaches a terminal status.
    ///
    /// Returns [`STATUS_RUNNING`] while the cycle is in flight, the worker's terminal
    /// code (success, cancelled, gate-blocked, sync-failed, internal, or
    /// needs-reconnect) once, [`STATUS_UNKNOWN_SESSION`] for an unregistered or
    /// already-reaped id, or [`STATUS_INTERNAL`] if the registry lock is poisoned.
    ///
    /// # Safety
    ///
    /// A stable unmangled symbol is required by the C-compatible Apple bridge.
    #[expect(
        unsafe_code,
        reason = "a stable unmangled symbol is required by the C-compatible Apple bridge"
    )]
    #[unsafe(no_mangle)]
    pub extern "C" fn tersa_mailbox_macos_sync_poll(session_id: u64) -> i32 {
        let Ok(mut sessions) = sync_sessions().lock() else {
            return STATUS_INTERNAL;
        };
        let Some(handles) = sessions.get(&session_id) else {
            return STATUS_UNKNOWN_SESSION;
        };
        let status = handles.status();
        if status != STATUS_RUNNING {
            sessions.remove(&session_id);
        }
        status
    }

    #[cfg(test)]
    mod tests {
        #![expect(
            unsafe_code,
            reason = "the C ABI tests exercise the raw pointer and unmangled-symbol contract"
        )]
        #![expect(
            clippy::unwrap_used,
            reason = "tests unwrap known-good fixtures and a never-poisoned registry lock"
        )]

        use std::ptr;

        use tersa_oauth_sync_macos::ConnectSession;
        use tersa_oauth_sync_macos::worker::{STATUS_RUNNING, STATUS_SUCCEEDED, WorkerHandles};
        use url::Url;

        use super::{
            BridgeConnectSession, MAX_INPUT_BYTES, STATUS_INVALID_INPUT, STATUS_UNKNOWN_SESSION,
            read_utf8, tersa_mailbox_macos_connect_begin, tersa_mailbox_macos_sync_begin,
            tersa_mailbox_macos_sync_poll,
        };

        fn insert_test_session(status: i32) -> u64 {
            let id = super::allocate_session_id().unwrap();
            super::sync_sessions()
                .lock()
                .unwrap()
                .insert(id, WorkerHandles::from_status_for_test(status));
            id
        }

        #[test]
        fn read_utf8_rejects_null_empty_oversized_and_invalid_bytes() {
            let bytes = b"abc";
            // SAFETY: each call passes either a null pointer or a valid slice pointer
            // with a length the function validates before reading.
            unsafe {
                assert!(read_utf8(ptr::null(), 3).is_err());
                assert!(read_utf8(bytes.as_ptr(), 0).is_err());
                // An oversized length is rejected before any read, so the pointer is
                // never dereferenced out of bounds.
                assert!(read_utf8(bytes.as_ptr(), MAX_INPUT_BYTES + 1).is_err());
                let invalid = [0xff_u8, 0xfe_u8];
                assert!(read_utf8(invalid.as_ptr(), invalid.len()).is_err());
                assert_eq!(read_utf8(bytes.as_ptr(), bytes.len()).unwrap(), "abc");
            }
        }

        #[test]
        fn begin_rejects_a_null_output_pointer() {
            let client = b"client-123";
            let account = b"account-123";
            // SAFETY: the input buffers are valid; the output pointer is null, which
            // the function rejects before any dereference.
            let status = unsafe {
                tersa_mailbox_macos_sync_begin(
                    client.as_ptr(),
                    client.len(),
                    account.as_ptr(),
                    account.len(),
                    ptr::null_mut(),
                )
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
        }

        #[test]
        fn begin_rejects_an_unreadable_client_buffer() {
            let account = b"account-123";
            let mut session_id = 0_u64;
            // SAFETY: the client pointer is null (rejected before any read); the
            // account buffer and output pointer are valid.
            let status = unsafe {
                tersa_mailbox_macos_sync_begin(
                    ptr::null(),
                    10,
                    account.as_ptr(),
                    account.len(),
                    &raw mut session_id,
                )
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
            assert_eq!(
                session_id, 0,
                "a rejected begin must not write a session id"
            );
        }

        #[test]
        fn begin_rejects_an_invalid_account_identifier() {
            let client = b"client-123";
            // An email-shaped account identifier is rejected by `AccountId::new`,
            // before any worker is spawned.
            let account = b"user@example.com";
            let mut session_id = 0_u64;
            // SAFETY: all buffers and the output pointer are valid.
            let status = unsafe {
                tersa_mailbox_macos_sync_begin(
                    client.as_ptr(),
                    client.len(),
                    account.as_ptr(),
                    account.len(),
                    &raw mut session_id,
                )
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
            assert_eq!(
                session_id, 0,
                "a rejected begin must not write a session id"
            );
        }

        #[test]
        fn begin_rejects_a_blank_client_identifier() {
            // A blank client id is rejected by `TokenClientConfig::new` while pinning
            // the configuration — still before any worker is spawned.
            let client = b"   ";
            let account = b"account-123";
            let mut session_id = 0_u64;
            // SAFETY: all buffers and the output pointer are valid.
            let status = unsafe {
                tersa_mailbox_macos_sync_begin(
                    client.as_ptr(),
                    client.len(),
                    account.as_ptr(),
                    account.len(),
                    &raw mut session_id,
                )
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
            assert_eq!(
                session_id, 0,
                "a rejected begin must not write a session id"
            );
        }

        #[test]
        fn connect_begin_rejects_a_null_output_pointer() {
            let account = b"account-123";
            // SAFETY: the input buffer is valid; the output pointer is null, which
            // the function rejects before any dereference.
            let status = unsafe {
                tersa_mailbox_macos_connect_begin(
                    account.as_ptr(),
                    account.len(),
                    1,
                    ptr::null_mut(),
                )
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
        }

        #[test]
        fn connect_begin_rejects_an_unreadable_account_buffer() {
            let mut session_id = 0_u64;
            // SAFETY: the account pointer is null (rejected before any read); the
            // output pointer is valid.
            let status = unsafe {
                tersa_mailbox_macos_connect_begin(ptr::null(), 10, 1, &raw mut session_id)
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
            assert_eq!(
                session_id, 0,
                "a rejected begin must not write a session id"
            );
        }

        #[test]
        fn connect_begin_rejects_an_invalid_account_identifier() {
            // An email-shaped account identifier is rejected by `AccountId::new`,
            // before any worker is spawned.
            let account = b"user@example.com";
            let mut session_id = 0_u64;
            // SAFETY: the input buffer and the output pointer are valid.
            let status = unsafe {
                tersa_mailbox_macos_connect_begin(
                    account.as_ptr(),
                    account.len(),
                    1,
                    &raw mut session_id,
                )
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
            assert_eq!(
                session_id, 0,
                "a rejected begin must not write a session id"
            );
        }

        /// Runs one real bridge iOS authorization begin for `client_id`,
        /// returning the bridge-issued OAuth session id and authorization URL.
        fn begin_bridge_oauth_session(client_id: &'static [u8]) -> (u64, Url) {
            let scheme = b"tersa-test";
            let mut oauth_session_id = 0_u64;
            let mut url_buffer = [0_u8; 4096];
            let mut url_len = 0_usize;
            // SAFETY: the input buffers are valid; the outputs are writable for
            // their declared sizes.
            let status = unsafe {
                tersa_apple_bridge::tersa_oauth_ios_begin(
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
            // The bridge's STATUS_OK.
            assert_eq!(status, 0, "a valid iOS begin must succeed");
            let authorization_url = str::from_utf8(&url_buffer[..url_len]).unwrap();
            (oauth_session_id, Url::parse(authorization_url).unwrap())
        }

        /// Finishes a bridge OAuth session with a state-matching callback so a
        /// claimable grant is stored under its id.
        fn finish_bridge_oauth_session(oauth_session_id: u64, authorization_url: &Url) {
            let state = authorization_url
                .query_pairs()
                .find(|(name, _value)| name == "state")
                .map(|(_name, value)| value.into_owned())
                .unwrap();
            let mut callback = Url::parse("tersa-test:/oauth/callback").unwrap();
            callback
                .query_pairs_mut()
                .append_pair("code", "test-code")
                .append_pair("state", &state);
            let callback = callback.as_str();
            // SAFETY: the callback buffer is valid for its stated length.
            let status = unsafe {
                tersa_apple_bridge::tersa_oauth_ios_finish(
                    oauth_session_id,
                    callback.as_ptr(),
                    callback.len(),
                )
            };
            // The bridge's STATUS_SUCCEEDED.
            assert_eq!(status, 1, "a state-matching finish must store the grant");
        }

        #[test]
        fn two_bridge_sessions_with_distinct_oauth_ids_never_cross_talk() {
            // Two production sessions built on DIFFERENT bridge OAuth ids, begun
            // with DIFFERENT client ids: claim, is_cancelled, and complete must
            // each operate on their own id, and each claim must return the client
            // id ITS OWN begin recorded. Driven against the real bridge registry
            // through its public begin/finish/cancel seams — the bridge's
            // registry_test_guard is cfg(test)-local to that crate — and this is
            // the only test here that touches that registry, so no cross-test
            // serialization is needed.
            let (oauth_a, url_a) = begin_bridge_oauth_session(b"client-123");
            let (oauth_b, url_b) = begin_bridge_oauth_session(b"client-456");
            assert_ne!(oauth_a, oauth_b);
            let session_a = BridgeConnectSession {
                oauth_session_id: oauth_a,
            };
            let session_b = BridgeConnectSession {
                oauth_session_id: oauth_b,
            };

            // Store a grant under EACH id, then claim a: the claim returns the
            // client id a's begin recorded, carried with the grant by the bridge.
            finish_bridge_oauth_session(oauth_a, &url_a);
            finish_bridge_oauth_session(oauth_b, &url_b);
            let Some((_grant_a, config_a)) = session_a.claim() else {
                panic!("the finished, uncancelled session must yield its grant");
            };
            assert_eq!(config_a.client_id(), "client-123");
            assert_eq!(
                config_a.redirect_uri().as_str(),
                "tersa-test:/oauth/callback"
            );

            // Cancel ONLY a (mid-connect: its claim already holds the lease, so
            // the tombstone is pinned). The tombstone is per-id.
            let _ = tersa_apple_bridge::tersa_oauth_cancel(oauth_a);
            assert!(
                session_a.is_cancelled(),
                "the cancelled session must report cancelled"
            );
            assert!(
                !session_b.is_cancelled(),
                "a cancel on one id must never mark the other session"
            );

            // b still claims after a's cancel, and the claim returns the client
            // id b's begin recorded — the client id follows its own session.
            let Some((_grant_b, config_b)) = session_b.claim() else {
                panic!("a cancel on the other id must not disturb this claim");
            };
            assert_eq!(config_b.client_id(), "client-456");
            // The grant is single-use: a second claim on the same id yields nothing.
            assert!(session_b.claim().is_none());

            // complete() is per-id, idempotent, and never consumes a tombstone:
            // a stays cancelled, b stays un-cancelled throughout.
            session_a.complete();
            session_b.complete();
            session_b.complete();
            assert!(session_a.is_cancelled());
            assert!(!session_b.is_cancelled());
        }

        #[test]
        fn poll_of_an_unknown_session_is_reported_without_a_status() {
            // A never-registered id is unknown; the atomic counter guarantees this id
            // was never handed out.
            assert_eq!(
                tersa_mailbox_macos_sync_poll(u64::MAX),
                STATUS_UNKNOWN_SESSION
            );
        }

        #[test]
        fn poll_returns_a_terminal_status_once_then_reaps_the_session() {
            let id = insert_test_session(STATUS_SUCCEEDED);
            assert_eq!(tersa_mailbox_macos_sync_poll(id), STATUS_SUCCEEDED);
            // The terminal poll reaped the session, so it is no longer registered.
            assert_eq!(tersa_mailbox_macos_sync_poll(id), STATUS_UNKNOWN_SESSION);
        }

        #[test]
        fn poll_keeps_a_running_session_registered() {
            let id = insert_test_session(STATUS_RUNNING);
            assert_eq!(tersa_mailbox_macos_sync_poll(id), STATUS_RUNNING);
            // A running poll does not reap, so the session is still pollable.
            assert_eq!(tersa_mailbox_macos_sync_poll(id), STATUS_RUNNING);
            // Clean up so the shared static does not retain a fabricated session.
            super::sync_sessions().lock().unwrap().remove(&id);
        }

        // The STATUS_STARTED and STATUS_SYNC_BUSY begin outcomes — sync and connect
        // alike — are intentionally not exercised here: both require spawning a real
        // worker, which builds the Keychain hasher and (on a provisioned host)
        // performs network I/O. The busy mapping is proven deterministically by the
        // worker crate's own `begin_default_account_sync_on_a_busy_slot_is_busy_and_builds_nothing`,
        // and the started/registry/reap round-trip is covered above via fabricated
        // handles; the live path is left to review and integration.
    }
}
