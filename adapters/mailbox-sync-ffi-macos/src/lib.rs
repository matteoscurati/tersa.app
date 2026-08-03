// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exposes the Rust-owned bounded Gmail sync worker through a narrow C ABI.
//!
//! This crate is a sibling static library to the minimal Apple bootstrap bridge,
//! kept separate so the network stack (tokio, reqwest, native-tls) the trusted
//! composition links stays out of that bridge's deliberately small trust surface.
//!
//! # Default production surface: broker-fed
//!
//! The default production build is BROKER-FED (ADR-0024): it links neither the
//! direct refresh-token lifecycle nor the legacy Apple OAuth surface. Swift
//! supplies only the broker-issued access token and the broker routing subject
//! to `tersa_mailbox_macos_broker_sync_begin` — no client id, no OAuth session
//! id, no refresh token, and no expiry cross this boundary — and coordinates
//! disconnect through the broker disconnect prepare/finalize pair, which
//! performs no token or network operation here because the separately signed
//! token broker owns the token lifecycle. The broker routing subject is stored
//! and loaded through the broker subject seams, the content-free lifecycle
//! projection is read through `tersa_mailbox_macos_lifecycle_get`, and every
//! begin shares the one `tersa_mailbox_macos_sync_poll` entry point. Both
//! broker secrets are copied under zeroizing wrappers immediately and are never
//! formatted or logged. Progress is a single closed status integer; no mailbox
//! content, address, subject, or count ever crosses this boundary.
//!
//! # Legacy in-process token lifecycle (opt in, never production)
//!
//! The obsolete in-process OAuth/token begins — `tersa_mailbox_macos_sync_begin`,
//! `tersa_mailbox_macos_connect_begin`, and `tersa_mailbox_macos_disconnect_begin`
//! — plus the optional build-time Desktop-client secret helpers and the
//! bridge-claiming `BridgeConnectSession` are compiled ONLY under the
//! `legacy-token-lifecycle` feature or this crate's own `cfg(test)` builds; no
//! production dependency enables them. On the legacy path Swift supplies only
//! two public strings — the OAuth client identifier and the opaque account
//! identifier — and never any URL: the Google token and revoke endpoints are
//! pinned downstream in the Gmail transport, and the registered redirect for a
//! plain sync begin is pinned here. A legacy connect begin supplies only the
//! account identifier plus the bridge-issued id of the finished OAuth session
//! whose grant the worker claims: the grant, its registered redirect, and the
//! client identifier all arrive with the claim from the bridge's session
//! registry, never from Swift, so the exchange configuration cannot disagree
//! with the session by construction. An optional Desktop-client secret may be
//! supplied at Rust compile time; installed applications cannot keep that value
//! confidential, so it is treated as client configuration rather than as a
//! runtime credential. A legacy disconnect begin takes no grant and no
//! configuration: the teardown (best-effort revoke, token delete, local purge)
//! is built entirely inside the trusted composition.
//!
//! # Single-archive link
//!
//! The application links ONLY this crate's static archive: depending on the
//! bridge with `default-features = false` re-exports its bootstrap and
//! read-only `tersa_macos_*` C symbols from the same archive, so one `.a`
//! carries both surfaces while the bridge's legacy `tersa_oauth_*` surface
//! stays out of the default link. Linking the bridge archive as well fails
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
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    use tersa_application::oauth::AuthorizationGrant;
    use tersa_application::token::AccountSubject;
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    use tersa_application::token::TokenClientConfig;
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    use tersa_oauth_sync_macos::ConnectSession;
    use tersa_oauth_sync_macos::worker::{
        self, BeginOutcome, BrokerDisconnectPrepareOutcome, STATUS_NEEDS_RECONNECT, STATUS_RUNNING,
        STATUS_SUCCEEDED, WorkerHandles, begin_broker_account_sync,
        begin_broker_disconnect_finalize, prepare_broker_disconnect,
    };
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    use tersa_oauth_sync_macos::worker::{begin_connect_account_sync, begin_default_account_sync};
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    use url::Url;
    use zeroize::Zeroizing;

    /// A worker was spawned; the caller reads its written session id and polls it.
    const STATUS_STARTED: i32 = 0;
    /// The account slot already has a whole cycle in flight; no worker was spawned
    /// and no session id was written. Positive so it never aliases a poll terminal.
    const STATUS_SYNC_BUSY: i32 = 2;
    /// The session registry lock was poisoned, or (legacy builds only) the pinned
    /// configuration could not be constructed — an internal anomaly rather than
    /// caller error. Matches the worker's own internal code so the two never
    /// disagree.
    const STATUS_INTERNAL: i32 = -5;
    /// A begin input was rejected: an unreadable or non-UTF-8 buffer, an invalid
    /// account identifier, a null output pointer, or (legacy builds only) a blank
    /// client identifier.
    const STATUS_INVALID_INPUT: i32 = -7;
    /// A poll named a session that is not (or is no longer) registered.
    const STATUS_UNKNOWN_SESSION: i32 = -8;

    /// The largest client- or account-identifier buffer this ABI copies. A Google
    /// OAuth client id and an opaque account id are both well under this bound; a
    /// larger length is a caller error, not a value to allocate.
    const MAX_INPUT_BYTES: usize = 512;

    /// The largest broker access-token buffer this ABI copies. A Google OAuth
    /// access token is well under this bound; a larger length is a caller error,
    /// not a value to allocate.
    const MAX_ACCESS_TOKEN_BYTES: usize = 4096;

    /// The largest broker-asserted subject buffer this ABI copies. A Google user
    /// id is a short numeric string, so a larger length is a caller error; the
    /// worker re-validates the value conservatively at the session trust
    /// boundary regardless.
    const MAX_SUBJECT_BYTES: usize = 255;

    /// The registered redirect pinned into every legacy configuration. It is a syntactically
    /// valid loopback placeholder that this worker's refresh grant never transmits;
    /// `TokenClientConfig` only requires the field to be a well-formed URL.
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
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

    /// Copies a caller-owned UTF-8 buffer holding a secret into an owned
    /// [`Zeroizing`] string, rejecting a null, empty, oversized (beyond `max`),
    /// or non-UTF-8 input with [`STATUS_INVALID_INPUT`]. The value is moved
    /// under the zeroizing wrapper immediately and is never formatted or
    /// logged.
    ///
    /// # Safety
    ///
    /// When `pointer` is non-null it must point to `length` readable bytes that
    /// remain valid for the duration of this call.
    #[expect(
        unsafe_code,
        reason = "raw C buffers are copied immediately into checked Rust values"
    )]
    unsafe fn read_secret(
        pointer: *const u8,
        length: usize,
        max: usize,
    ) -> Result<Zeroizing<String>, i32> {
        if pointer.is_null() || length == 0 || length > max {
            return Err(STATUS_INVALID_INPUT);
        }
        // SAFETY: the caller guarantees `length` readable bytes at `pointer`.
        let bytes = unsafe { slice::from_raw_parts(pointer, length) };
        str::from_utf8(bytes)
            .map(|text| Zeroizing::new(text.to_owned()))
            .map_err(|_error| STATUS_INVALID_INPUT)
    }

    /// Reads the optional Desktop-client secret embedded by the local build.
    ///
    /// Google documents this value as optional for installed apps, but some
    /// Desktop clients require it at the token endpoint. The value is compiled
    /// into the application and therefore is not treated as confidential.
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    fn configured_client_secret() -> Option<&'static str> {
        client_secret_from_build_setting(option_env!("TERSA_OAUTH_CLIENT_SECRET"))
    }

    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    fn client_secret_from_build_setting(value: Option<&str>) -> Option<&str> {
        value.filter(|secret| {
            !secret.trim().is_empty() && !secret.to_ascii_uppercase().contains("UNCONFIGURED")
        })
    }

    /// Builds the legacy token-client configuration pinned to this application's
    /// public posture: the caller-supplied client id, the pinned placeholder
    /// redirect, and the optional build-time Desktop-client secret. A blank
    /// client id is a caller error; the placeholder redirect is a compile-time
    /// constant whose parse failure could only be an internal fault.
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    fn pinned_configuration(client_id: String) -> Result<TokenClientConfig, i32> {
        let redirect = Url::parse(PLACEHOLDER_REDIRECT_URI).map_err(|_error| STATUS_INTERNAL)?;
        TokenClientConfig::new_with_optional_client_secret(
            client_id,
            redirect,
            configured_client_secret(),
        )
        .map_err(|_error| STATUS_INVALID_INPUT)
    }

    /// The legacy [`ConnectSession`] backed by the Apple bridge's session
    /// registry: the claim, the cancel fences, and the completion acknowledgement
    /// all act on the ONE OAuth session id this value was built with. The id is
    /// private and immutable, so no code path can re-point the session at a
    /// different id after construction — the worker's claim and its three cancel
    /// fences provably reference the same session. The client identifier arrives
    /// WITH the claim from the bridge, which validated it at begin and stored it
    /// with the grant, so it cannot disagree with the session by construction.
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    struct BridgeConnectSession {
        oauth_session_id: u64,
    }

    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    impl ConnectSession for BridgeConnectSession {
        fn claim(&self) -> Option<(AuthorizationGrant, TokenClientConfig)> {
            let (grant, redirect, client_id) =
                tersa_apple_bridge::claim_grant(self.oauth_session_id)?;
            // The optional build-time Desktop-client secret is paired with the
            // same claimed client id and redirect. The Google token and revoke
            // endpoints remain pinned downstream in the Gmail transport.
            match TokenClientConfig::new_with_optional_client_secret(
                client_id,
                redirect,
                configured_client_secret(),
            ) {
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
    /// Legacy in-process token lifecycle: compiled only under the
    /// `legacy-token-lifecycle` feature or `cfg(test)`, never by the default
    /// broker-fed production build.
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
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
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
    /// Legacy in-process token lifecycle: compiled only under the
    /// `legacy-token-lifecycle` feature or `cfg(test)`, never by the default
    /// broker-fed production build.
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
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
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

    /// Begins a bounded sync for `account_id` from an ADR-0024 token-broker
    /// reply on a Rust-owned background worker, writing an opaque session id
    /// the caller polls through the SAME [`tersa_mailbox_macos_sync_poll`] as
    /// every other begin.
    ///
    /// `access_token` and `subject` are the bearer token and the Google user id
    /// from the SAME broker reply. This begin takes no client id, no OAuth
    /// session id, no refresh token, and no expiry: nothing from the token
    /// lifecycle is constructed on this path. Both inputs are secrets (the
    /// subject is account-identifying): each is copied into a [`Zeroizing`]
    /// string immediately, is never formatted or logged here or downstream,
    /// and the caller MUST zero or discard its own buffers once this call
    /// returns. The token must be nonempty, at most [`MAX_ACCESS_TOKEN_BYTES`]
    /// bytes, and free of ASCII control characters; the subject must be
    /// nonempty and at most [`MAX_SUBJECT_BYTES`] bytes. The subject check
    /// here is only a syntactic pre-filter — the worker constructor performs
    /// the authoritative conservative subject validation at the session trust
    /// boundary.
    ///
    /// Returns [`STATUS_STARTED`] with `output_session_id` written when a
    /// worker was spawned, [`STATUS_SYNC_BUSY`] (nothing written, the secrets
    /// dropped without spawning) when the account slot already has a cycle in
    /// flight, [`STATUS_INVALID_INPUT`] for a rejected input, or
    /// [`STATUS_INTERNAL`] for a registry or session-id allocation fault.
    /// `output_session_id` is written only on [`STATUS_STARTED`]; the caller
    /// must not read it otherwise.
    ///
    /// # Safety
    ///
    /// `account_id`, `access_token`, and `subject` must each either be null or
    /// point to a readable buffer of the stated length. `output_session_id`,
    /// when non-null, must be writable for one `u64`. Every non-null pointer
    /// must remain valid for the duration of this call and must not alias a
    /// mutable output.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_mailbox_macos_broker_sync_begin(
        account_id: *const u8,
        account_id_len: usize,
        access_token: *const u8,
        access_token_len: usize,
        subject: *const u8,
        subject_len: usize,
        output_session_id: *mut u64,
    ) -> i32 {
        let result = (|| {
            if output_session_id.is_null() {
                return Err(STATUS_INVALID_INPUT);
            }
            // SAFETY: the function contract requires a readable account-id buffer.
            let account_id = unsafe { read_utf8(account_id, account_id_len) }?;
            let account = AccountId::new(account_id).map_err(|_error| STATUS_INVALID_INPUT)?;
            // SAFETY: the function contract requires a readable access-token buffer.
            let access_token =
                unsafe { read_secret(access_token, access_token_len, MAX_ACCESS_TOKEN_BYTES) }?;
            if access_token.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(STATUS_INVALID_INPUT);
            }
            // SAFETY: the function contract requires a readable subject buffer.
            let subject = unsafe { read_secret(subject, subject_len, MAX_SUBJECT_BYTES) }?;
            // Lock the registry BEFORE spawning: a poisoned registry must fail
            // without starting a worker no published session could ever track. The
            // guard is held across the spawn and insert, so registration always
            // precedes publishing the id.
            let mut sessions = sync_sessions().lock().map_err(|_error| STATUS_INTERNAL)?;
            // Allocate before spawning: id exhaustion likewise fails closed without
            // starting an untrackable worker, and the counter can never wrap onto a
            // live id.
            let session_id = allocate_session_id()?;
            match begin_broker_account_sync(account, access_token, subject) {
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

    /// Begins the disconnect (OAuth consent withdrawal + local teardown) for
    /// `account_id` on a Rust-owned background worker, writing an opaque
    /// session id the caller polls through the SAME
    /// [`tersa_mailbox_macos_sync_poll`] as a sync or connect.
    ///
    /// Legacy in-process token lifecycle: compiled only under the
    /// `legacy-token-lifecycle` feature or `cfg(test)`, never by the default
    /// broker-fed production build, whose disconnect is the broker-coordinated
    /// prepare/finalize pair below.
    ///
    /// The slot's `disconnecting` flag is set — and any in-flight sync's
    /// registered cancel flag is signaled — on the CALLER thread BEFORE the
    /// worker is spawned, so "`disconnect_begin` returned [`STATUS_STARTED`] ⇒
    /// no new sync or connect begins for the slot" is a hard guarantee. The
    /// worker then serializes BEHIND any in-flight cycle on the whole-cycle
    /// gate, loads the stored refresh token under that gate, revokes it
    /// best-effort (an offline withdrawal still tears down locally), deletes
    /// it, and purges the account's local mailbox and identity in one
    /// transaction. A locally-COMPLETE teardown reports the plain success code
    /// (1) when the provider confirmed the /revoke — or nothing was stored —
    /// and the DISTINCT success-revoke-unconfirmed code (3) when it could not
    /// be confirmed: the account is disconnected either way, and 3e renders
    /// the latter as "Disconnected — also revoke access in your Google Account
    /// settings." The flag clears on BOTH success codes; on any teardown
    /// FAILURE it stays set (fail-closed), the poll reports the internal code,
    /// and a retried disconnect converges.
    ///
    /// Returns [`STATUS_STARTED`] with `output_session_id` written when a
    /// worker was spawned, [`STATUS_SYNC_BUSY`] (nothing written) when a
    /// disconnect worker is ALREADY active on the slot — a concurrent request
    /// coalesces onto the running teardown rather than starting a second one;
    /// this does NOT refuse withdrawal, the running worker owns it, and a RETRY
    /// after a FAILED teardown is admitted, not busy — [`STATUS_INVALID_INPUT`]
    /// for a rejected input, or [`STATUS_INTERNAL`] for a registry or
    /// session-id allocation fault. `output_session_id` is written only on
    /// [`STATUS_STARTED`]; the caller must not read it otherwise.
    ///
    /// ON `STATUS_SYNC_BUSY`, the caller MUST poll the disconnect it already
    /// started to completion, NOT blindly re-issue: the running teardown owns
    /// the request, and a retry-until-STARTED loop would, once that teardown
    /// succeeds and the user reconnects, be admitted and tear down the NEW
    /// connection.
    ///
    /// CALLER OBLIGATION (the `disconnecting` fence covers sync/connect BEGINS,
    /// NOT the bridge's pending-authorization registry): the caller MUST cancel
    /// every in-flight OAuth authorization session for this account BEFORE
    /// calling disconnect. Disconnect does not — and, being bridge-free, cannot
    /// — tombstone a pending grant, so a pending authorization whose callback
    /// lands within `AUTHORIZATION_LIFETIME` after a successful disconnect would
    /// silently re-connect the account. 3e must enforce this ordering; a
    /// structural fix (a per-slot disconnect epoch stamped into the bridge
    /// session, refused by `connect_begin` when stale) is a deferred follow-up.
    ///
    /// # Safety
    ///
    /// `account_id` must either be null or point to a readable buffer of the
    /// stated length. `output_session_id`, when non-null, must be writable for
    /// one `u64`. Every non-null pointer must remain valid for the duration of
    /// this call and must not alias a mutable output.
    #[cfg(any(feature = "legacy-token-lifecycle", test))]
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_mailbox_macos_disconnect_begin(
        account_id: *const u8,
        account_id_len: usize,
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
            // guard is held across the begin and insert, so registration always
            // precedes publishing the id.
            let mut sessions = sync_sessions().lock().map_err(|_error| STATUS_INTERNAL)?;
            // Allocate before spawning: id exhaustion likewise fails closed without
            // starting an untrackable worker, and the counter can never wrap onto a
            // live id.
            let session_id = allocate_session_id()?;
            // `begin_disconnect` sets the disconnecting fence + claims the single-
            // worker lease SYNCHRONOUSLY here, before it spawns, so once this
            // returns STARTED no new sync or connect can begin for the slot.
            // `Busy` ⇒ a disconnect worker is already active on the slot:
            // coalesce onto it, writing no session id — withdrawal is not
            // refused, the running worker owns the teardown.
            match worker::begin_disconnect(account) {
                BeginOutcome::Busy => return Err(STATUS_SYNC_BUSY),
                BeginOutcome::Started(handles) => {
                    // Register before publishing the id, so a caller can never
                    // observe an id that is not yet pollable.
                    sessions.insert(session_id, handles);
                    // SAFETY: `output_session_id` was checked non-null above and
                    // the contract requires it writable for one `u64`.
                    unsafe {
                        *output_session_id = session_id;
                    }
                }
            }
            Ok(())
        })();
        result.map_or_else(|status| status, |()| STATUS_STARTED)
    }

    /// Runs the PREPARE step of an ADR-0024 broker-coordinated disconnect for
    /// `account_id`, synchronously, on the caller thread. This is the
    /// `SQLCipher marker` step of the order `outer intent → SQLCipher marker →
    /// broker revoke → broker token delete → main-app purge → marker clear`.
    ///
    /// Swift MUST call this only AFTER it has durably journaled its own outer
    /// disconnect intent, and — when this returns [`STATUS_SUCCEEDED`] — the
    /// separately signed broker owns the `broker revoke → broker token delete`
    /// steps that follow. The finalize tail is begun through
    /// [`tersa_mailbox_macos_broker_disconnect_finalize`] only after the broker
    /// reports its token delete succeeded.
    ///
    /// This seam performs NO token or network operation: the broker holds the
    /// token lifecycle, so no token is loaded, deleted, or revoked here. It
    /// sets the slot's disconnecting fence (cancel-signaling a running sync)
    /// and, when a mailbox store exists, persists the durable
    /// disconnect-started marker. There is no output payload: the caller learns
    /// only the closed status integer.
    ///
    /// Returns [`STATUS_SUCCEEDED`] when the slot was prepared and the broker
    /// revoke may proceed, [`STATUS_SYNC_BUSY`] when another disconnect
    /// operation already owns the slot (nothing was touched; the running
    /// operation owns the teardown — do NOT proceed to the broker revoke),
    /// [`STATUS_INVALID_INPUT`] for a rejected account identifier, or
    /// [`STATUS_INTERNAL`] when the marker could not be persisted (the fence
    /// stays set, fail-closed, and a retried prepare converges).
    ///
    /// # Safety
    ///
    /// `account_id` must either be null or point to a readable buffer of the
    /// stated length that remains valid for the duration of this call.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_mailbox_macos_broker_disconnect_prepare(
        account_id: *const u8,
        account_id_len: usize,
    ) -> i32 {
        let result = (|| {
            // SAFETY: the function contract requires a readable account-id buffer.
            let account_id = unsafe { read_utf8(account_id, account_id_len) }?;
            let account = AccountId::new(account_id).map_err(|_error| STATUS_INVALID_INPUT)?;
            match prepare_broker_disconnect(&account) {
                BrokerDisconnectPrepareOutcome::Prepared => Ok(()),
                BrokerDisconnectPrepareOutcome::Busy => Err(STATUS_SYNC_BUSY),
                BrokerDisconnectPrepareOutcome::Failed => Err(STATUS_INTERNAL),
            }
        })();
        result.map_or_else(|status| status, |()| STATUS_SUCCEEDED)
    }

    /// Begins the FINALIZE tail of an ADR-0024 broker-coordinated disconnect
    /// for `account_id` on a Rust-owned background worker, writing an opaque
    /// session id the caller polls through the SAME
    /// [`tersa_mailbox_macos_sync_poll`] as every other begin. This is the
    /// `main-app purge → marker clear` tail of the order `outer intent →
    /// SQLCipher marker → broker revoke → broker token delete → main-app
    /// purge → marker clear`.
    ///
    /// Swift MUST call this only AFTER [`tersa_mailbox_macos_broker_disconnect_prepare`]
    /// returned [`STATUS_SUCCEEDED`] AND the separately signed broker reported
    /// its token delete succeeded: the broker owns the `broker revoke → broker
    /// token delete` steps, so this seam performs NO token or network
    /// operation — no token is loaded, deleted, or revoked here.
    ///
    /// `revoke_unconfirmed` is the broker's CLOSED disposition of its revoke
    /// step: exactly 0 (the provider /revoke was confirmed) or 1 (it could not
    /// be confirmed). It is NOT an arbitrary status or error code — any other
    /// integer is rejected with [`STATUS_INVALID_INPUT`]. The disposition only
    /// selects which recovery marker the finalize persists and which success
    /// code the poll reports (1 for confirmed, 3 for unconfirmed); a broker
    /// token-delete FAILURE must never reach this call — it aborts the
    /// finalize instead, leaving the durable markers for a retried disconnect.
    ///
    /// Returns [`STATUS_STARTED`] with `output_session_id` written when a
    /// worker was spawned, [`STATUS_SYNC_BUSY`] (nothing written) when another
    /// disconnect operation is active on the slot — a concurrent request
    /// coalesces onto the running teardown — [`STATUS_INVALID_INPUT`] for a
    /// rejected input, or [`STATUS_INTERNAL`] for a registry or session-id
    /// allocation fault. `output_session_id` is written only on
    /// [`STATUS_STARTED`]; it is left untouched on every other return and the
    /// caller must not read it then.
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
    pub unsafe extern "C" fn tersa_mailbox_macos_broker_disconnect_finalize(
        account_id: *const u8,
        account_id_len: usize,
        revoke_unconfirmed: i32,
        output_session_id: *mut u64,
    ) -> i32 {
        let result = (|| {
            if output_session_id.is_null() {
                return Err(STATUS_INVALID_INPUT);
            }
            // SAFETY: the function contract requires a readable account-id buffer.
            let account_id = unsafe { read_utf8(account_id, account_id_len) }?;
            let account = AccountId::new(account_id).map_err(|_error| STATUS_INVALID_INPUT)?;
            // The disposition is a closed set: exactly 0 (confirmed) or 1
            // (unconfirmed). Any other integer is caller error, not a status.
            let revoke_unconfirmed = match revoke_unconfirmed {
                0 => false,
                1 => true,
                _other => return Err(STATUS_INVALID_INPUT),
            };
            // Lock the registry BEFORE spawning: a poisoned registry must fail
            // without starting a worker no published session could ever track. The
            // guard is held across the begin and insert, so registration always
            // precedes publishing the id.
            let mut sessions = sync_sessions().lock().map_err(|_error| STATUS_INTERNAL)?;
            // Allocate before spawning: id exhaustion likewise fails closed without
            // starting an untrackable worker, and the counter can never wrap onto a
            // live id.
            let session_id = allocate_session_id()?;
            match begin_broker_disconnect_finalize(account, revoke_unconfirmed) {
                BeginOutcome::Busy => Err(STATUS_SYNC_BUSY),
                BeginOutcome::Started(handles) => {
                    // Register before publishing the id, so a caller can never
                    // observe an id that is not yet pollable.
                    sessions.insert(session_id, handles);
                    // SAFETY: `output_session_id` was checked non-null above and
                    // the contract requires it writable for one `u64`.
                    unsafe {
                        *output_session_id = session_id;
                    }
                    Ok(())
                }
            }
        })();
        result.map_or_else(|status| status, |()| STATUS_STARTED)
    }

    /// Reads the content-free lifecycle projection for an account without
    /// creating a mailbox store. `output_recovery` receives 0 for none, 1 for
    /// incomplete teardown, or 2 for revoke unconfirmed. `output_last_sync`
    /// receives Unix milliseconds or -1 when no fully successful sync exists.
    /// No mailbox rows, OAuth material, provider identifiers, or account identity
    /// values cross this ABI.
    ///
    /// # Safety
    ///
    /// `account_id` must either be null or point to a readable buffer of the
    /// stated length. Both outputs must be writable for one integer and all
    /// non-null pointers must remain valid for the duration of this call.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_mailbox_macos_lifecycle_get(
        account_id: *const u8,
        account_id_len: usize,
        output_recovery: *mut i32,
        output_last_successful_sync_unix_millis: *mut i64,
    ) -> i32 {
        let result = (|| {
            if output_recovery.is_null() || output_last_successful_sync_unix_millis.is_null() {
                return Err(STATUS_INVALID_INPUT);
            }
            // SAFETY: the function contract requires a readable account-id buffer.
            let account_id = unsafe { read_utf8(account_id, account_id_len) }?;
            let account = AccountId::new(account_id).map_err(|_error| STATUS_INVALID_INPUT)?;
            let metadata =
                worker::lifecycle_metadata(&account).map_err(|_error| STATUS_INTERNAL)?;
            let (recovery, freshness) = match metadata {
                None => (0, -1),
                Some(metadata) => {
                    let recovery = match metadata.recovery() {
                        None => 0,
                        Some(tersa_application::lifecycle::DisconnectRecoveryState::IncompleteTeardown) => 1,
                        Some(tersa_application::lifecycle::DisconnectRecoveryState::RevokeUnconfirmed) => 2,
                    };
                    (
                        recovery,
                        metadata.last_successful_sync_unix_millis().unwrap_or(-1),
                    )
                }
            };
            // SAFETY: both outputs were checked non-null and the contract requires
            // one writable integer at each address.
            unsafe {
                *output_recovery = recovery;
                *output_last_successful_sync_unix_millis = freshness;
            }
            Ok(())
        })();
        result.map_or_else(|status| status, |()| STATUS_STARTED)
    }

    /// Stores the broker routing subject for an account in the default protected
    /// mailbox store, creating the store if needed. The subject is the
    /// account-identifying BROKER ROUTING identifier the separately signed token
    /// broker uses to route to the account's tokens — never an OAuth credential
    /// and never mailbox content. The buffer is copied under a zeroizing wrapper
    /// immediately on entry and the value is never formatted or logged.
    ///
    /// Returns [`STATUS_STARTED`] when the subject was persisted,
    /// [`STATUS_INVALID_INPUT`] for a rejected account-id or subject buffer
    /// (null, empty, oversized, or non-UTF-8), or [`STATUS_INTERNAL`] for a
    /// protected-store open/setup failure or stored-data corruption: every store
    /// fault collapses to the one opaque code so no store detail crosses the ABI.
    ///
    /// # Safety
    ///
    /// `account_id` and `subject` must each either be null or point to a readable
    /// buffer of the stated length. Every non-null pointer must remain valid for
    /// the duration of this call. Both buffers are copied synchronously before
    /// this call returns; the caller retains ownership of them.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_mailbox_macos_broker_subject_store(
        account_id: *const u8,
        account_id_len: usize,
        subject: *const u8,
        subject_len: usize,
    ) -> i32 {
        let result = (|| {
            // SAFETY: the function contract requires a readable account-id buffer.
            let account_id = unsafe { read_utf8(account_id, account_id_len) }?;
            let account = AccountId::new(account_id).map_err(|_error| STATUS_INVALID_INPUT)?;
            // SAFETY: the function contract requires a readable subject buffer.
            // The value moves under the zeroizing wrapper immediately and is
            // never formatted or logged.
            let subject = unsafe { read_secret(subject, subject_len, MAX_SUBJECT_BYTES) }?;
            let validated_subject = AccountSubject::from_broker_validated(subject)
                .map_err(|_error| STATUS_INVALID_INPUT)?;
            worker::store_broker_subject(&account, validated_subject.as_str())
                .map_err(|_error| STATUS_INTERNAL)
        })();
        result.map_or_else(|status| status, |()| STATUS_STARTED)
    }

    /// Loads the broker routing subject for an account from the default protected
    /// mailbox store WITHOUT creating one, copying the exact subject bytes into
    /// the caller's buffer. The subject is the account-identifying BROKER
    /// ROUTING identifier — never an OAuth credential and never mailbox
    /// content. The loaded value stays under its zeroizing wrapper, in scope
    /// until after the copy completes, and is never formatted or logged.
    ///
    /// Returns [`STATUS_STARTED`] when a stored subject was published: exactly
    /// `*output_subject_len` bytes are written at `output_subject` and the
    /// length is written last. Both outputs are published ONLY on this return;
    /// on every other return both are left untouched and the caller must not
    /// read them. Returns [`STATUS_NEEDS_RECONNECT`] when the account has no
    /// stored routing subject — the worker's own absent-routing code —
    /// [`STATUS_INVALID_INPUT`] for a rejected account id, a null output
    /// pointer, a capacity outside `1..=MAX_SUBJECT_BYTES`, or a capacity
    /// smaller than the stored subject, or [`STATUS_INTERNAL`] for any
    /// protected-store or corruption fault: every store fault collapses to the
    /// one opaque code so no store detail crosses the ABI.
    ///
    /// # Safety
    ///
    /// `account_id` must either be null or point to a readable buffer of the
    /// stated length. `output_subject`, when non-null, must be writable for
    /// `output_subject_capacity` bytes, and `output_subject_len`, when
    /// non-null, must be writable for one `usize`. Every non-null pointer must
    /// remain valid for the duration of this call and the two outputs must not
    /// alias each other.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_mailbox_macos_broker_subject_get(
        account_id: *const u8,
        account_id_len: usize,
        output_subject: *mut u8,
        output_subject_capacity: usize,
        output_subject_len: *mut usize,
    ) -> i32 {
        let result = (|| {
            if output_subject.is_null() || output_subject_len.is_null() {
                return Err(STATUS_INVALID_INPUT);
            }
            if output_subject_capacity == 0 || output_subject_capacity > MAX_SUBJECT_BYTES {
                return Err(STATUS_INVALID_INPUT);
            }
            // SAFETY: the function contract requires a readable account-id buffer.
            let account_id = unsafe { read_utf8(account_id, account_id_len) }?;
            let account = AccountId::new(account_id).map_err(|_error| STATUS_INVALID_INPUT)?;
            let Some(subject) =
                worker::load_broker_subject(&account).map_err(|_error| STATUS_INTERNAL)?
            else {
                return Err(STATUS_NEEDS_RECONNECT);
            };
            let bytes = subject.as_bytes();
            if bytes.len() > output_subject_capacity {
                return Err(STATUS_INVALID_INPUT);
            }
            // SAFETY: `output_subject` was checked non-null and the contract
            // requires `output_subject_capacity` writable bytes there; the copy
            // length fits within that capacity by the check above and cannot
            // overlap the source, which this call owns. `output_subject_len`
            // was checked non-null and the contract requires one writable
            // `usize` there. `subject` remains alive until after the copy.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), output_subject, bytes.len());
                *output_subject_len = bytes.len();
            }
            Ok(())
        })();
        result.map_or_else(|status| status, |()| STATUS_STARTED)
    }

    /// Polls one bounded-sync session, returning the worker's closed status integer
    /// and reaping the session once it reaches a terminal status.
    ///
    /// Returns [`STATUS_RUNNING`] while the cycle is in flight, the worker's terminal
    /// code (success, success-revoke-unconfirmed, cancelled, gate-blocked,
    /// sync-failed, internal, or needs-reconnect) once, [`STATUS_UNKNOWN_SESSION`]
    /// for an unregistered or already-reaped id, or [`STATUS_INTERNAL`] if the
    /// registry lock is poisoned.
    ///
    /// This one poll serves every begin: the broker sync begin and the broker
    /// disconnect finalize in the default build, plus the legacy sync, connect,
    /// AND disconnect begins under `legacy-token-lifecycle`/`cfg(test)`. The
    /// terminal codes are NOT all reachable from every session kind: only a
    /// DISCONNECT session can report [`STATUS_SUCCEEDED_REVOKE_UNCONFIRMED`] —
    /// a sync or a connect poll NEVER does. A Swift caller must not surface the
    /// revoke-in-Google-settings copy off a sync/connect poll.
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
            client_secret_from_build_setting, read_utf8, tersa_mailbox_macos_connect_begin,
            tersa_mailbox_macos_disconnect_begin, tersa_mailbox_macos_lifecycle_get,
            tersa_mailbox_macos_sync_begin, tersa_mailbox_macos_sync_poll,
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
        fn client_secret_build_setting_is_optional_and_rejects_placeholders() {
            assert!(client_secret_from_build_setting(None).is_none());
            assert!(client_secret_from_build_setting(Some("   ")).is_none());
            assert!(client_secret_from_build_setting(Some("UNCONFIGURED")).is_none());

            let secret = client_secret_from_build_setting(Some("desktop-test-secret")).unwrap();
            assert_eq!(secret, "desktop-test-secret");
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

        #[test]
        fn disconnect_begin_rejects_a_null_output_pointer() {
            let account = b"account-123";
            // SAFETY: the input buffer is valid; the output pointer is null, which
            // the function rejects before any dereference.
            let status = unsafe {
                tersa_mailbox_macos_disconnect_begin(
                    account.as_ptr(),
                    account.len(),
                    ptr::null_mut(),
                )
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
        }

        #[test]
        fn lifecycle_get_rejects_null_outputs_without_opening_storage() {
            let account = b"account";
            // SAFETY: the non-null input points to `account.len()` readable bytes;
            // null outputs are deliberately the invalid-input fixture.
            let status = unsafe {
                tersa_mailbox_macos_lifecycle_get(
                    account.as_ptr(),
                    account.len(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
        }

        #[test]
        fn disconnect_begin_rejects_an_unreadable_account_buffer() {
            let mut session_id = 0_u64;
            // SAFETY: the account pointer is null (rejected before any read); the
            // output pointer is valid.
            let status = unsafe {
                tersa_mailbox_macos_disconnect_begin(ptr::null(), 10, &raw mut session_id)
            };
            assert_eq!(status, STATUS_INVALID_INPUT);
            assert_eq!(
                session_id, 0,
                "a rejected begin must not write a session id"
            );
        }

        #[test]
        fn disconnect_begin_rejects_an_invalid_account_identifier() {
            // An email-shaped account identifier is rejected by `AccountId::new`,
            // before the slot is marked disconnecting or any worker is spawned.
            let account = b"user@example.com";
            let mut session_id = 0_u64;
            // SAFETY: the input buffer and the output pointer are valid.
            let status = unsafe {
                tersa_mailbox_macos_disconnect_begin(
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

        // The STATUS_STARTED and STATUS_SYNC_BUSY begin outcomes — sync, connect,
        // and disconnect alike — are intentionally not exercised here: each
        // requires spawning a real worker, which builds Keychain-backed objects
        // and (on a provisioned host) performs network I/O. The busy mapping is
        // proven deterministically by the worker crate's own
        // `begin_default_account_sync_on_a_busy_slot_is_busy_and_builds_nothing`,
        // the disconnect worker's spawn, blocking gate acquire, and fail-closed
        // flag handling are covered by the worker crate's own tests, and the
        // started/registry/reap round-trip is covered above via fabricated
        // handles; the live path is left to review and integration.
    }
}
