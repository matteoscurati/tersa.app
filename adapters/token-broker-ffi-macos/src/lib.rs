// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Narrow C ABI for the embedded macOS token-broker XPC service (ADR-0024).
//!
//! This crate is the sole Rust static archive linked into `TersaMacTokenBroker`.
//! It composes the portable broker core with the production Google token
//! transport and the broker-only Data Protection Keychain store, and exposes
//! only the five closed protocol operations as redacted integer statuses and
//! bounded success fields. Refresh tokens, PKCE material, authorization codes,
//! arbitrary URLs, provider bodies, and generic Keychain queries never cross
//! this boundary. The main app's mailbox-sync archive is never linked here.

#![deny(unsafe_code)]

// Rust guideline compliant 1.0.

#[cfg(target_os = "macos")]
mod macos {
    use std::slice;
    use std::str;
    use std::sync::mpsc;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use tersa_application::oauth::{MonotonicClock, SystemMonotonicClock, SystemWallClock};
    use tersa_domain::mailbox::AccountId;
    use tersa_gmail_rest_macos::GmailTokenTransport;
    use tersa_keychain_macos::oauth_token::{
        BrokerDataProtectionRefreshTokenStore, RefreshTokenError,
        RefreshTokenStore as KeychainStore,
    };
    use tersa_token_broker_core::{
        BrokerCore, BrokerError, BrokerToken, GetRandomEntropy, PendingAuthorization,
        RefreshTokenStore, RefreshTokenStoreError, ValidatedSubject,
    };
    use zeroize::Zeroizing;

    /// Wire status codes shared with `TersaTokenBrokerStatusV1` (Swift).
    /// Keep integer values stable; never carry strings or open error payloads.
    const STATUS_SUCCESS: i32 = 0;
    /// Reserved skeleton codes (1, 2, 4). Operational paths no longer emit them;
    /// unit tests pin the reviewed raw values against the Swift/XPC inventory.
    #[cfg(test)]
    const STATUS_NOT_IMPLEMENTED: i32 = 1;
    #[cfg(test)]
    const STATUS_NOT_PROVISIONED: i32 = 2;
    const STATUS_INVALID_REQUEST: i32 = 3;
    #[cfg(test)]
    const STATUS_REJECTED_CLIENT: i32 = 4;
    const STATUS_AUTHORIZATION_CODE_REJECTED: i32 = 5;
    const STATUS_PROVIDER_REJECTED: i32 = 6;
    const STATUS_INSUFFICIENT_SCOPE: i32 = 7;
    const STATUS_MISSING_REFRESH_TOKEN: i32 = 8;
    const STATUS_CONSENT_REVOKED: i32 = 9;
    const STATUS_REVOKE_UNCONFIRMED: i32 = 10;
    const STATUS_PERSISTENCE_FAILED: i32 = 11;
    const STATUS_INVALID_CONFIGURATION: i32 = 12;
    const STATUS_UNAVAILABLE: i32 = 13;
    const STATUS_BUSY: i32 = 14;
    const STATUS_SESSION_UNKNOWN: i32 = 15;
    const STATUS_TRANSPORT: i32 = 16;
    const STATUS_MALFORMED_RESPONSE: i32 = 17;
    const STATUS_IDENTITY_UNVERIFIED: i32 = 18;
    const STATUS_IDENTITY_MISMATCH: i32 = 19;

    /// Caps every UTF-8 input buffer accepted at the C ABI.
    const MAX_INPUT_BYTES: usize = 4_096;
    /// Caps a returned authorization URL (Google auth URLs are a few KiB).
    const MAX_AUTHORIZATION_URL_BYTES: usize = 4_096;
    /// Caps a returned session handle (URL-safe base64 of 16 bytes = 22 chars).
    const MAX_SESSION_HANDLE_BYTES: usize = 64;
    /// Caps a returned access token.
    const MAX_ACCESS_TOKEN_BYTES: usize = 4_096;
    /// Caps a returned subject.
    const MAX_SUBJECT_BYTES: usize = 255;
    /// Authorization-session TTL owned by the broker composition (10 minutes).
    const SESSION_TTL: Duration = Duration::from_secs(600);

    type ProductionBroker = BrokerCore<
        GmailTokenTransport,
        SubjectKeychainStore,
        SharedMonotonicClock,
        SystemWallClock,
        GetRandomEntropy,
    >;

    /// Cloneable production monotonic clock for the broker composition.
    ///
    /// [`BrokerCore`] clones the clock into each pending authorization session
    /// so every session measures expiry against the same origin.
    /// [`SystemMonotonicClock`] is not `Clone`; this thin `Arc` wrapper shares
    /// one process-local origin without inventing alternate time semantics.
    #[derive(Clone, Debug)]
    struct SharedMonotonicClock(Arc<SystemMonotonicClock>);

    impl SharedMonotonicClock {
        fn new() -> Self {
            Self(Arc::new(SystemMonotonicClock::new()))
        }
    }

    impl MonotonicClock for SharedMonotonicClock {
        fn now(&self) -> Duration {
            self.0.now()
        }
    }

    /// Adapts the broker-only Keychain store to the core's subject-keyed port.
    ///
    /// The Keychain account attribute is the validated Google subject. The
    /// adapter never accepts an arbitrary group, service, or query.
    #[derive(Debug)]
    struct SubjectKeychainStore {
        inner: BrokerDataProtectionRefreshTokenStore,
    }

    impl SubjectKeychainStore {
        fn new() -> Result<Self, BrokerError> {
            Ok(Self {
                inner: BrokerDataProtectionRefreshTokenStore::new()
                    .map_err(|_error| BrokerError::Unavailable)?,
            })
        }

        fn account(subject: &ValidatedSubject) -> Result<AccountId, RefreshTokenStoreError> {
            // Google subjects are conservative visible ASCII and never email-
            // shaped; AccountId validation is a second closed bound on the
            // Keychain account attribute.
            AccountId::new(subject.as_str()).map_err(|_error| RefreshTokenStoreError::Invalid)
        }
    }

    impl RefreshTokenStore for SubjectKeychainStore {
        fn store(
            &self,
            subject: &ValidatedSubject,
            token: &Zeroizing<String>,
        ) -> Result<(), RefreshTokenStoreError> {
            let account = Self::account(subject)?;
            self.inner
                .store(&account, token)
                .map_err(map_keychain_error)
        }

        fn load(
            &self,
            subject: &ValidatedSubject,
        ) -> Result<Option<Zeroizing<String>>, RefreshTokenStoreError> {
            let account = Self::account(subject)?;
            self.inner.load(&account).map_err(map_keychain_error)
        }

        fn delete(&self, subject: &ValidatedSubject) -> Result<(), RefreshTokenStoreError> {
            let account = Self::account(subject)?;
            self.inner.delete(&account).map_err(map_keychain_error)
        }
    }

    fn map_keychain_error(error: RefreshTokenError) -> RefreshTokenStoreError {
        match error {
            RefreshTokenError::Invalid => RefreshTokenStoreError::Invalid,
            // `OperationFailed` and every future closed variant fail closed as
            // unavailable (non-exhaustive enum; keep recovery distinct).
            _ => RefreshTokenStoreError::Unavailable,
        }
    }

    /// Maps every [`BrokerError`] to a stable wire status. Call-site context
    /// for `PersistenceFailed` is supplied by the operation the client invoked
    /// (see Swift mapping); the vocabulary deliberately does not widen.
    fn map_broker_error(error: BrokerError) -> i32 {
        match error {
            BrokerError::InvalidInput => STATUS_INVALID_REQUEST,
            BrokerError::InvalidConfiguration => STATUS_INVALID_CONFIGURATION,
            BrokerError::Busy => STATUS_BUSY,
            BrokerError::SessionUnknown => STATUS_SESSION_UNKNOWN,
            BrokerError::ProviderRejected => STATUS_PROVIDER_REJECTED,
            BrokerError::AuthorizationCodeRejected => STATUS_AUTHORIZATION_CODE_REJECTED,
            BrokerError::Transport => STATUS_TRANSPORT,
            BrokerError::MalformedResponse => STATUS_MALFORMED_RESPONSE,
            BrokerError::InsufficientScope => STATUS_INSUFFICIENT_SCOPE,
            BrokerError::IdentityUnverified => STATUS_IDENTITY_UNVERIFIED,
            BrokerError::IdentityMismatch => STATUS_IDENTITY_MISMATCH,
            BrokerError::MissingRefreshToken => STATUS_MISSING_REFRESH_TOKEN,
            BrokerError::ConsentRevoked => STATUS_CONSENT_REVOKED,
            BrokerError::PersistenceFailed => STATUS_PERSISTENCE_FAILED,
            BrokerError::RevokeUnconfirmed => STATUS_REVOKE_UNCONFIRMED,
            // `Unavailable` and every future closed variant fail closed rather
            // than invent a payload (non-exhaustive enum).
            _ => STATUS_UNAVAILABLE,
        }
    }

    /// True when a signing-time client-id value is empty/whitespace or still
    /// carries the reviewed `UNCONFIGURED` placeholder (case-insensitive).
    ///
    /// Shared by `configured_client_id` and unit tests so the preflight is not
    /// a tautological local predicate.
    fn is_unconfigured_client_id(raw: &str) -> bool {
        let trimmed = raw.trim();
        trimmed.is_empty() || trimmed.to_ascii_uppercase().contains("UNCONFIGURED")
    }

    /// Reads the public OAuth client id from the signing-time build setting.
    fn configured_client_id() -> Result<String, i32> {
        let raw = option_env!("TERSA_OAUTH_CLIENT_ID").ok_or(STATUS_INVALID_CONFIGURATION)?;
        if is_unconfigured_client_id(raw) {
            return Err(STATUS_INVALID_CONFIGURATION);
        }
        Ok(raw.trim().to_owned())
    }

    /// Reads the optional Desktop-client secret from the signing-time build
    /// setting. Never persisted or logged.
    fn configured_client_secret() -> Option<Zeroizing<String>> {
        option_env!("TERSA_OAUTH_CLIENT_SECRET").and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() || trimmed.to_ascii_uppercase().contains("UNCONFIGURED") {
                None
            } else {
                Some(Zeroizing::new(trimmed.to_owned()))
            }
        })
    }

    fn broker() -> Result<&'static ProductionBroker, i32> {
        static BROKER: OnceLock<Result<ProductionBroker, i32>> = OnceLock::new();
        match BROKER.get_or_init(construct_broker) {
            Ok(broker) => Ok(broker),
            Err(status) => Err(*status),
        }
    }

    fn construct_broker() -> Result<ProductionBroker, i32> {
        let client_id = configured_client_id()?;
        let transport = GmailTokenTransport::new().map_err(|_error| STATUS_UNAVAILABLE)?;
        let store = SubjectKeychainStore::new().map_err(map_broker_error)?;
        let dependencies = (
            transport,
            store,
            SharedMonotonicClock::new(),
            SystemWallClock,
            GetRandomEntropy,
        );
        BrokerCore::new(
            client_id,
            configured_client_secret(),
            SESSION_TTL,
            dependencies,
        )
        .map_err(map_broker_error)
    }

    /// One unit of work for the process-owned broker driver thread.
    ///
    /// The current-thread Tokio runtime must be driven from a single OS thread.
    /// A dedicated driver owns that runtime for the process lifetime so XPC
    /// worker threads never create a runtime per request and never call
    /// `block_on` on a current-thread runtime from arbitrary threads.
    struct DriverJob {
        run: Box<dyn FnOnce(&tokio::runtime::Runtime) + Send>,
    }

    /// Returns the process-owned driver channel, starting the driver thread once.
    fn driver_sender() -> Result<&'static mpsc::Sender<DriverJob>, i32> {
        static SENDER: OnceLock<Result<mpsc::Sender<DriverJob>, i32>> = OnceLock::new();
        match SENDER.get_or_init(|| {
            let (tx, rx) = mpsc::channel::<DriverJob>();
            let spawn = std::thread::Builder::new()
                .name("tersa-token-broker".to_owned())
                .spawn(move || {
                    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    else {
                        // Leave the channel disconnected so callers fail closed
                        // instead of hanging on a missing runtime.
                        return;
                    };
                    while let Ok(job) = rx.recv() {
                        (job.run)(&runtime);
                    }
                });
            match spawn {
                Ok(_join_handle) => Ok(tx),
                Err(_error) => Err(STATUS_UNAVAILABLE),
            }
        }) {
            Ok(sender) => Ok(sender),
            Err(status) => Err(*status),
        }
    }

    /// Runs `future` on the process-owned current-thread runtime.
    fn block_on<T>(future: impl std::future::Future<Output = T> + Send + 'static) -> Result<T, i32>
    where
        T: Send + 'static,
    {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        let sender = driver_sender()?;
        sender
            .send(DriverJob {
                run: Box::new(move |runtime| {
                    let value = runtime.block_on(future);
                    let _ = response_tx.send(value);
                }),
            })
            .map_err(|_error| STATUS_UNAVAILABLE)?;
        response_rx.recv().map_err(|_error| STATUS_UNAVAILABLE)
    }

    /// Copies a caller-owned UTF-8 buffer into an owned `String`.
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
            return Err(STATUS_INVALID_REQUEST);
        }
        // SAFETY: the caller guarantees `length` readable bytes at `pointer`.
        let bytes = unsafe { slice::from_raw_parts(pointer, length) };
        str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_error| STATUS_INVALID_REQUEST)
    }

    /// Writes a bounded UTF-8 string into a caller-owned output buffer.
    ///
    /// # Safety
    ///
    /// `pointer` must be non-null and writable for `capacity` bytes;
    /// `out_len` must be writable for one `usize`.
    #[expect(
        unsafe_code,
        reason = "validated success fields are copied into caller-owned C buffers"
    )]
    unsafe fn write_utf8(
        text: &str,
        pointer: *mut u8,
        capacity: usize,
        out_len: *mut usize,
        max_len: usize,
    ) -> Result<(), i32> {
        if pointer.is_null() || out_len.is_null() {
            return Err(STATUS_INVALID_REQUEST);
        }
        if text.len() > capacity || text.len() > max_len {
            return Err(STATUS_MALFORMED_RESPONSE);
        }
        // SAFETY: the caller guarantees `capacity` writable bytes at `pointer`
        // and a writable `out_len`.
        unsafe {
            pointer.copy_from_nonoverlapping(text.as_ptr(), text.len());
            out_len.write(text.len());
        }
        Ok(())
    }

    /// Safe test surface for [`read_utf8`] buffer-boundary coverage.
    ///
    /// `source == None` exercises the null-pointer rejection path. When
    /// `source` is `Some`, this wrapper enforces that any `length` which
    /// would reach the raw read (`1..=MAX_INPUT_BYTES`) is within the live
    /// slice. Lengths rejected before dereference (`0` is handled by the
    /// helper; `> MAX_INPUT_BYTES` is allowed to exceed the slice so the real
    /// helper rejection path stays covered) never enter the audited read.
    #[cfg(test)]
    fn test_read_utf8(source: Option<&[u8]>, length: usize) -> Result<String, i32> {
        // Soundness: a safe function must not create an out-of-bounds raw read
        // for any safe input. `read_utf8` only dereferences when
        // `1 <= length <= MAX_INPUT_BYTES`; enforce the slice bound for that
        // window. Oversized lengths are rejected by the helper before any read.
        if let Some(bytes) = source
            && length <= MAX_INPUT_BYTES
            && length > bytes.len()
        {
            return Err(STATUS_INVALID_REQUEST);
        }
        // SAFETY: null is rejected before any read. Non-null calls either pass
        // a length the helper rejects before reading (`0` or
        // `> MAX_INPUT_BYTES`) or a length within the live slice (enforced
        // above for the raw-read window).
        #[expect(
            unsafe_code,
            reason = "test-only wrapper keeps buffer-boundary coverage on the real FFI helper"
        )]
        unsafe {
            match source {
                None => read_utf8(std::ptr::null(), length),
                Some(bytes) => read_utf8(bytes.as_ptr(), length),
            }
        }
    }

    /// Safe test surface for [`write_utf8`] buffer-boundary coverage.
    ///
    /// `buffer == None` or `out_len == None` exercises null rejection. When
    /// `buffer` is `Some`, this wrapper enforces `capacity <= buffer.len()`
    /// before any raw write so the helper's writable-capacity contract cannot
    /// be violated by a safe caller.
    #[cfg(test)]
    fn test_write_utf8(
        text: &str,
        buffer: Option<&mut [u8]>,
        capacity: usize,
        out_len: Option<&mut usize>,
        max_len: usize,
    ) -> Result<(), i32> {
        // Soundness: a safe function must not claim more writable bytes than
        // the live slice provides. Enforce the capacity relationship before
        // entering the audited helper.
        if let Some(bytes) = buffer.as_ref()
            && capacity > bytes.len()
        {
            return Err(STATUS_INVALID_REQUEST);
        }
        // SAFETY: null outs are rejected before any write. Non-null buffer
        // paths pass a writable slice whose length is at least `capacity`
        // (enforced above) and a live `out_len` reference when present.
        #[expect(
            unsafe_code,
            reason = "test-only wrapper keeps buffer-boundary coverage on the real FFI helper"
        )]
        unsafe {
            let pointer = match buffer {
                None => std::ptr::null_mut(),
                Some(bytes) => bytes.as_mut_ptr(),
            };
            let out_len_ptr = match out_len {
                None => std::ptr::null_mut(),
                Some(len) => len as *mut usize,
            };
            write_utf8(text, pointer, capacity, out_len_ptr, max_len)
        }
    }

    /// Caller-owned C ABI success buffers for a closed token write.
    ///
    /// Groups the reviewed header's access-token, subject, and expiry outs so
    /// the write helper stays under Clippy's argument limit without widening
    /// the C ABI or copying secrets into non-zeroizing storage.
    struct TokenSuccessOut {
        access_token: *mut u8,
        access_token_capacity: usize,
        access_token_len: *mut usize,
        subject: *mut u8,
        subject_capacity: usize,
        subject_len: *mut usize,
        expires: *mut i64,
    }

    /// Writes the closed success fields of a [`BrokerToken`] into caller-owned
    /// C ABI output buffers.
    ///
    /// # Safety
    ///
    /// Each non-null output pointer in `out` must be writable for the declared
    /// capacity (`access_token` / `subject` byte buffers, their length outs,
    /// and one `i64` at `expires`). Null or undersized buffers are rejected
    /// before any write.
    #[expect(
        unsafe_code,
        reason = "validated success fields are copied into caller-owned C buffers"
    )]
    unsafe fn write_token_success(token: &BrokerToken, out: &TokenSuccessOut) -> Result<(), i32> {
        // Borrow through the Zeroizing wrappers as `&str` only. Never call
        // `to_string` / `to_owned` / `clone` into a plain `String` here: that
        // would mint a non-zeroizing secret copy of the access token.
        let access_token: &str = token.access_token().as_str();
        let subject: &str = token.subject();
        // SAFETY: the function contract requires writable access-token and
        // length-out buffers of the stated capacity; `write_utf8` re-checks
        // null and capacity before any raw write.
        unsafe {
            write_utf8(
                access_token,
                out.access_token,
                out.access_token_capacity,
                out.access_token_len,
                MAX_ACCESS_TOKEN_BYTES,
            )?;
        }
        // SAFETY: same contract as the access-token write for the subject
        // success fields.
        unsafe {
            write_utf8(
                subject,
                out.subject,
                out.subject_capacity,
                out.subject_len,
                MAX_SUBJECT_BYTES,
            )?;
        }
        if out.expires.is_null() {
            return Err(STATUS_INVALID_REQUEST);
        }
        let expires = i64::try_from(token.expires_in_seconds())
            .map_err(|_error| STATUS_MALFORMED_RESPONSE)?;
        // SAFETY: `out.expires` was checked non-null above and the C ABI
        // contract requires one writable `i64`.
        unsafe {
            out.expires.write(expires);
        }
        Ok(())
    }

    /// Begins an authorization session for a strictly validated loopback redirect.
    ///
    /// On success writes the authorization URL and opaque session handle. The
    /// PKCE verifier never leaves the broker composition.
    ///
    /// # Safety
    ///
    /// Input and output pointer contracts match the reviewed C header.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_token_broker_begin_authorization(
        redirect_uri: *const u8,
        redirect_uri_len: usize,
        authorization_url_out: *mut u8,
        authorization_url_capacity: usize,
        authorization_url_len: *mut usize,
        session_handle_out: *mut u8,
        session_handle_capacity: usize,
        session_handle_len: *mut usize,
    ) -> i32 {
        let result = (|| {
            // SAFETY: the function contract requires a readable redirect buffer.
            let redirect = unsafe { read_utf8(redirect_uri, redirect_uri_len) }?;
            let broker = broker()?;
            let pending: PendingAuthorization = broker
                .begin_authorization(&redirect)
                .map_err(map_broker_error)?;
            let url = pending.authorization_url().as_str();
            let handle = pending.session_handle();
            // SAFETY: callers supply writable output buffers of the stated capacity.
            unsafe {
                write_utf8(
                    url,
                    authorization_url_out,
                    authorization_url_capacity,
                    authorization_url_len,
                    MAX_AUTHORIZATION_URL_BYTES,
                )?;
                write_utf8(
                    handle,
                    session_handle_out,
                    session_handle_capacity,
                    session_handle_len,
                    MAX_SESSION_HANDLE_BYTES,
                )?;
            }
            Ok(())
        })();
        result.map_or_else(|status| status, |()| STATUS_SUCCESS)
    }

    /// Completes an authorization session from the main app's forwarded callback.
    ///
    /// # Safety
    ///
    /// Input and output pointer contracts match the reviewed C header.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_token_broker_complete_authorization(
        session_handle: *const u8,
        session_handle_len: usize,
        callback_url: *const u8,
        callback_url_len: usize,
        access_token_out: *mut u8,
        access_token_capacity: usize,
        access_token_len: *mut usize,
        subject_out: *mut u8,
        subject_capacity: usize,
        subject_len: *mut usize,
        expires_out: *mut i64,
    ) -> i32 {
        let result = (|| {
            // SAFETY: the function contract requires a readable session-handle
            // buffer of `session_handle_len` bytes that remain valid for this
            // call; `read_utf8` re-checks null, length, and UTF-8.
            let handle = unsafe { read_utf8(session_handle, session_handle_len) }?;
            // SAFETY: the function contract requires a readable callback-url
            // buffer of `callback_url_len` bytes that remain valid for this
            // call; `read_utf8` re-checks null, length, and UTF-8.
            let callback = unsafe { read_utf8(callback_url, callback_url_len) }?;
            let broker = broker()?;
            let token =
                block_on(async move { broker.complete_authorization(&handle, &callback).await })?
                    .map_err(map_broker_error)?;
            // SAFETY: callers supply the writable success buffers declared by
            // this C ABI entry point; `write_token_success` re-checks null and
            // capacity before any raw write.
            unsafe {
                write_token_success(
                    &token,
                    &TokenSuccessOut {
                        access_token: access_token_out,
                        access_token_capacity,
                        access_token_len,
                        subject: subject_out,
                        subject_capacity,
                        subject_len,
                        expires: expires_out,
                    },
                )?;
            }
            Ok(())
        })();
        result.map_or_else(|status| status, |()| STATUS_SUCCESS)
    }

    /// Refreshes a short-lived access token for a validated account subject.
    ///
    /// # Safety
    ///
    /// Input and output pointer contracts match the reviewed C header.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies caller-owned byte buffers"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_token_broker_refresh_access_token(
        account_subject: *const u8,
        account_subject_len: usize,
        access_token_out: *mut u8,
        access_token_capacity: usize,
        access_token_len: *mut usize,
        subject_out: *mut u8,
        subject_capacity: usize,
        subject_len: *mut usize,
        expires_out: *mut i64,
    ) -> i32 {
        let result = (|| {
            // SAFETY: the function contract requires a readable subject buffer.
            let subject = unsafe { read_utf8(account_subject, account_subject_len) }?;
            let broker = broker()?;
            let token = block_on(async move { broker.refresh_access_token(&subject).await })?
                .map_err(map_broker_error)?;
            // SAFETY: callers supply the writable success buffers declared by
            // this C ABI entry point; `write_token_success` re-checks null and
            // capacity before any raw write.
            unsafe {
                write_token_success(
                    &token,
                    &TokenSuccessOut {
                        access_token: access_token_out,
                        access_token_capacity,
                        access_token_len,
                        subject: subject_out,
                        subject_capacity,
                        subject_len,
                        expires: expires_out,
                    },
                )?;
            }
            Ok(())
        })();
        result.map_or_else(|status| status, |()| STATUS_SUCCESS)
    }

    /// Revokes the provider grant for a validated account subject.
    ///
    /// # Safety
    ///
    /// The subject pointer contract matches the reviewed C header.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies a caller-owned subject buffer"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_token_broker_revoke_provider_grant(
        account_subject: *const u8,
        account_subject_len: usize,
    ) -> i32 {
        let result = (|| {
            // SAFETY: the function contract requires a readable subject buffer.
            let subject = unsafe { read_utf8(account_subject, account_subject_len) }?;
            let broker = broker()?;
            block_on(async move { broker.revoke_provider_grant(&subject).await })?
                .map_err(map_broker_error)?;
            Ok(())
        })();
        result.map_or_else(|status| status, |()| STATUS_SUCCESS)
    }

    /// Deletes locally stored refresh-token material for a validated subject.
    ///
    /// # Safety
    ///
    /// The subject pointer contract matches the reviewed C header.
    #[expect(
        unsafe_code,
        reason = "the C ABI validates and copies a caller-owned subject buffer"
    )]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tersa_token_broker_delete_stored_tokens(
        account_subject: *const u8,
        account_subject_len: usize,
    ) -> i32 {
        let result = (|| {
            // SAFETY: the function contract requires a readable subject buffer.
            let subject = unsafe { read_utf8(account_subject, account_subject_len) }?;
            let broker = broker()?;
            broker
                .delete_stored_tokens(&subject)
                .map_err(map_broker_error)?;
            Ok(())
        })();
        result.map_or_else(|status| status, |()| STATUS_SUCCESS)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn maps_every_broker_error_to_a_distinct_stable_status() {
            let cases = [
                (BrokerError::InvalidInput, STATUS_INVALID_REQUEST),
                (
                    BrokerError::InvalidConfiguration,
                    STATUS_INVALID_CONFIGURATION,
                ),
                (BrokerError::Unavailable, STATUS_UNAVAILABLE),
                (BrokerError::Busy, STATUS_BUSY),
                (BrokerError::SessionUnknown, STATUS_SESSION_UNKNOWN),
                (BrokerError::ProviderRejected, STATUS_PROVIDER_REJECTED),
                (
                    BrokerError::AuthorizationCodeRejected,
                    STATUS_AUTHORIZATION_CODE_REJECTED,
                ),
                (BrokerError::Transport, STATUS_TRANSPORT),
                (BrokerError::MalformedResponse, STATUS_MALFORMED_RESPONSE),
                (BrokerError::InsufficientScope, STATUS_INSUFFICIENT_SCOPE),
                (BrokerError::IdentityUnverified, STATUS_IDENTITY_UNVERIFIED),
                (BrokerError::IdentityMismatch, STATUS_IDENTITY_MISMATCH),
                (
                    BrokerError::MissingRefreshToken,
                    STATUS_MISSING_REFRESH_TOKEN,
                ),
                (BrokerError::ConsentRevoked, STATUS_CONSENT_REVOKED),
                (BrokerError::PersistenceFailed, STATUS_PERSISTENCE_FAILED),
                (BrokerError::RevokeUnconfirmed, STATUS_REVOKE_UNCONFIRMED),
            ];
            let mut seen = std::collections::BTreeSet::new();
            for (error, status) in cases {
                assert_eq!(map_broker_error(error), status, "{error:?}");
                assert!(
                    seen.insert(status),
                    "status {status} must be unique across the closed set"
                );
            }
            // Authorization-code rejection must never collapse into ordinary
            // provider rejection or consent revoked.
            assert_ne!(STATUS_AUTHORIZATION_CODE_REJECTED, STATUS_PROVIDER_REJECTED);
            assert_ne!(STATUS_AUTHORIZATION_CODE_REJECTED, STATUS_CONSENT_REVOKED);
            // Skeleton codes remain reserved and distinct.
            assert_eq!(STATUS_NOT_IMPLEMENTED, 1);
            assert_eq!(STATUS_NOT_PROVISIONED, 2);
            assert_eq!(STATUS_REJECTED_CLIENT, 4);
            assert_eq!(STATUS_SUCCESS, 0);
        }

        #[test]
        fn authorization_code_rejected_is_not_provider_or_consent() {
            assert_eq!(
                map_broker_error(BrokerError::AuthorizationCodeRejected),
                STATUS_AUTHORIZATION_CODE_REJECTED
            );
            assert_ne!(
                map_broker_error(BrokerError::AuthorizationCodeRejected),
                map_broker_error(BrokerError::ProviderRejected)
            );
            assert_ne!(
                map_broker_error(BrokerError::AuthorizationCodeRejected),
                map_broker_error(BrokerError::ConsentRevoked)
            );
        }

        #[test]
        fn maps_keychain_errors_without_payloads() {
            assert_eq!(
                map_keychain_error(RefreshTokenError::OperationFailed),
                RefreshTokenStoreError::Unavailable
            );
            assert_eq!(
                map_keychain_error(RefreshTokenError::Invalid),
                RefreshTokenStoreError::Invalid
            );
            let rendered = format!(
                "{:?} {:?}",
                RefreshTokenError::OperationFailed,
                RefreshTokenStoreError::Unavailable
            );
            for sentinel in [
                "ya29.sentinel-access-token",
                "1//sentinel-refresh-token",
                "GOCSPX-sentinel-client-secret",
            ] {
                assert!(!rendered.contains(sentinel));
            }
        }

        #[test]
        fn subject_account_conversion_accepts_conservative_google_subjects() {
            let subject = ValidatedSubject::new("110169484474386276334").expect("fixture");
            let account = SubjectKeychainStore::account(&subject).expect("account");
            assert_eq!(account.as_str(), subject.as_str());
        }

        #[test]
        fn client_id_preflight_rejects_unconfigured_shapes() {
            // Exercises the real helper used by `configured_client_id`.
            for bad in [
                "",
                "   ",
                "UNCONFIGURED",
                "app.UNCONFIGURED.client",
                "unconfigured",
            ] {
                assert!(
                    is_unconfigured_client_id(bad),
                    "expected unconfigured rejection for {bad:?}"
                );
            }
            assert!(!is_unconfigured_client_id(
                "1234567890-abc.apps.googleusercontent.com"
            ));
        }

        #[test]
        fn read_utf8_rejects_null_empty_oversized_and_invalid_bytes() {
            let bytes = b"abc";
            assert_eq!(test_read_utf8(None, 3), Err(STATUS_INVALID_REQUEST));
            assert_eq!(test_read_utf8(Some(bytes), 0), Err(STATUS_INVALID_REQUEST));
            assert_eq!(
                test_read_utf8(Some(bytes), MAX_INPUT_BYTES + 1),
                Err(STATUS_INVALID_REQUEST)
            );
            let invalid = [0xff_u8, 0xfe_u8];
            assert_eq!(
                test_read_utf8(Some(&invalid), invalid.len()),
                Err(STATUS_INVALID_REQUEST)
            );
            assert_eq!(
                test_read_utf8(Some(bytes), bytes.len())
                    .expect("valid UTF-8 within declared length must succeed"),
                "abc"
            );
            // Hostile: declared length in the raw-read window exceeds the live
            // slice. Must be rejected by the safe wrapper without UB.
            assert_eq!(
                test_read_utf8(Some(bytes), bytes.len() + 1),
                Err(STATUS_INVALID_REQUEST)
            );
            assert_eq!(test_read_utf8(Some(&[]), 1), Err(STATUS_INVALID_REQUEST));
        }

        #[test]
        fn write_utf8_rejects_null_oversize_and_capacity_bounds() {
            let text = "ok";
            let mut out = [0_u8; 8];
            let mut len = 0_usize;
            assert_eq!(
                test_write_utf8(text, None, 8, Some(&mut len), 8),
                Err(STATUS_INVALID_REQUEST)
            );
            assert_eq!(
                test_write_utf8(text, Some(&mut out), 8, None, 8),
                Err(STATUS_INVALID_REQUEST)
            );
            assert_eq!(
                test_write_utf8(text, Some(&mut out), 1, Some(&mut len), 8),
                Err(STATUS_MALFORMED_RESPONSE)
            );
            assert_eq!(
                test_write_utf8(text, Some(&mut out), 8, Some(&mut len), 1),
                Err(STATUS_MALFORMED_RESPONSE)
            );
            assert!(test_write_utf8(text, Some(&mut out), 8, Some(&mut len), 8).is_ok());
            assert_eq!(len, 2);
            assert_eq!(&out[..2], b"ok");
            // Hostile: declared capacity exceeds the live slice. Must be
            // rejected by the safe wrapper without UB, even when the text
            // would otherwise fit a successful write.
            let mut short = [0_u8; 2];
            let mut short_len = 0_usize;
            assert_eq!(
                test_write_utf8(text, Some(&mut short), 8, Some(&mut short_len), 8),
                Err(STATUS_INVALID_REQUEST)
            );
            assert_eq!(short_len, 0);
            assert_eq!(short, [0_u8; 2]);
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::{
    tersa_token_broker_begin_authorization, tersa_token_broker_complete_authorization,
    tersa_token_broker_delete_stored_tokens, tersa_token_broker_refresh_access_token,
    tersa_token_broker_revoke_provider_grant,
};
