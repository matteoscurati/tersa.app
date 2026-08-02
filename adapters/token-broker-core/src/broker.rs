// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The production token-broker composition (ADR-0024).
//!
//! [`BrokerCore`] wires the portable OAuth and token state machines to the
//! injected transport, refresh-token store, clocks, and entropy ports. It owns
//! the full lifecycle — begin/complete authorization, refresh, provider
//! revoke, and local delete — under the crate's security invariants: strict
//! literal-IPv4 loopback redirects with an explicit ephemeral port, an
//! atomically claimed bounded session registry, per-subject single-flight
//! permits released by RAII, persistence of any refresh credential BEFORE a
//! success is reported, and public values that carry no refresh token, PKCE
//! verifier, state, or authorization code. No mutex guard is held across an
//! `.await`, and no access token is ever cached: every success value is
//! minted fresh from a provider round trip.

use std::fmt;
use std::time::Duration;

use tersa_application::oauth::{
    AuthorizationConfig, MonotonicClock, OAuthError, WallClock, prepare_authorization,
};
use tersa_application::token::{
    TokenClientConfig, TokenError, TokenScopeOutcome, TokenSuccess, TokenTransport,
    exchange_grant_with_scope_outcome, refresh_access_token_with_scope_outcome,
};
use url::Url;
use zeroize::Zeroizing;

use crate::error::BrokerError;
use crate::handle::SessionHandle;
use crate::permits::SubjectPermits;
use crate::ports::{RefreshTokenStore, SessionHandleEntropy};
use crate::registry::SessionRegistry;
use crate::subject::ValidatedSubject;

// Rust guideline compliant 1.0.

/// The only accepted redirect prefix: plain HTTP on the literal dotted-quad
/// IPv4 loopback with an explicit port. Requiring this exact prefix up front
/// rejects the non-canonical IPv4 encodings (`127.1`, integer or octal forms)
/// the URL parser would otherwise normalize to the same address.
const LOOPBACK_REDIRECT_PREFIX: &str = "http://127.0.0.1:";

/// The inclusive ephemeral port range accepted for the loopback redirect.
const MIN_LOOPBACK_PORT: u16 = 1024;
const MAX_LOOPBACK_PORT: u16 = 65535;

/// Caps the redirect text accepted by `begin_authorization`. The accepted
/// shape is a few dozen bytes; anything larger is adversarial.
const MAX_REDIRECT_LEN: usize = 256;

/// Caps the callback text accepted by `complete_authorization`. A Google
/// loopback callback is a few hundred bytes.
const MAX_CALLBACK_LEN: usize = 4_096;

/// Caps a provider-minted access token. Real tokens are well under 2 KiB.
const MAX_ACCESS_TOKEN_LEN: usize = 4_096;

/// Caps a provider-minted or stored refresh token. Real tokens are ~512 bytes.
const MAX_REFRESH_TOKEN_LEN: usize = 1_024;

/// Caps the access-token lifetime the broker reports, in seconds (24 hours).
const MAX_EXPIRES_IN_SECS: u64 = 86_400;

/// The largest authorization-session TTL accepted at construction (one hour).
const MAX_SESSION_TTL: Duration = Duration::from_secs(3_600);

/// The conservative wall-clock skew tolerated when validating `id_token`
/// freshness, in seconds.
const IDENTITY_FRESHNESS_SKEW_SECS: u64 = 60;

/// The public half of a pending authorization: the browser URL and the opaque
/// session handle needed to complete it exactly once.
///
/// `Debug` redacts both values: the URL carries the PKCE challenge and state.
pub struct PendingAuthorization {
    authorization_url: Url,
    session_handle: SessionHandle,
}

impl PendingAuthorization {
    /// Returns the authorization URL intended for the system browser.
    #[must_use]
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// Returns the opaque session handle text the caller presents to
    /// [`BrokerCore::complete_authorization`] exactly once.
    #[must_use]
    pub fn session_handle(&self) -> &str {
        self.session_handle.as_str()
    }
}

impl fmt::Debug for PendingAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAuthorization")
            .field("authorization_url", &"[REDACTED]")
            .field("session_handle", &self.session_handle)
            .finish()
    }
}

/// The only success value the broker exposes: a zeroizing access token, the
/// validated account subject, and a bounded positive lifetime in seconds.
///
/// No refresh token, PKCE verifier, state, or authorization code is ever part
/// of a broker success value, and `Debug` redacts the token and subject.
pub struct BrokerToken {
    access_token: Zeroizing<String>,
    subject: Zeroizing<String>,
    expires_in_seconds: u64,
}

impl BrokerToken {
    /// Returns the access token without transferring ownership.
    ///
    /// Returns the `Zeroizing` wrapper so callers clone without minting a
    /// non-zeroizing plaintext copy of this hot secret.
    #[must_use]
    pub fn access_token(&self) -> &Zeroizing<String> {
        &self.access_token
    }

    /// Returns the validated account subject without transferring ownership.
    ///
    /// The subject is account-identifying, not a secret: it is the storage key
    /// under which the refresh credential was persisted.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the access token's remaining lifetime in seconds, measured
    /// against the broker's monotonic clock when the token was minted. Always
    /// positive and bounded by `MAX_EXPIRES_IN_SECS`.
    #[must_use]
    pub fn expires_in_seconds(&self) -> u64 {
        self.expires_in_seconds
    }
}

impl fmt::Debug for BrokerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerToken")
            .field("access_token", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("expires_in_seconds", &self.expires_in_seconds)
            .finish()
    }
}

/// The production token-broker lifecycle composition.
///
/// Generic over the token `T`ransport, the refresh-token `S`tore, the
/// cloneable monotonic `C`lock, the `W`all clock, and the session-handle
/// `E`ntropy source. Dependencies are stored by value and only ever borrowed
/// by the methods. The broker owns no async runtime: its async methods are
/// driven by the composition-owned runtime of the hosting process.
pub struct BrokerCore<T, S, C, W, E> {
    client_id: String,
    client_secret: Option<Zeroizing<String>>,
    session_ttl: Duration,
    transport: T,
    store: S,
    clock: C,
    wall_clock: W,
    entropy: E,
    registry: SessionRegistry<C>,
    permits: SubjectPermits,
}

impl<T, S, C, W, E> BrokerCore<T, S, C, W, E>
where
    T: TokenTransport,
    S: RefreshTokenStore,
    C: MonotonicClock + Clone,
    W: WallClock,
    E: SessionHandleEntropy,
{
    /// Creates a broker, validating the reusable client configuration.
    ///
    /// `dependencies` bundles the five ports in field order: `(transport,
    /// store, monotonic_clock, wall_clock, entropy)`. No redirect is accepted
    /// here: the redirect is supplied and strictly validated per authorization
    /// attempt in [`Self::begin_authorization`].
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidConfiguration`] when the client
    /// identifier is blank, a present client secret is blank, or the session
    /// TTL is zero or exceeds one hour.
    pub fn new(
        client_id: String,
        client_secret: Option<Zeroizing<String>>,
        session_ttl: Duration,
        dependencies: (T, S, C, W, E),
    ) -> Result<Self, BrokerError> {
        let (transport, store, clock, wall_clock, entropy) = dependencies;
        let blank_secret = client_secret
            .as_ref()
            .is_some_and(|secret| secret.trim().is_empty());
        if client_id.trim().is_empty()
            || session_ttl.is_zero()
            || session_ttl > MAX_SESSION_TTL
            || blank_secret
        {
            return Err(BrokerError::InvalidConfiguration);
        }
        Ok(Self {
            client_id,
            client_secret,
            session_ttl,
            transport,
            store,
            clock,
            wall_clock,
            entropy,
            registry: SessionRegistry::new(),
            permits: SubjectPermits::new(),
        })
    }

    /// Begins an authorization attempt for a strictly validated redirect.
    ///
    /// Accepts only `http://127.0.0.1:PORT/` with an explicit port in
    /// `1024..=65535`, the exact root path, and no credentials, query, or
    /// fragment. The same client identifier feeds the authorization and token
    /// client configurations, so they match by construction; the token
    /// configuration is validated now (failing before the browser round trip)
    /// and rebuilt from the claimed session at completion.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] when the redirect is not the
    /// exact loopback root form, [`BrokerError::InvalidConfiguration`] when
    /// the reusable client configuration is unusable,
    /// [`BrokerError::Unavailable`] when entropy fails, and
    /// [`BrokerError::Busy`] when the bounded pending-session registry is at
    /// capacity (retry after pending sessions expire).
    pub fn begin_authorization(
        &self,
        redirect_uri: &str,
    ) -> Result<PendingAuthorization, BrokerError> {
        let redirect = parse_loopback_redirect(redirect_uri)?;
        let authorization_config =
            AuthorizationConfig::new(self.client_id.clone(), redirect.clone(), self.session_ttl)
                .map_err(|_error| BrokerError::InvalidConfiguration)?;
        let _validated_token_config = self.token_client_config(&redirect)?;
        let prepared = prepare_authorization(authorization_config, self.clock.clone())
            .map_err(map_oauth_error)?;
        let (authorization_url, session) = prepared.into_parts();
        let session_handle = self.registry.insert(session, &self.entropy)?;
        Ok(PendingAuthorization {
            authorization_url,
            session_handle,
        })
    }

    /// Completes an authorization attempt from its loopback callback.
    ///
    /// The session is claimed atomically BEFORE the callback is parsed or
    /// validated, so every callback attempt — valid, malformed, or replayed —
    /// is terminal. On success the returned refresh token is required and
    /// persisted BEFORE the [`BrokerToken`] is returned. When the grant is
    /// under-scoped or carries no refresh token, the minted access token is
    /// revoked best-effort and nothing is persisted.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] for a malformed handle, an
    /// oversized or unparseable callback, or a callback that does not match
    /// the pending session; [`BrokerError::SessionUnknown`] when the handle
    /// names no live session (unknown, expired, or consumed);
    /// [`BrokerError::InsufficientScope`] when the grant omitted Gmail read
    /// access; [`BrokerError::MissingRefreshToken`] when the exchange granted
    /// no refresh token; [`BrokerError::IdentityUnverified`] when identity
    /// validation or freshness fails; [`BrokerError::PersistenceFailed`] when
    /// the refresh credential could not be stored; and the mapped transport,
    /// provider, or malformed-response terminal otherwise.
    pub async fn complete_authorization(
        &self,
        session_handle: &str,
        callback_url: &str,
    ) -> Result<BrokerToken, BrokerError> {
        let handle = SessionHandle::parse(session_handle)?;
        // The claim IS the consumption: the session leaves the registry before
        // any callback validation runs, so a replay can only ever meet
        // `SessionUnknown`.
        let mut session = self.registry.claim(&handle)?;
        let token_config = self.token_client_config(session.redirect_uri())?;
        if callback_url.len() > MAX_CALLBACK_LEN {
            return Err(BrokerError::InvalidInput);
        }
        let callback = Url::parse(callback_url).map_err(|_error| BrokerError::InvalidInput)?;
        let grant = session.finish(&callback).map_err(map_oauth_error)?;
        let outcome =
            exchange_grant_with_scope_outcome(&grant, &token_config, &self.transport, &self.clock)
                .await
                .map_err(map_token_error)?;
        match outcome {
            TokenScopeOutcome::Granted(success) => {
                success
                    .identity_expiry()
                    .validate_fresh(self.wall_clock.unix_time(), IDENTITY_FRESHNESS_SKEW_SECS)
                    .map_err(|_error| BrokerError::IdentityUnverified)?;
                let token = self.broker_token(&success)?;
                let Some(refresh_token) = success.rotated_refresh_token() else {
                    self.revoke_best_effort(success.access_token().secret())
                        .await;
                    return Err(BrokerError::MissingRefreshToken);
                };
                if refresh_token.is_empty() || refresh_token.len() > MAX_REFRESH_TOKEN_LEN {
                    self.revoke_best_effort(success.access_token().secret())
                        .await;
                    return Err(BrokerError::MalformedResponse);
                }
                let subject = ValidatedSubject::new(success.subject().as_str())
                    .map_err(|_error| BrokerError::IdentityUnverified)?;
                // Persist BEFORE success: a reported success must survive a
                // restart, and a persistence failure must fail closed.
                self.store
                    .store(&subject, refresh_token)
                    .map_err(|_error| BrokerError::PersistenceFailed)?;
                Ok(token)
            }
            TokenScopeOutcome::InsufficientScope { access_token, .. } => {
                // The under-scoped grant must not strand a live credential at
                // the provider; nothing is ever persisted for it.
                self.revoke_best_effort(&access_token).await;
                Err(BrokerError::InsufficientScope)
            }
        }
    }

    /// Refreshes the stored credential for a validated subject.
    ///
    /// Serialized per subject through a single-flight permit. A
    /// `invalid_grant` answer deletes the stored token (consent is gone);
    /// transport, provider, malformed-response, and identity failures retain
    /// it for a retry. A successful refresh re-validates the exact subject
    /// and the `id_token` freshness, and persists any rotated refresh token
    /// BEFORE the [`BrokerToken`] is returned. An explicitly under-scoped
    /// refresh persists a rotation first, then reports the scope failure.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] for invalid subject text,
    /// [`BrokerError::Busy`] when the subject already has a mutation in
    /// flight, [`BrokerError::MissingRefreshToken`] when nothing is stored,
    /// [`BrokerError::ConsentRevoked`] after deleting the stored token,
    /// [`BrokerError::IdentityMismatch`] when the refresh re-validated to a
    /// different account, [`BrokerError::InsufficientScope`] after persisting
    /// any rotation, and the mapped persistence, transport, provider,
    /// malformed-response, or identity terminal otherwise.
    pub async fn refresh_access_token(
        &self,
        account_subject: &str,
    ) -> Result<BrokerToken, BrokerError> {
        let subject = ValidatedSubject::new(account_subject)?;
        let _permit = self.permits.claim(subject.as_str())?;
        let stored = self
            .store
            .load(&subject)
            .map_err(|_error| BrokerError::PersistenceFailed)?
            .ok_or(BrokerError::MissingRefreshToken)?;
        if stored.is_empty() || stored.len() > MAX_REFRESH_TOKEN_LEN {
            // A well-behaved store reports a malformed item as `Invalid`; a
            // slipped-through value is a store-integrity failure.
            return Err(BrokerError::PersistenceFailed);
        }
        let token_config = self.refresh_client_config()?;
        let outcome = match refresh_access_token_with_scope_outcome(
            &stored,
            &token_config,
            &self.transport,
            &self.clock,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(TokenError::ConsentRevoked) => {
                // Consent is gone: the stored credential is dead weight and a
                // re-connect signal must not be masked by a delete failure.
                self.store
                    .delete(&subject)
                    .map_err(|_error| BrokerError::PersistenceFailed)?;
                return Err(BrokerError::ConsentRevoked);
            }
            Err(error) => return Err(map_token_error(error)),
        };
        match outcome {
            TokenScopeOutcome::Granted(success) => {
                if success.subject().as_str() != subject.as_str() {
                    // The credential no longer belongs to the requested
                    // account. Retain the stored token and drop the minted
                    // access token without exposing it.
                    return Err(BrokerError::IdentityMismatch);
                }
                success
                    .identity_expiry()
                    .validate_fresh(self.wall_clock.unix_time(), IDENTITY_FRESHNESS_SKEW_SECS)
                    .map_err(|_error| BrokerError::IdentityUnverified)?;
                let token = self.broker_token(&success)?;
                if let Some(rotated) = success.rotated_refresh_token() {
                    if rotated.is_empty() || rotated.len() > MAX_REFRESH_TOKEN_LEN {
                        return Err(BrokerError::MalformedResponse);
                    }
                    // Rotation is persisted BEFORE success so a reported
                    // success never strands the new credential.
                    self.store
                        .store(&subject, rotated)
                        .map_err(|_error| BrokerError::PersistenceFailed)?;
                }
                Ok(token)
            }
            TokenScopeOutcome::InsufficientScope {
                rotated_refresh_token,
                ..
            } => {
                // Retain any rotated credential before surfacing the
                // permission error, so the grant keeps a local revocation
                // handle.
                if let Some(rotated) = rotated_refresh_token {
                    if rotated.is_empty() || rotated.len() > MAX_REFRESH_TOKEN_LEN {
                        return Err(BrokerError::MalformedResponse);
                    }
                    self.store
                        .store(&subject, &rotated)
                        .map_err(|_error| BrokerError::PersistenceFailed)?;
                }
                Err(BrokerError::InsufficientScope)
            }
        }
    }

    /// Revokes the subject's grant at the provider, keeping the local copy.
    ///
    /// Serialized per subject. A missing stored token succeeds: the desired
    /// end state (no usable grant known locally) already holds. A failed
    /// provider revocation maps to [`BrokerError::RevokeUnconfirmed`] and the
    /// stored token is NEVER deleted here — ADR-0024's disconnect ordering
    /// runs broker revoke and broker token delete as separate steps, and an
    /// unconfirmed revoke must stay visible.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] for invalid subject text,
    /// [`BrokerError::Busy`] when the subject already has a mutation in
    /// flight, [`BrokerError::PersistenceFailed`] when the store rejects the
    /// read or the stored item is unusable, and
    /// [`BrokerError::RevokeUnconfirmed`] when the provider did not confirm
    /// the revocation.
    pub async fn revoke_provider_grant(&self, account_subject: &str) -> Result<(), BrokerError> {
        let subject = ValidatedSubject::new(account_subject)?;
        let _permit = self.permits.claim(subject.as_str())?;
        let stored = self
            .store
            .load(&subject)
            .map_err(|_error| BrokerError::PersistenceFailed)?;
        let Some(token) = stored else {
            return Ok(());
        };
        if token.is_empty() || token.len() > MAX_REFRESH_TOKEN_LEN {
            return Err(BrokerError::PersistenceFailed);
        }
        self.transport
            .revoke(&token)
            .await
            .map_err(|_error| BrokerError::RevokeUnconfirmed)
    }

    /// Deletes the subject's stored refresh token. Idempotent by store
    /// contract: deleting an absent subject succeeds.
    ///
    /// Serialized per subject through the same single-flight permit as the
    /// other mutations, so a delete never overlaps a refresh or revoke.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] for invalid subject text,
    /// [`BrokerError::Busy`] when the subject already has a mutation in
    /// flight, and [`BrokerError::PersistenceFailed`] when the store rejects
    /// the delete.
    pub fn delete_stored_tokens(&self, account_subject: &str) -> Result<(), BrokerError> {
        let subject = ValidatedSubject::new(account_subject)?;
        let _permit = self.permits.claim(subject.as_str())?;
        self.store
            .delete(&subject)
            .map_err(|_error| BrokerError::PersistenceFailed)
    }

    /// Builds the validated token client configuration for `redirect`.
    ///
    /// The client identifier and secret come from the broker's own validated
    /// configuration, so the token configuration always matches the
    /// authorization configuration by construction.
    fn token_client_config(&self, redirect: &Url) -> Result<TokenClientConfig, BrokerError> {
        TokenClientConfig::new(
            self.client_id.clone(),
            redirect.clone(),
            self.client_secret.clone(),
        )
        .map_err(|_error| BrokerError::InvalidConfiguration)
    }

    /// Builds the token client configuration for a refresh grant.
    ///
    /// A refresh request never transmits `redirect_uri` (its parameters are
    /// the grant type, refresh token, client identifier, and optional
    /// secret), so an inert literal loopback URL satisfies the
    /// validated-config invariant without persisting a redirect per account.
    fn refresh_client_config(&self) -> Result<TokenClientConfig, BrokerError> {
        let redirect =
            Url::parse("http://127.0.0.1/").map_err(|_error| BrokerError::InvalidConfiguration)?;
        self.token_client_config(&redirect)
    }

    /// Mints the public success value from a validated token success.
    ///
    /// Bounds the access token and computes the remaining lifetime from the
    /// same monotonic clock that minted the deadline, saturating rather than
    /// panicking or overflowing; a zero or out-of-bound lifetime is a
    /// malformed response.
    fn broker_token(&self, success: &TokenSuccess) -> Result<BrokerToken, BrokerError> {
        let access_token = success.access_token().secret().clone();
        if access_token.len() > MAX_ACCESS_TOKEN_LEN {
            return Err(BrokerError::MalformedResponse);
        }
        let remaining = success
            .access_token()
            .expires_at()
            .saturating_sub(self.clock.now());
        let expires_in_seconds = remaining.as_secs();
        if expires_in_seconds == 0 || expires_in_seconds > MAX_EXPIRES_IN_SECS {
            return Err(BrokerError::MalformedResponse);
        }
        Ok(BrokerToken {
            access_token,
            subject: Zeroizing::new(success.subject().as_str().to_owned()),
            expires_in_seconds,
        })
    }

    /// Revokes a minted token at the provider, ignoring the outcome.
    ///
    /// Used only on paths that persist nothing: a permanently failed revoke
    /// there leaves a live token at the provider, but the caller has no local
    /// handle and no better remedy, and the failure must never mask the real
    /// terminal being reported.
    async fn revoke_best_effort(&self, token: &Zeroizing<String>) {
        let _outcome = self.transport.revoke(token).await;
    }
}

impl<T, S, C, W, E> fmt::Debug for BrokerCore<T, S, C, W, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerCore")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_secret| "[REDACTED]"),
            )
            .field("session_ttl", &self.session_ttl)
            .field("registry", &self.registry)
            .field("permits", &self.permits)
            // The transport, store, clocks, and entropy ports have no
            // safe-to-print state; mark them omitted rather than expose them.
            .finish_non_exhaustive()
    }
}

/// Parses a redirect, accepting only the exact root-form literal IPv4
/// loopback with an explicit ephemeral port: `http://127.0.0.1:PORT/` with
/// `PORT` in `1024..=65535` and no credentials, query, or fragment.
fn parse_loopback_redirect(text: &str) -> Result<Url, BrokerError> {
    if text.len() > MAX_REDIRECT_LEN || !text.starts_with(LOOPBACK_REDIRECT_PREFIX) {
        return Err(BrokerError::InvalidInput);
    }
    let url = Url::parse(text).map_err(|_error| BrokerError::InvalidInput)?;
    let ephemeral_port = url
        .port()
        .is_some_and(|port| (MIN_LOOPBACK_PORT..=MAX_LOOPBACK_PORT).contains(&port));
    let exact_root_loopback = url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && ephemeral_port
        && url.path() == "/"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    if exact_root_loopback {
        Ok(url)
    } else {
        Err(BrokerError::InvalidInput)
    }
}

/// Maps the OAuth state-machine failures into the closed broker vocabulary.
///
/// Callback-shape failures (missing, duplicate, or conflicting parameters,
/// redirect and state mismatches) are caller-input failures. An expired or
/// already consumed session answers [`BrokerError::SessionUnknown`]: the
/// handle no longer names a live session, and that is all a caller may learn.
fn map_oauth_error(error: OAuthError) -> BrokerError {
    match error {
        OAuthError::InvalidConfiguration => BrokerError::InvalidConfiguration,
        OAuthError::ProviderRejected => BrokerError::ProviderRejected,
        OAuthError::InsufficientScope => BrokerError::InsufficientScope,
        OAuthError::Expired | OAuthError::AlreadyConsumed => BrokerError::SessionUnknown,
        OAuthError::MissingParameter(_)
        | OAuthError::DuplicateParameter
        | OAuthError::ConflictingCallback
        | OAuthError::RedirectMismatch
        | OAuthError::StateMismatch => BrokerError::InvalidInput,
        // `EntropyUnavailable`, `NotExpired` (which never escapes `finish`),
        // and any future variant fail closed as an internal failure.
        _ => BrokerError::Unavailable,
    }
}

/// Maps the token state-machine failures into the closed broker vocabulary.
fn map_token_error(error: TokenError) -> BrokerError {
    match error {
        TokenError::InvalidConfiguration => BrokerError::InvalidConfiguration,
        TokenError::Transport => BrokerError::Transport,
        TokenError::ProviderRejected => BrokerError::ProviderRejected,
        TokenError::MalformedResponse => BrokerError::MalformedResponse,
        TokenError::InsufficientScope => BrokerError::InsufficientScope,
        TokenError::ConsentRevoked => BrokerError::ConsentRevoked,
        TokenError::IdentityUnverified => BrokerError::IdentityUnverified,
        // Any future variant fails closed as an internal failure.
        _ => BrokerError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures use static URLs and assert setup success before behavior"
    )]

    use std::collections::HashMap;
    use std::fmt;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use tersa_application::mailbox::BoxFuture;
    use tersa_application::oauth::{MonotonicClock, WallClock};
    use tersa_application::token::{
        ExchangeRequest, IdTokenClaims, RefreshRequest, TokenResponse, TokenTransport,
        TokenTransportError,
    };
    use url::Url;
    use zeroize::Zeroizing;

    use super::{
        BrokerCore, BrokerToken, MAX_ACCESS_TOKEN_LEN, MAX_CALLBACK_LEN, MAX_EXPIRES_IN_SECS,
        MAX_REDIRECT_LEN, MAX_REFRESH_TOKEN_LEN, MAX_SESSION_TTL, PendingAuthorization,
    };
    use crate::error::BrokerError;
    use crate::handle::SESSION_HANDLE_BYTES;
    use crate::ports::{RefreshTokenStore, RefreshTokenStoreError, SessionHandleEntropy};
    use crate::subject::ValidatedSubject;

    const CLIENT_ID: &str = "broker-test-client";
    const REDIRECT: &str = "http://127.0.0.1:8080/";
    const SUBJECT: &str = "110169484474386276334";
    const OTHER_SUBJECT: &str = "210169484474386276335";
    const NOW: u64 = 1_700_000_000;

    // Sentinel VALUES shaped like real provider secrets (see the error-vocabulary
    // tests): any occurrence of one in a rendered `Debug` proves a live leak.
    // They are held in `Zeroizing<String>` whenever they flow through the
    // broker, transport, or store surfaces.
    const ACCESS_TOKEN: &str = "ya29.sentinel-access-token";
    const REFRESH_TOKEN: &str = "1//sentinel-refresh-token";
    const ROTATED_REFRESH_TOKEN: &str = "1//sentinel-rotated-refresh-token";
    const AUTH_CODE: &str = "4/0AfJM-sentinel-authorization-code";
    const CLIENT_SECRET: &str = "GOCSPX-sentinel-client-secret";

    type TestBroker =
        BrokerCore<FakeTransport, FakeStore, TestClock, TestWallClock, CounterEntropy>;

    /// Drives an immediately-ready fake-port future to completion, matching the
    /// established no-runtime fake-transport driver.
    fn ready<T, F: Future<Output = T>>(future: F) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the fake-driven broker future must be immediately ready"),
        }
    }

    /// A deterministic, cloneable monotonic clock counting whole seconds.
    #[derive(Clone, Debug, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl MonotonicClock for TestClock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::Relaxed))
        }
    }

    /// A deterministic wall clock pinned to one Unix second.
    #[derive(Clone, Debug)]
    struct TestWallClock(u64);

    impl WallClock for TestWallClock {
        fn unix_time(&self) -> u64 {
            self.0
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

    /// One recorded cross-port call, in call order, for event-ordering
    /// assertions. Carries the subject (account-identifying test data, never a
    /// secret) only where the port is subject-keyed.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Exchange,
        Refresh,
        Revoke,
        Store(String),
        Load(String),
        Delete(String),
    }

    type SharedEvents = Arc<Mutex<Vec<Event>>>;

    fn events() -> SharedEvents {
        SharedEvents::default()
    }

    /// Fully validated Google identity claims for `subject`, valid across
    /// `[issued_at, expires_at]`.
    fn claims_for(subject: &str, issued_at: u64, expires_at: u64) -> IdTokenClaims {
        IdTokenClaims::new(
            Zeroizing::new(subject.to_owned()),
            vec![CLIENT_ID.to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            issued_at,
            expires_at,
        )
    }

    /// Fully validated Google identity claims fresh at `NOW`.
    fn valid_claims() -> IdTokenClaims {
        claims_for(SUBJECT, NOW - 10, NOW + 3_600)
    }

    /// A scripted token transport: every exchange or refresh resolves
    /// immediately with one reusable fully-shaped response unless a scripted
    /// refresh failure or a pending gate is installed, records its observed
    /// exchange requests, and appends to the shared event log. Its `Debug`
    /// redacts every secret it holds or observes.
    #[derive(Clone)]
    struct FakeTransport {
        events: SharedEvents,
        recorded: Arc<Mutex<Vec<ExchangeRequest>>>,
        access_token: Zeroizing<String>,
        expires_in: Duration,
        rotated_refresh_token: Option<Zeroizing<String>>,
        id_token_claims: Option<IdTokenClaims>,
        gmail_read_granted: bool,
        revoke_error: Option<TokenTransportError>,
        refresh_error: Option<TokenTransportError>,
        refresh_gate: Option<Arc<AtomicBool>>,
    }

    impl FakeTransport {
        fn success(events: &SharedEvents, rotated_refresh_token: Option<&str>) -> Self {
            Self {
                events: Arc::clone(events),
                recorded: Arc::new(Mutex::new(Vec::new())),
                access_token: Zeroizing::new(ACCESS_TOKEN.to_owned()),
                expires_in: Duration::from_secs(3_600),
                rotated_refresh_token: rotated_refresh_token
                    .map(|token| Zeroizing::new(token.to_owned())),
                id_token_claims: Some(valid_claims()),
                gmail_read_granted: true,
                revoke_error: None,
                refresh_error: None,
                refresh_gate: None,
            }
        }

        fn with_claims(mut self, claims: Option<IdTokenClaims>) -> Self {
            self.id_token_claims = claims;
            self
        }

        fn without_gmail_read(mut self) -> Self {
            self.gmail_read_granted = false;
            self
        }

        fn with_revoke_error(mut self, error: TokenTransportError) -> Self {
            self.revoke_error = Some(error);
            self
        }

        fn with_refresh_error(mut self, error: TokenTransportError) -> Self {
            self.refresh_error = Some(error);
            self
        }

        /// Holds every refresh response pending until `gate` opens, so a test
        /// can park a broker future across a real `.await` with no runtime.
        fn with_gated_refresh(mut self, gate: &Arc<AtomicBool>) -> Self {
            self.refresh_gate = Some(Arc::clone(gate));
            self
        }

        fn with_access_token_and_expiry(
            mut self,
            access_token: &str,
            expires_in: Duration,
        ) -> Self {
            self.access_token = Zeroizing::new(access_token.to_owned());
            self.expires_in = expires_in;
            self
        }

        fn response(&self) -> TokenResponse {
            TokenResponse::new(
                self.access_token.clone(),
                self.expires_in,
                self.rotated_refresh_token.clone(),
                self.id_token_claims.clone(),
                self.gmail_read_granted,
            )
        }
    }

    impl fmt::Debug for FakeTransport {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FakeTransport")
                .field("access_token", &"[REDACTED]")
                .field("expires_in", &self.expires_in)
                .field(
                    "rotated_refresh_token",
                    &self
                        .rotated_refresh_token
                        .as_ref()
                        .map(|_token| "[REDACTED]"),
                )
                .field("id_token_claims", &self.id_token_claims)
                .field("gmail_read_granted", &self.gmail_read_granted)
                .field("revoke_error", &self.revoke_error)
                .field("refresh_error", &self.refresh_error)
                .field("refresh_gated", &self.refresh_gate.is_some())
                .field("recorded", &self.recorded)
                .finish_non_exhaustive()
        }
    }

    impl TokenTransport for FakeTransport {
        fn exchange(
            &self,
            request: ExchangeRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            Box::pin(async move {
                self.events.lock().unwrap().push(Event::Exchange);
                self.recorded.lock().unwrap().push(request);
                Ok(self.response())
            })
        }

        fn refresh(
            &self,
            _request: RefreshRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            Box::pin(async move {
                if let Some(gate) = &self.refresh_gate {
                    std::future::poll_fn(|_context| {
                        if gate.load(Ordering::Relaxed) {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await;
                }
                self.events.lock().unwrap().push(Event::Refresh);
                if let Some(error) = self.refresh_error {
                    return Err(error);
                }
                Ok(self.response())
            })
        }

        fn revoke<'a>(
            &'a self,
            _token: &'a Zeroizing<String>,
        ) -> BoxFuture<'a, Result<(), TokenTransportError>> {
            Box::pin(async move {
                self.events.lock().unwrap().push(Event::Revoke);
                match self.revoke_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
            })
        }
    }

    /// An in-memory refresh-token store with scripted per-operation failures,
    /// sharing the event log so persistence ordering against the transport is
    /// assertable. Its `Debug` never prints a stored token.
    #[derive(Clone)]
    struct FakeStore {
        events: SharedEvents,
        tokens: Arc<Mutex<HashMap<String, Zeroizing<String>>>>,
        store_error: Option<RefreshTokenStoreError>,
        load_error: Option<RefreshTokenStoreError>,
        delete_error: Option<RefreshTokenStoreError>,
    }

    impl FakeStore {
        fn new(events: &SharedEvents) -> Self {
            Self {
                events: Arc::clone(events),
                tokens: Arc::new(Mutex::new(HashMap::new())),
                store_error: None,
                load_error: None,
                delete_error: None,
            }
        }

        fn failing_store(events: &SharedEvents) -> Self {
            Self {
                store_error: Some(RefreshTokenStoreError::Unavailable),
                ..Self::new(events)
            }
        }

        fn failing_load(events: &SharedEvents) -> Self {
            Self {
                load_error: Some(RefreshTokenStoreError::Unavailable),
                ..Self::new(events)
            }
        }

        fn failing_delete(events: &SharedEvents) -> Self {
            Self {
                delete_error: Some(RefreshTokenStoreError::Unavailable),
                ..Self::new(events)
            }
        }

        /// Preloads a stored credential as fixture setup, bypassing the store
        /// port so the event log records only broker-driven operations.
        fn with_stored_token(self, subject: &str, token: &str) -> Self {
            self.tokens
                .lock()
                .unwrap()
                .insert(subject.to_owned(), Zeroizing::new(token.to_owned()));
            self
        }

        fn stored_token(&self, subject: &str) -> Option<String> {
            self.tokens
                .lock()
                .unwrap()
                .get(subject)
                .map(|token| token.as_str().to_owned())
        }

        fn is_empty(&self) -> bool {
            self.tokens.lock().unwrap().is_empty()
        }
    }

    impl fmt::Debug for FakeStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FakeStore")
                .field("store_error", &self.store_error)
                .field("load_error", &self.load_error)
                .field("delete_error", &self.delete_error)
                .field(
                    "stored_subjects",
                    &self.tokens.lock().map_or(0, |tokens| tokens.len()),
                )
                .finish_non_exhaustive()
        }
    }

    impl RefreshTokenStore for FakeStore {
        fn store(
            &self,
            subject: &ValidatedSubject,
            token: &Zeroizing<String>,
        ) -> Result<(), RefreshTokenStoreError> {
            self.events
                .lock()
                .unwrap()
                .push(Event::Store(subject.as_str().to_owned()));
            if let Some(error) = self.store_error {
                return Err(error);
            }
            self.tokens
                .lock()
                .unwrap()
                .insert(subject.as_str().to_owned(), token.clone());
            Ok(())
        }

        fn load(
            &self,
            subject: &ValidatedSubject,
        ) -> Result<Option<Zeroizing<String>>, RefreshTokenStoreError> {
            self.events
                .lock()
                .unwrap()
                .push(Event::Load(subject.as_str().to_owned()));
            if let Some(error) = self.load_error {
                return Err(error);
            }
            Ok(self.tokens.lock().unwrap().get(subject.as_str()).cloned())
        }

        fn delete(&self, subject: &ValidatedSubject) -> Result<(), RefreshTokenStoreError> {
            self.events
                .lock()
                .unwrap()
                .push(Event::Delete(subject.as_str().to_owned()));
            if let Some(error) = self.delete_error {
                return Err(error);
            }
            self.tokens.lock().unwrap().remove(subject.as_str());
            Ok(())
        }
    }

    fn make_broker(
        transport: &FakeTransport,
        store: &FakeStore,
        client_secret: Option<&str>,
    ) -> TestBroker {
        BrokerCore::new(
            CLIENT_ID.to_owned(),
            client_secret.map(|secret| Zeroizing::new(secret.to_owned())),
            Duration::from_secs(600),
            (
                transport.clone(),
                store.clone(),
                TestClock::default(),
                TestWallClock(NOW),
                CounterEntropy::default(),
            ),
        )
        .unwrap()
    }

    fn query_value(url: &Url, name: &str) -> String {
        url.query_pairs()
            .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
            .unwrap()
    }

    /// Builds the exact loopback callback Google would return for `pending`.
    fn callback_for(pending: &PendingAuthorization, code: &str) -> Url {
        let state = query_value(pending.authorization_url(), "state");
        let mut callback = Url::parse(REDIRECT).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", code);
        callback
    }

    /// Runs one full begin→callback→exchange lifecycle against the fakes.
    fn run_authorization(
        transport: &FakeTransport,
        store: &FakeStore,
    ) -> Result<BrokerToken, BrokerError> {
        let broker = make_broker(transport, store, None);
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let callback = callback_for(&pending, AUTH_CODE);
        ready(broker.complete_authorization(pending.session_handle(), callback.as_str()))
    }

    #[test]
    fn constructor_rejects_invalid_client_configuration() {
        let shared = events();
        let valid_ttl = Duration::from_secs(600);
        let make = |client_id: &str, client_secret: Option<Zeroizing<String>>, ttl: Duration| {
            BrokerCore::new(
                client_id.to_owned(),
                client_secret,
                ttl,
                (
                    FakeTransport::success(&shared, None),
                    FakeStore::new(&shared),
                    TestClock::default(),
                    TestWallClock(NOW),
                    CounterEntropy::default(),
                ),
            )
        };
        for blank_id in ["", "   "] {
            assert!(matches!(
                make(blank_id, None, valid_ttl),
                Err(BrokerError::InvalidConfiguration)
            ));
        }
        assert!(matches!(
            make(CLIENT_ID, Some(Zeroizing::new("   ".to_owned())), valid_ttl),
            Err(BrokerError::InvalidConfiguration)
        ));
        assert!(matches!(
            make(CLIENT_ID, None, Duration::ZERO),
            Err(BrokerError::InvalidConfiguration)
        ));
        assert!(matches!(
            make(CLIENT_ID, None, MAX_SESSION_TTL + Duration::from_secs(1)),
            Err(BrokerError::InvalidConfiguration)
        ));
        // The exact TTL bound and a present non-blank secret are accepted.
        assert!(make(CLIENT_ID, None, MAX_SESSION_TTL).is_ok());
        assert!(
            make(
                CLIENT_ID,
                Some(Zeroizing::new(CLIENT_SECRET.to_owned())),
                valid_ttl,
            )
            .is_ok()
        );
    }

    #[test]
    fn begin_accepts_only_the_exact_loopback_root_redirect() {
        let shared = events();
        let broker = make_broker(
            &FakeTransport::success(&shared, None),
            &FakeStore::new(&shared),
            None,
        );
        for accepted in [
            "http://127.0.0.1:1024/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:65535/",
        ] {
            assert!(
                broker.begin_authorization(accepted).is_ok(),
                "must accept {accepted}"
            );
        }
        let mut oversized = REDIRECT.to_owned();
        oversized.push_str(&"A".repeat(MAX_REDIRECT_LEN));
        for rejected in [
            "http://127.0.0.1/",              // no explicit port
            "http://127.0.0.1:1023/",         // below the ephemeral range
            "http://localhost:8080/",         // named loopback
            "http://[::1]:8080/",             // IPv6 loopback
            "http://127.1:8080/",             // noncanonical IPv4
            "http://127.0.0.01:8080/",        // alternate spelling
            "HTTP://127.0.0.1:8080/",         // uppercase scheme
            "https://127.0.0.1:8080/",        // TLS scheme
            "http://127.0.0.1:8080/callback", // non-root path
            "http://user@127.0.0.1:8080/",    // credentials
            "http://user:pass@127.0.0.1:8080/",
            "http://127.0.0.1:8080/?a=b",      // query
            "http://127.0.0.1:8080/#fragment", // fragment
            oversized.as_str(),
        ] {
            assert!(
                matches!(
                    broker.begin_authorization(rejected),
                    Err(BrokerError::InvalidInput)
                ),
                "must reject {rejected}"
            );
        }
    }

    #[test]
    fn pending_authorization_debug_redacts_url_state_challenge_and_handle() {
        let shared = events();
        let broker = make_broker(
            &FakeTransport::success(&shared, None),
            &FakeStore::new(&shared),
            None,
        );
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let url = pending.authorization_url();
        let state = query_value(url, "state");
        let challenge = query_value(url, "code_challenge");
        let debug = format!("{pending:?}");
        assert!(debug.contains("[REDACTED]"));
        for sensitive in [
            url.as_str(),
            state.as_str(),
            challenge.as_str(),
            pending.session_handle(),
        ] {
            assert!(
                !debug.contains(sensitive),
                "PendingAuthorization Debug leaks {sensitive}: {debug}"
            );
        }
    }

    #[test]
    fn successful_authorization_persists_the_refresh_token_before_reporting_success() {
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN));
        let store = FakeStore::new(&shared);
        let broker = make_broker(&transport, &store, Some(CLIENT_SECRET));
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let challenge = query_value(pending.authorization_url(), "code_challenge");
        let callback = callback_for(&pending, AUTH_CODE);
        let token =
            ready(broker.complete_authorization(pending.session_handle(), callback.as_str()))
                .unwrap();

        assert_eq!(token.access_token().as_str(), ACCESS_TOKEN);
        assert_eq!(token.subject(), SUBJECT);
        assert_eq!(token.expires_in_seconds(), 3_600);
        assert!((1..=MAX_EXPIRES_IN_SECS).contains(&token.expires_in_seconds()));

        // The exchange ran before the store write, and the store write
        // completed before the success could be observed.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Exchange, Event::Store(SUBJECT.to_owned())]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // The public success value redacts both the token and the subject.
        let debug = format!("{token:?}");
        assert!(debug.contains("[REDACTED]"));
        for sensitive in [ACCESS_TOKEN, SUBJECT, REFRESH_TOKEN] {
            assert!(
                !debug.contains(sensitive),
                "BrokerToken Debug leaks {sensitive}: {debug}"
            );
        }

        // The transport observed the exact exchange shape: the callback code,
        // the session's PKCE verifier, the exact redirect, and the client
        // identity, with the configured secret last.
        let recorded = transport.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let parameters = recorded[0].parameters();
        drop(recorded);
        let pairs: Vec<(&str, &str)> = parameters
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        assert_eq!(pairs.len(), 6);
        assert_eq!(pairs[0], ("grant_type", "authorization_code"));
        assert_eq!(pairs[1], ("code", AUTH_CODE));
        assert_eq!(pairs[3], ("client_id", CLIENT_ID));
        assert_eq!(pairs[4], ("redirect_uri", REDIRECT));
        assert_eq!(pairs[5], ("client_secret", CLIENT_SECRET));
        assert_eq!(pairs[2].0, "code_verifier");
        let verifier = pairs[2].1;
        assert_eq!(verifier.len(), 43);
        assert!(
            verifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        // The verifier is the session's secret, distinct from the public
        // challenge derived from it.
        assert_ne!(verifier, challenge);

        // The fake itself never renders a secret through Debug.
        let transport_debug = format!("{transport:?}");
        for sensitive in [
            ACCESS_TOKEN,
            REFRESH_TOKEN,
            AUTH_CODE,
            CLIENT_SECRET,
            verifier,
        ] {
            assert!(
                !transport_debug.contains(sensitive),
                "FakeTransport Debug leaks {sensitive}: {transport_debug}"
            );
        }
    }

    #[test]
    fn every_callback_attempt_consumes_the_session() {
        let shared = events();
        let broker = make_broker(
            &FakeTransport::success(&shared, Some(REFRESH_TOKEN)),
            &FakeStore::new(&shared),
            None,
        );

        // An unparseable callback consumes the session; a replay of the same
        // handle with the otherwise valid callback meets SessionUnknown.
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let handle = pending.session_handle().to_owned();
        let valid_callback = callback_for(&pending, AUTH_CODE);
        assert!(matches!(
            ready(broker.complete_authorization(&handle, "not a url")),
            Err(BrokerError::InvalidInput)
        ));
        assert!(matches!(
            ready(broker.complete_authorization(&handle, valid_callback.as_str())),
            Err(BrokerError::SessionUnknown)
        ));

        // A wrong-state callback consumes the session too.
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let handle = pending.session_handle().to_owned();
        let valid_callback = callback_for(&pending, AUTH_CODE);
        let wrong_state = format!("{REDIRECT}?state=wrong-state&code={AUTH_CODE}");
        assert!(matches!(
            ready(broker.complete_authorization(&handle, &wrong_state)),
            Err(BrokerError::InvalidInput)
        ));
        assert!(matches!(
            ready(broker.complete_authorization(&handle, valid_callback.as_str())),
            Err(BrokerError::SessionUnknown)
        ));

        // An oversized callback consumes the session before it is even parsed.
        let pending = broker.begin_authorization(REDIRECT).unwrap();
        let handle = pending.session_handle().to_owned();
        let valid_callback = callback_for(&pending, AUTH_CODE);
        let state = query_value(pending.authorization_url(), "state");
        let padding = "A".repeat(MAX_CALLBACK_LEN);
        let oversized = format!("{REDIRECT}?state={state}&code={padding}");
        assert!(matches!(
            ready(broker.complete_authorization(&handle, &oversized)),
            Err(BrokerError::InvalidInput)
        ));
        assert!(matches!(
            ready(broker.complete_authorization(&handle, valid_callback.as_str())),
            Err(BrokerError::SessionUnknown)
        ));

        // No malformed attempt ever reached the transport.
        assert!(shared.lock().unwrap().is_empty());
    }

    #[test]
    fn an_exchange_without_a_refresh_token_is_terminal_and_revokes_best_effort() {
        let shared = events();
        // The best-effort revoke may itself fail; the terminal must not change.
        let transport =
            FakeTransport::success(&shared, None).with_revoke_error(TokenTransportError::Transport);
        let store = FakeStore::new(&shared);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::MissingRefreshToken)));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Exchange, Event::Revoke]
        );
        assert!(store.is_empty());
    }

    #[test]
    fn an_explicitly_under_scoped_grant_is_terminal_and_revokes_best_effort() {
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN)).without_gmail_read();
        let store = FakeStore::new(&shared);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::InsufficientScope)));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Exchange, Event::Revoke]
        );
        assert!(store.is_empty());
    }

    #[test]
    fn unverified_missing_stale_or_future_identity_is_terminal_and_persists_nothing() {
        let wrong_audience = IdTokenClaims::new(
            Zeroizing::new(SUBJECT.to_owned()),
            vec!["another-client".to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            NOW - 10,
            NOW + 3_600,
        );
        let stale = IdTokenClaims::new(
            Zeroizing::new(SUBJECT.to_owned()),
            vec![CLIENT_ID.to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            NOW - 7_200,
            NOW - 3_600,
        );
        let future = IdTokenClaims::new(
            Zeroizing::new(SUBJECT.to_owned()),
            vec![CLIENT_ID.to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            NOW + 3_600,
            NOW + 7_200,
        );
        for claims in [None, Some(wrong_audience), Some(stale), Some(future)] {
            let shared = events();
            let transport =
                FakeTransport::success(&shared, Some(REFRESH_TOKEN)).with_claims(claims);
            let store = FakeStore::new(&shared);
            let result = run_authorization(&transport, &store);
            assert!(
                matches!(result, Err(BrokerError::IdentityUnverified)),
                "identity failure must be IdentityUnverified: {result:?}"
            );
            // No token is exposed, nothing is persisted, and the identity
            // failure path performs no revoke.
            assert_eq!(*shared.lock().unwrap(), vec![Event::Exchange]);
            assert!(store.is_empty());
        }
    }

    #[test]
    fn a_store_write_failure_fails_closed_after_the_exchange() {
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN));
        let store = FakeStore::failing_store(&shared);
        let result = run_authorization(&transport, &store);
        assert!(matches!(result, Err(BrokerError::PersistenceFailed)));
        // The exchange preceded the store write, and the store write preceded
        // the (failed) result the caller could observe.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Exchange, Event::Store(SUBJECT.to_owned())]
        );
        assert!(store.is_empty());
    }

    #[test]
    fn out_of_bound_access_tokens_and_expiries_are_malformed_responses() {
        let oversized_token = format!("{ACCESS_TOKEN}{}", "A".repeat(MAX_ACCESS_TOKEN_LEN));
        let cases = [
            (oversized_token, Duration::from_secs(3_600)),
            (ACCESS_TOKEN.to_owned(), Duration::ZERO),
            (
                ACCESS_TOKEN.to_owned(),
                Duration::from_secs(MAX_EXPIRES_IN_SECS + 1),
            ),
        ];
        for (access_token, expires_in) in cases {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(REFRESH_TOKEN))
                .with_access_token_and_expiry(&access_token, expires_in);
            let store = FakeStore::new(&shared);
            let result = run_authorization(&transport, &store);
            assert!(
                matches!(result, Err(BrokerError::MalformedResponse)),
                "out-of-bound provider outcome must be MalformedResponse: {result:?}"
            );
            assert_eq!(*shared.lock().unwrap(), vec![Event::Exchange]);
            assert!(store.is_empty());
        }
    }

    #[test]
    fn refresh_without_a_stored_token_never_contacts_the_transport() {
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::MissingRefreshToken)
        ));
        // The load ran; no refresh, store, or delete ever did.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned())]
        );
    }

    #[test]
    fn a_successful_refresh_without_rotation_retains_the_stored_token() {
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let token = ready(broker.refresh_access_token(SUBJECT)).unwrap();
        assert_eq!(token.access_token().as_str(), ACCESS_TOKEN);
        assert_eq!(token.subject(), SUBJECT);
        assert_eq!(token.expires_in_seconds(), 3_600);
        // No store write at all: the original credential stays exactly as
        // stored, and the success was minted only after the exact subject and
        // the id_token freshness validated (see the mismatch and staleness
        // cases below for the negative gate).
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn a_successful_refresh_with_rotation_persists_the_new_token_before_reporting_success() {
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let token = ready(broker.refresh_access_token(SUBJECT)).unwrap();
        assert_eq!(token.access_token().as_str(), ACCESS_TOKEN);
        // The rotation was persisted after the provider answer and BEFORE the
        // success could be observed.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Refresh,
                Event::Store(SUBJECT.to_owned()),
            ]
        );
        assert_eq!(
            store.stored_token(SUBJECT).as_deref(),
            Some(ROTATED_REFRESH_TOKEN)
        );
    }

    #[test]
    fn consent_revoked_deletes_the_stored_credential_and_a_delete_failure_fails_closed() {
        // An invalid_grant answer means consent is gone: the stored
        // credential is deleted before ConsentRevoked is reported.
        let shared = events();
        let transport = FakeTransport::success(&shared, None)
            .with_refresh_error(TokenTransportError::InvalidGrant);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::ConsentRevoked)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Refresh,
                Event::Delete(SUBJECT.to_owned()),
            ]
        );
        assert!(store.is_empty());

        // When the delete itself fails the broker fails closed as
        // PersistenceFailed: the re-connect signal is masked, never reported.
        let shared = events();
        let transport = FakeTransport::success(&shared, None)
            .with_refresh_error(TokenTransportError::InvalidGrant);
        let store = FakeStore::failing_delete(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::PersistenceFailed)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Refresh,
                Event::Delete(SUBJECT.to_owned()),
            ]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn failed_or_identity_unverified_refreshes_retain_the_stored_token() {
        // Transport, provider, and malformed-response failures are retryable:
        // the stored credential stays and no rotation is persisted.
        for (error, expected) in [
            (TokenTransportError::Transport, BrokerError::Transport),
            (
                TokenTransportError::ProviderRejected,
                BrokerError::ProviderRejected,
            ),
            (
                TokenTransportError::MalformedResponse,
                BrokerError::MalformedResponse,
            ),
        ] {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN))
                .with_refresh_error(error);
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let broker = make_broker(&transport, &store, None);
            let result = ready(broker.refresh_access_token(SUBJECT));
            assert_eq!(result.err(), Some(expected));
            assert_eq!(
                *shared.lock().unwrap(),
                vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
            );
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        }

        // Identity failures retain the credential too: a missing id_token
        // fails in the token layer, a stale one fails the broker's wall-clock
        // freshness check.
        let stale = claims_for(SUBJECT, NOW - 7_200, NOW - 3_600);
        for claims in [None, Some(stale)] {
            let shared = events();
            let transport =
                FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN)).with_claims(claims);
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let broker = make_broker(&transport, &store, None);
            let result = ready(broker.refresh_access_token(SUBJECT));
            assert_eq!(result.err(), Some(BrokerError::IdentityUnverified));
            assert_eq!(
                *shared.lock().unwrap(),
                vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
            );
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        }
    }

    #[test]
    fn a_refresh_validating_to_a_different_subject_is_an_identity_mismatch_that_retains_the_token()
    {
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN))
            .with_claims(Some(claims_for(OTHER_SUBJECT, NOW - 10, NOW + 3_600)));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let result = ready(broker.refresh_access_token(SUBJECT));
        assert_eq!(result.err(), Some(BrokerError::IdentityMismatch));
        // No rotation persisted, nothing deleted: the original stays stored.
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn an_under_scoped_refresh_persists_a_valid_rotation_before_reporting_the_scope_failure() {
        // A valid rotation is retained BEFORE the permission error surfaces,
        // so the grant keeps a local revocation handle.
        let shared = events();
        let transport =
            FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN)).without_gmail_read();
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let result = ready(broker.refresh_access_token(SUBJECT));
        assert_eq!(result.err(), Some(BrokerError::InsufficientScope));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Refresh,
                Event::Store(SUBJECT.to_owned()),
            ]
        );
        assert_eq!(
            store.stored_token(SUBJECT).as_deref(),
            Some(ROTATED_REFRESH_TOKEN)
        );

        // No rotation: the original credential stays exactly as stored.
        let shared = events();
        let transport = FakeTransport::success(&shared, None).without_gmail_read();
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        let result = ready(broker.refresh_access_token(SUBJECT));
        assert_eq!(result.err(), Some(BrokerError::InsufficientScope));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));

        // An empty or oversized rotation is a malformed response, rejected
        // BEFORE any store write: the original is never replaced.
        let oversized = format!("1//{}", "A".repeat(MAX_REFRESH_TOKEN_LEN));
        for rotated in ["", oversized.as_str()] {
            let shared = events();
            let transport = FakeTransport::success(&shared, Some(rotated)).without_gmail_read();
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
            let broker = make_broker(&transport, &store, None);
            let result = ready(broker.refresh_access_token(SUBJECT));
            assert!(
                matches!(result, Err(BrokerError::MalformedResponse)),
                "invalid rotation must be MalformedResponse: {result:?}"
            );
            assert_eq!(
                *shared.lock().unwrap(),
                vec![Event::Load(SUBJECT.to_owned()), Event::Refresh]
            );
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        }
    }

    #[test]
    fn provider_revoke_and_local_delete_are_strictly_separate() {
        // No stored token: revoke succeeds without touching the network.
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned())]
        );

        // A confirmed revoke contacts the provider but retains the stored
        // token; only the explicit delete removes it, and delete is
        // idempotent.
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(ready(broker.revoke_provider_grant(SUBJECT)).is_ok());
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Revoke]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
        assert!(broker.delete_stored_tokens(SUBJECT).is_ok());
        assert!(store.stored_token(SUBJECT).is_none());
        assert!(broker.delete_stored_tokens(SUBJECT).is_ok());

        // An unconfirmed revoke stays visible and retains the stored token.
        let shared = events();
        let transport =
            FakeTransport::success(&shared, None).with_revoke_error(TokenTransportError::Transport);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.revoke_provider_grant(SUBJECT)),
            Err(BrokerError::RevokeUnconfirmed)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned()), Event::Revoke]
        );
        assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(REFRESH_TOKEN));
    }

    #[test]
    fn the_single_flight_permit_is_held_across_a_pending_refresh_and_released_on_drop() {
        let shared = events();
        let gate = Arc::new(AtomicBool::new(false));
        let transport =
            FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN)).with_gated_refresh(&gate);
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, None);

        // Poll the refresh once: the permit is claimed, the credential is
        // loaded, and the future is genuinely parked inside the gated
        // transport call (no Refresh event has fired).
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut pending_refresh = Box::pin(broker.refresh_access_token(SUBJECT));
        assert!(matches!(
            pending_refresh.as_mut().poll(&mut context),
            Poll::Pending
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![Event::Load(SUBJECT.to_owned())]
        );

        // Every same-subject mutation is Busy while the permit is held: the
        // async methods answer on their first poll, the sync delete directly.
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::Busy)
        ));
        assert!(matches!(
            ready(broker.revoke_provider_grant(SUBJECT)),
            Err(BrokerError::Busy)
        ));
        assert!(matches!(
            broker.delete_stored_tokens(SUBJECT),
            Err(BrokerError::Busy)
        ));

        // Another subject is not blocked: its own terminal answers normally.
        assert!(matches!(
            ready(broker.refresh_access_token(OTHER_SUBJECT)),
            Err(BrokerError::MissingRefreshToken)
        ));
        assert!(broker.delete_stored_tokens(OTHER_SUBJECT).is_ok());

        // Cancelling the parked future releases the permit by RAII: the
        // subject is operable again, with no sleeping and no runtime.
        drop(pending_refresh);
        assert!(broker.delete_stored_tokens(SUBJECT).is_ok());
        assert!(store.stored_token(SUBJECT).is_none());
    }

    #[test]
    fn stored_token_bounds_invalid_subjects_and_debug_redaction_stay_fail_closed() {
        // An empty or oversized stored item is a store-integrity failure:
        // refresh and revoke fail closed without contacting the transport.
        let oversized = format!("1//{}", "A".repeat(MAX_REFRESH_TOKEN_LEN));
        for stored in ["", oversized.as_str()] {
            let shared = events();
            let transport = FakeTransport::success(&shared, None);
            let store = FakeStore::new(&shared).with_stored_token(SUBJECT, stored);
            let broker = make_broker(&transport, &store, None);
            assert!(matches!(
                ready(broker.refresh_access_token(SUBJECT)),
                Err(BrokerError::PersistenceFailed)
            ));
            assert!(matches!(
                ready(broker.revoke_provider_grant(SUBJECT)),
                Err(BrokerError::PersistenceFailed)
            ));
            // Only the two loads ran: no transport call, no store mutation.
            assert_eq!(
                *shared.lock().unwrap(),
                vec![
                    Event::Load(SUBJECT.to_owned()),
                    Event::Load(SUBJECT.to_owned()),
                ]
            );
            assert_eq!(store.stored_token(SUBJECT).as_deref(), Some(stored));
        }

        // A store read failure fails closed identically on both read paths.
        let shared = events();
        let transport = FakeTransport::success(&shared, None);
        let store = FakeStore::failing_load(&shared);
        let broker = make_broker(&transport, &store, None);
        assert!(matches!(
            ready(broker.refresh_access_token(SUBJECT)),
            Err(BrokerError::PersistenceFailed)
        ));
        assert!(matches!(
            ready(broker.revoke_provider_grant(SUBJECT)),
            Err(BrokerError::PersistenceFailed)
        ));
        assert_eq!(
            *shared.lock().unwrap(),
            vec![
                Event::Load(SUBJECT.to_owned()),
                Event::Load(SUBJECT.to_owned()),
            ]
        );

        // Invalid subject text is rejected before any permit, store, or
        // transport interaction. 256 bytes exceeds the 255-byte subject cap.
        let oversized_subject = "1".repeat(256);
        for invalid in ["", "has space", oversized_subject.as_str()] {
            let shared = events();
            let transport = FakeTransport::success(&shared, None);
            let store = FakeStore::new(&shared);
            let broker = make_broker(&transport, &store, None);
            assert!(matches!(
                ready(broker.refresh_access_token(invalid)),
                Err(BrokerError::InvalidInput)
            ));
            assert!(matches!(
                ready(broker.revoke_provider_grant(invalid)),
                Err(BrokerError::InvalidInput)
            ));
            assert!(matches!(
                broker.delete_stored_tokens(invalid),
                Err(BrokerError::InvalidInput)
            ));
            assert!(shared.lock().unwrap().is_empty());
        }

        // With live secrets loaded, no broker, fake, or token Debug rendering
        // leaks one.
        let shared = events();
        let transport = FakeTransport::success(&shared, Some(ROTATED_REFRESH_TOKEN));
        let store = FakeStore::new(&shared).with_stored_token(SUBJECT, REFRESH_TOKEN);
        let broker = make_broker(&transport, &store, Some(CLIENT_SECRET));
        let token = ready(broker.refresh_access_token(SUBJECT)).unwrap();
        for rendered in [
            format!("{broker:?}"),
            format!("{transport:?}"),
            format!("{store:?}"),
            format!("{token:?}"),
        ] {
            for sensitive in [
                ACCESS_TOKEN,
                REFRESH_TOKEN,
                ROTATED_REFRESH_TOKEN,
                CLIENT_SECRET,
                SUBJECT,
            ] {
                assert!(
                    !rendered.contains(sensitive),
                    "Debug leaks {sensitive}: {rendered}"
                );
            }
        }
    }
}
