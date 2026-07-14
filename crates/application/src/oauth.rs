// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements the portable OAuth authorization-code and PKCE state machine.
//!
//! This module prepares a Google authorization request and validates exactly
//! one redirect. It intentionally does not exchange the authorization code,
//! persist tokens, contact Gmail, or launch a browser. Platform adapters own
//! the browser and redirect transport.

use std::fmt;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

// Rust guideline compliant 1.0.

/// The only Gmail scope requested by the feasibility flow.
pub const GMAIL_MODIFY_SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify";

const GOOGLE_AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const SECRET_BYTES: usize = 32;

/// Supplies monotonic time to an authorization session.
pub trait MonotonicClock: fmt::Debug + Send + Sync {
    /// Returns elapsed monotonic time from a clock-specific origin.
    fn now(&self) -> Duration;
}

/// Uses [`Instant`] as the production monotonic clock.
#[derive(Debug)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    /// Creates a monotonic clock with a new process-local origin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Configures one Google OAuth authorization attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationConfig {
    client_id: String,
    redirect_uri: Url,
    lifetime: Duration,
}

impl AuthorizationConfig {
    /// Creates a validated authorization configuration.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::InvalidConfiguration`] when the client identifier
    /// is blank, the redirect contains credentials, query, or fragment, or the
    /// lifetime is zero.
    pub fn new<T: Into<String>>(
        client_id: T,
        redirect_uri: Url,
        lifetime: Duration,
    ) -> Result<Self, OAuthError> {
        let client_id = client_id.into();
        let has_credentials =
            !redirect_uri.username().is_empty() || redirect_uri.password().is_some();
        if client_id.trim().is_empty()
            || lifetime.is_zero()
            || has_credentials
            || redirect_uri.query().is_some()
            || redirect_uri.fragment().is_some()
        {
            return Err(OAuthError::InvalidConfiguration);
        }

        Ok(Self {
            client_id,
            redirect_uri,
            lifetime,
        })
    }

    /// Returns the exact registered redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }
}

/// Contains the public authorization URL and its pending state machine.
pub struct PreparedAuthorization<C> {
    authorization_url: Url,
    session: AuthorizationSession<C>,
}

impl<C> fmt::Debug for PreparedAuthorization<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAuthorization")
            .field("authorization_url", &"[REDACTED]")
            .field("session", &self.session)
            .finish()
    }
}

impl<C> PreparedAuthorization<C> {
    /// Returns the authorization URL intended for the system browser.
    #[must_use]
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// Separates the public URL from its one-shot session.
    #[must_use]
    pub fn into_parts(self) -> (Url, AuthorizationSession<C>) {
        (self.authorization_url, self.session)
    }
}

/// Owns the sensitive state for one pending authorization attempt.
pub struct AuthorizationSession<C> {
    clock: C,
    expires_at: Duration,
    redirect_uri: Url,
    state: Zeroizing<Vec<u8>>,
    verifier: Zeroizing<String>,
    consumed: bool,
}

impl<C> fmt::Debug for AuthorizationSession<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationSession")
            .field("expires_at", &self.expires_at)
            .field("redirect_uri", &"[REDACTED]")
            .field("clock", &"[MONOTONIC]")
            .field("state", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl<C: MonotonicClock> AuthorizationSession<C> {
    /// Validates and consumes the one permitted redirect.
    ///
    /// The session is consumed before validation, so every callback attempt is
    /// terminal, including malformed and adversarial callbacks.
    ///
    /// # Errors
    ///
    /// Returns a typed error for replay, expiry, malformed callbacks, provider
    /// errors, redirect mismatch, or state mismatch.
    pub fn finish(&mut self, callback: &Url) -> Result<AuthorizationGrant, OAuthError> {
        self.consume()?;
        let result = self.validate_callback(callback);
        self.state.zeroize();
        if result.is_err() {
            self.verifier.zeroize();
        }
        result
    }

    /// Cancels and consumes the pending session.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::AlreadyConsumed`] after any terminal outcome.
    pub fn cancel(&mut self) -> Result<(), OAuthError> {
        self.consume()?;
        self.state.zeroize();
        self.verifier.zeroize();
        Err(OAuthError::Cancelled)
    }

    /// Expires and consumes the session once its deadline has elapsed.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::NotExpired`] before the deadline or
    /// [`OAuthError::AlreadyConsumed`] after a terminal outcome.
    pub fn expire(&mut self) -> Result<(), OAuthError> {
        if self.consumed {
            return Err(OAuthError::AlreadyConsumed);
        }
        if self.clock.now() < self.expires_at {
            return Err(OAuthError::NotExpired);
        }
        self.consume()?;
        self.state.zeroize();
        self.verifier.zeroize();
        Err(OAuthError::Expired)
    }

    fn consume(&mut self) -> Result<(), OAuthError> {
        if self.consumed {
            return Err(OAuthError::AlreadyConsumed);
        }
        self.consumed = true;
        Ok(())
    }

    fn validate_callback(&mut self, callback: &Url) -> Result<AuthorizationGrant, OAuthError> {
        if self.clock.now() >= self.expires_at {
            return Err(OAuthError::Expired);
        }
        self.validate_redirect(callback)?;

        let parameters = unique_query_parameters(callback)?;
        let state = required_parameter(&parameters, "state")?;
        if self.state.as_slice().ct_eq(state.as_bytes()).unwrap_u8() != 1 {
            return Err(OAuthError::StateMismatch);
        }

        let code = parameters.get("code");
        let provider_error = parameters.get("error");
        match (code, provider_error) {
            (Some(_), Some(_)) => Err(OAuthError::ConflictingCallback),
            (None, Some(_)) => Err(OAuthError::ProviderRejected),
            (None, None) => Err(OAuthError::MissingParameter("code")),
            (Some(code), None) if code.is_empty() => Err(OAuthError::MissingParameter("code")),
            (Some(code), None) => Ok(AuthorizationGrant {
                code: code.clone(),
                verifier: Zeroizing::new(std::mem::take(&mut *self.verifier)),
            }),
        }
    }

    fn validate_redirect(&self, callback: &Url) -> Result<(), OAuthError> {
        let callback_identity = callback
            .as_str()
            .split_once('?')
            .map_or(callback.as_str(), |(identity, _query)| identity);
        if callback.fragment().is_some() || callback_identity != self.redirect_uri.as_str() {
            return Err(OAuthError::RedirectMismatch);
        }
        Ok(())
    }
}

/// Holds the short-lived code and verifier for a future token exchange.
pub struct AuthorizationGrant {
    code: Zeroizing<String>,
    verifier: Zeroizing<String>,
}

impl AuthorizationGrant {
    /// Returns the authorization code without transferring ownership.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the PKCE verifier without transferring ownership.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }
}

impl fmt::Debug for AuthorizationGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationGrant")
            .field("code", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .finish()
    }
}

/// Describes a terminal or configuration failure without sensitive values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OAuthError {
    /// A required configuration value is absent or unsafe.
    InvalidConfiguration,
    /// The operating system could not provide cryptographic randomness.
    EntropyUnavailable,
    /// A callback parameter is missing.
    MissingParameter(&'static str),
    /// A callback parameter occurs more than once.
    DuplicateParameter,
    /// The callback includes both a code and provider error.
    ConflictingCallback,
    /// The provider returned an OAuth error.
    ProviderRejected,
    /// The callback redirect does not exactly match the configured redirect.
    RedirectMismatch,
    /// The returned state does not match the pending session.
    StateMismatch,
    /// The user or platform cancelled the authorization session.
    Cancelled,
    /// The authorization deadline elapsed.
    Expired,
    /// The session has not yet reached its deadline.
    NotExpired,
    /// A terminal outcome already consumed the session.
    AlreadyConsumed,
}

impl fmt::Display for OAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "invalid OAuth configuration",
            Self::EntropyUnavailable => "cryptographic entropy is unavailable",
            Self::MissingParameter(_) => "the OAuth callback is incomplete",
            Self::DuplicateParameter => "the OAuth callback contains duplicate parameters",
            Self::ConflictingCallback => "the OAuth callback contains conflicting outcomes",
            Self::ProviderRejected => "the OAuth provider rejected the request",
            Self::RedirectMismatch => "the OAuth redirect does not match",
            Self::StateMismatch => "the OAuth state does not match",
            Self::Cancelled => "the OAuth request was cancelled",
            Self::Expired => "the OAuth request expired",
            Self::NotExpired => "the OAuth request has not expired",
            Self::AlreadyConsumed => "the OAuth request was already consumed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OAuthError {}

/// Prepares an authorization request using operating-system randomness.
///
/// # Errors
///
/// Returns [`OAuthError::EntropyUnavailable`] when the OS CSPRNG fails.
pub fn prepare_authorization<C: MonotonicClock>(
    config: AuthorizationConfig,
    clock: C,
) -> Result<PreparedAuthorization<C>, OAuthError> {
    let mut verifier_bytes = Zeroizing::new([0_u8; SECRET_BYTES]);
    let mut state_bytes = Zeroizing::new([0_u8; SECRET_BYTES]);
    getrandom::fill(&mut *verifier_bytes).map_err(|_error| OAuthError::EntropyUnavailable)?;
    getrandom::fill(&mut *state_bytes).map_err(|_error| OAuthError::EntropyUnavailable)?;
    prepare_with_secrets(config, clock, &verifier_bytes[..], &state_bytes[..])
}

fn prepare_with_secrets<C: MonotonicClock>(
    config: AuthorizationConfig,
    clock: C,
    verifier_bytes: &[u8],
    state_bytes: &[u8],
) -> Result<PreparedAuthorization<C>, OAuthError> {
    if verifier_bytes.len() != SECRET_BYTES || state_bytes.len() != SECRET_BYTES {
        return Err(OAuthError::InvalidConfiguration);
    }
    let verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(verifier_bytes));
    let state = Zeroizing::new(URL_SAFE_NO_PAD.encode(state_bytes));
    let challenge = pkce_challenge(&verifier);
    let now = clock.now();
    let expires_at = now
        .checked_add(config.lifetime)
        .ok_or(OAuthError::InvalidConfiguration)?;

    let mut authorization_url =
        Url::parse(GOOGLE_AUTHORIZATION_ENDPOINT).expect("the static Google URL is valid");
    authorization_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", config.redirect_uri.as_str())
        .append_pair("scope", GMAIL_MODIFY_SCOPE)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("access_type", "offline");

    Ok(PreparedAuthorization {
        authorization_url,
        session: AuthorizationSession {
            clock,
            expires_at,
            redirect_uri: config.redirect_uri,
            state: Zeroizing::new(state.as_bytes().to_vec()),
            verifier,
            consumed: false,
        },
    })
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn unique_query_parameters(
    callback: &Url,
) -> Result<std::collections::BTreeMap<String, Zeroizing<String>>, OAuthError> {
    let mut parameters = std::collections::BTreeMap::new();
    for (name, value) in callback.query_pairs() {
        if parameters
            .insert(name.into_owned(), Zeroizing::new(value.into_owned()))
            .is_some()
        {
            return Err(OAuthError::DuplicateParameter);
        }
    }
    Ok(parameters)
}

fn required_parameter<'a>(
    parameters: &'a std::collections::BTreeMap<String, Zeroizing<String>>,
    name: &'static str,
) -> Result<&'a str, OAuthError> {
    parameters
        .get(name)
        .filter(|value| !value.is_empty())
        .map(|value| value.as_str())
        .ok_or(OAuthError::MissingParameter(name))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures use static URLs and assert setup success before behavior"
    )]

    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        AuthorizationConfig, GMAIL_MODIFY_SCOPE, MonotonicClock, OAuthError, SystemMonotonicClock,
        pkce_challenge, prepare_authorization, prepare_with_secrets,
    };
    use std::time::Duration;
    use url::Url;

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

    fn make_prepared(seed: u8) -> super::PreparedAuthorization<TestClock> {
        let redirect = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        let config =
            AuthorizationConfig::new("public-test-client", redirect, Duration::from_secs(60))
                .unwrap();
        prepare_with_secrets(config, TestClock::default(), &[seed; 32], &[seed + 1; 32]).unwrap()
    }

    fn state(url: &Url) -> String {
        url.query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap()
    }

    fn make_callback(url: &Url, code: &str) -> Url {
        let mut callback = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        callback
            .query_pairs_mut()
            .append_pair("state", &state(url))
            .append_pair("code", code);
        callback
    }

    #[test]
    fn matches_the_rfc_7636_s256_vector() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generates_well_shaped_verifier_state_and_exact_parameters() {
        let prepared = make_prepared(7);
        let pairs: Vec<_> = prepared.authorization_url().query_pairs().collect();
        let parameters: BTreeMap<_, _> = pairs.iter().cloned().collect();
        assert_eq!(pairs.len(), 8);
        assert_eq!(parameters.len(), pairs.len());
        assert_eq!(parameters.get("scope").unwrap(), GMAIL_MODIFY_SCOPE);
        assert_eq!(parameters.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(parameters.get("response_type").unwrap(), "code");
        assert_eq!(parameters.get("client_id").unwrap(), "public-test-client");
        assert_eq!(
            parameters.get("redirect_uri").unwrap(),
            "app.tersa.oauth.test:/oauth/callback"
        );
        assert_eq!(parameters.get("access_type").unwrap(), "offline");
        let state = parameters.get("state").unwrap();
        let challenge = parameters.get("code_challenge").unwrap();
        assert_eq!(state.len(), 43);
        assert_eq!(challenge.len(), 43);
        assert!(
            state
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        let debug = format!("{prepared:?}");
        assert!(!debug.contains(state.as_ref()));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn operating_system_entropy_makes_sessions_unique() {
        let redirect = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        let config =
            AuthorizationConfig::new("public-test-client", redirect, Duration::from_secs(60))
                .unwrap();
        let first = prepare_authorization(config.clone(), SystemMonotonicClock::new()).unwrap();
        let second = prepare_authorization(config, SystemMonotonicClock::new()).unwrap();
        assert_ne!(
            state(first.authorization_url()),
            state(second.authorization_url())
        );
        let first_challenge = first
            .authorization_url()
            .query_pairs()
            .find_map(|(name, value)| (name == "code_challenge").then(|| value.into_owned()))
            .unwrap();
        let second_challenge = second
            .authorization_url()
            .query_pairs()
            .find_map(|(name, value)| (name == "code_challenge").then(|| value.into_owned()))
            .unwrap();
        assert_ne!(first_challenge, second_challenge);
    }

    #[test]
    fn accepts_one_exact_callback_and_redacts_the_grant() {
        let prepared = make_prepared(1);
        let callback = make_callback(prepared.authorization_url(), "short-lived-code");
        let (_, mut session) = prepared.into_parts();
        let grant = session.finish(&callback).unwrap();
        assert_eq!(grant.code(), "short-lived-code");
        assert_eq!(grant.verifier().len(), 43);
        assert!(
            grant
                .verifier()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert!(!format!("{grant:?}").contains("short-lived-code"));
        assert!(matches!(
            session.finish(&callback),
            Err(OAuthError::AlreadyConsumed)
        ));
    }

    #[test]
    fn rejects_wrong_missing_and_duplicate_state_or_code() {
        let cases = [
            "?state=wrong&code=ok",
            "?code=ok",
            "?state=wrong&state=wrong&code=ok",
            "?state=wrong&code=one&code=two",
        ];
        for suffix in cases {
            let prepared = make_prepared(2);
            let mut callback = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
            callback.set_query(Some(suffix.trim_start_matches('?')));
            let (_, mut session) = prepared.into_parts();
            assert!(session.finish(&callback).is_err());
            assert!(matches!(
                session.finish(&callback),
                Err(OAuthError::AlreadyConsumed)
            ));
        }
    }

    #[test]
    fn rejects_conflicting_or_provider_error_outcomes() {
        let prepared = make_prepared(3);
        let returned_state = state(prepared.authorization_url());
        let mut conflicting = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        conflicting
            .query_pairs_mut()
            .append_pair("state", &returned_state)
            .append_pair("code", "code")
            .append_pair("error", "access_denied");
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&conflicting),
            Err(OAuthError::ConflictingCallback)
        ));

        let prepared = make_prepared(4);
        let returned_state = state(prepared.authorization_url());
        let mut rejected = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        rejected
            .query_pairs_mut()
            .append_pair("state", &returned_state)
            .append_pair("error", "access_denied");
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&rejected),
            Err(OAuthError::ProviderRejected)
        ));
    }

    #[test]
    fn rejects_missing_code_and_any_redirect_difference() {
        let prepared = make_prepared(8);
        let returned_state = state(prepared.authorization_url());
        let mut missing_code = Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap();
        missing_code
            .query_pairs_mut()
            .append_pair("state", &returned_state);
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&missing_code),
            Err(OAuthError::MissingParameter("code"))
        ));

        let prepared = make_prepared(11);
        let empty_code = make_callback(prepared.authorization_url(), "");
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&empty_code),
            Err(OAuthError::MissingParameter("code"))
        ));

        let prepared = make_prepared(9);
        let mut wrong_redirect = make_callback(prepared.authorization_url(), "code");
        wrong_redirect.set_path("/oauth/other");
        let (_, mut session) = prepared.into_parts();
        assert!(matches!(
            session.finish(&wrong_redirect),
            Err(OAuthError::RedirectMismatch)
        ));
    }

    #[test]
    fn cancellation_and_expiry_are_terminal() {
        let prepared = make_prepared(5);
        let callback = make_callback(prepared.authorization_url(), "code");
        let (_, mut cancelled) = prepared.into_parts();
        assert_eq!(cancelled.cancel(), Err(OAuthError::Cancelled));
        assert!(matches!(
            cancelled.finish(&callback),
            Err(OAuthError::AlreadyConsumed)
        ));

        let prepared = make_prepared(6);
        let callback = make_callback(prepared.authorization_url(), "code");
        let clock = prepared.session.clock.clone();
        let (_, mut expired) = prepared.into_parts();
        clock.advance(60);
        assert!(matches!(
            expired.finish(&callback),
            Err(OAuthError::Expired)
        ));
        assert!(matches!(
            expired.finish(&callback),
            Err(OAuthError::AlreadyConsumed)
        ));
    }

    #[test]
    fn concurrent_sessions_remain_isolated() {
        let first = make_prepared(10);
        let second = make_prepared(20);
        let first_callback = make_callback(first.authorization_url(), "first-code");
        let second_callback = make_callback(second.authorization_url(), "second-code");
        let (_, mut first_session) = first.into_parts();
        let (_, mut second_session) = second.into_parts();
        assert_eq!(
            first_session.finish(&first_callback).unwrap().code(),
            "first-code"
        );
        assert_eq!(
            second_session.finish(&second_callback).unwrap().code(),
            "second-code"
        );
    }
}
