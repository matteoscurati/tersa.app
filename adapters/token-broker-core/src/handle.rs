// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The opaque authorization-session handle.
//!
//! A handle is 128 bits of injected entropy encoded URL-safe (no padding), so
//! it is never sequential and never guessable from a sibling session. It is
//! held in zeroizing memory, redacted in `Debug`, and is the ONLY value a
//! caller needs to complete an authorization.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use crate::error::BrokerError;
use crate::ports::SessionHandleEntropy;

/// The entropy size of one session handle, in bytes (128 bits).
pub const SESSION_HANDLE_BYTES: usize = 16;

/// The URL-safe-no-pad base64 length of a [`SESSION_HANDLE_BYTES`] handle.
const SESSION_HANDLE_LEN: usize = 22;

/// An opaque, cryptographically random authorization-session handle.
///
/// Opaque to callers: it identifies one pending session exactly once and
/// carries no account or session content. `Debug` redacts it.
pub struct SessionHandle(Zeroizing<String>);

impl SessionHandle {
    /// Allocates a handle from the injected entropy source.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Unavailable`] when the entropy source fails.
    pub(crate) fn generate<E: SessionHandleEntropy>(entropy: &E) -> Result<Self, BrokerError> {
        let bytes = Zeroizing::new(entropy.handle_bytes()?);
        Ok(Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(*bytes))))
    }

    /// Validates handle text previously returned by
    /// [`PendingAuthorization::session_handle`](crate::PendingAuthorization::session_handle).
    ///
    /// Accepts only the exact shape this crate mints: 22 URL-safe base64
    /// characters. A malformed handle is rejected BEFORE any registry access,
    /// so it can never collide with a live session.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] when the text is not exactly the
    /// minted handle shape.
    pub fn parse(text: &str) -> Result<Self, BrokerError> {
        let well_formed = text.len() == SESSION_HANDLE_LEN
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if !well_formed {
            return Err(BrokerError::InvalidInput);
        }
        Ok(Self(Zeroizing::new(text.to_owned())))
    }

    /// Returns the opaque handle text without transferring ownership.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionHandle([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::collections::HashSet;

    use super::{SESSION_HANDLE_BYTES, SESSION_HANDLE_LEN, SessionHandle};
    use crate::error::BrokerError;
    use crate::ports::GetRandomEntropy;

    #[test]
    fn production_handles_are_unique_url_safe_and_redacted() {
        let entropy = GetRandomEntropy;
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let handle = SessionHandle::generate(&entropy).unwrap();
            let text = handle.as_str();
            assert_eq!(text.len(), SESSION_HANDLE_LEN);
            assert!(
                text.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            );
            assert!(seen.insert(text.to_owned()), "handles must never repeat");
            assert!(!format!("{handle:?}").contains(text));
        }
    }

    #[test]
    fn parse_accepts_only_the_exact_minted_shape() {
        let entropy = GetRandomEntropy;
        let handle = SessionHandle::generate(&entropy).unwrap();
        let round_tripped = SessionHandle::parse(handle.as_str()).unwrap();
        assert_eq!(round_tripped.as_str(), handle.as_str());

        let mut short = handle.as_str().to_owned();
        short.pop();
        let long = format!("{}A", handle.as_str());
        let bad_charset = format!("{}+", &handle.as_str()[..SESSION_HANDLE_LEN - 1]);
        for invalid in ["", &short, &long, &bad_charset, "======================"] {
            // Compare the result shape, not the value: `SessionHandle`
            // deliberately has no equality, so no secret-bearing `PartialEq`
            // exists solely for tests.
            assert!(
                matches!(
                    SessionHandle::parse(invalid),
                    Err(BrokerError::InvalidInput)
                ),
                "a malformed handle must fail closed as InvalidInput"
            );
        }
        // The source length is a constant, not derived from the handle text.
        const { assert!(SESSION_HANDLE_BYTES * 8 >= 128) };
    }
}
