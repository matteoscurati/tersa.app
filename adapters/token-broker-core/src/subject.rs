// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Validated account-subject text used to key refresh-token storage.
//!
//! The validation is a conservative Google-subject shape: nonempty visible
//! ASCII capped at 255 bytes. Digits are expected (a Google `sub` is ~21
//! digits) but not required — the shape must not assume an email or a
//! numeric-only form.

use std::fmt;

use crate::error::BrokerError;

/// Caps the accepted subject length, matching the token layer's cap.
const MAX_SUBJECT_LEN: usize = 255;

/// Account-subject text that passed the conservative shape validation.
///
/// Not a secret, but account-identifying: redacted in `Debug` and never
/// logged. Constructing one is proof the text is nonempty visible ASCII of at
/// most 255 bytes, so the store port never sees an arbitrary caller string.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedSubject(String);

impl ValidatedSubject {
    /// Validates conservative Google-subject text.
    ///
    /// Accepts only nonempty visible ASCII (`!` through `~`: no space,
    /// control, or DEL characters) of at most 255 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidInput`] when the text is empty,
    /// oversized, or contains a non-visible or non-ASCII character.
    pub fn new<T: Into<String>>(text: T) -> Result<Self, BrokerError> {
        let text = text.into();
        let visible_ascii = text.bytes().all(|byte| byte.is_ascii_graphic());
        if text.is_empty() || text.len() > MAX_SUBJECT_LEN || !visible_ascii {
            return Err(BrokerError::InvalidInput);
        }
        Ok(Self(text))
    }

    /// Returns the validated subject text without transferring ownership.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ValidatedSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedSubject([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use super::{BrokerError, MAX_SUBJECT_LEN, ValidatedSubject};

    #[test]
    fn accepts_conservative_google_subject_shapes() {
        for valid in ["110169484474386276334", "subject-xyz", "~!123"] {
            let subject = ValidatedSubject::new(valid).unwrap();
            assert_eq!(subject.as_str(), valid);
        }
        let longest = "1".repeat(MAX_SUBJECT_LEN);
        assert!(ValidatedSubject::new(longest).is_ok());
    }

    #[test]
    fn rejects_empty_oversized_and_non_visible_text() {
        let oversized = "1".repeat(MAX_SUBJECT_LEN + 1);
        for invalid in [
            "",
            "has space",
            "tab\tsubject",
            "newline\nsubject",
            "del\u{7f}subject",
            "unicode-ø-subject",
            oversized.as_str(),
        ] {
            assert_eq!(
                ValidatedSubject::new(invalid),
                Err(BrokerError::InvalidInput)
            );
        }
    }

    #[test]
    fn debug_redacts_the_subject() {
        let subject = ValidatedSubject::new("110169484474386276334").unwrap();
        let rendered = format!("{subject:?}");
        assert!(!rendered.contains("110169484474386276334"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
