// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Terminal-safe text (ADR 0031).
//!
//! Every provider-derived string must become [`SafeText`] before it reaches a
//! terminal. Sanitizing removes the characters a terminal interprets as
//! commands or that can disguise text:
//!
//! - C0 controls except newline and tab (this includes ESC, which starts ANSI,
//!   OSC, DCS, and similar sequences), and DEL;
//! - C1 controls (U+0080–U+009F), which some terminals treat as 8-bit
//!   introducers such as CSI and OSC;
//! - bidirectional embedding, override, and isolate controls
//!   (U+202A–U+202E, U+2066–U+2069), used to reorder displayed text.

use std::fmt;

/// Text that is safe to write to a terminal.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SafeText(String);

impl SafeText {
    /// Sanitizes multi-line text, keeping newlines and tabs.
    #[must_use]
    pub fn multi_line(input: &str) -> Self {
        Self(
            input
                .chars()
                .filter(|&character| matches!(character, '\n' | '\t') || is_allowed(character))
                .collect(),
        )
    }

    /// Sanitizes text for a single line: newlines and tabs become spaces.
    #[must_use]
    pub fn single_line(input: &str) -> Self {
        Self(
            input
                .chars()
                .filter_map(|character| match character {
                    '\n' | '\r' | '\t' => Some(' '),
                    other if is_allowed(other) => Some(other),
                    _ => None,
                })
                .collect(),
        )
    }

    /// The sanitized text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

const fn is_allowed(character: char) -> bool {
    !matches!(
        character,
        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::SafeText;

    #[test]
    fn strips_escape_sequences_and_controls() {
        let hostile = "a\u{1b}]52;c;ZXZpbA==\u{7}b\u{1b}[2Jc\u{9b}31md\u{7f}e\u{0}";
        let safe = SafeText::multi_line(hostile);
        assert!(
            !safe
                .as_str()
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
        );
        assert_eq!(safe.as_str(), "a]52;c;ZXZpbA==b[2Jc31mde");
    }

    #[test]
    fn strips_bidi_controls() {
        assert_eq!(
            SafeText::single_line("invoice\u{202e}fdp.exe\u{2066}x\u{2069}").as_str(),
            "invoicefdp.exex"
        );
    }

    #[test]
    fn line_handling_differs_by_mode() {
        assert_eq!(SafeText::multi_line("a\r\nb\tc").as_str(), "a\nb\tc");
        assert_eq!(SafeText::single_line("a\r\nb\tc").as_str(), "a  b c");
    }

    #[test]
    fn keeps_ordinary_unicode() {
        assert_eq!(
            SafeText::single_line("Città → ok ✓").as_str(),
            "Città → ok ✓"
        );
    }
}
