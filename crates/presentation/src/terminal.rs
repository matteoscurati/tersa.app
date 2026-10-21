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
//! - bidirectional embeddings, overrides, and isolates (U+202A–U+202E,
//!   U+2066–U+2069) and marks (U+200E, U+200F, U+061C), used to reorder
//!   displayed text;
//! - zero-width and invisible formatting characters (U+200B–U+200D,
//!   U+2060–U+2064, U+FEFF, the soft hyphen U+00AD, the combining grapheme
//!   joiner U+034F, Hangul and Mongolian fillers and selectors) and the Tag
//!   block (U+E0000–U+E007F), used to hide content or pad previews;
//! - variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF). They switch emoji
//!   presentation, which terminals and width tables disagree on, so keeping
//!   them misaligns the screen.

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

/// Whether `character` survives sanitizing.
pub(crate) const fn is_allowed(character: char) -> bool {
    !matches!(
        character,
        '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{e0000}'..='\u{e007f}'
            | '\u{e0100}'..='\u{e01ef}'
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
    fn strips_bidi_marks_and_invisible_characters() {
        let hostile = "a\u{200e}b\u{200f}c\u{61c}d\u{200b}e\u{200d}f\u{2060}g\u{feff}h\u{e0041}i";
        assert_eq!(SafeText::single_line(hostile).as_str(), "abcdefghi");
    }

    #[test]
    fn strips_padding_fillers_and_variation_selectors() {
        let padded = "a\u{34f}\u{ad}b\u{3164}c\u{fe0f}d\u{e0100}e\u{2063}f";
        assert_eq!(SafeText::single_line(padded).as_str(), "abcdef");
        assert_eq!(
            SafeText::single_line("\u{2764}\u{fe0f}").as_str(),
            "\u{2764}"
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
