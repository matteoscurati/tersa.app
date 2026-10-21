// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Display-width-aware text wrapping and truncation.

use unicode_width::UnicodeWidthChar;

const TAB_STOP: usize = 4;

fn char_width(character: char) -> usize {
    character.width().unwrap_or(0)
}

/// The display width of `text`.
pub fn width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// Cuts `text` to at most `max` display columns, ending in `…` when cut.
pub fn truncate(text: &str, max: usize) -> String {
    if width(text) <= max {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut used = 0;
    for character in text.chars() {
        let next = char_width(character);
        if used + next + 1 > max {
            break;
        }
        out.push(character);
        used += next;
    }
    if max > 0 {
        out.push('…');
    }
    out
}

/// Wraps `text` to `columns` display columns, breaking at spaces when it
/// can and inside words when it must. Tabs expand to the next tab stop and
/// leading indentation is kept.
pub fn wrap(text: &str, columns: usize) -> Vec<String> {
    let columns = columns.max(1);
    let mut lines = Vec::new();
    for source in text.split('\n') {
        wrap_line(source, columns, &mut lines);
    }
    lines
}

fn wrap_line(source: &str, columns: usize, lines: &mut Vec<String>) {
    let mut line = String::new();
    let mut line_width = 0;
    // Byte offset in `line` just after the last space, and the width there.
    let mut last_space: Option<(usize, usize)> = None;
    for character in source.chars() {
        if character == '\t' {
            let spaces = TAB_STOP - line_width % TAB_STOP;
            for _ in 0..spaces {
                push_char(
                    ' ',
                    columns,
                    lines,
                    &mut line,
                    &mut line_width,
                    &mut last_space,
                );
            }
            continue;
        }
        push_char(
            character,
            columns,
            lines,
            &mut line,
            &mut line_width,
            &mut last_space,
        );
    }
    lines.push(line);
}

fn push_char(
    character: char,
    columns: usize,
    lines: &mut Vec<String>,
    line: &mut String,
    line_width: &mut usize,
    last_space: &mut Option<(usize, usize)>,
) {
    let added = char_width(character);
    if *line_width + added > columns && *line_width > 0 {
        if character == ' ' {
            // The line is full exactly here; the space becomes the break.
            lines.push(line.trim_end().to_owned());
            line.clear();
            *line_width = 0;
            *last_space = None;
            return;
        }
        match last_space.take() {
            Some((at, width_at)) if at < line.len() => {
                let rest = line.split_off(at);
                lines.push(line.trim_end().to_owned());
                *line = rest;
                *line_width -= width_at;
            }
            _ => {
                lines.push(line.trim_end().to_owned());
                line.clear();
                *line_width = 0;
            }
        }
    }
    line.push(character);
    *line_width += added;
    if character == ' ' {
        *last_space = Some((line.len(), *line_width));
    }
}

#[cfg(test)]
mod tests {
    use super::{truncate, width, wrap};

    #[test]
    fn wraps_at_spaces_and_inside_long_words() {
        assert_eq!(wrap("the quick brown fox", 9), ["the quick", "brown fox"]);
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("a\n\nb", 10), ["a", "", "b"]);
        assert_eq!(
            wrap("  indented text here", 10),
            ["  indented", "text here"]
        );
    }

    #[test]
    fn counts_display_width_and_expands_tabs() {
        assert_eq!(width("日本"), 4);
        assert_eq!(wrap("日本語の文", 4), ["日本", "語の", "文"]);
        assert_eq!(wrap("a\tb", 10), ["a   b"]);
    }

    #[test]
    fn truncates_by_display_width() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 6), "hello…");
        assert_eq!(truncate("日本語", 4), "日…");
        assert_eq!(truncate("abc", 0), "");
    }
}
