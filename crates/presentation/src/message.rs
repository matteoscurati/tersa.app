// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Terminal rendering of cached RFC 5322 messages (ADR 0031).
//!
//! MIME structure, transfer encodings, charsets, and encoded header words are
//! decoded by `mail-parser`. HTML bodies go through [`crate::html`], so nothing
//! remote is ever fetched. Every string leaves this module as [`SafeText`].

use std::fmt::{self, Write as _};

use mail_parser::{Address, MessageParser, MessagePart, MimeHeaders};

use crate::html::{self, html_to_text};
use crate::terminal::SafeText;

/// The most addresses shown per header.
pub const MAX_ADDRESSES: usize = 50;
/// The most attachments listed.
pub const MAX_ATTACHMENTS: usize = 100;
/// The largest plain-text body shown.
pub const MAX_PLAIN_OUTPUT: usize = html::MAX_TEXT_OUTPUT;
const TRUNCATED: &str = "[… message truncated]";
const UNREADABLE: &str = "This message could not be read.";

/// Which body the reader would rather see.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BodyPreference {
    /// The plain-text part, falling back to converted HTML.
    #[default]
    Plain,
    /// Converted HTML, falling back to the plain-text part.
    Html,
}

/// Which body was rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyFormat {
    /// A `text/plain` part.
    Plain,
    /// A `text/html` part converted to text.
    Html,
}

/// An attachment as listed to the reader. Nothing is opened or saved here.
#[derive(Clone, Eq, PartialEq)]
pub struct AttachmentSummary {
    /// The file name the sender gave, sanitized.
    pub name: SafeText,
    /// The declared MIME type, such as `application/pdf`.
    pub mime_type: SafeText,
    /// The decoded size in bytes.
    pub size: usize,
}

/// A message ready for display.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedMessage {
    /// The decoded subject.
    pub subject: SafeText,
    /// `From`, as `Name <address>` entries.
    pub from: SafeText,
    /// `To`, as `Name <address>` entries.
    pub to: SafeText,
    /// `Cc`, as `Name <address>` entries.
    pub cc: SafeText,
    /// The body text; may contain newlines and tabs.
    pub body: SafeText,
    /// The part the body came from, or `None` when there is no readable body.
    pub format: Option<BodyFormat>,
    /// Whether the other body format also exists, so the reader can switch.
    pub has_alternative: bool,
    /// Link targets referenced as `[n]` in an HTML body.
    pub links: Vec<SafeText>,
    /// The message's attachments.
    pub attachments: Vec<AttachmentSummary>,
}

impl fmt::Debug for AttachmentSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentSummary")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RenderedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Message content is personal data; keep it out of logs.
        formatter
            .debug_struct("RenderedMessage")
            .field("format", &self.format)
            .field("body_len", &self.body.as_str().len())
            .field("links", &self.links.len())
            .field("attachments", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

/// Renders a raw RFC 5322 message for the terminal.
#[must_use]
pub fn render_message(raw: &[u8], preference: BodyPreference) -> RenderedMessage {
    let Some(message) = MessageParser::default().parse(raw) else {
        return RenderedMessage {
            subject: SafeText::default(),
            from: SafeText::default(),
            to: SafeText::default(),
            cc: SafeText::default(),
            body: SafeText::multi_line(UNREADABLE),
            format: None,
            has_alternative: false,
            links: Vec::new(),
            attachments: Vec::new(),
        };
    };
    let plain = message
        .text_bodies()
        .find(|part| !part.is_text_html())
        .and_then(MessagePart::text_contents)
        .filter(|text| !text.trim().is_empty());
    let html = message
        .html_bodies()
        .find(|part| part.is_text_html())
        .and_then(MessagePart::text_contents)
        .filter(|text| !text.trim().is_empty());
    let chosen = match (preference, plain, html) {
        (BodyPreference::Html, _, Some(html)) | (BodyPreference::Plain, None, Some(html)) => {
            Some(BodyFormat::Html).zip(Some(html))
        }
        (_, Some(plain), _) => Some(BodyFormat::Plain).zip(Some(plain)),
        (_, None, None) => None,
    };
    let (body, links) = match chosen {
        Some((BodyFormat::Plain, text)) => (plain_text(text), Vec::new()),
        Some((BodyFormat::Html, text)) => {
            let converted = html_to_text(text);
            (converted.text, converted.links)
        }
        None => (String::new(), Vec::new()),
    };
    let attachments = message
        .attachments()
        .take(MAX_ATTACHMENTS)
        .map(|part| AttachmentSummary {
            name: SafeText::single_line(part.attachment_name().unwrap_or("(unnamed)")),
            mime_type: SafeText::single_line(&part.content_type().map_or_else(
                || "application/octet-stream".to_owned(),
                |kind| match kind.subtype() {
                    Some(subtype) => format!("{}/{subtype}", kind.ctype()),
                    None => kind.ctype().to_owned(),
                },
            )),
            size: part.len(),
        })
        .collect();
    RenderedMessage {
        subject: SafeText::single_line(message.subject().unwrap_or_default()),
        from: addresses(message.from()),
        to: addresses(message.to()),
        cc: addresses(message.cc()),
        body: SafeText::multi_line(&body),
        format: chosen.map(|(format, _)| format),
        has_alternative: plain.is_some() && html.is_some(),
        links: links
            .iter()
            .map(|link| SafeText::single_line(link))
            .collect(),
        attachments,
    }
}

/// Normalizes line endings, trims trailing spaces, and caps the size.
fn plain_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_PLAIN_OUTPUT));
    for line in text.split('\n') {
        let line = line.trim_end();
        if out.len() + line.len() + 1 > MAX_PLAIN_OUTPUT {
            out.push_str(TRUNCATED);
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim_end().to_owned()
}

fn addresses(header: Option<&Address<'_>>) -> SafeText {
    let Some(header) = header else {
        return SafeText::default();
    };
    let mut parts: Vec<String> = Vec::new();
    let mut total = 0_usize;
    for entry in header.iter() {
        total += 1;
        if parts.len() == MAX_ADDRESSES {
            continue;
        }
        let name = entry.name().map(str::trim).filter(|name| !name.is_empty());
        let address = entry
            .address()
            .map(str::trim)
            .filter(|address| !address.is_empty());
        parts.push(match (name, address) {
            (Some(name), Some(address)) if name != address => format!("{name} <{address}>"),
            (_, Some(address)) => address.to_owned(),
            (Some(name), None) => name.to_owned(),
            (None, None) => continue,
        });
    }
    let mut joined = parts.join(", ");
    if total > MAX_ADDRESSES {
        let _ = write!(joined, ", … and {} more", total - MAX_ADDRESSES);
    }
    SafeText::single_line(&joined)
}

#[cfg(test)]
mod tests {
    use super::{BodyFormat, BodyPreference, render_message};

    const ALTERNATIVE: &[u8] = b"From: =?utf-8?q?Ren=C3=A9e?= <renee@example.com>\r\n\
To: a@example.com, \"B, Person\" <b@example.com>\r\n\
Subject: =?utf-8?B?Q2lhbyDwn5GL?=\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain; charset=iso-8859-1\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Caff=E8 at 10?   \r\n\
\r\n\
--b\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PHA+Q2FmZsOoIDxhIGhyZWY9Imh0dHBzOi8vZXhhbXBsZS5jb20iPmF0IDEwPC9hPj88L3A+\r\n\
--b--\r\n";

    #[test]
    fn decodes_headers_charsets_and_transfer_encodings() {
        let plain = render_message(ALTERNATIVE, BodyPreference::Plain);
        assert_eq!(plain.subject.as_str(), "Ciao 👋");
        assert_eq!(plain.from.as_str(), "Renée <renee@example.com>");
        assert_eq!(
            plain.to.as_str(),
            "a@example.com, B, Person <b@example.com>"
        );
        assert_eq!(plain.body.as_str(), "Caffè at 10?");
        assert_eq!(plain.format, Some(BodyFormat::Plain));
        assert!(plain.has_alternative);
        assert!(plain.links.is_empty());

        let html = render_message(ALTERNATIVE, BodyPreference::Html);
        assert_eq!(html.body.as_str(), "Caffè at 10 [1]?");
        assert_eq!(html.format, Some(BodyFormat::Html));
        assert_eq!(html.links[0].as_str(), "https://example.com");
    }

    #[test]
    fn html_only_messages_fall_back_to_converted_html() {
        let raw = b"Subject: s\r\nContent-Type: text/html\r\n\r\n<p>only <b>html</b></p>";
        let rendered = render_message(raw, BodyPreference::Plain);
        assert_eq!(rendered.body.as_str(), "only html");
        assert_eq!(rendered.format, Some(BodyFormat::Html));
        assert!(!rendered.has_alternative);
    }

    #[test]
    fn terminal_controls_are_removed_everywhere() {
        let raw = "Subject: \u{1b}]0;pwned\u{7}hi\u{202e}x\r\n\
From: \"\u{1b}[31mEvil\" <e@example.com>\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\n\
safe\u{1b}[2J\u{9b}31m text\u{200b}\r\n";
        let rendered = render_message(raw.as_bytes(), BodyPreference::Plain);
        for text in [&rendered.subject, &rendered.from, &rendered.body] {
            assert!(
                !text.as_str().chars().any(|character| character == '\u{1b}'
                    || character == '\u{9b}'
                    || character == '\u{7}'
                    || character == '\u{202e}'
                    || character == '\u{200b}'),
                "{:?}",
                text.as_str()
            );
        }
        assert_eq!(rendered.body.as_str(), "safe[2J31m text");
    }

    #[test]
    fn attachments_are_listed_not_opened() {
        let raw = b"Subject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
--x\r\nContent-Type: application/pdf; name=\"../../etc/\x1b[0mreport.pdf\"\r\n\
Content-Disposition: attachment\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n";
        let rendered = render_message(raw, BodyPreference::Plain);
        assert_eq!(rendered.body.as_str(), "see attached");
        assert_eq!(rendered.attachments.len(), 1);
        let attachment = &rendered.attachments[0];
        assert_eq!(attachment.mime_type.as_str(), "application/pdf");
        assert_eq!(attachment.size, 5);
        assert!(!attachment.name.as_str().contains('\u{1b}'));
    }

    #[test]
    fn garbage_and_empty_input_do_not_panic() {
        for raw in [
            &b""[..],
            b"\xff\xfe\x00",
            b"no headers at all",
            b"Content-Type: multipart/mixed\r\n\r\n--",
        ] {
            let rendered = render_message(raw, BodyPreference::Html);
            assert!(rendered.body.as_str().len() < 1024);
        }
    }

    #[test]
    fn redacted_debug_output() {
        let rendered = render_message(ALTERNATIVE, BodyPreference::Plain);
        let debug = format!("{rendered:?}");
        assert!(!debug.contains("Caff"));
        assert!(!debug.contains("renee"));
    }
}
