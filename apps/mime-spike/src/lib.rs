// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded MIME display selection and HTML sanitization diagnostic primitives.
//!
//! This crate is feasibility code, not a production mail renderer. It accepts
//! only synthetic MIME input supplied by its caller, validates it with
//! `mail-parser`, then applies a second bounded traversal before producing a
//! deny-by-default `SafeHtml` value. It never performs I/O or resolves URLs.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;

use ammonia::Builder;
use mail_parser::MessageParser;

/// Maximum resource use accepted by the diagnostic traversal.
///
/// These limits are intentionally small because this code establishes a
/// fail-closed feasibility boundary, rather than a production throughput goal.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Limits {
    /// Rejects the complete encoded message before invoking any parser.
    pub input_bytes: usize,
    /// Rejects a MIME tree deeper than this number of multipart containers.
    pub nesting: usize,
    /// Rejects more leaf or multipart MIME parts than this number.
    pub parts: usize,
    /// Rejects more header fields in an individual part than this number.
    pub header_count: usize,
    /// Rejects header sections larger than this number of bytes.
    pub header_bytes: usize,
    /// Rejects a decoded candidate display part larger than this number of bytes.
    pub decoded_display_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 512 * 1024,
            nesting: 12,
            parts: 128,
            header_count: 96,
            header_bytes: 24 * 1024,
            decoded_display_bytes: 256 * 1024,
        }
    }
}

/// A deterministic category for a rejected synthetic message.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ErrorCategory {
    /// The encoded message crossed the pre-parse byte cap.
    InputLimit,
    /// A header section crossed a configured limit or was structurally invalid.
    HeaderLimit,
    /// MIME syntax, boundaries, or the parser's validation result was invalid.
    MalformedMime,
    /// A declared MIME nesting or part count crossed a configured limit.
    TraversalLimit,
    /// A display part decoded beyond the configured byte cap.
    DecodedDisplayLimit,
    /// A transfer encoding is unsupported or malformed.
    Encoding,
    /// A display part is not valid UTF-8 or declares an unsupported charset.
    Charset,
    /// No non-attachment text/plain or text/html display part was available.
    NoDisplayPart,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputLimit => "input_limit",
            Self::HeaderLimit => "header_limit",
            Self::MalformedMime => "malformed_mime",
            Self::TraversalLimit => "traversal_limit",
            Self::DecodedDisplayLimit => "decoded_display_limit",
            Self::Encoding => "encoding",
            Self::Charset => "charset",
            Self::NoDisplayPart => "no_display_part",
        })
    }
}

impl std::error::Error for ErrorCategory {}

/// Sanitized HTML which is safe only for the diagnostic display boundary.
///
/// The inner HTML is private so callers cannot accidentally bypass the
/// sanitizer. It contains no URL-bearing attributes; CID values are surfaced
/// separately as inert typed placeholders.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SafeHtml(String);

impl SafeHtml {
    /// Returns the sanitized, URL-free diagnostic HTML fragment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns a deterministic non-cryptographic diagnostic hash.
    #[must_use]
    pub fn diagnostic_hash(&self) -> u64 {
        stable_hash(self.0.as_bytes())
    }
}

/// An inert reference to a MIME content identifier removed from display HTML.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CidPlaceholder(String);

impl CidPlaceholder {
    /// Returns the normalized content identifier without a URL scheme.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.0
    }
}

/// The safe display result selected from a synthetic MIME message.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DisplayDocument {
    html: SafeHtml,
    cid_placeholders: Vec<CidPlaceholder>,
    source: DisplaySource,
}

impl DisplayDocument {
    /// Returns the deny-by-default sanitized HTML fragment.
    #[must_use]
    pub fn html(&self) -> &SafeHtml {
        &self.html
    }

    /// Returns inert CID placeholders removed from the HTML fragment.
    #[must_use]
    pub fn cid_placeholders(&self) -> &[CidPlaceholder] {
        &self.cid_placeholders
    }

    /// Returns the MIME representation selected for display.
    #[must_use]
    pub fn source(&self) -> DisplaySource {
        self.source
    }
}

/// The representation chosen for the display document.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DisplaySource {
    /// A safe `text/html` part was selected from the MIME tree.
    Html,
    /// No safe HTML was available, so `text/plain` was escaped for display.
    PlainText,
}

/// Processes one synthetic MIME message under deterministic resource limits.
///
/// # Errors
///
/// Returns a stable [`ErrorCategory`] for input, header, MIME traversal,
/// decoding, charset, or display-selection failure. No error contains input
/// bytes or parser diagnostics.
pub fn inspect_synthetic_mime(
    input: &[u8],
    limits: Limits,
) -> Result<DisplayDocument, ErrorCategory> {
    if input.len() > limits.input_bytes {
        return Err(ErrorCategory::InputLimit);
    }

    // This is a validation gate only. The bounded traversal below deliberately
    // does not retain parser-owned trees, protecting this diagnostic from parser
    // graph shape changes such as cyclic MIME references.
    MessageParser::default()
        .parse(input)
        .ok_or(ErrorCategory::MalformedMime)?;

    let mut budget = Budget::new(limits);
    let root = parse_part(input, 0, &mut budget)?;
    let candidate = select_display(&root).ok_or(ErrorCategory::NoDisplayPart)?;
    let cid_placeholders = extract_cid_placeholders(&candidate.body);
    let html = match candidate.kind {
        DisplaySource::Html => sanitize_html(&candidate.body),
        DisplaySource::PlainText => {
            SafeHtml(format!("<pre>{}</pre>", escape_html(&candidate.body)))
        }
    };
    Ok(DisplayDocument {
        html,
        cid_placeholders,
        source: candidate.kind,
    })
}

#[derive(Debug)]
struct Budget {
    limits: Limits,
    parts: usize,
}

impl Budget {
    fn new(limits: Limits) -> Self {
        Self { limits, parts: 0 }
    }

    fn visit(&mut self, depth: usize) -> Result<(), ErrorCategory> {
        if depth > self.limits.nesting {
            return Err(ErrorCategory::TraversalLimit);
        }
        self.parts = self
            .parts
            .checked_add(1)
            .ok_or(ErrorCategory::TraversalLimit)?;
        if self.parts > self.limits.parts {
            return Err(ErrorCategory::TraversalLimit);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Part {
    content_type: ContentType,
    attachment: bool,
    body: Vec<u8>,
    children: Vec<Part>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ContentType {
    MultipartAlternative,
    MultipartOther,
    TextHtml,
    TextPlain,
    Other,
}

#[derive(Debug, Clone)]
struct Candidate {
    kind: DisplaySource,
    body: String,
}

fn parse_part(input: &[u8], depth: usize, budget: &mut Budget) -> Result<Part, ErrorCategory> {
    budget.visit(depth)?;
    let (headers, body) = parse_headers(input, budget.limits)?;
    let content_type_value = headers
        .get("content-type")
        .map_or("text/plain", String::as_str);
    let content_type = parse_content_type(content_type_value);
    let attachment = headers
        .get("content-disposition")
        .is_some_and(|value| value.to_ascii_lowercase().contains("attachment"));

    if matches!(content_type, ContentType::TextHtml | ContentType::TextPlain)
        && !supported_charset(content_type_value)
    {
        return Err(ErrorCategory::Charset);
    }

    if matches!(
        content_type,
        ContentType::MultipartAlternative | ContentType::MultipartOther
    ) {
        let boundary =
            boundary_parameter(content_type_value).ok_or(ErrorCategory::MalformedMime)?;
        let chunks = split_multipart(body, &boundary)?;
        let children = chunks
            .iter()
            .map(|chunk| parse_part(chunk, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Part {
            content_type,
            attachment,
            body: Vec::new(),
            children,
        });
    }

    Ok(Part {
        content_type,
        attachment,
        // Only display candidates are decoded or retained. Attachment and other
        // body bytes never influence the display cap or safe HTML output.
        body: (!attachment
            && matches!(content_type, ContentType::TextHtml | ContentType::TextPlain))
        .then(|| {
            decode_display_body(
                body,
                headers.get("content-transfer-encoding"),
                budget.limits,
            )
        })
        .transpose()?
        .unwrap_or_default(),
        children: Vec::new(),
    })
}

fn parse_headers(
    input: &[u8],
    limits: Limits,
) -> Result<(std::collections::BTreeMap<String, String>, &[u8]), ErrorCategory> {
    let separator = input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| (index, 4))
        .or_else(|| {
            input
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| (index, 2))
        })
        .ok_or(ErrorCategory::MalformedMime)?;
    let (header_end, separator_len) = separator;
    if header_end > limits.header_bytes {
        return Err(ErrorCategory::HeaderLimit);
    }
    let header_text =
        std::str::from_utf8(&input[..header_end]).map_err(|_error| ErrorCategory::MalformedMime)?;
    let mut headers = std::collections::BTreeMap::<String, String>::new();
    let mut count = 0_usize;
    let mut previous_name: Option<String> = None;
    for line in header_text.lines() {
        if line.starts_with([' ', '\t']) {
            let name = previous_name.as_ref().ok_or(ErrorCategory::MalformedMime)?;
            let value = headers.get_mut(name).ok_or(ErrorCategory::MalformedMime)?;
            value.push(' ');
            value.push_str(line.trim());
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(ErrorCategory::MalformedMime)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ErrorCategory::MalformedMime);
        }
        count = count.checked_add(1).ok_or(ErrorCategory::HeaderLimit)?;
        if count > limits.header_count {
            return Err(ErrorCategory::HeaderLimit);
        }
        let name = name.to_ascii_lowercase();
        headers.insert(name.clone(), value.trim().to_owned());
        previous_name = Some(name);
    }
    Ok((headers, &input[(header_end + separator_len)..]))
}

fn parse_content_type(value: &str) -> ContentType {
    match value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "multipart/alternative" => ContentType::MultipartAlternative,
        value if value.starts_with("multipart/") => ContentType::MultipartOther,
        "text/html" => ContentType::TextHtml,
        "text/plain" => ContentType::TextPlain,
        _ => ContentType::Other,
    }
}

fn boundary_parameter(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.trim().split_once('=')?;
        (name.trim().eq_ignore_ascii_case("boundary"))
            .then(|| value.trim().trim_matches('"').to_owned())
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 70
                    && value.bytes().all(|byte| byte.is_ascii_graphic())
            })
    })
}

fn supported_charset(content_type: &str) -> bool {
    content_type.split(';').skip(1).all(|parameter| {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            return true;
        };
        !name.trim().eq_ignore_ascii_case("charset")
            || matches!(
                value.trim().trim_matches('"').to_ascii_lowercase().as_str(),
                "utf-8" | "us-ascii"
            )
    })
}

fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Result<Vec<&'a [u8]>, ErrorCategory> {
    let marker = format!("--{boundary}");
    let marker = marker.as_bytes();
    let mut parts = Vec::new();
    let mut current: Option<usize> = None;
    let mut closed = false;
    for line in body.split_inclusive(|byte| *byte == b'\n') {
        let line_start = body[..].as_ptr() as usize;
        let piece_start = line.as_ptr() as usize - line_start;
        let trimmed = line.trim_ascii_end();
        if trimmed == marker {
            if let Some(start) = current.replace(piece_start + line.len()) {
                parts.push(trim_mime_newline(&body[start..piece_start]));
            }
        } else if trimmed == [marker, b"--".as_slice()].concat() {
            if let Some(start) = current.take() {
                parts.push(trim_mime_newline(&body[start..piece_start]));
            }
            closed = true;
            break;
        }
    }
    if !closed || parts.is_empty() {
        return Err(ErrorCategory::MalformedMime);
    }
    Ok(parts)
}

fn trim_mime_newline(mut bytes: &[u8]) -> &[u8] {
    if bytes.ends_with(b"\r\n") {
        bytes = &bytes[..bytes.len() - 2];
    } else if bytes.ends_with(b"\n") {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn decode_body(
    body: &[u8],
    transfer_encoding: Option<&String>,
    limits: Limits,
) -> Result<Vec<u8>, ErrorCategory> {
    let encoding = transfer_encoding
        .map_or("7bit", |value| value.as_str())
        .trim()
        .to_ascii_lowercase();
    let decoded = match encoding.as_str() {
        "7bit" | "8bit" | "binary" | "" => body.to_vec(),
        "base64" => decode_base64(body)?,
        "quoted-printable" => decode_quoted_printable(body)?,
        _ => return Err(ErrorCategory::Encoding),
    };
    if decoded.len() > limits.decoded_display_bytes {
        return Err(ErrorCategory::DecodedDisplayLimit);
    }
    Ok(decoded)
}

fn decode_display_body(
    body: &[u8],
    transfer_encoding: Option<&String>,
    limits: Limits,
) -> Result<Vec<u8>, ErrorCategory> {
    let decoded = decode_body(body, transfer_encoding, limits)?;
    std::str::from_utf8(&decoded).map_err(|_error| ErrorCategory::Charset)?;
    Ok(decoded)
}

fn decode_base64(input: &[u8]) -> Result<Vec<u8>, ErrorCategory> {
    let compact = input
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if compact.len() % 4 != 0 {
        return Err(ErrorCategory::Encoding);
    }
    let mut output = Vec::with_capacity(compact.len() / 4 * 3);
    for chunk in compact.chunks_exact(4) {
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = (chunk[2] != b'=')
            .then(|| base64_value(chunk[2]))
            .transpose()?
            .unwrap_or(0);
        let d = (chunk[3] != b'=')
            .then(|| base64_value(chunk[3]))
            .transpose()?
            .unwrap_or(0);
        if chunk[2] == b'=' && chunk[3] != b'=' {
            return Err(ErrorCategory::Encoding);
        }
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, ErrorCategory> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(ErrorCategory::Encoding),
    }
}

fn decode_quoted_printable(input: &[u8]) -> Result<Vec<u8>, ErrorCategory> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] != b'=' {
            output.push(input[index]);
            index += 1;
        } else if input.get(index + 1) == Some(&b'\r') && input.get(index + 2) == Some(&b'\n') {
            index += 3;
        } else if input.get(index + 1) == Some(&b'\n') {
            index += 2;
        } else {
            let high = *input.get(index + 1).ok_or(ErrorCategory::Encoding)?;
            let low = *input.get(index + 2).ok_or(ErrorCategory::Encoding)?;
            output.push((hex_value(high)? << 4) | hex_value(low)?);
            index += 3;
        }
    }
    Ok(output)
}

fn hex_value(byte: u8) -> Result<u8, ErrorCategory> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ErrorCategory::Encoding),
    }
}

fn select_display(part: &Part) -> Option<Candidate> {
    if part.attachment {
        return None;
    }
    match part.content_type {
        ContentType::TextHtml => decode_text(part).map(|body| Candidate {
            kind: DisplaySource::Html,
            body,
        }),
        ContentType::TextPlain => decode_text(part).map(|body| Candidate {
            kind: DisplaySource::PlainText,
            body,
        }),
        ContentType::MultipartAlternative => {
            let candidates = part
                .children
                .iter()
                .filter_map(select_display)
                .collect::<Vec<_>>();
            candidates
                .iter()
                .rev()
                .find(|candidate| candidate.kind == DisplaySource::Html)
                .or_else(|| {
                    candidates
                        .iter()
                        .rev()
                        .find(|candidate| candidate.kind == DisplaySource::PlainText)
                })
                .cloned()
        }
        ContentType::MultipartOther => part.children.iter().find_map(select_display),
        ContentType::Other => None,
    }
}

fn decode_text(part: &Part) -> Option<String> {
    String::from_utf8(part.body.clone()).ok()
}

fn sanitize_html(input: &str) -> SafeHtml {
    let tags = HashSet::from([
        "a",
        "b",
        "blockquote",
        "br",
        "code",
        "em",
        "i",
        "li",
        "ol",
        "p",
        "pre",
        "span",
        "strong",
        "ul",
    ]);
    let cleaned = Builder::default()
        .tags(tags)
        .generic_attributes(HashSet::<&str>::new())
        .tag_attributes(HashMap::<&str, HashSet<&str>>::new())
        .clean(input)
        .to_string();
    SafeHtml(cleaned)
}

fn extract_cid_placeholders(input: &str) -> Vec<CidPlaceholder> {
    let lower = input.to_ascii_lowercase();
    let mut placeholders = Vec::new();
    let mut start = 0;
    while let Some(offset) = lower[start..].find("cid:") {
        let value_start = start + offset + 4;
        let value_end = input[value_start..]
            .find(|character: char| {
                character.is_ascii_whitespace() || matches!(character, '\"' | '\'' | '>' | '<')
            })
            .map_or(input.len(), |offset| value_start + offset);
        let identifier = input[value_start..value_end].trim_matches(['<', '>']);
        if !identifier.is_empty() && identifier.len() <= 255 {
            placeholders.push(CidPlaceholder(identifier.to_owned()));
        }
        start = value_end;
    }
    placeholders.sort_by(|left, right| left.0.cmp(&right.0));
    placeholders.dedup_by(|left, right| left.0 == right.0);
    placeholders
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&#39;")
}

fn stable_hash(input: &[u8]) -> u64 {
    input.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

// Rust guideline compliant 1.0.

#[cfg(test)]
mod tests {
    use super::*;

    const ALTERNATIVE: &str = "Content-Type: multipart/alternative; boundary=outer\r\n\r\n--outer\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlain fallback\r\n--outer\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello <strong>safe</strong></p>\r\n--outer--\r\n";

    fn inspect(input: &str) -> Result<DisplayDocument, ErrorCategory> {
        inspect_synthetic_mime(input.as_bytes(), Limits::default())
    }

    #[test]
    fn alternative_prefers_safe_html_deterministically() {
        let first = inspect(ALTERNATIVE).expect("synthetic alternative must parse");
        let second = inspect(ALTERNATIVE).expect("synthetic alternative must parse");
        assert_eq!(first, second);
        assert_eq!(first.source(), DisplaySource::Html);
        assert_eq!(
            first.html().diagnostic_hash(),
            second.html().diagnostic_hash()
        );
    }

    #[test]
    fn hostile_corpus_never_panics_and_only_returns_categories() {
        let nested_bomb = nested_multipart(20);
        let corpus = [
            "Content-Type: multipart/alternative; boundary=missing\r\n\r\n--wrong--\r\n",
            "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n%%%",
            "Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=QZ",
            "Content-Type: text/plain; charset=iso-2022-jp\r\n\r\ntext",
            "X-Good: one\r\nInjected header\r\n\r\nbody",
            "Content-Type: image/html\r\n\r\nnot displayable",
            "Content-Type: text/html\r\n\r\n<svg><script>alert(1)</script></svg><p onclick=\"x()\">safe</p>",
            "Content-Type: text/html\r\n\r\n<style>p{background:url(https://bad.example/x)}</style><form action=https://bad.example><input></form>",
            "Content-Type: text/html\r\n\r\n<meta http-equiv=refresh content=\"0;https://bad.example\"><img src=https://bad.example/pixel>",
            "Content-Type: text/html\r\n\r\n<a href=javascript:alert(1)>x</a><a href=data:text/html,x>y</a><a href=file:///tmp/x>z</a>",
            "Content-Type: text/html\r\n\r\n<img src=cid:part-1@example.invalid><p>safe</p>",
            nested_bomb.as_str(),
        ];
        for message in corpus {
            let first = std::panic::catch_unwind(|| inspect(message));
            let second = std::panic::catch_unwind(|| inspect(message));
            assert!(first.is_ok());
            assert!(second.is_ok());
            assert_eq!(first.expect("no panic"), second.expect("no panic"));
        }
    }

    #[test]
    fn limits_fail_precisely_before_parser_or_traversal() {
        let limits = Limits {
            input_bytes: 4,
            ..Limits::default()
        };
        assert_eq!(
            inspect_synthetic_mime(b"Content-Type: text/plain\r\n\r\nok", limits),
            Err(ErrorCategory::InputLimit)
        );
        let limits = Limits {
            header_count: 1,
            ..Limits::default()
        };
        assert_eq!(
            inspect_synthetic_mime(b"A: one\r\nB: two\r\n\r\nok", limits),
            Err(ErrorCategory::HeaderLimit)
        );
        let nested = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nok\r\n--b--\r\n";
        let limits = Limits {
            parts: 1,
            ..Limits::default()
        };
        assert_eq!(
            inspect_synthetic_mime(nested.as_bytes(), limits),
            Err(ErrorCategory::TraversalLimit)
        );
        let limits = Limits {
            decoded_display_bytes: 2,
            ..Limits::default()
        };
        assert_eq!(
            inspect_synthetic_mime(b"Content-Type: text/plain\r\n\r\nthree", limits),
            Err(ErrorCategory::DecodedDisplayLimit)
        );
        assert_eq!(
            inspect_synthetic_mime(
                b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\ntext",
                Limits::default()
            ),
            Err(ErrorCategory::Charset)
        );
    }

    #[test]
    fn attachment_bodies_are_excluded_and_plain_text_falls_back() {
        let attachment = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\nContent-Disposition: attachment\r\n\r\n<p>attachment-secret</p>\r\n--b\r\nContent-Type: text/plain\r\n\r\nvisible\r\n--b--\r\n";
        let output = inspect(attachment).expect("plain display part must be selected");
        assert_eq!(output.source(), DisplaySource::PlainText);
        assert!(!output.html().as_str().contains("attachment-secret"));
        assert!(output.html().as_str().contains("visible"));
    }

    #[test]
    fn sanitizer_removes_active_and_remote_content_and_keeps_cid_inert() {
        let output = inspect("Content-Type: text/html\r\n\r\n<script>x</script><svg><path></path></svg><p onclick=\"x()\">ok</p><style>p{background:url(https://bad.example/x)}</style><form><input></form><meta http-equiv=refresh><img src=https://bad.example/p><img src=cid:one@example.invalid><a href=https://bad.example>r</a><a href=javascript:x>j</a><a href=data:x>d</a><a href=file:///x>f</a>").expect("HTML must sanitize");
        let html = output.html().as_str();
        for forbidden in [
            "script",
            "svg",
            "onclick",
            "style",
            "form",
            "meta",
            "https:",
            "javascript:",
            "data:",
            "file:",
            "src=",
            "href=",
        ] {
            assert!(!html.to_ascii_lowercase().contains(forbidden));
        }
        assert_eq!(
            output.cid_placeholders(),
            &[CidPlaceholder("one@example.invalid".to_owned())]
        );
    }

    fn nested_multipart(depth: usize) -> String {
        if depth == 0 {
            return "Content-Type: text/plain\r\n\r\nleaf".to_owned();
        }
        format!(
            "Content-Type: multipart/mixed; boundary=b{depth}\r\n\r\n--b{depth}\r\n{}\r\n--b{depth}--\r\n",
            nested_multipart(depth - 1)
        )
    }
}

// Rust guideline compliant 1.0.
