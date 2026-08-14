// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! UI-neutral mailbox view models projected from metadata documents.

use std::fmt;

use tersa_application::mailbox_metadata::{
    MailboxMetadataCommand, MailboxMetadataDocument, MailboxMetadataMessage,
};
use tersa_application::mailbox_search::MailboxSearchDocument;
use tersa_domain::mailbox::ThreadId;

/// Reports a rejected mailbox view-model projection without exposing content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MailboxViewModelError {
    /// The document command did not match the requested view model.
    UnexpectedCommand,
}

impl fmt::Display for MailboxViewModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the document command does not match the requested view model")
    }
}

impl std::error::Error for MailboxViewModelError {}

/// Holds one owned mailbox row with the stable metadata field parity.
///
/// Values are projected verbatim: no date formatting and no output escaping,
/// which remain the output adapter's responsibility. `body_text` / `body_html`
/// are optional display payloads derived from a cached complete message.
#[derive(Clone, Eq, PartialEq)]
pub struct MessageRowViewModel {
    /// The opaque message identifier.
    pub message_id: String,
    /// The opaque thread identifier.
    pub thread_id: String,
    /// The sender header text.
    pub from: String,
    /// The subject header text.
    pub subject: String,
    /// The provider preview/snippet text.
    pub preview: String,
    /// Optional plain-text body for display when a cached complete message is present.
    pub body_text: Option<String>,
    /// Optional unsanitized HTML extracted from a `text/html` part.
    ///
    /// The current UI does not decode or render this field. Any future renderer
    /// requires a separately approved `SafeHtml` boundary.
    pub body_html: Option<String>,
    /// Milliseconds since the Unix epoch.
    pub received_at_millis: i64,
    /// Whether the message is unread.
    pub unread: bool,
}

impl MessageRowViewModel {
    /// Projects one metadata message into an owned view row without a body.
    #[must_use]
    pub fn from_message(message: &MailboxMetadataMessage) -> Self {
        Self {
            message_id: message.message_id().as_str().to_owned(),
            thread_id: message.thread_id().as_str().to_owned(),
            from: message.from().as_str().to_owned(),
            subject: message.subject().as_str().to_owned(),
            preview: message.preview().as_str().to_owned(),
            body_text: None,
            body_html: None,
            received_at_millis: message.received_at().as_millis(),
            unread: message.is_unread(),
        }
    }

    /// Projects one metadata message and attaches plain + HTML display bodies.
    #[must_use]
    pub fn from_message_with_body(
        message: &MailboxMetadataMessage,
        body_bytes: Option<&[u8]>,
    ) -> Self {
        let mut row = Self::from_message(message);
        if let Some(bytes) = body_bytes {
            let text = display_text_from_rfc5322(bytes);
            if !text.is_empty() {
                row.body_text = Some(text);
            }
            let html = display_html_from_rfc5322(bytes);
            if !html.is_empty() {
                row.body_html = Some(html);
            }
        }
        row
    }
}

impl fmt::Debug for MessageRowViewModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageRowViewModel")
            .field("message_id", &"[REDACTED]")
            .field("thread_id", &"[REDACTED]")
            .field("from", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("preview", &"[REDACTED]")
            .field("body_text", &self.body_text.as_ref().map(|_| "[REDACTED]"))
            .field("body_html", &self.body_html.as_ref().map(|_| "[REDACTED]"))
            .field("received_at_millis", &self.received_at_millis)
            .field("unread", &self.unread)
            .finish()
    }
}

/// Maximum characters of body text exposed to the UI from a cached raw message.
const MAX_DISPLAY_BODY_CHARS: usize = 32_768;

/// Derives bounded plain-text display content from a cached RFC 5322 message.
///
/// Conservative offline extraction only:
/// - prefers the first `text/plain` MIME part and stops at the next boundary
/// - fully decodes quoted-printable (`=XX` and soft line breaks)
/// - never renders HTML, never loads remote resources
///
/// This is not a full MIME library: base64 parts, nested multiparts beyond the
/// first plain part, and HTML-only messages fall back to best-effort text.
#[must_use]
pub fn display_text_from_rfc5322(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    decode_mime_text_part(text.as_ref(), "content-type: text/plain", true)
}

/// Derives bounded unsanitized HTML from a cached RFC 5322 message.
///
/// Extracts the first `text/html` MIME part (quoted-printable decoded). The
/// current UI must not decode or render this output. This function does not
/// sanitize HTML tags; any future renderer requires a separately approved
/// `SafeHtml` boundary.
#[must_use]
pub fn display_html_from_rfc5322(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    decode_mime_text_part(text.as_ref(), "content-type: text/html", false)
}

fn decode_mime_text_part(
    message: &str,
    content_type_marker: &str,
    fallback_top_level: bool,
) -> String {
    let Some((part_headers, part_body)) =
        extract_mime_part(message, content_type_marker, fallback_top_level)
    else {
        return String::new();
    };
    let decoded = if part_is_quoted_printable(part_headers) || looks_quoted_printable(part_body) {
        decode_quoted_printable(part_body)
    } else if part_is_base64(part_headers) {
        // Base64 bodies are common for HTML; leave undecoded rather than
        // emitting unreadable binary-looking text in the UI.
        return String::new();
    } else {
        part_body.to_owned()
    };
    let normalized = decoded.replace("\r\n", "\n").replace('\r', "\n");
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    trimmed.chars().take(MAX_DISPLAY_BODY_CHARS).collect()
}

fn strip_rfc5322_headers(message: &str) -> (&str, &str) {
    if let Some(index) = message.find("\r\n\r\n") {
        return (&message[..index], &message[index + 4..]);
    }
    if let Some(index) = message.find("\n\n") {
        return (&message[..index], &message[index + 2..]);
    }
    ("", message)
}

/// Returns `(part_headers, part_body)` for the first MIME part matching `marker`.
///
/// When `fallback_top_level` is true and no matching part is found, the top-level
/// body is returned (single-part plain messages). HTML extraction never falls
/// back to the top-level body unless it is itself marked as HTML.
fn extract_mime_part<'a>(
    message: &'a str,
    content_type_marker: &str,
    fallback_top_level: bool,
) -> Option<(&'a str, &'a str)> {
    let (top_headers, top_body) = strip_rfc5322_headers(message);
    let lowered = message.to_ascii_lowercase();
    let top_lower = top_headers.to_ascii_lowercase();

    if let Some(part_at) = lowered.find(content_type_marker) {
        let after_type = &message[part_at..];
        let (part_headers, part_body) = strip_rfc5322_headers(after_type);
        let boundary = mime_boundary(top_headers).or_else(|| mime_boundary(message));
        let part_body = if let Some(boundary) = boundary {
            let marker = format!("--{boundary}");
            if let Some(end) = part_body.find(&marker) {
                &part_body[..end]
            } else {
                part_body
            }
        } else {
            // No boundary: cut before a sibling part header when present.
            let part_lower = part_body.to_ascii_lowercase();
            let sibling = [
                "content-type: text/html",
                "content-type: text/plain",
                "------=",
            ]
            .into_iter()
            .filter_map(|needle| {
                // Skip the current part's own residual headers if any.
                part_lower.find(needle).filter(|&at| at > 0)
            })
            .min();
            if let Some(at) = sibling {
                &part_body[..at]
            } else {
                part_body
            }
        };
        return Some((part_headers, part_body));
    }

    if fallback_top_level {
        // Single-part plain (or unmarked) body.
        if top_lower.contains("content-type: text/html") {
            return None;
        }
        return Some((top_headers, top_body));
    }

    // HTML requested: allow single-part HTML top-level messages.
    if top_lower.contains("content-type: text/html") {
        return Some((top_headers, top_body));
    }
    None
}

fn part_is_base64(headers: &str) -> bool {
    headers
        .to_ascii_lowercase()
        .contains("content-transfer-encoding: base64")
}

fn mime_boundary(headers_or_message: &str) -> Option<String> {
    let lowered = headers_or_message.to_ascii_lowercase();
    let key = "boundary=";
    let idx = lowered.find(key)?;
    let rest = headers_or_message[idx + key.len()..].trim_start();
    let rest = rest
        .strip_prefix('"')
        .or_else(|| rest.strip_prefix('\''))
        .unwrap_or(rest);
    let end = rest
        .find(|c: char| {
            c == '"' || c == '\'' || c == ';' || c == '\r' || c == '\n' || c.is_whitespace()
        })
        .unwrap_or(rest.len());
    let boundary = rest[..end].trim();
    if boundary.is_empty() {
        None
    } else {
        Some(boundary.to_owned())
    }
}

fn part_is_quoted_printable(headers: &str) -> bool {
    headers
        .to_ascii_lowercase()
        .contains("content-transfer-encoding: quoted-printable")
}

fn looks_quoted_printable(body: &str) -> bool {
    // LinkedIn digests and many marketing mails ship soft breaks / =XX without
    // always being easy to re-parse from part headers alone.
    body.contains("=\r\n")
        || body.contains("=\n")
        || body.contains("=20")
        || body.contains("=3D")
        || body.contains("=C2=")
        || body.contains("=F0=")
}

/// RFC 2045 quoted-printable decoder (soft breaks + `=HH` hex bytes).
fn decode_quoted_printable(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 1 < bytes.len() && (bytes[i + 1] == b'\n') {
                i += 2;
                continue;
            }
            if i + 2 < bytes.len() && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                let hi = hex_nibble(bytes[i + 1]);
                let lo = hex_nibble(bytes[i + 2]);
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
            // Lone '=' — keep as-is (malformed input).
            out.push(b'=');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

/// Holds an owned inbox listing ready for a platform presentation adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct InboxViewModel {
    account_id: String,
    limit: u16,
    rows: Vec<MessageRowViewModel>,
}

impl InboxViewModel {
    /// Projects an inbox metadata document into an owned view model.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxViewModelError::UnexpectedCommand`] if the document
    /// does not represent the inbox command.
    pub fn from_document(
        document: &MailboxMetadataDocument,
    ) -> Result<Self, MailboxViewModelError> {
        if document.command() != MailboxMetadataCommand::Inbox {
            return Err(MailboxViewModelError::UnexpectedCommand);
        }
        Ok(Self {
            account_id: document.account_id().as_str().to_owned(),
            limit: document.limit().get(),
            rows: rows_from_document(document),
        })
    }

    /// Returns the opaque account identifier.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// Returns whether the view model has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Returns the projected rows in document order.
    #[must_use]
    pub fn rows(&self) -> &[MessageRowViewModel] {
        &self.rows
    }
}

impl fmt::Debug for InboxViewModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboxViewModel")
            .field("account_id", &"[REDACTED]")
            .field("limit", &self.limit)
            .field("row_count", &self.rows.len())
            .finish()
    }
}

/// Holds an owned thread listing ready for a platform presentation adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct ThreadViewModel {
    account_id: String,
    thread_id: String,
    limit: u16,
    rows: Vec<MessageRowViewModel>,
}

impl ThreadViewModel {
    /// Projects a thread metadata document into an owned view model.
    ///
    /// An empty thread is a valid view model; mapping an absent thread to a
    /// not-found outcome belongs to a later adapter.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxViewModelError::UnexpectedCommand`] if the document
    /// does not represent the thread command.
    pub fn from_document(
        document: &MailboxMetadataDocument,
        thread_id: &ThreadId,
    ) -> Result<Self, MailboxViewModelError> {
        if document.command() != MailboxMetadataCommand::Thread {
            return Err(MailboxViewModelError::UnexpectedCommand);
        }
        Ok(Self {
            account_id: document.account_id().as_str().to_owned(),
            thread_id: thread_id.as_str().to_owned(),
            limit: document.limit().get(),
            rows: rows_from_document(document),
        })
    }

    /// Builds a thread view model from already-projected rows.
    ///
    /// Used by the trusted composition after attaching cached body display text
    /// and applying local mark-as-read.
    #[must_use]
    pub fn from_rows(
        account_id: String,
        thread_id: String,
        limit: u16,
        rows: Vec<MessageRowViewModel>,
    ) -> Self {
        Self {
            account_id,
            thread_id,
            limit,
            rows,
        }
    }

    /// Returns the opaque account identifier.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the requested opaque thread identifier.
    #[must_use]
    pub fn thread_id(&self) -> &str {
        &self.thread_id
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// Returns whether the view model has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Returns the projected rows in document order.
    #[must_use]
    pub fn rows(&self) -> &[MessageRowViewModel] {
        &self.rows
    }
}

impl fmt::Debug for ThreadViewModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreadViewModel")
            .field("account_id", &"[REDACTED]")
            .field("thread_id", &"[REDACTED]")
            .field("limit", &self.limit)
            .field("row_count", &self.rows.len())
            .finish()
    }
}

/// Holds an owned search result listing ready for a platform presentation adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct SearchViewModel {
    account_id: String,
    query: String,
    limit: u16,
    rows: Vec<MessageRowViewModel>,
}

impl SearchViewModel {
    /// Projects a metadata search document into an owned view model.
    ///
    /// An empty result is a valid view model; mapping an absent result to a
    /// not-found outcome belongs to a later adapter.
    #[must_use]
    pub fn from_document(document: &MailboxSearchDocument) -> Self {
        Self {
            account_id: document.account_id().as_str().to_owned(),
            query: document.query().as_str().to_owned(),
            limit: document.limit().get(),
            rows: document
                .messages()
                .iter()
                .map(MessageRowViewModel::from_message)
                .collect(),
        }
    }

    /// Returns the opaque account identifier.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the submitted search query text.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// Returns whether the view model has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Returns the projected rows in document order.
    #[must_use]
    pub fn rows(&self) -> &[MessageRowViewModel] {
        &self.rows
    }
}

impl fmt::Debug for SearchViewModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchViewModel")
            .field("account_id", &"[REDACTED]")
            .field("query", &"[REDACTED]")
            .field("limit", &self.limit)
            .field("row_count", &self.rows.len())
            .finish()
    }
}

/// Projects every document message into an owned view row, preserving order.
fn rows_from_document(document: &MailboxMetadataDocument) -> Vec<MessageRowViewModel> {
    document
        .messages()
        .iter()
        .map(MessageRowViewModel::from_message)
        .collect()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Test fixtures use valid literals and fail immediately on unexpected results."
)]
mod tests {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use tersa_application::mailbox::{BoxFuture, MailboxReader, MailboxStoreError, StoreLimit};
    use tersa_application::mailbox_metadata::{inbox_metadata, thread_metadata};
    use tersa_application::mailbox_search::{MailboxSearchQuery, search_metadata};
    use tersa_domain::mailbox::{
        AccountId, HeaderText, Message, MessageEnvelope, MessageId, UnixTimestampMillis,
    };

    use super::*;

    struct FakeReader {
        envelopes: Vec<MessageEnvelope>,
    }

    impl MailboxReader for FakeReader {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let result = Ok(self.envelopes.clone());
            Box::pin(async move { result })
        }

        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let result = Ok(self.envelopes.clone());
            Box::pin(async move { result })
        }

        fn get_message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async move { Ok(None) })
        }
    }

    fn account() -> AccountId {
        AccountId::new("account-1").unwrap()
    }

    fn thread() -> ThreadId {
        ThreadId::new("thread-1").unwrap()
    }

    fn limit() -> StoreLimit {
        StoreLimit::new(50).unwrap()
    }

    fn envelope(id: &str, timestamp: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).unwrap(),
            thread(),
            HeaderText::new(format!("from-{id}")).unwrap(),
            HeaderText::new(format!("subject-{id}")).unwrap(),
            HeaderText::new(format!("preview-{id}")).unwrap(),
            UnixTimestampMillis::new(timestamp).unwrap(),
            true,
        )
    }

    #[test]
    fn display_text_strips_headers_and_prefers_plain_part() {
        let raw = b"From: a@b\r\nSubject: s\r\n\r\nHello body\r\n";
        assert_eq!(display_text_from_rfc5322(raw), "Hello body");

        let multipart = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n\
--b\r\nContent-Type: text/html\r\n\r\n<html>x</html>\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nPlain body\r\n--b--\r\n";
        assert_eq!(display_text_from_rfc5322(multipart), "Plain body");
    }

    #[test]
    fn display_text_decodes_quoted_printable_and_stops_before_html() {
        let raw = b"Content-Type: multipart/alternative; boundary=\"----=_Part_1\"\r\n\r\n\
------=_Part_1\r\n\
Content-Type: text/plain;charset=UTF-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
You appeared in 19 searches this week.=20\r\n\
It's a Dutch company: =F0=9F=87=B3=F0=9F=87=B1\r\n\
link?x=3D1\r\n\
------=_Part_1\r\n\
Content-Type: text/html;charset=UTF-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
<html xmlns=3D\"http://www.w3.org/1999/xhtml\">body</html>\r\n\
------=_Part_1--\r\n";
        let text = display_text_from_rfc5322(raw);
        assert!(text.contains("You appeared in 19 searches this week."));
        assert!(text.contains("It's a Dutch company:"));
        assert!(text.contains("link?x=1"));
        assert!(!text.contains("=20"));
        assert!(!text.contains("=3D"));
        assert!(!text.contains("<html"));
        assert!(!text.contains("Content-Type: text/html"));

        let html = display_html_from_rfc5322(raw);
        assert!(html.contains("<html xmlns=\"http://www.w3.org/1999/xhtml\">body</html>"));
        assert!(!html.contains("=3D"));
        assert!(!html.contains("You appeared in 19 searches"));
    }

    #[test]
    fn row_projection_carries_preview_and_optional_body() {
        let document = inbox_document(vec![envelope("m1", 1)]);
        let message = &document.messages()[0];
        let row = MessageRowViewModel::from_message(message);
        assert_eq!(row.preview, "preview-m1");
        assert!(row.body_text.is_none());

        let with_body = MessageRowViewModel::from_message_with_body(
            message,
            Some(b"From: x\r\n\r\nCached body"),
        );
        assert_eq!(with_body.body_text.as_deref(), Some("Cached body"));
    }

    fn run<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("application metadata future must complete synchronously"),
        }
    }

    fn inbox_document(envelopes: Vec<MessageEnvelope>) -> MailboxMetadataDocument {
        let reader = FakeReader { envelopes };
        run(inbox_metadata(&reader, &account(), limit())).unwrap()
    }

    fn thread_document(envelopes: Vec<MessageEnvelope>) -> MailboxMetadataDocument {
        let reader = FakeReader { envelopes };
        run(thread_metadata(&reader, &account(), &thread(), limit())).unwrap()
    }

    fn search_document(envelopes: Vec<MessageEnvelope>, query: &str) -> MailboxSearchDocument {
        let reader = FakeReader { envelopes };
        let query = MailboxSearchQuery::new(query).unwrap();
        run(search_metadata(&reader, &account(), &query, limit())).unwrap()
    }

    #[test]
    fn search_view_model_projects_every_document_field() {
        let document = search_document(
            vec![
                MessageEnvelope::new(
                    MessageId::new("hit").unwrap(),
                    thread(),
                    HeaderText::new("alice@example.test").unwrap(),
                    HeaderText::new("weekly status").unwrap(),
                    HeaderText::new("preview-hit").unwrap(),
                    UnixTimestampMillis::new(20).unwrap(),
                    false,
                ),
                envelope("miss", 10),
            ],
            "alice",
        );
        let model = SearchViewModel::from_document(&document);

        assert_eq!(model.account_id(), "account-1");
        assert_eq!(model.query(), "alice");
        assert_eq!(model.limit(), 50);
        assert!(!model.is_empty());
        assert_eq!(model.rows().len(), 1);
        let row = &model.rows()[0];
        assert_eq!(row.message_id, "hit");
        assert_eq!(row.thread_id, "thread-1");
        assert_eq!(row.from, "alice@example.test");
        assert_eq!(row.subject, "weekly status");
        assert_eq!(row.received_at_millis, 20);
        assert!(!row.unread);
    }

    #[test]
    fn empty_search_document_produces_an_empty_view_model() {
        let model = SearchViewModel::from_document(&search_document(Vec::new(), "alice"));
        assert!(model.is_empty());
        assert!(model.rows().is_empty());
        assert_eq!(model.query(), "alice");
        assert_eq!(model.limit(), 50);
    }

    #[test]
    fn search_view_model_debug_redacts_account_query_and_rows() {
        let document = search_document(vec![envelope("msgid-secret", 10)], "msgid-secret");
        let model = SearchViewModel::from_document(&document);
        let debug = format!("{model:?} {:?}", model.rows()[0]);

        assert!(debug.contains("row_count"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("account-1"));
        assert!(!debug.contains("query-secret"));
        assert!(!debug.contains("msgid-secret"));
        assert!(!debug.contains("from-msgid-secret"));
        assert!(!debug.contains("subject-msgid-secret"));
    }

    #[test]
    fn inbox_view_model_projects_every_document_field() {
        let document = inbox_document(vec![envelope("newest", 20), envelope("older", 10)]);
        let model = InboxViewModel::from_document(&document).unwrap();

        assert_eq!(model.account_id(), "account-1");
        assert_eq!(model.limit(), 50);
        assert!(!model.is_empty());
        assert_eq!(model.rows().len(), 2);
        let row = &model.rows()[0];
        assert_eq!(row.message_id, "newest");
        assert_eq!(row.thread_id, "thread-1");
        assert_eq!(row.from, "from-newest");
        assert_eq!(row.subject, "subject-newest");
        assert_eq!(row.received_at_millis, 20);
        assert!(row.unread);
        assert_eq!(model.rows()[1].message_id, "older");
    }

    #[test]
    fn thread_view_model_projects_fields_and_threads_the_requested_id() {
        let document = thread_document(vec![envelope("oldest", 10), envelope("newer", 20)]);
        let requested = ThreadId::new("thread-1").unwrap();
        let model = ThreadViewModel::from_document(&document, &requested).unwrap();

        assert_eq!(model.account_id(), "account-1");
        assert_eq!(model.thread_id(), "thread-1");
        assert_eq!(model.limit(), 50);
        assert!(!model.is_empty());
        assert_eq!(model.rows().len(), 2);
        assert_eq!(model.rows()[0].message_id, "oldest");
        assert_eq!(model.rows()[0].thread_id, "thread-1");
        assert_eq!(model.rows()[0].received_at_millis, 10);
    }

    #[test]
    fn view_models_reject_a_mismatched_document_command() {
        let inbox_document = inbox_document(Vec::new());
        assert_eq!(
            ThreadViewModel::from_document(&inbox_document, &thread()),
            Err(MailboxViewModelError::UnexpectedCommand)
        );
        let thread_document = thread_document(Vec::new());
        assert_eq!(
            InboxViewModel::from_document(&thread_document),
            Err(MailboxViewModelError::UnexpectedCommand)
        );
    }

    #[test]
    fn empty_documents_produce_empty_view_models() {
        let inbox = InboxViewModel::from_document(&inbox_document(Vec::new())).unwrap();
        assert!(inbox.is_empty());
        assert!(inbox.rows().is_empty());

        let thread = ThreadViewModel::from_document(&thread_document(Vec::new()), &thread())
            .expect("an empty thread is a valid view model");
        assert!(thread.is_empty());
        assert!(thread.rows().is_empty());
        assert_eq!(thread.thread_id(), "thread-1");
    }

    #[test]
    fn debug_output_is_structural_and_redacted() {
        let account = AccountId::new("acct-secret").unwrap();
        let thread = ThreadId::new("thrd-secret").unwrap();
        let envelopes = vec![MessageEnvelope::new(
            MessageId::new("msgid-secret").unwrap(),
            thread.clone(),
            HeaderText::new("fromtext-secret").unwrap(),
            HeaderText::new("subjtext-secret").unwrap(),
            HeaderText::new("prevtext-secret").unwrap(),
            UnixTimestampMillis::new(10).unwrap(),
            true,
        )];
        let reader = FakeReader { envelopes };
        let inbox_document = run(inbox_metadata(&reader, &account, limit())).unwrap();
        let thread_document = run(thread_metadata(&reader, &account, &thread, limit())).unwrap();
        let inbox = InboxViewModel::from_document(&inbox_document).unwrap();
        let thread = ThreadViewModel::from_document(&thread_document, &thread).unwrap();
        let debug = format!("{inbox:?} {thread:?} {:?}", inbox.rows()[0]);

        assert!(debug.contains("row_count"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("acct-secret"));
        assert!(!debug.contains("thrd-secret"));
        assert!(!debug.contains("msgid-secret"));
        assert!(!debug.contains("fromtext-secret"));
        assert!(!debug.contains("subjtext-secret"));
        assert!(!debug.contains("prevtext-secret"));
    }
}
