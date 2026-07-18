// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded metadata-only mailbox search projections for narrow output adapters.

use std::fmt;

use tersa_domain::mailbox::{AccountId, MessageEnvelope};

use crate::mailbox::{BoxFuture, MailboxReader, MailboxStoreError, StoreLimit};
use crate::mailbox_metadata::MailboxMetadataMessage;

const MAX_QUERY_LEN: usize = 256;

/// Reports a rejected mailbox search query without exposing its content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MailboxSearchQueryError {
    /// The supplied query was empty.
    Empty,
    /// The supplied query exceeds its documented byte limit.
    TooLong {
        /// The rejected byte length.
        len: usize,
        /// The maximum accepted byte length.
        max_len: usize,
    },
    /// The supplied query contains a control character.
    InvalidCharacter,
}

impl fmt::Display for MailboxSearchQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "the search query must not be empty",
            Self::TooLong { .. } => "the search query exceeds its maximum length",
            Self::InvalidCharacter => "the search query contains an invalid character",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MailboxSearchQueryError {}

/// Holds a bounded mailbox search query without control characters.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxSearchQuery(String);

impl MailboxSearchQuery {
    /// The maximum accepted query length in bytes.
    pub const MAX_LEN: usize = MAX_QUERY_LEN;

    /// Creates a non-empty query without control characters.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxSearchQueryError`] if the query is empty, larger than
    /// [`Self::MAX_LEN`], or contains a Unicode control character.
    pub fn new<T: Into<String>>(value: T) -> Result<Self, MailboxSearchQueryError> {
        let value = value.into();
        if value.is_empty() {
            return Err(MailboxSearchQueryError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(MailboxSearchQueryError::TooLong {
                len: value.len(),
                max_len: Self::MAX_LEN,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(MailboxSearchQueryError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the query text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MailboxSearchQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MailboxSearchQuery([REDACTED])")
    }
}

/// Describes one metadata search result without serialization concerns.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxSearchDocument {
    account_id: AccountId,
    query: MailboxSearchQuery,
    limit: StoreLimit,
    messages: Vec<MailboxMetadataMessage>,
}

impl MailboxSearchDocument {
    fn new(
        account_id: AccountId,
        query: MailboxSearchQuery,
        limit: StoreLimit,
        envelopes: &[MessageEnvelope],
    ) -> Self {
        Self {
            account_id,
            query,
            limit,
            messages: envelopes
                .iter()
                .map(MailboxMetadataMessage::from_envelope)
                .collect(),
        }
    }

    /// Returns the opaque account identifier.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the validated search query.
    #[must_use]
    pub const fn query(&self) -> &MailboxSearchQuery {
        &self.query
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn limit(&self) -> StoreLimit {
        self.limit
    }

    /// Returns matched messages in the order supplied by the reader contract.
    #[must_use]
    pub fn messages(&self) -> &[MailboxMetadataMessage] {
        &self.messages
    }
}

impl fmt::Debug for MailboxSearchDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxSearchDocument")
            .field("account_id", &self.account_id)
            .field("query", &self.query)
            .field("limit", &self.limit)
            .field("message_count", &self.messages.len())
            .finish()
    }
}

/// Searches metadata while preserving the reader's deterministic order.
///
/// The scan reads the bounded full cache with one listing call. Matching is an
/// ASCII case-insensitive substring test over the sender and subject headers
/// only; preview and body content are never considered. Only the matched
/// results are truncated to the caller's limit.
pub fn search_metadata<'a>(
    reader: &'a dyn MailboxReader,
    account: &'a AccountId,
    query: &'a MailboxSearchQuery,
    limit: StoreLimit,
) -> BoxFuture<'a, Result<MailboxSearchDocument, MailboxStoreError>> {
    Box::pin(async move {
        reader
            .list_envelopes(account, full_scan_limit())
            .await
            .map(|envelopes| {
                let mut matched: Vec<MessageEnvelope> = envelopes
                    .into_iter()
                    .filter(|envelope| matches_query(envelope, query.as_str()))
                    .collect();
                matched.truncate(usize::from(limit.get()));
                MailboxSearchDocument::new(account.clone(), query.clone(), limit, &matched)
            })
    })
}

/// Returns the bounded full-cache scan limit used by metadata search.
fn full_scan_limit() -> StoreLimit {
    StoreLimit::new(StoreLimit::MAX).expect("`StoreLimit::MAX` is a valid store limit")
}

/// Reports whether the sender or subject header contains the query.
fn matches_query(envelope: &MessageEnvelope, query: &str) -> bool {
    contains_ascii_case_insensitive(envelope.from().as_str(), query)
        || contains_ascii_case_insensitive(envelope.subject().as_str(), query)
}

/// Reports whether `text` contains `query` as an ASCII case-insensitive
/// substring. [`MailboxSearchQuery`] guarantees `query` is non-empty, so
/// fixed-size windowing never panics.
fn contains_ascii_case_insensitive(text: &str, query: &str) -> bool {
    text.as_bytes()
        .windows(query.len())
        .any(|window| window.eq_ignore_ascii_case(query.as_bytes()))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Test fixtures use valid literals and fail immediately on unexpected results."
)]
mod tests {
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    use tersa_domain::mailbox::{HeaderText, MessageId, ThreadId, UnixTimestampMillis};

    use super::*;

    struct FakeReader {
        listed: Result<Vec<MessageEnvelope>, MailboxStoreError>,
        calls: AtomicUsize,
        last_limit: AtomicUsize,
    }

    impl FakeReader {
        fn successful(envelopes: Vec<MessageEnvelope>) -> Self {
            Self {
                listed: Ok(envelopes),
                calls: AtomicUsize::new(0),
                last_limit: AtomicUsize::new(0),
            }
        }

        fn failing(error: MailboxStoreError) -> Self {
            Self {
                listed: Err(error),
                calls: AtomicUsize::new(0),
                last_limit: AtomicUsize::new(0),
            }
        }
    }

    impl MailboxReader for FakeReader {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.last_limit
                .store(usize::from(limit.get()), Ordering::SeqCst);
            let result = self.listed.clone();
            Box::pin(async move { result })
        }

        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async move { Ok(Vec::new()) })
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

    fn query(value: &str) -> MailboxSearchQuery {
        MailboxSearchQuery::new(value).unwrap()
    }

    fn envelope(id: &str, from: &str, subject: &str, timestamp: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).unwrap(),
            thread(),
            HeaderText::new(from).unwrap(),
            HeaderText::new(subject).unwrap(),
            HeaderText::new("preview-secret").unwrap(),
            UnixTimestampMillis::new(timestamp).unwrap(),
            true,
        )
    }

    fn run<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("application search future must complete synchronously"),
        }
    }

    #[test]
    fn search_matches_the_from_header_with_one_scan() {
        let reader = FakeReader::successful(vec![
            envelope("hit", "alice@example.test", "weekly status", 20),
            envelope("miss", "bob@example.test", "weekly status", 10),
        ]);
        let document = run(search_metadata(
            &reader,
            &account(),
            &query("alice"),
            limit(),
        ))
        .unwrap();

        assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
        assert_eq!(document.account_id(), &account());
        assert_eq!(document.query(), &query("alice"));
        assert_eq!(document.limit(), limit());
        assert_eq!(document.messages().len(), 1);
        assert_eq!(document.messages()[0].message_id().as_str(), "hit");
        assert_eq!(document.messages()[0].thread_id(), &thread());
        assert_eq!(document.messages()[0].from().as_str(), "alice@example.test");
        assert_eq!(document.messages()[0].subject().as_str(), "weekly status");
        assert_eq!(document.messages()[0].received_at().as_millis(), 20);
        assert!(document.messages()[0].is_unread());
    }

    #[test]
    fn search_scans_the_full_cache_with_the_maximum_store_limit() {
        let reader = FakeReader::successful(Vec::new());
        let document = run(search_metadata(
            &reader,
            &account(),
            &query("alice"),
            limit(),
        ))
        .unwrap();

        assert!(document.messages().is_empty());
        assert_eq!(reader.last_limit.load(Ordering::SeqCst), 10_000);
    }

    #[test]
    fn search_matches_the_subject_header() {
        let reader = FakeReader::successful(vec![
            envelope("hit", "bob@example.test", "invoice from alice", 20),
            envelope("miss", "carol@example.test", "hello", 10),
        ]);
        let document = run(search_metadata(
            &reader,
            &account(),
            &query("invoice"),
            limit(),
        ))
        .unwrap();

        assert_eq!(document.messages().len(), 1);
        assert_eq!(document.messages()[0].message_id().as_str(), "hit");
    }

    #[test]
    fn search_is_ascii_case_insensitive_only() {
        let reader = FakeReader::successful(vec![
            envelope("upper", "ALICE@EXAMPLE.TEST", "status", 30),
            envelope("mixed", "bob@example.test", "Re: InVoIce", 20),
            envelope("accented", "carol@example.test", "Émile", 10),
        ]);

        let upper = run(search_metadata(
            &reader,
            &account(),
            &query("alice"),
            limit(),
        ))
        .unwrap();
        assert_eq!(
            upper
                .messages()
                .iter()
                .map(|message| message.message_id().as_str())
                .collect::<Vec<_>>(),
            ["upper"]
        );
        let mixed = run(search_metadata(
            &reader,
            &account(),
            &query("invoice"),
            limit(),
        ))
        .unwrap();
        assert_eq!(
            mixed
                .messages()
                .iter()
                .map(|message| message.message_id().as_str())
                .collect::<Vec<_>>(),
            ["mixed"]
        );
        let accented = run(search_metadata(
            &reader,
            &account(),
            &query("émile"),
            limit(),
        ))
        .unwrap();
        assert!(accented.messages().is_empty());
    }

    #[test]
    fn search_never_matches_preview_content() {
        let reader = FakeReader::successful(vec![envelope(
            "preview-only",
            "dan@example.test",
            "hello",
            10,
        )]);
        let document = run(search_metadata(
            &reader,
            &account(),
            &query("preview-secret"),
            limit(),
        ))
        .unwrap();

        assert!(document.messages().is_empty());
    }

    #[test]
    fn search_without_a_match_returns_an_empty_document() {
        let reader =
            FakeReader::successful(vec![envelope("miss", "erin@example.test", "hello", 10)]);
        let document = run(search_metadata(
            &reader,
            &account(),
            &query("absent"),
            limit(),
        ))
        .unwrap();

        assert!(document.messages().is_empty());
        assert_eq!(document.account_id(), &account());
        assert_eq!(document.limit(), limit());
    }

    #[test]
    fn search_truncates_matched_results_to_the_limit() {
        let reader = FakeReader::successful(vec![
            envelope("lead-miss", "bob@example.test", "status", 40),
            envelope("newest", "alice@example.test", "status", 30),
            envelope("mid-miss", "carol@example.test", "status", 25),
            envelope("middle", "alice@example.test", "status", 20),
            envelope("oldest", "alice@example.test", "status", 10),
        ]);
        let limit = StoreLimit::new(2).unwrap();
        let document = run(search_metadata(&reader, &account(), &query("alice"), limit)).unwrap();

        assert_eq!(document.limit(), limit);
        assert_eq!(
            document
                .messages()
                .iter()
                .map(|message| message.message_id().as_str())
                .collect::<Vec<_>>(),
            ["newest", "middle"]
        );
    }

    #[test]
    fn search_preserves_the_reader_order() {
        let reader = FakeReader::successful(vec![
            envelope("third", "alice@example.test", "status", 10),
            envelope("first", "alice@example.test", "status", 30),
            envelope("second", "alice@example.test", "status", 20),
        ]);
        let document = run(search_metadata(
            &reader,
            &account(),
            &query("alice"),
            limit(),
        ))
        .unwrap();

        assert_eq!(
            document
                .messages()
                .iter()
                .map(|message| message.message_id().as_str())
                .collect::<Vec<_>>(),
            ["third", "first", "second"]
        );
    }

    #[test]
    fn search_queries_enforce_bounds_and_redact_text() {
        assert_eq!(
            MailboxSearchQuery::new(""),
            Err(MailboxSearchQueryError::Empty)
        );
        assert!(MailboxSearchQuery::new("a".repeat(256)).is_ok());
        assert_eq!(
            MailboxSearchQuery::new("a".repeat(257)),
            Err(MailboxSearchQueryError::TooLong {
                len: 257,
                max_len: 256
            })
        );
        assert_eq!("é".repeat(128).len(), 256);
        assert!(MailboxSearchQuery::new("é".repeat(128)).is_ok());
        let overlong = format!("{}a", "é".repeat(128));
        assert_eq!(overlong.len(), 257);
        assert_eq!(
            MailboxSearchQuery::new(overlong),
            Err(MailboxSearchQueryError::TooLong {
                len: 257,
                max_len: 256
            })
        );
        assert_eq!(
            MailboxSearchQuery::new("bad\nvalue"),
            Err(MailboxSearchQueryError::InvalidCharacter)
        );
        assert_eq!(
            MailboxSearchQuery::new("bad\u{0085}value"),
            Err(MailboxSearchQueryError::InvalidCharacter)
        );
        let query = MailboxSearchQuery::new("query-sentinel").unwrap();
        assert_eq!(query.as_str(), "query-sentinel");
        let debug = format!("{query:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("query-sentinel"));
    }

    #[test]
    fn search_document_debug_is_structural_and_redacted() {
        let reader = FakeReader::successful(vec![envelope(
            "identifier-sentinel",
            "from-sentinel",
            "subject-sentinel",
            10,
        )]);
        let document = run(search_metadata(
            &reader,
            &account(),
            &query("query-sentinel"),
            limit(),
        ))
        .unwrap();
        let debug = format!("{document:?}");

        assert!(debug.contains("message_count"));
        assert!(!debug.contains("account-1"));
        assert!(!debug.contains("query-sentinel"));
        assert!(!debug.contains("identifier-sentinel"));
        assert!(!debug.contains("from-sentinel"));
        assert!(!debug.contains("subject-sentinel"));
    }

    #[test]
    fn storage_errors_pass_through_unchanged() {
        for error in [MailboxStoreError::Storage, MailboxStoreError::Corrupted] {
            let reader = FakeReader::failing(error);
            assert_eq!(
                run(search_metadata(
                    &reader,
                    &account(),
                    &query("alice"),
                    limit()
                )),
                Err(error)
            );
        }
    }

    #[test]
    fn dropping_an_unpolled_use_case_does_not_call_the_reader() {
        let reader = FakeReader::successful(Vec::new());
        let account = account();
        let query = query("alice");
        let future = search_metadata(&reader, &account, &query, limit());
        assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
        drop(future);
        assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
    }
}
