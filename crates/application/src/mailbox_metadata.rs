// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

//! Portable metadata-only mailbox projections for narrow output adapters.

use std::fmt;

use tersa_domain::mailbox::{
    AccountId, HeaderText, MessageEnvelope, MessageId, ThreadId, UnixTimestampMillis,
};

use crate::mailbox::{BoxFuture, MailboxReader, MailboxStoreError, StoreLimit};

/// The stable metadata document schema version.
pub const MAILBOX_METADATA_SCHEMA_VERSION: u16 = 1;

/// Identifies the metadata operation represented by one document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxMetadataCommand {
    /// A bounded recent-envelope listing.
    Inbox,
    /// A bounded listing for one thread.
    Thread,
}

impl MailboxMetadataCommand {
    /// Returns the stable command spelling used by output adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Thread => "thread",
        }
    }
}

/// Contains only the fields approved for metadata output.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxMetadataMessage {
    message_id: MessageId,
    thread_id: ThreadId,
    from: HeaderText,
    subject: HeaderText,
    received_at: UnixTimestampMillis,
    unread: bool,
}

impl MailboxMetadataMessage {
    pub(crate) fn from_envelope(envelope: &MessageEnvelope) -> Self {
        Self {
            message_id: envelope.message_id().clone(),
            thread_id: envelope.thread_id().clone(),
            from: envelope.from().clone(),
            subject: envelope.subject().clone(),
            received_at: envelope.received_at(),
            unread: envelope.is_unread(),
        }
    }

    /// Returns the opaque message identifier.
    #[must_use]
    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }

    /// Returns the opaque thread identifier.
    #[must_use]
    pub fn thread_id(&self) -> &ThreadId {
        &self.thread_id
    }

    /// Returns the sender header.
    #[must_use]
    pub fn from(&self) -> &HeaderText {
        &self.from
    }

    /// Returns the subject header.
    #[must_use]
    pub fn subject(&self) -> &HeaderText {
        &self.subject
    }

    /// Returns the received timestamp.
    #[must_use]
    pub const fn received_at(&self) -> UnixTimestampMillis {
        self.received_at
    }

    /// Returns whether the message is unread.
    #[must_use]
    pub const fn is_unread(&self) -> bool {
        self.unread
    }
}

impl fmt::Debug for MailboxMetadataMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxMetadataMessage")
            .field("message_id", &self.message_id)
            .field("thread_id", &self.thread_id)
            .field("from", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("received_at", &self.received_at)
            .field("unread", &self.unread)
            .finish()
    }
}

/// Describes one stable metadata result without serialization concerns.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxMetadataDocument {
    command: MailboxMetadataCommand,
    account_id: AccountId,
    limit: StoreLimit,
    messages: Vec<MailboxMetadataMessage>,
}

impl MailboxMetadataDocument {
    fn new(
        command: MailboxMetadataCommand,
        account_id: AccountId,
        limit: StoreLimit,
        envelopes: &[MessageEnvelope],
    ) -> Self {
        Self {
            command,
            account_id,
            limit,
            messages: envelopes
                .iter()
                .map(MailboxMetadataMessage::from_envelope)
                .collect(),
        }
    }

    /// Returns the stable schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        MAILBOX_METADATA_SCHEMA_VERSION
    }

    /// Returns the represented metadata command.
    #[must_use]
    pub const fn command(&self) -> MailboxMetadataCommand {
        self.command
    }

    /// Returns the opaque account identifier.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn limit(&self) -> StoreLimit {
        self.limit
    }

    /// Returns messages in the order supplied by the reader contract.
    #[must_use]
    pub fn messages(&self) -> &[MailboxMetadataMessage] {
        &self.messages
    }
}

impl fmt::Debug for MailboxMetadataDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxMetadataDocument")
            .field("schema_version", &self.schema_version())
            .field("command", &self.command)
            .field("account_id", &self.account_id)
            .field("limit", &self.limit)
            .field("message_count", &self.messages.len())
            .finish()
    }
}

/// Lists inbox metadata while preserving the reader's deterministic order.
pub fn inbox_metadata<'a>(
    reader: &'a dyn MailboxReader,
    account: &'a AccountId,
    limit: StoreLimit,
) -> BoxFuture<'a, Result<MailboxMetadataDocument, MailboxStoreError>> {
    Box::pin(async move {
        reader
            .list_envelopes(account, limit)
            .await
            .map(|envelopes| {
                MailboxMetadataDocument::new(
                    MailboxMetadataCommand::Inbox,
                    account.clone(),
                    limit,
                    &envelopes,
                )
            })
    })
}

/// Lists one thread's metadata while preserving the reader's deterministic order.
pub fn thread_metadata<'a>(
    reader: &'a dyn MailboxReader,
    account: &'a AccountId,
    thread: &'a ThreadId,
    limit: StoreLimit,
) -> BoxFuture<'a, Result<MailboxMetadataDocument, MailboxStoreError>> {
    Box::pin(async move {
        reader
            .thread_envelopes(account, thread, limit)
            .await
            .map(|envelopes| {
                MailboxMetadataDocument::new(
                    MailboxMetadataCommand::Thread,
                    account.clone(),
                    limit,
                    &envelopes,
                )
            })
    })
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

    use super::*;

    struct FakeReader {
        inbox: Result<Vec<MessageEnvelope>, MailboxStoreError>,
        thread: Result<Vec<MessageEnvelope>, MailboxStoreError>,
        calls: AtomicUsize,
    }

    impl FakeReader {
        fn successful(envelopes: Vec<MessageEnvelope>) -> Self {
            Self {
                inbox: Ok(envelopes.clone()),
                thread: Ok(envelopes),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl MailboxReader for FakeReader {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.inbox.clone();
            Box::pin(async move { result })
        }

        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.thread.clone();
            Box::pin(async move { result })
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
            HeaderText::new(format!("preview-secret-{id}")).unwrap(),
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
            Poll::Pending => panic!("application metadata future must complete synchronously"),
        }
    }

    #[test]
    fn inbox_projects_exact_fields_and_preserves_reader_order() {
        let reader = FakeReader::successful(vec![envelope("newest", 20), envelope("older", 10)]);
        let document = run(inbox_metadata(&reader, &account(), limit())).unwrap();

        assert_eq!(document.schema_version(), 1);
        assert_eq!(document.command(), MailboxMetadataCommand::Inbox);
        assert_eq!(document.account_id(), &account());
        assert_eq!(document.limit(), limit());
        assert_eq!(document.messages().len(), 2);
        assert_eq!(document.messages()[0].message_id().as_str(), "newest");
        assert_eq!(document.messages()[1].message_id().as_str(), "older");
        assert_eq!(document.messages()[0].thread_id(), &thread());
        assert_eq!(document.messages()[0].from().as_str(), "from-newest");
        assert_eq!(document.messages()[0].subject().as_str(), "subject-newest");
        assert_eq!(document.messages()[0].received_at().as_millis(), 20);
        assert!(document.messages()[0].is_unread());
        assert!(!format!("{document:?}").contains("preview-secret"));
    }

    #[test]
    fn thread_projects_exact_fields_and_preserves_reader_order() {
        let reader = FakeReader::successful(vec![envelope("oldest", 10), envelope("newer", 20)]);
        let document = run(thread_metadata(&reader, &account(), &thread(), limit())).unwrap();

        assert_eq!(document.command(), MailboxMetadataCommand::Thread);
        assert_eq!(document.messages()[0].message_id().as_str(), "oldest");
        assert_eq!(document.messages()[1].message_id().as_str(), "newer");
    }

    #[test]
    fn empty_results_are_successful_documents() {
        let reader = FakeReader::successful(Vec::new());
        assert!(
            run(inbox_metadata(&reader, &account(), limit()))
                .unwrap()
                .messages()
                .is_empty()
        );
        assert!(
            run(thread_metadata(&reader, &account(), &thread(), limit()))
                .unwrap()
                .messages()
                .is_empty()
        );
    }

    #[test]
    fn storage_errors_pass_through_unchanged() {
        for error in [MailboxStoreError::Storage, MailboxStoreError::Corrupted] {
            let reader = FakeReader {
                inbox: Err(error),
                thread: Err(error),
                calls: AtomicUsize::new(0),
            };
            assert_eq!(
                run(inbox_metadata(&reader, &account(), limit())),
                Err(error)
            );
            assert_eq!(
                run(thread_metadata(&reader, &account(), &thread(), limit())),
                Err(error)
            );
        }
    }

    #[test]
    fn debug_output_is_structural_and_redacted() {
        let reader = FakeReader::successful(vec![envelope("identifier-sentinel", 10)]);
        let document = run(inbox_metadata(&reader, &account(), limit())).unwrap();
        let debug = format!("{document:?} {:?}", document.messages()[0]);

        assert!(debug.contains("message_count"));
        assert!(!debug.contains("account-1"));
        assert!(!debug.contains("identifier-sentinel"));
        assert!(!debug.contains("subject-identifier-sentinel"));
    }

    #[test]
    fn dropping_an_unpolled_use_case_does_not_call_the_reader() {
        let reader = FakeReader::successful(Vec::new());
        let account = account();
        let future = inbox_metadata(&reader, &account, limit());
        assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
        drop(future);
        assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
    }
}
