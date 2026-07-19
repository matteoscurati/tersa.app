// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Trusted read-only mailbox read compositions for the fixed default profile.
//!
//! Each entry validates opaque bytes, opens the one fixed account mailbox
//! through the sole trusted opening path, runs one bounded metadata use case,
//! and returns an owned presentation view model. No key, reader, store, path,
//! or storage capability appears in any signature.

use std::fmt;
use std::task::{Context, Poll, Waker};

use tersa_application::mailbox::{
    BoxFuture, MailboxReader, MailboxStoreError, StoreLimit, ThreadId,
};
use tersa_application::mailbox_metadata::{inbox_metadata, thread_metadata};
use tersa_application::mailbox_search::{MailboxSearchQuery, search_metadata};
use tersa_platform::secure_storage::AccountId;
use tersa_presentation::mailbox::{InboxViewModel, SearchViewModel, ThreadViewModel};

use crate::{ReadOnlyMailboxOpenError, open_default_read_only_mailbox};

// Rust guideline compliant 1.0.

const DEFAULT_LIMIT: u16 = 50;

/// Closed result of the trusted read-only mailbox composition.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(i32)]
pub enum MailboxReadStatus {
    /// The bounded read completed and produced a view model.
    Ok = 0,
    /// Opaque bytes were not a canonical identifier, query, or limit.
    InvalidInput = 1,
    /// The bridge called the synchronous operation from an invalid context.
    InvalidExecutionContext = 2,
    /// The fixed profile, its key, or the bounded read was unavailable.
    Unavailable = 3,
    /// The encrypted mailbox failed strict validation.
    Corrupted = 4,
    /// The output buffer was too small for the encoded document.
    BufferTooSmall = 5,
}

impl fmt::Debug for MailboxReadStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MailboxReadStatus([REDACTED])")
    }
}

/// Reads the fixed default account inbox as bounded metadata rows.
///
/// Validation completes before the sole trusted opening path is used, and the
/// reader is dropped before the owned view model is returned. A zero limit
/// selects the bounded default.
///
/// # Errors
///
/// Returns a closed redacted status when the execution context, opaque bytes,
/// fixed-profile opening, or bounded read fails.
pub fn read_default_inbox(
    account_bytes: &[u8],
    limit: u16,
) -> Result<InboxViewModel, MailboxReadStatus> {
    read_default_inbox_with_dependencies(
        objc2_foundation::NSThread::isMainThread_class(),
        account_bytes,
        limit,
        open_default_read_only_mailbox,
    )
}

/// Reads one thread of the fixed default account as bounded metadata rows.
///
/// An empty thread is a successful read with empty rows. Validation completes
/// before the sole trusted opening path is used, and the reader is dropped
/// before the owned view model is returned. A zero limit selects the bounded
/// default.
///
/// # Errors
///
/// Returns a closed redacted status when the execution context, opaque bytes,
/// fixed-profile opening, or bounded read fails.
pub fn read_default_thread(
    account_bytes: &[u8],
    thread_bytes: &[u8],
    limit: u16,
) -> Result<ThreadViewModel, MailboxReadStatus> {
    read_default_thread_with_dependencies(
        objc2_foundation::NSThread::isMainThread_class(),
        account_bytes,
        thread_bytes,
        limit,
        open_default_read_only_mailbox,
    )
}

/// Searches the fixed default account cache as bounded metadata rows.
///
/// Validation completes before the sole trusted opening path is used, and the
/// reader is dropped before the owned view model is returned. A zero limit
/// selects the bounded default.
///
/// # Errors
///
/// Returns a closed redacted status when the execution context, opaque bytes,
/// fixed-profile opening, or bounded read fails.
pub fn search_default_mailbox(
    account_bytes: &[u8],
    query_bytes: &[u8],
    limit: u16,
) -> Result<SearchViewModel, MailboxReadStatus> {
    search_default_mailbox_with_dependencies(
        objc2_foundation::NSThread::isMainThread_class(),
        account_bytes,
        query_bytes,
        limit,
        open_default_read_only_mailbox,
    )
}

/// Executes the inbox read through an injected trusted opening capability.
///
/// This internal seam is deliberately capability-based: tests can exercise
/// every status without exporting a key or adding a configurable production
/// path.
fn read_default_inbox_with_dependencies<R: MailboxReader>(
    is_main_thread: bool,
    account_bytes: &[u8],
    limit: u16,
    open_reader: impl FnOnce(&AccountId) -> Result<R, ReadOnlyMailboxOpenError>,
) -> Result<InboxViewModel, MailboxReadStatus> {
    let (account, limit) = validated_account_and_limit(is_main_thread, account_bytes, limit)?;
    let reader = open_reader(&account).map_err(open_failure_status)?;
    let document = poll_once(inbox_metadata(&reader, &account, limit))
        .map_err(|_pending| MailboxReadStatus::Unavailable)?
        .map_err(store_failure_status)?;
    let model = InboxViewModel::from_document(&document)
        .map_err(|_mismatched_command| MailboxReadStatus::Unavailable)?;
    drop(reader);
    Ok(model)
}

/// Executes the thread read through an injected trusted opening capability.
fn read_default_thread_with_dependencies<R: MailboxReader>(
    is_main_thread: bool,
    account_bytes: &[u8],
    thread_bytes: &[u8],
    limit: u16,
    open_reader: impl FnOnce(&AccountId) -> Result<R, ReadOnlyMailboxOpenError>,
) -> Result<ThreadViewModel, MailboxReadStatus> {
    let (account, limit) = validated_account_and_limit(is_main_thread, account_bytes, limit)?;
    let thread = validated_thread_id(thread_bytes)?;
    let reader = open_reader(&account).map_err(open_failure_status)?;
    let document = poll_once(thread_metadata(&reader, &account, &thread, limit))
        .map_err(|_pending| MailboxReadStatus::Unavailable)?
        .map_err(store_failure_status)?;
    let model = ThreadViewModel::from_document(&document, &thread)
        .map_err(|_mismatched_command| MailboxReadStatus::Unavailable)?;
    drop(reader);
    Ok(model)
}

/// Executes the metadata search through an injected trusted opening capability.
fn search_default_mailbox_with_dependencies<R: MailboxReader>(
    is_main_thread: bool,
    account_bytes: &[u8],
    query_bytes: &[u8],
    limit: u16,
    open_reader: impl FnOnce(&AccountId) -> Result<R, ReadOnlyMailboxOpenError>,
) -> Result<SearchViewModel, MailboxReadStatus> {
    let (account, limit) = validated_account_and_limit(is_main_thread, account_bytes, limit)?;
    let query = validated_search_query(query_bytes)?;
    let reader = open_reader(&account).map_err(open_failure_status)?;
    let document = poll_once(search_metadata(&reader, &account, &query, limit))
        .map_err(|_pending| MailboxReadStatus::Unavailable)?
        .map_err(store_failure_status)?;
    let model = SearchViewModel::from_document(&document);
    drop(reader);
    Ok(model)
}

/// Validates the main-thread rejection, opaque account bytes, and the bounded
/// result limit before any capability is constructed.
fn validated_account_and_limit(
    is_main_thread: bool,
    account_bytes: &[u8],
    limit: u16,
) -> Result<(AccountId, StoreLimit), MailboxReadStatus> {
    if is_main_thread {
        return Err(MailboxReadStatus::InvalidExecutionContext);
    }
    let account_text =
        std::str::from_utf8(account_bytes).map_err(|_error| MailboxReadStatus::InvalidInput)?;
    let account = AccountId::new(account_text.to_owned())
        .map_err(|_error| MailboxReadStatus::InvalidInput)?;
    let limit = if limit == 0 { DEFAULT_LIMIT } else { limit };
    let limit = StoreLimit::new(limit).map_err(|_error| MailboxReadStatus::InvalidInput)?;
    Ok((account, limit))
}

/// Validates opaque bytes as a canonical thread identifier.
fn validated_thread_id(thread_bytes: &[u8]) -> Result<ThreadId, MailboxReadStatus> {
    let thread_text =
        std::str::from_utf8(thread_bytes).map_err(|_error| MailboxReadStatus::InvalidInput)?;
    ThreadId::new(thread_text.to_owned()).map_err(|_error| MailboxReadStatus::InvalidInput)
}

/// Validates opaque bytes as a bounded search query.
fn validated_search_query(query_bytes: &[u8]) -> Result<MailboxSearchQuery, MailboxReadStatus> {
    let query_text =
        std::str::from_utf8(query_bytes).map_err(|_error| MailboxReadStatus::InvalidInput)?;
    MailboxSearchQuery::new(query_text.to_owned()).map_err(|_error| MailboxReadStatus::InvalidInput)
}

/// Polls one immediately-ready use-case future with a noop waker.
fn poll_once<T>(mut future: BoxFuture<'_, T>) -> Result<T, ()> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => Ok(value),
        Poll::Pending => Err(()),
    }
}

/// Collapses the trusted opening failures into the closed read vocabulary.
fn open_failure_status(error: ReadOnlyMailboxOpenError) -> MailboxReadStatus {
    match error {
        ReadOnlyMailboxOpenError::KeyAccess | ReadOnlyMailboxOpenError::ProfileUnavailable => {
            MailboxReadStatus::Unavailable
        }
        ReadOnlyMailboxOpenError::MailboxCorrupted => MailboxReadStatus::Corrupted,
    }
}

/// Collapses the store failures into the closed read vocabulary.
fn store_failure_status(error: MailboxStoreError) -> MailboxReadStatus {
    if error == MailboxStoreError::Corrupted {
        MailboxReadStatus::Corrupted
    } else {
        MailboxReadStatus::Unavailable
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Test fixtures use valid literals and fail immediately on unexpected results."
)]
mod tests {
    use std::future::pending;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tersa_application::mailbox::{HeaderText, MessageEnvelope, MessageId, UnixTimestampMillis};

    use super::*;

    struct FakeReader {
        listed: Result<Vec<MessageEnvelope>, MailboxStoreError>,
        threaded: Result<Vec<MessageEnvelope>, MailboxStoreError>,
        last_limit: Arc<AtomicUsize>,
    }

    impl MailboxReader for FakeReader {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            self.last_limit
                .store(usize::from(limit.get()), Ordering::SeqCst);
            let result = self.listed.clone();
            Box::pin(async move { result })
        }

        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            self.last_limit
                .store(usize::from(limit.get()), Ordering::SeqCst);
            let result = self.threaded.clone();
            Box::pin(async move { result })
        }
    }

    impl FakeReader {
        fn successful(
            listed: Vec<MessageEnvelope>,
            threaded: Vec<MessageEnvelope>,
        ) -> (Self, Arc<AtomicUsize>) {
            let last_limit = Arc::new(AtomicUsize::new(0));
            let reader = Self {
                listed: Ok(listed),
                threaded: Ok(threaded),
                last_limit: Arc::clone(&last_limit),
            };
            (reader, last_limit)
        }
    }

    struct PendingReader;

    impl MailboxReader for PendingReader {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(pending())
        }

        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(pending())
        }
    }

    struct DropReader {
        dropped: Arc<AtomicBool>,
    }

    impl Drop for DropReader {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl MailboxReader for DropReader {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn envelope(id: &str, thread: &str, from: &str, timestamp: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).unwrap(),
            ThreadId::new(thread).unwrap(),
            HeaderText::new(from).unwrap(),
            HeaderText::new(format!("subject-{id}")).unwrap(),
            HeaderText::new(format!("preview-secret-{id}")).unwrap(),
            UnixTimestampMillis::new(timestamp).unwrap(),
            true,
        )
    }

    /// An opening capability that proves validation failures never open.
    fn unopened_reader<R: MailboxReader>()
    -> impl FnOnce(&AccountId) -> Result<R, ReadOnlyMailboxOpenError> {
        |_account| panic!("the trusted opening path must not be used")
    }

    #[test]
    fn main_thread_is_rejected_before_any_capability() {
        assert_eq!(
            read_default_inbox_with_dependencies(
                true,
                b"account-1",
                0,
                unopened_reader::<FakeReader>()
            )
            .map(|_| ()),
            Err(MailboxReadStatus::InvalidExecutionContext)
        );
        assert_eq!(
            read_default_thread_with_dependencies(
                true,
                b"account-1",
                b"thread-1",
                0,
                unopened_reader::<FakeReader>()
            )
            .map(|_| ()),
            Err(MailboxReadStatus::InvalidExecutionContext)
        );
        assert_eq!(
            search_default_mailbox_with_dependencies(
                true,
                b"account-1",
                b"alice",
                0,
                unopened_reader::<FakeReader>()
            )
            .map(|_| ()),
            Err(MailboxReadStatus::InvalidExecutionContext)
        );
    }

    #[test]
    fn malformed_utf8_is_rejected_without_opening() {
        assert_eq!(
            read_default_inbox_with_dependencies(
                false,
                b"\xff",
                0,
                unopened_reader::<FakeReader>()
            )
            .map(|_| ()),
            Err(MailboxReadStatus::InvalidInput)
        );
        assert_eq!(
            read_default_thread_with_dependencies(
                false,
                b"account-1",
                b"\xff",
                0,
                unopened_reader::<FakeReader>()
            )
            .map(|_| ()),
            Err(MailboxReadStatus::InvalidInput)
        );
        assert_eq!(
            search_default_mailbox_with_dependencies(
                false,
                b"account-1",
                b"\xff",
                0,
                unopened_reader::<FakeReader>()
            )
            .map(|_| ()),
            Err(MailboxReadStatus::InvalidInput)
        );
    }

    #[test]
    fn domain_invalid_inputs_are_rejected_without_opening() {
        for account in [
            &b""[..],
            b"person@example.com",
            b"bad account",
            &[b'a'; 257],
        ] {
            assert_eq!(
                read_default_inbox_with_dependencies(
                    false,
                    account,
                    0,
                    unopened_reader::<FakeReader>()
                )
                .map(|_| ()),
                Err(MailboxReadStatus::InvalidInput),
                "account input must be rejected: {account:?}"
            );
        }
        for thread in [&b""[..], b"bad thread", &[b'a'; 257]] {
            assert_eq!(
                read_default_thread_with_dependencies(
                    false,
                    b"account-1",
                    thread,
                    0,
                    unopened_reader::<FakeReader>()
                )
                .map(|_| ()),
                Err(MailboxReadStatus::InvalidInput),
                "thread input must be rejected: {thread:?}"
            );
        }
        for query in [&b""[..], b"bad\nquery", &[b'a'; 257]] {
            assert_eq!(
                search_default_mailbox_with_dependencies(
                    false,
                    b"account-1",
                    query,
                    0,
                    unopened_reader::<FakeReader>()
                )
                .map(|_| ()),
                Err(MailboxReadStatus::InvalidInput),
                "query input must be rejected: {query:?}"
            );
        }
    }

    #[test]
    fn limits_default_to_fifty_and_reject_out_of_range_without_opening() {
        let (reader, last_limit) = FakeReader::successful(Vec::new(), Vec::new());
        read_default_inbox_with_dependencies(false, b"account-1", 0, |_account| Ok(reader))
            .unwrap();
        assert_eq!(last_limit.load(Ordering::SeqCst), 50);

        let (reader, last_limit) = FakeReader::successful(Vec::new(), Vec::new());
        read_default_inbox_with_dependencies(false, b"account-1", 1, |_account| Ok(reader))
            .unwrap();
        assert_eq!(last_limit.load(Ordering::SeqCst), 1);

        let (reader, last_limit) = FakeReader::successful(Vec::new(), Vec::new());
        read_default_inbox_with_dependencies(false, b"account-1", 10_000, |_account| Ok(reader))
            .unwrap();
        assert_eq!(last_limit.load(Ordering::SeqCst), 10_000);

        assert_eq!(
            read_default_inbox_with_dependencies(
                false,
                b"account-1",
                10_001,
                unopened_reader::<FakeReader>()
            )
            .map(|_| ()),
            Err(MailboxReadStatus::InvalidInput)
        );
    }

    #[test]
    fn inbox_round_trip_projects_rows_and_applies_the_limit() {
        let (reader, _last_limit) = FakeReader::successful(
            vec![
                envelope("newest", "thread-a", "alice@example.test", 20),
                envelope("older", "thread-b", "bob@example.test", 10),
            ],
            Vec::new(),
        );
        let model =
            read_default_inbox_with_dependencies(false, b"account-1", 50, |_account| Ok(reader))
                .unwrap();

        assert_eq!(model.account_id(), "account-1");
        assert_eq!(model.limit(), 50);
        assert_eq!(model.rows().len(), 2);
        assert_eq!(model.rows()[0].message_id, "newest");
        assert_eq!(model.rows()[0].thread_id, "thread-a");
        assert_eq!(model.rows()[0].from, "alice@example.test");
        assert_eq!(model.rows()[0].subject, "subject-newest");
        assert_eq!(model.rows()[0].received_at_millis, 20);
        assert!(model.rows()[0].unread);
        assert_eq!(model.rows()[1].message_id, "older");
        assert!(!format!("{model:?}").contains("preview-secret"));
    }

    #[test]
    fn thread_round_trip_projects_rows_and_an_empty_thread_is_successful() {
        let (reader, _last_limit) = FakeReader::successful(
            Vec::new(),
            vec![envelope("oldest", "thread-a", "alice@example.test", 10)],
        );
        let model = read_default_thread_with_dependencies(
            false,
            b"account-1",
            b"thread-a",
            50,
            |_account| Ok(reader),
        )
        .unwrap();
        assert_eq!(model.thread_id(), "thread-a");
        assert_eq!(model.rows().len(), 1);
        assert_eq!(model.rows()[0].message_id, "oldest");

        let (reader, _last_limit) = FakeReader::successful(Vec::new(), Vec::new());
        let model = read_default_thread_with_dependencies(
            false,
            b"account-1",
            b"thread-missing",
            50,
            |_account| Ok(reader),
        )
        .unwrap();
        assert!(model.is_empty());
        assert_eq!(model.thread_id(), "thread-missing");
    }

    #[test]
    fn search_round_trip_filters_rows_through_the_use_case() {
        let (reader, _last_limit) = FakeReader::successful(
            vec![
                envelope("hit", "thread-a", "alice@example.test", 20),
                envelope("miss", "thread-b", "bob@example.test", 10),
            ],
            Vec::new(),
        );
        let model = search_default_mailbox_with_dependencies(
            false,
            b"account-1",
            b"alice",
            50,
            |_account| Ok(reader),
        )
        .unwrap();

        assert_eq!(model.account_id(), "account-1");
        assert_eq!(model.query(), "alice");
        assert_eq!(model.limit(), 50);
        assert_eq!(model.rows().len(), 1);
        assert_eq!(model.rows()[0].message_id, "hit");
    }

    #[test]
    fn the_reader_is_dropped_before_the_view_model_is_returned() {
        let dropped = Arc::new(AtomicBool::new(false));
        let reader = DropReader {
            dropped: Arc::clone(&dropped),
        };
        let model = read_default_inbox_with_dependencies(false, b"account-1", 0, move |_account| {
            Ok(reader)
        })
        .unwrap();

        assert!(model.is_empty());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn opening_failures_collapse_into_the_closed_vocabulary() {
        for (failure, status) in [
            (
                ReadOnlyMailboxOpenError::KeyAccess,
                MailboxReadStatus::Unavailable,
            ),
            (
                ReadOnlyMailboxOpenError::ProfileUnavailable,
                MailboxReadStatus::Unavailable,
            ),
            (
                ReadOnlyMailboxOpenError::MailboxCorrupted,
                MailboxReadStatus::Corrupted,
            ),
        ] {
            assert_eq!(
                read_default_inbox_with_dependencies(
                    false,
                    b"account-1",
                    0,
                    |_account: &AccountId| -> Result<FakeReader, ReadOnlyMailboxOpenError> {
                        Err(failure)
                    }
                )
                .map(|_| ()),
                Err(status)
            );
        }
    }

    #[test]
    fn store_failures_collapse_into_the_closed_vocabulary() {
        for (error, status) in [
            (MailboxStoreError::Storage, MailboxReadStatus::Unavailable),
            (MailboxStoreError::Corrupted, MailboxReadStatus::Corrupted),
        ] {
            let reader = FakeReader {
                listed: Err(error),
                threaded: Err(error),
                last_limit: Arc::new(AtomicUsize::new(0)),
            };
            assert_eq!(
                read_default_inbox_with_dependencies(false, b"account-1", 0, |_account| Ok(reader))
                    .map(|_| ()),
                Err(status)
            );
            let reader = FakeReader {
                listed: Err(error),
                threaded: Err(error),
                last_limit: Arc::new(AtomicUsize::new(0)),
            };
            assert_eq!(
                read_default_thread_with_dependencies(
                    false,
                    b"account-1",
                    b"thread-a",
                    0,
                    |_account| Ok(reader)
                )
                .map(|_| ()),
                Err(status)
            );
        }
    }

    #[test]
    fn a_pending_use_case_future_is_an_unavailable_read() {
        assert_eq!(
            read_default_inbox_with_dependencies(false, b"account-1", 0, |_account| Ok(
                PendingReader
            ))
            .map(|_| ()),
            Err(MailboxReadStatus::Unavailable)
        );
    }

    #[test]
    fn production_entries_reject_malformed_bytes_off_the_main_thread() {
        let status = std::thread::spawn(|| read_default_inbox(b"\xff", 0).map(|_| ()))
            .join()
            .expect("the production entry must not panic");
        assert_eq!(status, Err(MailboxReadStatus::InvalidInput));
    }

    #[test]
    fn read_status_debug_is_redacted() {
        for status in [
            MailboxReadStatus::Ok,
            MailboxReadStatus::InvalidInput,
            MailboxReadStatus::InvalidExecutionContext,
            MailboxReadStatus::Unavailable,
            MailboxReadStatus::Corrupted,
            MailboxReadStatus::BufferTooSmall,
        ] {
            let debug = format!("{status:?}");
            assert_eq!(debug, "MailboxReadStatus([REDACTED])");
        }
    }
}
