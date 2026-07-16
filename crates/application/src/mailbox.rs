// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines runtime-free inward mailbox ports for remote and local adapters.
//!
//! Returned futures are owned by callers. Dropping one cancels the pending
//! operation, so implementations must be drop-safe and release resources.

use std::fmt;
use std::pin::Pin;

use tersa_domain::mailbox::{AccountId, Message, MessageEnvelope, MessageId, ThreadId};

/// Owns a `Send` future without selecting an async runtime.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

const MAX_PAGE_TOKEN_LEN: usize = 4_096;

/// Reports rejected application contract values without exposing their content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MailboxContractError {
    /// A page token was empty.
    EmptyPageToken,
    /// A page token was too long.
    PageTokenTooLong { len: usize },
    /// A page token contained a control character.
    InvalidPageToken,
    /// A requested page size was outside 1 through 500.
    InvalidPageSize { value: u16 },
}

impl fmt::Display for MailboxContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPageToken => "the page token must not be empty",
            Self::PageTokenTooLong { .. } => "the page token exceeds its maximum length",
            Self::InvalidPageToken => "the page token contains an invalid character",
            Self::InvalidPageSize { .. } => "the page size must be between 1 and 500",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MailboxContractError {}

/// Holds a bounded opaque provider pagination token.
#[derive(Clone, Eq, PartialEq)]
pub struct PageToken(String);

impl PageToken {
    /// The conservative provider-neutral token cap in bytes.
    pub const MAX_LEN: usize = MAX_PAGE_TOKEN_LEN;
    /// Creates a non-empty token without control characters.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxContractError`] if the token is empty, larger than
    /// [`Self::MAX_LEN`], or contains a Unicode control character.
    pub fn new<T: Into<String>>(value: T) -> Result<Self, MailboxContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(MailboxContractError::EmptyPageToken);
        }
        if value.len() > Self::MAX_LEN {
            return Err(MailboxContractError::PageTokenTooLong { len: value.len() });
        }
        if value.chars().any(char::is_control) {
            return Err(MailboxContractError::InvalidPageToken);
        }
        Ok(Self(value))
    }
    /// Returns the opaque token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PageToken([REDACTED])")
    }
}

/// Limits one remote mailbox listing request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageSize(u16);

impl PageSize {
    /// Creates a page size from 1 through 500 inclusive.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxContractError::InvalidPageSize`] outside that range.
    pub fn new(value: u16) -> Result<Self, MailboxContractError> {
        if !(1..=500).contains(&value) {
            return Err(MailboxContractError::InvalidPageSize { value });
        }
        Ok(Self(value))
    }
    /// Returns the validated page size.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Contains one remote mailbox listing page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    items: Vec<T>,
    next_token: Option<PageToken>,
}

impl<T> Page<T> {
    /// Creates a page from its items and optional continuation token.
    #[must_use]
    pub fn new(items: Vec<T>, next_token: Option<PageToken>) -> Self {
        Self { items, next_token }
    }
    /// Returns the page items.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }
    /// Returns the optional continuation token.
    #[must_use]
    pub fn next_token(&self) -> Option<&PageToken> {
        self.next_token.as_ref()
    }
    /// Separates page items from the optional continuation token.
    #[must_use]
    pub fn into_parts(self) -> (Vec<T>, Option<PageToken>) {
        (self.items, self.next_token)
    }
}

/// Describes a remote mailbox failure without provider payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteMailboxError {
    /// The account needs a new authorization grant.
    AuthorizationRequired,
    /// The provider rejected work because a rate limit was reached.
    RateLimited,
    /// The requested remote mailbox item does not exist.
    NotFound,
    /// The provider transport failed before a valid response was available.
    Transport,
    /// The provider returned a response that violated the adapter contract.
    InvalidResponse,
}
impl fmt::Display for RemoteMailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthorizationRequired => "remote mailbox authorization is required",
            Self::RateLimited => "remote mailbox rate limit reached",
            Self::NotFound => "remote mailbox item was not found",
            Self::Transport => "remote mailbox transport failed",
            Self::InvalidResponse => "remote mailbox returned an invalid response",
        })
    }
}
impl std::error::Error for RemoteMailboxError {}

/// Describes a local mailbox storage failure without backend payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MailboxStoreError {
    /// The store could not complete the requested operation.
    Storage,
    /// Stored mailbox data failed an integrity or format check.
    Corrupted,
}
impl fmt::Display for MailboxStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Storage => "local mailbox storage failed",
            Self::Corrupted => "local mailbox storage is corrupted",
        })
    }
}
impl std::error::Error for MailboxStoreError {}

/// Retrieves mailbox data from a remote provider.
///
/// A future revision or checkpoint must be acquired atomically with listing,
/// never through a separate post-list getter. This trait adds no sync protocol.
pub trait RemoteMailbox: Send + Sync {
    /// Lists recent envelopes for an account and optional continuation token.
    ///
    /// Future revision acquisition must be atomic with this listing, never a
    /// separate post-list getter.
    fn list_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        size: PageSize,
        page_token: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>>;
    /// Fetches one complete message for an account.
    fn fetch_message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>>;
}

/// Persists mailbox data in a local store.
pub trait MailboxStore: Send + Sync {
    /// Inserts or replaces mailbox envelopes for an account.
    fn upsert_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        envelopes: &'a [MessageEnvelope],
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;
    /// Inserts or replaces one complete message for an account.
    fn put_message<'a>(
        &'a self,
        account: &'a AccountId,
        message: &'a Message,
    ) -> BoxFuture<'a, Result<(), MailboxStoreError>>;
    /// Lists newest-first envelopes, limited by the requested page size.
    fn list_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        size: PageSize,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>>;
    /// Lists one thread's envelopes in chronological received-time order.
    fn thread_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        thread_id: &'a ThreadId,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>>;
    /// Retrieves an optional complete message.
    fn message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>>;
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests assert valid fixtures")]
    use super::*;
    use std::collections::HashMap;
    use std::future::ready;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};
    use tersa_domain::mailbox::{HeaderText, MessageContent, UnixTimestampMillis};

    fn account() -> AccountId {
        AccountId::new("account").unwrap()
    }
    fn envelope(id: &str, thread: &str, at: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).unwrap(),
            ThreadId::new(thread).unwrap(),
            HeaderText::new("from-sentinel").unwrap(),
            HeaderText::new("subject-sentinel").unwrap(),
            HeaderText::new("preview-sentinel").unwrap(),
            UnixTimestampMillis::new(at).unwrap(),
            false,
        )
    }
    fn message(id: &str, thread: &str, at: i64) -> Message {
        Message::new(
            envelope(id, thread, at),
            MessageContent::new(b"body-sentinel".to_vec()).unwrap(),
        )
    }

    #[test]
    fn pagination_contracts_enforce_bounds_and_redact_tokens() {
        assert!(PageToken::new("é".repeat(2048)).is_ok());
        assert!(matches!(
            PageToken::new("é".repeat(2049)),
            Err(MailboxContractError::PageTokenTooLong { len: 4098 })
        ));
        assert_eq!(
            PageToken::new(""),
            Err(MailboxContractError::EmptyPageToken)
        );
        assert_eq!(
            PageToken::new("bad\nvalue"),
            Err(MailboxContractError::InvalidPageToken)
        );
        let token = PageToken::new("token-sentinel").unwrap();
        assert!(!format!("{token:?}").contains("token-sentinel"));
        assert_eq!(token, PageToken::new("token-sentinel").unwrap());
        assert_eq!(token.as_str(), "token-sentinel");
        assert_eq!(
            PageSize::new(0),
            Err(MailboxContractError::InvalidPageSize { value: 0 })
        );
        assert_eq!(
            PageSize::new(501),
            Err(MailboxContractError::InvalidPageSize { value: 501 })
        );
        assert_eq!(PageSize::new(500).unwrap().get(), 500);
        let page = Page::new(vec![1], Some(token));
        assert_eq!(page.items(), &[1]);
        assert!(page.next_token().is_some());
        assert_eq!(page.into_parts().0, vec![1]);
    }

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    fn poll_once<T>(future: &mut BoxFuture<'_, T>) -> Poll<T> {
        let waker = Waker::from(Arc::new(Noop));
        let mut context = Context::from_waker(&waker);
        future.as_mut().poll(&mut context)
    }

    struct DropGuard(Arc<AtomicBool>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    struct Pending {
        _guard: DropGuard,
    }
    impl Future for Pending {
        type Output = Result<Page<MessageEnvelope>, RemoteMailboxError>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }
    struct CancellingRemote {
        dropped: Arc<AtomicBool>,
    }
    impl RemoteMailbox for CancellingRemote {
        fn list_recent_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: PageSize,
            _: Option<&'a PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            Box::pin(Pending {
                _guard: DropGuard(Arc::clone(&self.dropped)),
            })
        }
        fn fetch_message<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            Box::pin(ready(Err(RemoteMailboxError::NotFound)))
        }
    }

    #[test]
    fn ports_are_object_safe_and_dropping_a_pending_future_cancels_it() {
        let dropped = Arc::new(AtomicBool::new(false));
        let remote: Box<dyn RemoteMailbox> = Box::new(CancellingRemote {
            dropped: Arc::clone(&dropped),
        });
        let account = account();
        let mut future = remote.list_recent_envelopes(&account, PageSize::new(1).unwrap(), None);
        assert!(matches!(poll_once(&mut future), Poll::Pending));
        drop(future);
        assert!(dropped.load(Ordering::SeqCst));
        let _: Box<dyn MailboxStore> = Box::new(FakeStore::default());
    }

    #[derive(Default)]
    struct FakeStore {
        envelopes: Mutex<HashMap<String, Vec<MessageEnvelope>>>,
        messages: Mutex<HashMap<String, Message>>,
    }
    impl MailboxStore for FakeStore {
        fn upsert_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            values: &'a [MessageEnvelope],
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            let mut map = self.envelopes.lock().unwrap();
            map.insert(account.as_str().to_owned(), values.to_vec());
            Box::pin(ready(Ok(())))
        }
        fn put_message<'a>(
            &'a self,
            _: &'a AccountId,
            value: &'a Message,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            self.messages.lock().unwrap().insert(
                value.envelope().message_id().as_str().to_owned(),
                value.clone(),
            );
            Box::pin(ready(Ok(())))
        }
        fn list_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            size: PageSize,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let mut values = self
                .envelopes
                .lock()
                .unwrap()
                .get(account.as_str())
                .cloned()
                .unwrap_or_default();
            values.sort_by_key(|value| std::cmp::Reverse(value.received_at()));
            values.truncate(usize::from(size.get()));
            Box::pin(ready(Ok(values)))
        }
        fn thread_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            thread: &'a ThreadId,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let mut values: Vec<_> = self
                .envelopes
                .lock()
                .unwrap()
                .get(account.as_str())
                .into_iter()
                .flatten()
                .filter(|value| value.thread_id() == thread)
                .cloned()
                .collect();
            values.sort_by_key(MessageEnvelope::received_at);
            Box::pin(ready(Ok(values)))
        }
        fn message<'a>(
            &'a self,
            _: &'a AccountId,
            id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(ready(Ok(self
                .messages
                .lock()
                .unwrap()
                .get(id.as_str())
                .cloned())))
        }
    }

    #[test]
    fn fake_store_round_trips_messages_and_documents_stable_ordering() {
        let store = FakeStore::default();
        let account = account();
        let values = [
            envelope("old", "thread", 1),
            envelope("new", "thread", 3),
            envelope("middle", "other", 2),
        ];
        let mut stored = store.upsert_envelopes(&account, &values);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));
        let mut listed = store.list_envelopes(&account, PageSize::new(500).unwrap());
        let Poll::Ready(Ok(listed)) = poll_once(&mut listed) else {
            panic!("the fake is immediately ready");
        };
        assert_eq!(
            listed
                .iter()
                .map(|value| value.message_id().as_str())
                .collect::<Vec<_>>(),
            ["new", "middle", "old"]
        );
        let thread = ThreadId::new("thread").unwrap();
        let mut threaded = store.thread_envelopes(&account, &thread);
        let Poll::Ready(Ok(threaded)) = poll_once(&mut threaded) else {
            panic!("the fake is immediately ready");
        };
        assert_eq!(
            threaded
                .iter()
                .map(|value| value.message_id().as_str())
                .collect::<Vec<_>>(),
            ["old", "new"]
        );
        let value = message("complete", "thread", 4);
        let expected = value.clone();
        let mut stored = store.put_message(&account, &value);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));
        let mut found = store.message(&account, value.envelope().message_id());
        assert_eq!(poll_once(&mut found), Poll::Ready(Ok(Some(expected))));
    }
}
