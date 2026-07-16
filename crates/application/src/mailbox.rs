// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines runtime-free inward mailbox ports for remote and local adapters.
//!
//! Returned futures are owned by callers. Dropping one is the caller's
//! cancellation request and releases future-owned state. An adapter should stop
//! before dispatch or commit when possible. An already-dispatched or
//! irreversible operation may finish once, but must not start retries or
//! unbounded detached work after drop.

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
    /// A requested local result limit was outside 1 through 10,000.
    InvalidStoreLimit { value: u16 },
}

impl fmt::Display for MailboxContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPageToken => "the page token must not be empty",
            Self::PageTokenTooLong { .. } => "the page token exceeds its maximum length",
            Self::InvalidPageToken => "the page token contains an invalid character",
            Self::InvalidPageSize { .. } => "the page size must be between 1 and 500",
            Self::InvalidStoreLimit { .. } => "the store limit must be between 1 and 10000",
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

/// Limits one remote provider pagination request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageSize(u16);

impl PageSize {
    /// Creates a remote pagination size from 1 through 500 inclusive.
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
    /// Returns the validated remote pagination size.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Limits one local store listing result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLimit(u16);

impl StoreLimit {
    /// The defensive maximum number of envelopes returned by one local query.
    pub const MAX: u16 = 10_000;

    /// Creates a local result limit from 1 through 10,000 inclusive.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxContractError::InvalidStoreLimit`] outside that range.
    pub fn new(value: u16) -> Result<Self, MailboxContractError> {
        if !(1..=Self::MAX).contains(&value) {
            return Err(MailboxContractError::InvalidStoreLimit { value });
        }
        Ok(Self(value))
    }

    /// Returns the validated local result limit.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Contains one remote mailbox listing page.
#[derive(Clone, Eq, PartialEq)]
pub struct Page<T> {
    items: Vec<T>,
    next_token: Option<PageToken>,
}

impl<T> fmt::Debug for Page<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Page")
            .field("item_count", &self.items.len())
            .field("has_next_token", &self.next_token.is_some())
            .finish()
    }
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
    /// separate post-list getter. The returned items preserve provider page
    /// order. Global ordering, including equal-time ordering, is provider
    /// defined or unspecified; callers must not treat this as a lossless sync
    /// snapshot.
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
///
/// Store mutations must be atomic and all-or-nothing. After dropping a future,
/// the outcome may be unknown, but partial durable state is forbidden; callers
/// may reconcile by re-reading. Each concrete adapter must test its own
/// cancellation and atomicity behavior. Reusable cross-crate test support is
/// deferred.
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
    /// Lists envelopes in a deterministic total order: received time descending,
    /// then message identifier ascending, limited by the local result limit.
    fn list_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        limit: StoreLimit,
    ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>>;
    /// Lists one thread's envelopes in a deterministic total order: received
    /// time ascending, then message identifier ascending, limited by the local
    /// result limit.
    fn thread_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        thread_id: &'a ThreadId,
        limit: StoreLimit,
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

    struct NonDebugItem(&'static str);

    fn account() -> AccountId {
        AccountId::new("account").unwrap()
    }
    fn named_account(name: &str) -> AccountId {
        AccountId::new(name).unwrap()
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
        assert_eq!(PageSize::new(1).unwrap().get(), 1);
        assert_eq!(PageSize::new(500).unwrap().get(), 500);
        assert_eq!(
            StoreLimit::new(0),
            Err(MailboxContractError::InvalidStoreLimit { value: 0 })
        );
        assert_eq!(
            StoreLimit::new(10_001),
            Err(MailboxContractError::InvalidStoreLimit { value: 10_001 })
        );
        assert_eq!(StoreLimit::new(StoreLimit::MAX).unwrap().get(), 10_000);
        let page = Page::new(vec![NonDebugItem("item-sentinel")], Some(token));
        assert_eq!(page.items().len(), 1);
        assert_eq!(page.items()[0].0, "item-sentinel");
        assert!(page.next_token().is_some());
        let debug = format!("{page:?}");
        assert!(debug.contains("item_count: 1"));
        assert!(debug.contains("has_next_token: true"));
        assert!(!debug.contains("item-sentinel"));
        assert!(!debug.contains("token-sentinel"));
        assert_eq!(page.into_parts().0.len(), 1);
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
    fn ports_are_object_safe_and_dropping_a_pending_future_releases_owned_state() {
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
        envelopes: Mutex<HashMap<AccountId, Vec<MessageEnvelope>>>,
        messages: Mutex<HashMap<(AccountId, MessageId), Message>>,
    }
    impl MailboxStore for FakeStore {
        fn upsert_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            values: &'a [MessageEnvelope],
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            let mut map = self.envelopes.lock().unwrap();
            let stored = map.entry(account.clone()).or_default();
            for value in values {
                if let Some(position) = stored
                    .iter()
                    .position(|existing| existing.message_id() == value.message_id())
                {
                    stored[position] = value.clone();
                } else {
                    stored.push(value.clone());
                }
            }
            Box::pin(ready(Ok(())))
        }
        fn put_message<'a>(
            &'a self,
            account: &'a AccountId,
            value: &'a Message,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            self.messages.lock().unwrap().insert(
                (account.clone(), value.envelope().message_id().clone()),
                value.clone(),
            );
            Box::pin(ready(Ok(())))
        }
        fn list_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let mut values = self
                .envelopes
                .lock()
                .unwrap()
                .get(account)
                .cloned()
                .unwrap_or_default();
            values.sort_by(|left, right| {
                right
                    .received_at()
                    .cmp(&left.received_at())
                    .then_with(|| left.message_id().as_str().cmp(right.message_id().as_str()))
            });
            values.truncate(usize::from(limit.get()));
            Box::pin(ready(Ok(values)))
        }
        fn thread_envelopes<'a>(
            &'a self,
            account: &'a AccountId,
            thread: &'a ThreadId,
            limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            let mut values: Vec<_> = self
                .envelopes
                .lock()
                .unwrap()
                .get(account)
                .into_iter()
                .flatten()
                .filter(|value| value.thread_id() == thread)
                .cloned()
                .collect();
            values.sort_by(|left, right| {
                left.received_at()
                    .cmp(&right.received_at())
                    .then_with(|| left.message_id().as_str().cmp(right.message_id().as_str()))
            });
            values.truncate(usize::from(limit.get()));
            Box::pin(ready(Ok(values)))
        }
        fn message<'a>(
            &'a self,
            account: &'a AccountId,
            id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(ready(Ok(self
                .messages
                .lock()
                .unwrap()
                .get(&(account.clone(), id.clone()))
                .cloned())))
        }
    }

    #[test]
    fn fake_store_round_trips_messages_and_documents_stable_ordering() {
        let store = FakeStore::default();
        let account = account();
        let values = [
            envelope("old", "thread", 1),
            envelope("thread-b", "thread", 3),
            envelope("thread-a", "thread", 3),
            envelope("middle", "other", 2),
        ];
        let mut stored = store.upsert_envelopes(&account, &values);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));
        let mut listed = store.list_envelopes(&account, StoreLimit::new(500).unwrap());
        let Poll::Ready(Ok(listed)) = poll_once(&mut listed) else {
            panic!("the fake is immediately ready");
        };
        assert_eq!(
            listed
                .iter()
                .map(|value| value.message_id().as_str())
                .collect::<Vec<_>>(),
            ["thread-a", "thread-b", "middle", "old"]
        );
        let thread = ThreadId::new("thread").unwrap();
        let mut threaded = store.thread_envelopes(&account, &thread, StoreLimit::new(2).unwrap());
        let Poll::Ready(Ok(threaded)) = poll_once(&mut threaded) else {
            panic!("the fake is immediately ready");
        };
        assert_eq!(
            threaded
                .iter()
                .map(|value| value.message_id().as_str())
                .collect::<Vec<_>>(),
            ["old", "thread-a"]
        );
        let value = message("complete", "thread", 4);
        let expected = value.clone();
        let mut stored = store.put_message(&account, &value);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));
        let mut found = store.message(&account, value.envelope().message_id());
        assert_eq!(poll_once(&mut found), Poll::Ready(Ok(Some(expected))));
    }

    #[test]
    fn fake_store_upserts_by_account_and_message_id() {
        let store = FakeStore::default();
        let account = account();
        let initial = [
            envelope("replace", "thread", 1),
            envelope("preserve", "thread", 2),
        ];
        let mut stored = store.upsert_envelopes(&account, &initial);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));

        let replacement = [envelope("replace", "thread", 4)];
        let mut stored = store.upsert_envelopes(&account, &replacement);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));

        let mut listed = store.list_envelopes(&account, StoreLimit::new(10).unwrap());
        let Poll::Ready(Ok(listed)) = poll_once(&mut listed) else {
            panic!("the fake is immediately ready");
        };
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].message_id().as_str(), "replace");
        assert_eq!(listed[0].received_at().as_millis(), 4);
        assert_eq!(listed[1].message_id().as_str(), "preserve");
    }

    #[test]
    fn fake_store_isolates_envelopes_and_complete_messages_by_account() {
        let store = FakeStore::default();
        let first = named_account("first-account");
        let second = named_account("second-account");
        let first_envelope = envelope("shared-id", "thread", 1);
        let second_envelope = envelope("shared-id", "thread", 2);
        let first_values = [first_envelope.clone()];
        let mut stored = store.upsert_envelopes(&first, &first_values);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));
        let second_values = [second_envelope.clone()];
        let mut stored = store.upsert_envelopes(&second, &second_values);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));

        let mut first_listed = store.list_envelopes(&first, StoreLimit::new(10).unwrap());
        assert_eq!(
            poll_once(&mut first_listed),
            Poll::Ready(Ok(vec![first_envelope]))
        );
        let mut second_listed = store.list_envelopes(&second, StoreLimit::new(10).unwrap());
        assert_eq!(
            poll_once(&mut second_listed),
            Poll::Ready(Ok(vec![second_envelope]))
        );

        let first_message = message("shared-message", "thread", 3);
        let second_message = message("shared-message", "thread", 4);
        let mut stored = store.put_message(&first, &first_message);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));
        let mut stored = store.put_message(&second, &second_message);
        assert_eq!(poll_once(&mut stored), Poll::Ready(Ok(())));
        let id = MessageId::new("shared-message").unwrap();
        let mut found = store.message(&first, &id);
        assert_eq!(
            poll_once(&mut found),
            Poll::Ready(Ok(Some(first_message.clone())))
        );
        let mut found = store.message(&second, &id);
        assert_eq!(
            poll_once(&mut found),
            Poll::Ready(Ok(Some(second_message.clone())))
        );
    }
}
