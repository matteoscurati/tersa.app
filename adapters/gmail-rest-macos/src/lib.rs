// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides a bounded, read-only Gmail REST implementation of `RemoteMailbox`.
//!
//! The adapter is deliberately limited to authenticated `GET` requests against
//! Gmail's `users/me` resource. It owns one locally assigned account and a
//! short-lived token on macOS. It neither exchanges, refreshes, persists, nor
//! logs credentials.

#![forbid(unsafe_code)]

use std::fmt;
use std::pin::Pin;

use base64::Engine;
use serde::Deserialize;
use tersa_application::mailbox::{
    BoxFuture, Page, PageSize, PageToken, RemoteMailbox, RemoteMailboxError,
};
use tersa_domain::mailbox::{
    AccountId, HeaderText, Message, MessageContent, MessageEnvelope, MessageId, ThreadId,
    UnixTimestampMillis,
};
use url::Url;
#[cfg(target_os = "macos")]
use zeroize::Zeroizing;

const BASE_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
const JSON_LIMIT: usize = 2 * 1024 * 1024;
const RAW_ENCODED_LIMIT: usize = MessageContent::MAX_LEN.div_ceil(3) * 4;
const RAW_JSON_OVERHEAD: usize = 4 * 1024;
const RAW_JSON_LIMIT: usize = RAW_ENCODED_LIMIT + RAW_JSON_OVERHEAD;
const METADATA_FIELDS: &str = "id,threadId,internalDate,labelIds,snippet,payload(headers)";
const RAW_FIELDS: &str = "id,threadId,raw";
#[cfg(target_os = "macos")]
const MAX_ACCESS_TOKEN_LEN: usize = 16 * 1024;
#[cfg(target_os = "macos")]
const CONNECT_TIMEOUT_SECS: u64 = 10;
#[cfg(target_os = "macos")]
const REQUEST_TIMEOUT_SECS: u64 = 30;

type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>>;

/// Reads Gmail messages for one locally assigned account.
pub struct GmailMailbox {
    account: AccountId,
    transport: Box<dyn Transport>,
}

impl fmt::Debug for GmailMailbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GmailMailbox([REDACTED])")
    }
}

impl GmailMailbox {
    #[cfg(target_os = "macos")]
    /// Creates a Gmail adapter with a short-lived access token for `account`.
    ///
    /// Replacing a rotated token requires replacing this adapter. The token is
    /// retained only in zeroizing memory and is never included in diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteMailboxError::AuthorizationRequired`] for an empty,
    /// oversized, or control-character-containing token. Client construction
    /// failures return [`RemoteMailboxError::Transport`].
    pub fn new(account: AccountId, access_token: String) -> Result<Self, RemoteMailboxError> {
        validate_access_token(&access_token)?;
        Ok(Self {
            account,
            transport: Box::new(ReqwestTransport::new(Zeroizing::new(access_token))?),
        })
    }

    #[cfg(test)]
    fn with_transport(account: AccountId, transport: impl Transport + 'static) -> Self {
        Self {
            account,
            transport: Box::new(transport),
        }
    }

    fn checked_account(&self, account: &AccountId) -> Result<(), RemoteMailboxError> {
        (self.account == *account)
            .then_some(())
            .ok_or(RemoteMailboxError::AuthorizationRequired)
    }

    async fn request_json<T: for<'de> Deserialize<'de>>(
        &self,
        request: Request,
        limit: usize,
    ) -> Result<T, RemoteMailboxError> {
        let response = self
            .transport
            .get(request, limit)
            .await
            .map_err(TransportError::into_mailbox_error)?;
        if !(200..300).contains(&response.status) {
            return Err(map_status(response.status, &response.body));
        }
        serde_json::from_slice(&response.body).map_err(|_error| RemoteMailboxError::InvalidResponse)
    }

    async fn metadata(&self, id: &MessageId) -> Result<GmailMetadata, RemoteMailboxError> {
        self.request_json(message_request(id, MessageFormat::Metadata)?, JSON_LIMIT)
            .await
    }
}

impl RemoteMailbox for GmailMailbox {
    fn list_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        size: PageSize,
        page_token: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
        Box::pin(async move {
            self.checked_account(account)?;
            let list: GmailList = self
                .request_json(list_request(size, page_token)?, JSON_LIMIT)
                .await?;
            let next = list
                .next_page_token
                .map(PageToken::new)
                .transpose()
                .map_err(|_error| RemoteMailboxError::InvalidResponse)?;
            let mut envelopes = Vec::with_capacity(list.messages.len());
            for listed in list.messages {
                let id = MessageId::new(listed.id)
                    .map_err(|_error| RemoteMailboxError::InvalidResponse)?;
                let listed_thread = ThreadId::new(listed.thread_id)
                    .map_err(|_error| RemoteMailboxError::InvalidResponse)?;
                match self.metadata(&id).await {
                    Ok(metadata) => {
                        let envelope = envelope_from(metadata, &id)?;
                        if envelope.thread_id() != &listed_thread {
                            return Err(RemoteMailboxError::InvalidResponse);
                        }
                        envelopes.push(envelope);
                    }
                    Err(RemoteMailboxError::NotFound) => {
                        // Gmail may delete a listed message before hydration.
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(Page::new(envelopes, next))
        })
    }

    fn fetch_message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
        Box::pin(async move {
            self.checked_account(account)?;
            let envelope = envelope_from(self.metadata(message_id).await?, message_id)?;
            let raw: GmailRaw = self
                .request_json(
                    message_request(message_id, MessageFormat::Raw)?,
                    RAW_JSON_LIMIT,
                )
                .await?;
            if raw.id != message_id.as_str() || raw.thread_id != envelope.thread_id().as_str() {
                return Err(RemoteMailboxError::InvalidResponse);
            }
            let content = decode_raw_with_limit(&raw.raw, MessageContent::MAX_LEN)?;
            MessageContent::new(content)
                .map_err(|_error| RemoteMailboxError::InvalidResponse)
                .map(|content| Message::new(envelope, content))
        })
    }
}

trait Transport: Send + Sync {
    fn get(&self, request: Request, response_limit: usize) -> TransportFuture<'_>;
}

struct Request {
    #[cfg(any(target_os = "macos", test))]
    url: Url,
}

impl Request {
    fn new(
        mut url: Url,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<Self, RemoteMailboxError> {
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| RemoteMailboxError::InvalidResponse)?;
            path.pop_if_empty();
            path.extend(segments);
        }
        url.query_pairs_mut()
            .extend_pairs(query.iter().map(|(key, value)| (*key, value.as_str())));
        #[cfg(any(target_os = "macos", test))]
        return Ok(Self { url });
        #[cfg(not(any(target_os = "macos", test)))]
        {
            drop(url);
            Ok(Self {})
        }
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

enum TransportError {
    #[cfg(any(target_os = "macos", test))]
    Network,
    #[cfg(any(target_os = "macos", test))]
    InvalidResponse,
}

impl TransportError {
    const fn into_mailbox_error(self) -> RemoteMailboxError {
        match self {
            #[cfg(any(target_os = "macos", test))]
            Self::Network => RemoteMailboxError::Transport,
            #[cfg(any(target_os = "macos", test))]
            Self::InvalidResponse => RemoteMailboxError::InvalidResponse,
        }
    }
}

#[cfg(any(target_os = "macos", test))]
struct BoundedBody {
    bytes: Vec<u8>,
    limit: usize,
}

#[cfg(any(target_os = "macos", test))]
const fn body_limit(status: u16, success_limit: usize) -> usize {
    if status >= 200 && status < 300 {
        success_limit
    } else {
        JSON_LIMIT
    }
}

#[cfg(any(target_os = "macos", test))]
const fn reads_response_body(status: u16) -> bool {
    (status >= 200 && status < 300) || status == 403
}

#[cfg(any(target_os = "macos", test))]
impl BoundedBody {
    fn new(content_length: Option<usize>, limit: usize) -> Result<Self, TransportError> {
        if content_length.is_some_and(|length| length > limit) {
            return Err(TransportError::InvalidResponse);
        }
        Ok(Self {
            bytes: Vec::with_capacity(content_length.unwrap_or(0).min(limit)),
            limit,
        })
    }

    fn push(&mut self, chunk: &[u8]) -> Result<(), TransportError> {
        let next = self
            .bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(TransportError::InvalidResponse)?;
        if next > self.limit {
            return Err(TransportError::InvalidResponse);
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(target_os = "macos")]
struct ReqwestTransport {
    client: reqwest::Client,
    token: Zeroizing<String>,
}

#[cfg(target_os = "macos")]
impl ReqwestTransport {
    fn new(token: Zeroizing<String>) -> Result<Self, RemoteMailboxError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .build()
            .map_err(|_error| RemoteMailboxError::Transport)?;
        Ok(Self { client, token })
    }
}

#[cfg(target_os = "macos")]
impl Transport for ReqwestTransport {
    fn get(&self, request: Request, response_limit: usize) -> TransportFuture<'_> {
        Box::pin(async move {
            let mut response = self
                .client
                .get(request.url)
                .bearer_auth(&*self.token)
                .send()
                .await
                .map_err(|_error| TransportError::Network)?;
            let status = response.status().as_u16();
            if !reads_response_body(status) {
                return Ok(HttpResponse {
                    status,
                    body: Vec::new(),
                });
            }
            let content_length = response
                .content_length()
                .and_then(|length| usize::try_from(length).ok());
            let mut body = BoundedBody::new(content_length, body_limit(status, response_limit))?;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_error| TransportError::Network)?
            {
                body.push(&chunk)?;
            }
            Ok(HttpResponse {
                status,
                body: body.finish(),
            })
        })
    }
}

#[cfg(target_os = "macos")]
fn validate_access_token(token: &str) -> Result<(), RemoteMailboxError> {
    if token.is_empty() || token.len() > MAX_ACCESS_TOKEN_LEN || token.chars().any(char::is_control)
    {
        return Err(RemoteMailboxError::AuthorizationRequired);
    }
    Ok(())
}

fn list_request(size: PageSize, token: Option<&PageToken>) -> Result<Request, RemoteMailboxError> {
    let mut query = vec![
        ("maxResults", size.get().to_string()),
        ("fields", "messages(id,threadId),nextPageToken".to_owned()),
    ];
    if let Some(token) = token {
        query.push(("pageToken", token.as_str().to_owned()));
    }
    Request::new(
        Url::parse(BASE_URL).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        &["messages"],
        &query,
    )
}

#[derive(Clone, Copy)]
enum MessageFormat {
    Metadata,
    Raw,
}

fn message_request(id: &MessageId, format: MessageFormat) -> Result<Request, RemoteMailboxError> {
    let query = match format {
        MessageFormat::Metadata => vec![
            ("format", "metadata".to_owned()),
            ("metadataHeaders", "From".to_owned()),
            ("metadataHeaders", "Subject".to_owned()),
            ("fields", METADATA_FIELDS.to_owned()),
        ],
        MessageFormat::Raw => vec![
            ("format", "raw".to_owned()),
            ("fields", RAW_FIELDS.to_owned()),
        ],
    };
    Request::new(
        Url::parse(BASE_URL).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        &["messages", id.as_str()],
        &query,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailList {
    #[serde(default)]
    messages: Vec<ListedMessage>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListedMessage {
    id: String,
    thread_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailMetadata {
    id: String,
    thread_id: String,
    internal_date: String,
    #[serde(default)]
    label_ids: Vec<String>,
    #[serde(default)]
    snippet: String,
    #[serde(default)]
    payload: Payload,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailRaw {
    id: String,
    thread_id: String,
    raw: String,
}

#[derive(Default, Deserialize)]
struct Payload {
    #[serde(default)]
    headers: Vec<Header>,
}

#[derive(Deserialize)]
struct Header {
    name: String,
    value: String,
}

fn envelope_from(
    message: GmailMetadata,
    expected_id: &MessageId,
) -> Result<MessageEnvelope, RemoteMailboxError> {
    if message.id != expected_id.as_str() {
        return Err(RemoteMailboxError::InvalidResponse);
    }
    let thread =
        ThreadId::new(message.thread_id).map_err(|_error| RemoteMailboxError::InvalidResponse)?;
    let timestamp = message
        .internal_date
        .parse::<i64>()
        .map_err(|_error| RemoteMailboxError::InvalidResponse)
        .and_then(|value| {
            UnixTimestampMillis::new(value).map_err(|_error| RemoteMailboxError::InvalidResponse)
        })?;
    let (from, subject) = headers(message.payload.headers)?;
    Ok(MessageEnvelope::new(
        expected_id.clone(),
        thread,
        HeaderText::new(from).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        HeaderText::new(subject).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        HeaderText::new(message.snippet).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        timestamp,
        message.label_ids.iter().any(|label| label == "UNREAD"),
    ))
}

fn headers(headers: Vec<Header>) -> Result<(String, String), RemoteMailboxError> {
    let mut from = None;
    let mut subject = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("from") {
            if from.replace(header.value).is_some() {
                return Err(RemoteMailboxError::InvalidResponse);
            }
        } else if header.name.eq_ignore_ascii_case("subject")
            && subject.replace(header.value).is_some()
        {
            return Err(RemoteMailboxError::InvalidResponse);
        }
    }
    Ok((from.unwrap_or_default(), subject.unwrap_or_default()))
}

fn decode_raw_with_limit(
    encoded: &str,
    decoded_limit: usize,
) -> Result<Vec<u8>, RemoteMailboxError> {
    let encoded_limit = decoded_limit
        .div_ceil(3)
        .checked_mul(4)
        .ok_or(RemoteMailboxError::InvalidResponse)?;
    if encoded.len() > encoded_limit {
        return Err(RemoteMailboxError::InvalidResponse);
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        .map_err(|_error| RemoteMailboxError::InvalidResponse)?;
    if decoded.len() > decoded_limit {
        return Err(RemoteMailboxError::InvalidResponse);
    }
    Ok(decoded)
}

fn map_status(status: u16, bytes: &[u8]) -> RemoteMailboxError {
    match status {
        401 => RemoteMailboxError::AuthorizationRequired,
        404 => RemoteMailboxError::NotFound,
        429 => RemoteMailboxError::RateLimited,
        500..=599 => RemoteMailboxError::Transport,
        403 => map_forbidden(bytes),
        _ => RemoteMailboxError::InvalidResponse,
    }
}

fn map_forbidden(bytes: &[u8]) -> RemoteMailboxError {
    let reasons = error_reasons(bytes);
    if reasons.iter().any(|reason| {
        matches!(
            reason.as_str(),
            "dailyLimitExceeded" | "rateLimitExceeded" | "userRateLimitExceeded" | "quotaExceeded"
        )
    }) {
        return RemoteMailboxError::RateLimited;
    }
    if reasons.iter().any(|reason| {
        matches!(
            reason.as_str(),
            "authError" | "insufficientPermissions" | "domainPolicy"
        )
    }) {
        return RemoteMailboxError::AuthorizationRequired;
    }
    RemoteMailboxError::InvalidResponse
}

fn error_reasons(bytes: &[u8]) -> Vec<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: ErrorDetail,
    }
    #[derive(Deserialize)]
    struct ErrorDetail {
        #[serde(default)]
        errors: Vec<ErrorReason>,
    }
    #[derive(Deserialize)]
    struct ErrorReason {
        reason: String,
    }
    serde_json::from_slice::<ErrorBody>(bytes)
        .map(|body| {
            body.error
                .errors
                .into_iter()
                .map(|error| error.reason)
                .collect()
        })
        .unwrap_or_default()
}

// Rust guideline compliant 1.0.

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::pending;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};

    use tersa_application::mailbox::{PageSize, PageToken, RemoteMailbox, RemoteMailboxError};
    use tersa_domain::mailbox::{AccountId, MessageId};

    use super::{
        BoundedBody, GmailMailbox, HttpResponse, JSON_LIMIT, RAW_JSON_LIMIT, Request, Transport,
        TransportError, TransportFuture, body_limit, decode_raw_with_limit, map_status,
        reads_response_body,
    };

    const ACCOUNT: &str = "account-1";

    #[derive(Clone)]
    struct FakeTransport {
        state: Arc<FakeState>,
    }

    struct FakeState {
        replies: Mutex<VecDeque<Reply>>,
        requests: Mutex<Vec<(String, usize)>>,
    }

    enum Reply {
        Response {
            status: u16,
            content_length: Option<usize>,
            chunks: Vec<Vec<u8>>,
        },
        Network,
        Pending(Arc<AtomicBool>),
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl FakeTransport {
        fn new(replies: Vec<Reply>) -> Self {
            Self {
                state: Arc::new(FakeState {
                    replies: Mutex::new(replies.into()),
                    requests: Mutex::new(Vec::new()),
                }),
            }
        }

        fn requests(&self) -> Vec<(String, usize)> {
            self.state.requests.lock().map_or_else(
                |poisoned| poisoned.into_inner().clone(),
                |guard| guard.clone(),
            )
        }
    }

    impl Transport for FakeTransport {
        fn get(&self, request: Request, response_limit: usize) -> TransportFuture<'_> {
            self.state
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((request.url.into(), response_limit));
            let reply = self
                .state
                .replies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front();
            Box::pin(async move {
                match reply {
                    Some(Reply::Response {
                        status,
                        content_length,
                        chunks,
                    }) => {
                        if !reads_response_body(status) {
                            return Ok(HttpResponse {
                                status,
                                body: Vec::new(),
                            });
                        }
                        let mut body =
                            BoundedBody::new(content_length, body_limit(status, response_limit))?;
                        for chunk in chunks {
                            body.push(&chunk)?;
                        }
                        Ok(HttpResponse {
                            status,
                            body: body.finish(),
                        })
                    }
                    Some(Reply::Network) | None => Err(TransportError::Network),
                    Some(Reply::Pending(dropped)) => {
                        let _drop_signal = DropSignal(dropped);
                        pending::<()>().await;
                        unreachable!("pending fake transport completed")
                    }
                }
            })
        }
    }

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn poll_once<T>(future: Pin<&mut dyn Future<Output = T>>) -> Poll<T> {
        let waker = Waker::from(Arc::new(NoopWake));
        future.poll(&mut Context::from_waker(&waker))
    }

    fn ready<T>(mut future: Pin<Box<dyn Future<Output = T> + Send + '_>>) -> T {
        match poll_once(future.as_mut()) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly remained pending"),
        }
    }

    fn account(value: &str) -> AccountId {
        AccountId::new(value).unwrap_or_else(|error| panic!("invalid test account: {error}"))
    }

    fn message_id(value: &str) -> MessageId {
        MessageId::new(value).unwrap_or_else(|error| panic!("invalid test message ID: {error}"))
    }

    fn json(status: u16, body: &str) -> Reply {
        Reply::Response {
            status,
            content_length: Some(body.len()),
            chunks: body.as_bytes().chunks(7).map(<[u8]>::to_vec).collect(),
        }
    }

    fn metadata(id: &str, thread: &str, unread: bool) -> String {
        let labels = if unread {
            r#"["UNREAD","INBOX"]"#
        } else {
            "[]"
        };
        format!(
            r#"{{"id":"{id}","threadId":"{thread}","internalDate":"42","labelIds":{labels},"snippet":"Preview","payload":{{"headers":[{{"name":"From","value":"Sender <sender@example.test>"}},{{"name":"Subject","value":"Subject"}}]}}}}"#
        )
    }

    #[test]
    fn lists_in_provider_order_with_exact_requests_and_next_token() {
        let transport = FakeTransport::new(vec![
            json(
                200,
                r#"{"messages":[{"id":"m1","threadId":"t1"},{"id":"m2","threadId":"t2"}],"nextPageToken":"next/token"}"#,
            ),
            json(200, &metadata("m1", "t1", true)),
            json(200, &metadata("m2", "t2", false)),
        ]);
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
        let page_token = PageToken::new("page/token").unwrap_or_else(|error| panic!("{error}"));
        let result = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(2).unwrap_or_else(|error| panic!("{error}")),
            Some(&page_token),
        ))
        .unwrap_or_else(|error| panic!("list failed: {error}"));

        assert_eq!(result.items().len(), 2);
        assert_eq!(result.items()[0].message_id().as_str(), "m1");
        assert!(result.items()[0].is_unread());
        assert_eq!(result.items()[1].message_id().as_str(), "m2");
        assert!(!result.items()[1].is_unread());
        assert_eq!(
            result.next_token().map(PageToken::as_str),
            Some("next/token")
        );

        let requests = transport.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].1, JSON_LIMIT);
        assert_eq!(requests[1].1, JSON_LIMIT);
        assert_eq!(
            requests[0].0,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=2&fields=messages%28id%2CthreadId%29%2CnextPageToken&pageToken=page%2Ftoken"
        );
        assert_eq!(
            requests[1].0,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/m1?format=metadata&metadataHeaders=From&metadataHeaders=Subject&fields=id%2CthreadId%2CinternalDate%2ClabelIds%2Csnippet%2Cpayload%28headers%29"
        );
        assert_eq!(
            requests[2].0,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/m2?format=metadata&metadataHeaders=From&metadataHeaders=Subject&fields=id%2CthreadId%2CinternalDate%2ClabelIds%2Csnippet%2Cpayload%28headers%29"
        );
    }

    #[test]
    fn rejects_an_account_mismatch_before_transport_work() {
        let transport = FakeTransport::new(vec![]);
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
        let result = ready(mailbox.list_recent_envelopes(
            &account("account-2"),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::AuthorizationRequired));
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn skips_only_a_not_found_hydration() {
        let transport = FakeTransport::new(vec![
            json(
                200,
                r#"{"messages":[{"id":"gone","threadId":"tg"},{"id":"kept","threadId":"tk"}]}"#,
            ),
            json(404, r#"{"error":{"errors":[]}}"#),
            json(200, &metadata("kept", "tk", false)),
        ]);
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport);
        let page = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(2).unwrap_or_else(|error| panic!("{error}")),
            None,
        ))
        .unwrap_or_else(|error| panic!("list failed: {error}"));
        assert_eq!(page.items().len(), 1);
        assert_eq!(page.items()[0].message_id().as_str(), "kept");
    }

    #[test]
    fn fails_the_page_on_a_non_not_found_hydration_error() {
        let transport = FakeTransport::new(vec![
            json(
                200,
                r#"{"messages":[{"id":"first","threadId":"t1"},{"id":"second","threadId":"t2"}]}"#,
            ),
            json(500, r#"{"error":{"errors":[]}}"#),
            json(200, &metadata("second", "t2", false)),
        ]);
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
        let result = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(2).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::Transport));
        assert_eq!(transport.requests().len(), 2);
    }

    #[test]
    fn rejects_malformed_page_data_and_thread_mismatch() {
        for replies in [
            vec![json(
                200,
                r#"{"messages":[{"id":"bad id","threadId":"t"}]}"#,
            )],
            vec![
                json(200, r#"{"messages":[{"id":"m","threadId":"listed"}]}"#),
                json(200, &metadata("m", "hydrated", false)),
            ],
            vec![json(200, r#"{"nextPageToken":""}"#)],
        ] {
            let mailbox =
                GmailMailbox::with_transport(account(ACCOUNT), FakeTransport::new(replies));
            let result = ready(mailbox.list_recent_envelopes(
                &account(ACCOUNT),
                PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
                None,
            ));
            assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
        }
    }

    #[test]
    fn rejects_malformed_or_oversized_metadata() {
        let oversized = format!(
            r#"{{"id":"m","threadId":"t","internalDate":"0","snippet":"{}"}}"#,
            "x".repeat(1_025)
        );
        for metadata_body in [
            r#"{"id":"other","threadId":"t","internalDate":"0"}"#.to_owned(),
            r#"{"id":"m","threadId":"t","internalDate":"-1"}"#.to_owned(),
            r#"{"id":"m","threadId":"t","internalDate":"not-a-number"}"#.to_owned(),
            r#"{"threadId":"t","internalDate":"0"}"#.to_owned(),
            r#"{"id":"m","threadId":"t","internalDate":"0","labelIds":[1]}"#.to_owned(),
            r#"{"id":"m","threadId":"t","internalDate":"0","payload":{"headers":[{"name":"From","value":"line\nbreak"}]}}"#.to_owned(),
            oversized,
        ] {
            let mailbox = GmailMailbox::with_transport(
                account(ACCOUNT),
                FakeTransport::new(vec![
                    json(200, r#"{"messages":[{"id":"m","threadId":"t"}]}"#),
                    json(200, &metadata_body),
                ]),
            );
            let result = ready(mailbox.list_recent_envelopes(
                &account(ACCOUNT),
                PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
                None,
            ));
            assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
        }
    }

    #[test]
    fn accepts_missing_headers_and_rejects_duplicate_singletons() {
        let missing = r#"{"id":"m","threadId":"t","internalDate":"0","payload":{"headers":[]}}"#;
        let duplicate = r#"{"id":"m","threadId":"t","internalDate":"0","payload":{"headers":[{"name":"From","value":"one"},{"name":"from","value":"two"}]}}"#;

        let mailbox = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![
                json(200, r#"{"messages":[{"id":"m","threadId":"t"}]}"#),
                json(200, missing),
            ]),
        );
        let page = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ))
        .unwrap_or_else(|error| panic!("list failed: {error}"));
        assert_eq!(page.items()[0].from().as_str(), "");
        assert_eq!(page.items()[0].subject().as_str(), "");

        let mailbox = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![
                json(200, r#"{"messages":[{"id":"m","threadId":"t"}]}"#),
                json(200, duplicate),
            ]),
        );
        let result = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
    }

    #[test]
    fn fetches_padded_and_unpadded_raw_with_encoded_path() {
        for encoded in ["SGVsbG8", "SGVsbG8="] {
            let transport = FakeTransport::new(vec![
                json(200, &metadata("id/with?chars", "thread", false)),
                json(
                    200,
                    &format!(r#"{{"id":"id/with?chars","threadId":"thread","raw":"{encoded}"}}"#),
                ),
            ]);
            let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
            let message_id = message_id("id/with?chars");
            let message = ready(mailbox.fetch_message(&account(ACCOUNT), &message_id))
                .unwrap_or_else(|error| panic!("fetch failed: {error}"));
            assert_eq!(message.content().as_bytes(), b"Hello");
            let requests = transport.requests();
            assert_eq!(requests.len(), 2);
            assert!(requests[0].0.contains("/messages/id%2Fwith%3Fchars?"));
            assert_eq!(requests[1].1, RAW_JSON_LIMIT);
            assert_eq!(
                requests[1].0,
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/id%2Fwith%3Fchars?format=raw&fields=id%2CthreadId%2Craw"
            );
        }
    }

    #[test]
    fn rejects_raw_identity_mismatch_and_invalid_base64() {
        for raw in [
            r#"{"id":"other","threadId":"thread","raw":"SGVsbG8"}"#,
            r#"{"id":"m","threadId":"other","raw":"SGVsbG8"}"#,
            r#"{"id":"m","threadId":"thread","raw":"%%%"}"#,
        ] {
            let mailbox = GmailMailbox::with_transport(
                account(ACCOUNT),
                FakeTransport::new(vec![
                    json(200, &metadata("m", "thread", false)),
                    json(200, raw),
                ]),
            );
            let result = ready(mailbox.fetch_message(&account(ACCOUNT), &message_id("m")));
            assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
        }
    }

    #[test]
    fn enforces_encoded_and_decoded_raw_boundaries_without_large_allocations() {
        assert_eq!(decode_raw_with_limit("QQ", 1), Ok(vec![b'A']));
        assert_eq!(
            decode_raw_with_limit("QUE", 1),
            Err(RemoteMailboxError::InvalidResponse)
        );
        assert_eq!(
            decode_raw_with_limit("QUJDRA", 3),
            Err(RemoteMailboxError::InvalidResponse)
        );
    }

    #[test]
    fn rejects_content_length_and_stream_overflow_before_unbounded_growth() {
        assert_eq!(body_limit(200, RAW_JSON_LIMIT), RAW_JSON_LIMIT);
        assert_eq!(body_limit(403, RAW_JSON_LIMIT), JSON_LIMIT);
        assert!(reads_response_body(200));
        assert!(reads_response_body(403));
        assert!(!reads_response_body(500));
        assert!(matches!(
            BoundedBody::new(Some(5), 4),
            Err(TransportError::InvalidResponse)
        ));
        let mut body = BoundedBody::new(None, 4)
            .unwrap_or_else(|_| panic!("bounded body construction failed"));
        assert!(body.push(b"1234").is_ok());
        assert!(matches!(
            body.push(b"5"),
            Err(TransportError::InvalidResponse)
        ));
    }

    #[test]
    fn maps_documented_statuses_and_all_forbidden_reasons() {
        assert_eq!(
            map_status(401, b""),
            RemoteMailboxError::AuthorizationRequired
        );
        assert_eq!(map_status(404, b""), RemoteMailboxError::NotFound);
        assert_eq!(map_status(429, b""), RemoteMailboxError::RateLimited);
        assert_eq!(map_status(503, b""), RemoteMailboxError::Transport);
        for reason in [
            "dailyLimitExceeded",
            "rateLimitExceeded",
            "userRateLimitExceeded",
            "quotaExceeded",
        ] {
            let body = format!(r#"{{"error":{{"errors":[{{"reason":"{reason}"}}]}}}}"#);
            assert_eq!(
                map_status(403, body.as_bytes()),
                RemoteMailboxError::RateLimited
            );
        }
        for reason in ["authError", "insufficientPermissions", "domainPolicy"] {
            let body = format!(r#"{{"error":{{"errors":[{{"reason":"{reason}"}}]}}}}"#);
            assert_eq!(
                map_status(403, body.as_bytes()),
                RemoteMailboxError::AuthorizationRequired
            );
        }
        let later_reason =
            br#"{"error":{"errors":[{"reason":"unknown"},{"reason":"rateLimitExceeded"}]}}"#;
        assert_eq!(
            map_status(403, later_reason),
            RemoteMailboxError::RateLimited
        );
        assert_eq!(map_status(400, b""), RemoteMailboxError::InvalidResponse);
        assert_eq!(
            map_status(403, b"malformed"),
            RemoteMailboxError::InvalidResponse
        );
    }

    #[test]
    fn maps_network_and_oversized_transport_failures_without_payloads() {
        let network = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![Reply::Network]),
        );
        let result = ready(network.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::Transport));

        let oversized = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![Reply::Response {
                status: 200,
                content_length: Some(JSON_LIMIT + 1),
                chunks: vec![],
            }]),
        );
        let result = ready(oversized.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));

        let server_error = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![Reply::Response {
                status: 503,
                content_length: Some(usize::MAX),
                chunks: vec![vec![0; 8]],
            }]),
        );
        let result = ready(server_error.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::Transport));
    }

    #[test]
    fn debug_output_is_redacted() {
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), FakeTransport::new(vec![]));
        assert_eq!(format!("{mailbox:?}"), "GmailMailbox([REDACTED])");
        assert!(!format!("{mailbox:?}").contains(ACCOUNT));
    }

    #[test]
    fn dropping_a_pending_operation_releases_future_owned_state() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mailbox = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![Reply::Pending(Arc::clone(&dropped))]),
        );
        let selected_account = account(ACCOUNT);
        let mut future = mailbox.list_recent_envelopes(
            &selected_account,
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        );
        assert!(poll_once(future.as_mut()).is_pending());
        assert!(!dropped.load(Ordering::SeqCst));
        drop(future);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validates_access_tokens_without_constructing_a_network_client() {
        use super::{MAX_ACCESS_TOKEN_LEN, validate_access_token};

        assert!(validate_access_token("short-lived-token").is_ok());
        assert_eq!(
            validate_access_token(""),
            Err(RemoteMailboxError::AuthorizationRequired)
        );
        assert_eq!(
            validate_access_token("line\nbreak"),
            Err(RemoteMailboxError::AuthorizationRequired)
        );
        assert_eq!(
            validate_access_token(&"x".repeat(MAX_ACCESS_TOKEN_LEN + 1)),
            Err(RemoteMailboxError::AuthorizationRequired)
        );
    }
}
