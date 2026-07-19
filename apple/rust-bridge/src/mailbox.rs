// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exposes bounded read-only mailbox queries through a narrow C ABI.
//!
//! The bridge validates and copies caller-owned bytes, then delegates every
//! check to the trusted Keychain read composition. Only serialized JSON
//! documents cross back through caller-allocated buffers.

use std::fmt::Write as _;
use std::slice;

use tersa_application::mailbox_metadata::MAILBOX_METADATA_SCHEMA_VERSION;
use tersa_presentation::mailbox::{
    InboxViewModel, MessageRowViewModel, SearchViewModel, ThreadViewModel,
};

// Rust guideline compliant 1.0.

/// Reads the fixed default inbox into a caller-allocated JSON buffer.
///
/// On success the buffer holds the bounded serialized document and
/// `output_len` holds its byte count. When the declared capacity is too
/// small, `output_len` receives the required byte count and the closed
/// buffer-too-small status is returned so the caller can retry once.
///
/// # Safety
///
/// A non-null `account_id` must point to `account_id_len` readable bytes for
/// the duration of this call. Non-null `output` and `output_len` must be
/// writable for `output_capacity` bytes and one `usize` respectively.
#[expect(
    unsafe_code,
    reason = "the narrow C ABI validates and immediately copies caller-owned account bytes"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_macos_mailbox_read_inbox(
    account_id: *const u8,
    account_id_len: usize,
    limit: u16,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if account_id.is_null()
        || account_id_len == 0
        || account_id_len > 256
        || output.is_null()
        || output_len.is_null()
    {
        return tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32;
    }
    // SAFETY: The C ABI contract requires the checked range to be readable.
    let account = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();
    let model = match tersa_keychain_macos::mailbox_read::read_default_inbox(&account, limit) {
        Ok(model) => model,
        Err(status) => return status as i32,
    };
    let encoded = encode_inbox(&model);
    // SAFETY: The validated outputs are writable for the declared capacity.
    if unsafe { write_bounded_output(&encoded, output, output_capacity, output_len) } {
        tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32
    } else {
        tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall as i32
    }
}

/// Reads one fixed default thread into a caller-allocated JSON buffer.
///
/// The output contract matches [`tersa_macos_mailbox_read_inbox`].
///
/// # Safety
///
/// Non-null `account_id` and `thread_id` must point to `account_id_len` and
/// `thread_id_len` readable bytes for the duration of this call. Non-null
/// `output` and `output_len` must be writable for `output_capacity` bytes and
/// one `usize` respectively.
#[expect(
    unsafe_code,
    reason = "the narrow C ABI validates and immediately copies caller-owned account and thread bytes"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_macos_mailbox_read_thread(
    account_id: *const u8,
    account_id_len: usize,
    thread_id: *const u8,
    thread_id_len: usize,
    limit: u16,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if account_id.is_null()
        || account_id_len == 0
        || account_id_len > 256
        || thread_id.is_null()
        || thread_id_len == 0
        || thread_id_len > 256
        || output.is_null()
        || output_len.is_null()
    {
        return tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32;
    }
    // SAFETY: The C ABI contract requires the checked range to be readable.
    let account = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();
    // SAFETY: The C ABI contract requires the checked range to be readable.
    let thread = unsafe { slice::from_raw_parts(thread_id, thread_id_len) }.to_vec();
    let model =
        match tersa_keychain_macos::mailbox_read::read_default_thread(&account, &thread, limit) {
            Ok(model) => model,
            Err(status) => return status as i32,
        };
    let encoded = encode_thread(&model);
    // SAFETY: The validated outputs are writable for the declared capacity.
    if unsafe { write_bounded_output(&encoded, output, output_capacity, output_len) } {
        tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32
    } else {
        tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall as i32
    }
}

/// Searches the fixed default cache into a caller-allocated JSON buffer.
///
/// The output contract matches [`tersa_macos_mailbox_read_inbox`].
///
/// # Safety
///
/// Non-null `account_id` and `query` must point to `account_id_len` and
/// `query_len` readable bytes for the duration of this call. Non-null
/// `output` and `output_len` must be writable for `output_capacity` bytes and
/// one `usize` respectively.
#[expect(
    unsafe_code,
    reason = "the narrow C ABI validates and immediately copies caller-owned account and query bytes"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_macos_mailbox_search(
    account_id: *const u8,
    account_id_len: usize,
    query: *const u8,
    query_len: usize,
    limit: u16,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if account_id.is_null()
        || account_id_len == 0
        || account_id_len > 256
        || query.is_null()
        || query_len == 0
        || query_len > 256
        || output.is_null()
        || output_len.is_null()
    {
        return tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32;
    }
    // SAFETY: The C ABI contract requires the checked range to be readable.
    let account = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();
    // SAFETY: The C ABI contract requires the checked range to be readable.
    let query = unsafe { slice::from_raw_parts(query, query_len) }.to_vec();
    let model =
        match tersa_keychain_macos::mailbox_read::search_default_mailbox(&account, &query, limit) {
            Ok(model) => model,
            Err(status) => return status as i32,
        };
    let encoded = encode_search(&model);
    // SAFETY: The validated outputs are writable for the declared capacity.
    if unsafe { write_bounded_output(&encoded, output, output_capacity, output_len) } {
        tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32
    } else {
        tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall as i32
    }
}

/// Writes `bytes` into the caller buffer, always reporting through
/// `output_len`.
///
/// Returns `false` when the declared capacity is too small; `output_len` then
/// holds the required byte count so the caller can map the closed
/// buffer-too-small status and retry once with a larger buffer.
#[expect(
    unsafe_code,
    reason = "the C ABI writes bounded bytes into validated caller outputs"
)]
unsafe fn write_bounded_output(
    bytes: &[u8],
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> bool {
    if bytes.len() > output_capacity {
        // SAFETY: The caller guarantees a writable length-out pointer.
        unsafe { output_len.write(bytes.len()) };
        return false;
    }
    // SAFETY: The caller guarantees writable outputs with the declared capacity.
    unsafe {
        output.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
        output_len.write(bytes.len());
    }
    true
}

/// Encodes one inbox view model with the stable CLI field parity.
fn encode_inbox(model: &InboxViewModel) -> Vec<u8> {
    let mut output = envelope_prefix("inbox", model.account_id());
    push_limit(&mut output, model.limit());
    push_rows(&mut output, model.rows());
    output.into_bytes()
}

/// Encodes one thread view model with the stable CLI field parity.
fn encode_thread(model: &ThreadViewModel) -> Vec<u8> {
    let mut output = envelope_prefix("thread", model.account_id());
    output.push_str(",\"thread_id\":");
    push_json_string(&mut output, model.thread_id());
    push_limit(&mut output, model.limit());
    push_rows(&mut output, model.rows());
    output.into_bytes()
}

/// Encodes one search view model with the stable CLI field parity.
fn encode_search(model: &SearchViewModel) -> Vec<u8> {
    let mut output = envelope_prefix("search", model.account_id());
    output.push_str(",\"query\":");
    push_json_string(&mut output, model.query());
    push_limit(&mut output, model.limit());
    push_rows(&mut output, model.rows());
    output.into_bytes()
}

/// Writes the stable envelope prefix shared by every read document.
fn envelope_prefix(command: &str, account_id: &str) -> String {
    let mut output = String::from("{\"schema_version\":");
    // Writing to a String cannot fail.
    let _ = write!(output, "{MAILBOX_METADATA_SCHEMA_VERSION}");
    output.push_str(",\"command\":");
    push_json_string(&mut output, command);
    output.push_str(",\"account_id\":");
    push_json_string(&mut output, account_id);
    output
}

/// Writes the validated result limit field.
fn push_limit(output: &mut String, limit: u16) {
    output.push_str(",\"limit\":");
    // Writing to a String cannot fail.
    let _ = write!(output, "{limit}");
}

/// Writes the message rows in document order with the stable field parity.
fn push_rows(output: &mut String, rows: &[MessageRowViewModel]) {
    output.push_str(",\"messages\":[");
    for (index, row) in rows.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"message_id\":");
        push_json_string(output, &row.message_id);
        output.push_str(",\"thread_id\":");
        push_json_string(output, &row.thread_id);
        output.push_str(",\"from\":");
        push_json_string(output, &row.from);
        output.push_str(",\"subject\":");
        push_json_string(output, &row.subject);
        output.push_str(",\"received_at_millis\":");
        // Writing to a String cannot fail.
        let _ = write!(output, "{}", row.received_at_millis);
        output.push_str(",\"unread\":");
        output.push_str(if row.unread { "true" } else { "false" });
        output.push('}');
    }
    output.push_str("]}");
}

/// Writes one JSON string literal, escaping C0, DEL, and C1 scalars as
/// uppercase `\uXXXX` exactly like the metadata-only CLI.
fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            character
                if character <= '\u{001F}' || ('\u{007F}'..='\u{009F}').contains(&character) =>
            {
                // Writing to a String cannot fail.
                let _ = write!(output, "\\u{:04X}", u32::from(character));
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
#[expect(
    unsafe_code,
    clippy::unwrap_used,
    reason = "the public C ABI is unsafe to call and these tests exercise its checked boundary with valid fixtures"
)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tersa_application::mailbox::{
        AccountId, BoxFuture, HeaderText, MailboxReader, MailboxStoreError, MessageEnvelope,
        MessageId, StoreLimit, ThreadId, UnixTimestampMillis,
    };
    use tersa_application::mailbox_metadata::{inbox_metadata, thread_metadata};
    use tersa_application::mailbox_search::{MailboxSearchQuery, search_metadata};

    use super::*;

    struct FakeReader {
        envelopes: Vec<MessageEnvelope>,
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
    }

    fn account() -> AccountId {
        AccountId::new("account-1").unwrap()
    }

    fn thread() -> ThreadId {
        ThreadId::new("thread-a").unwrap()
    }

    fn limit() -> StoreLimit {
        StoreLimit::new(50).unwrap()
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

    fn run<T>(future: impl Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => {
                panic!("application metadata future must complete synchronously")
            }
        }
    }

    fn inbox_model(envelopes: Vec<MessageEnvelope>) -> InboxViewModel {
        let reader = FakeReader {
            envelopes,
            last_limit: Arc::new(AtomicUsize::new(0)),
        };
        let document = run(inbox_metadata(&reader, &account(), limit())).unwrap();
        InboxViewModel::from_document(&document).unwrap()
    }

    fn thread_model(envelopes: Vec<MessageEnvelope>) -> ThreadViewModel {
        let reader = FakeReader {
            envelopes,
            last_limit: Arc::new(AtomicUsize::new(0)),
        };
        let document = run(thread_metadata(&reader, &account(), &thread(), limit())).unwrap();
        ThreadViewModel::from_document(&document, &thread()).unwrap()
    }

    fn search_model(envelopes: Vec<MessageEnvelope>, query: &str) -> SearchViewModel {
        let reader = FakeReader {
            envelopes,
            last_limit: Arc::new(AtomicUsize::new(0)),
        };
        let query = MailboxSearchQuery::new(query).unwrap();
        let document = run(search_metadata(&reader, &account(), &query, limit())).unwrap();
        SearchViewModel::from_document(&document)
    }

    #[test]
    fn inbox_golden_json_matches_the_cli_byte_for_byte() {
        let model = inbox_model(vec![
            envelope("newest", "thread-a", "from-newest", 20),
            envelope("older", "thread-b", "from-older", 10),
        ]);
        let encoded = encode_inbox(&model);

        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            "{\"schema_version\":1,\"command\":\"inbox\",\"account_id\":\"account-1\",\"limit\":50,\"messages\":[{\"message_id\":\"newest\",\"thread_id\":\"thread-a\",\"from\":\"from-newest\",\"subject\":\"subject-newest\",\"received_at_millis\":20,\"unread\":true},{\"message_id\":\"older\",\"thread_id\":\"thread-b\",\"from\":\"from-older\",\"subject\":\"subject-older\",\"received_at_millis\":10,\"unread\":true}]}"
        );
    }

    #[test]
    fn thread_golden_json_carries_the_thread_envelope_field() {
        let model = thread_model(vec![envelope(
            "message-1",
            "thread-a",
            "from-message-1",
            10,
        )]);
        let encoded = encode_thread(&model);

        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            "{\"schema_version\":1,\"command\":\"thread\",\"account_id\":\"account-1\",\"thread_id\":\"thread-a\",\"limit\":50,\"messages\":[{\"message_id\":\"message-1\",\"thread_id\":\"thread-a\",\"from\":\"from-message-1\",\"subject\":\"subject-message-1\",\"received_at_millis\":10,\"unread\":true}]}"
        );
    }

    #[test]
    fn search_golden_json_carries_the_query_envelope_field() {
        let model = search_model(
            vec![
                envelope("hit", "thread-a", "alice@example.test", 20),
                envelope("miss", "thread-b", "bob@example.test", 10),
            ],
            "alice",
        );
        let encoded = encode_search(&model);

        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            "{\"schema_version\":1,\"command\":\"search\",\"account_id\":\"account-1\",\"query\":\"alice\",\"limit\":50,\"messages\":[{\"message_id\":\"hit\",\"thread_id\":\"thread-a\",\"from\":\"alice@example.test\",\"subject\":\"subject-hit\",\"received_at_millis\":20,\"unread\":true}]}"
        );
    }

    #[test]
    fn empty_read_encodes_an_empty_messages_array() {
        let model = inbox_model(Vec::new());
        let encoded = encode_inbox(&model);
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            "{\"schema_version\":1,\"command\":\"inbox\",\"account_id\":\"account-1\",\"limit\":50,\"messages\":[]}"
        );
    }

    #[test]
    fn row_escaping_covers_every_c0_del_and_c1_scalar() {
        let controls = (0_u32..=0x1F)
            .chain(0x7F..=0x9F)
            .map(|value| char::from_u32(value).unwrap())
            .collect::<String>();
        let row = MessageRowViewModel {
            message_id: format!("m{controls}"),
            thread_id: "thread".to_owned(),
            from: "quote=\" slash=\\ snow=雪".to_owned(),
            subject: String::new(),
            received_at_millis: 7,
            unread: false,
        };
        let mut output = String::new();
        push_rows(&mut output, &[row]);

        let expected_controls =
            (0_u32..=0x1F)
                .chain(0x7F..=0x9F)
                .fold(String::new(), |mut encoded, value| {
                    // Writing to a String cannot fail.
                    let _ = write!(encoded, "\\u{value:04X}");
                    encoded
                });
        assert_eq!(
            output,
            format!(
                ",\"messages\":[{{\"message_id\":\"m{expected_controls}\",\"thread_id\":\"thread\",\"from\":\"quote=\\\" slash=\\\\ snow=雪\",\"subject\":\"\",\"received_at_millis\":7,\"unread\":false}}]}}"
            )
        );
    }

    #[test]
    fn ffi_rejects_invalid_inbox_inputs_without_capability_access() {
        let invalid = tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32;
        let account = b"account-1";
        let mut buffer = [0_u8; 64];
        let mut length = usize::MAX;
        // SAFETY: every pointer is valid; rejected classes return before any
        // capability access or pointer dereference.
        unsafe {
            assert_eq!(
                tersa_macos_mailbox_read_inbox(
                    std::ptr::null(),
                    account.len(),
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
            assert_eq!(
                tersa_macos_mailbox_read_inbox(
                    account.as_ptr(),
                    0,
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
            let oversized = [b'a'; 257];
            assert_eq!(
                tersa_macos_mailbox_read_inbox(
                    oversized.as_ptr(),
                    oversized.len(),
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
            assert_eq!(
                tersa_macos_mailbox_read_inbox(
                    account.as_ptr(),
                    account.len(),
                    50,
                    std::ptr::null_mut(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
            assert_eq!(
                tersa_macos_mailbox_read_inbox(
                    account.as_ptr(),
                    account.len(),
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    std::ptr::null_mut(),
                ),
                invalid
            );
        }
        assert_eq!(length, usize::MAX);
    }

    #[test]
    fn ffi_rejects_invalid_thread_inputs_without_capability_access() {
        let invalid = tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32;
        let account = b"account-1";
        let thread = b"thread-a";
        let mut buffer = [0_u8; 64];
        let mut length = usize::MAX;
        // SAFETY: every pointer is valid; rejected classes return before any
        // capability access or pointer dereference.
        unsafe {
            assert_eq!(
                tersa_macos_mailbox_read_thread(
                    account.as_ptr(),
                    account.len(),
                    std::ptr::null(),
                    thread.len(),
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
            assert_eq!(
                tersa_macos_mailbox_read_thread(
                    account.as_ptr(),
                    account.len(),
                    thread.as_ptr(),
                    0,
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
            let oversized = [b'a'; 257];
            assert_eq!(
                tersa_macos_mailbox_read_thread(
                    account.as_ptr(),
                    account.len(),
                    oversized.as_ptr(),
                    oversized.len(),
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
        }
        assert_eq!(length, usize::MAX);
    }

    #[test]
    fn ffi_rejects_invalid_search_inputs_without_capability_access() {
        let invalid = tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32;
        let account = b"account-1";
        let query = b"alice";
        let mut buffer = [0_u8; 64];
        let mut length = usize::MAX;
        // SAFETY: every pointer is valid; rejected classes return before any
        // capability access or pointer dereference.
        unsafe {
            assert_eq!(
                tersa_macos_mailbox_search(
                    account.as_ptr(),
                    account.len(),
                    std::ptr::null(),
                    query.len(),
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
            assert_eq!(
                tersa_macos_mailbox_search(
                    account.as_ptr(),
                    account.len(),
                    query.as_ptr(),
                    0,
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
            let oversized = [b'a'; 257];
            assert_eq!(
                tersa_macos_mailbox_search(
                    account.as_ptr(),
                    account.len(),
                    oversized.as_ptr(),
                    oversized.len(),
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                ),
                invalid
            );
        }
        assert_eq!(length, usize::MAX);
    }

    #[test]
    fn bounded_output_reports_the_required_size_when_capacity_is_too_small() {
        let bytes = b"{\"schema_version\":1}";
        let mut length = usize::MAX;
        // SAFETY: `length` is a valid writable length-out pointer; the output
        // pointer is never dereferenced on the too-small path.
        let written = unsafe {
            write_bounded_output(
                bytes,
                std::ptr::null_mut(),
                bytes.len() - 1,
                &raw mut length,
            )
        };
        assert!(!written);
        assert_eq!(length, bytes.len());

        let mut buffer = [0_u8; 64];
        let mut length = 0_usize;
        // SAFETY: `buffer` is writable for its declared capacity.
        let written = unsafe {
            write_bounded_output(bytes, buffer.as_mut_ptr(), buffer.len(), &raw mut length)
        };
        assert!(written);
        assert_eq!(length, bytes.len());
        assert_eq!(&buffer[..bytes.len()], bytes);
    }

    #[test]
    fn ffi_background_thread_preserves_boundary_status_mapping() {
        let status = std::thread::spawn(|| {
            let invalid = b"invalid account";
            let mut buffer = [0_u8; 64];
            let mut length = usize::MAX;
            // SAFETY: `invalid` has the stated readable length and is copied by
            // the ABI; `buffer` is writable for its declared capacity.
            let status = unsafe {
                tersa_macos_mailbox_read_inbox(
                    invalid.as_ptr(),
                    invalid.len(),
                    50,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                )
            };
            assert_eq!(length, usize::MAX);
            status
        })
        .join()
        .expect("background boundary call must not panic");
        assert_eq!(
            status,
            tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32
        );
    }
}
