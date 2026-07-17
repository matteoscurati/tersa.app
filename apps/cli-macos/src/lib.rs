// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

//! Strict process boundary for metadata-only mailbox output.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Write;
use std::task::{Context, Poll, Waker};

use tersa_application::mailbox::{MailboxReader, MailboxStoreError, StoreLimit};
use tersa_application::mailbox_metadata::{
    MailboxMetadataDocument, inbox_metadata, thread_metadata,
};
use tersa_domain::mailbox::{AccountId, ThreadId};

const DEFAULT_LIMIT: u16 = 50;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Exit {
    Success = 0,
    Invocation = 2,
    KeyAccess = 3,
    Profile = 4,
    MissingThread = 5,
    Corrupted = 6,
    Operation = 7,
}

impl Exit {
    const fn stderr(self) -> Option<&'static str> {
        match self {
            Self::Success => None,
            Self::Invocation => Some("mailctl: invalid invocation\n"),
            Self::KeyAccess => Some("mailctl: key access failed\n"),
            Self::Profile => Some("mailctl: local profile is unavailable\n"),
            Self::MissingThread => Some("mailctl: mailbox item was not found\n"),
            Self::Corrupted => Some("mailctl: local mailbox is corrupted\n"),
            Self::Operation => Some("mailctl: operation failed\n"),
        }
    }
}

#[derive(Debug)]
enum Command {
    Inbox,
    Thread(ThreadId),
}

#[derive(Debug)]
struct Invocation {
    command: Command,
    account: AccountId,
    limit: StoreLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenFailure {
    KeyAccess,
    Profile,
    Corrupted,
    #[cfg_attr(
        all(target_os = "macos", not(test)),
        expect(
            dead_code,
            reason = "This fail-closed class is constructed by non-macOS production builds and deterministic tests."
        )
    )]
    Operation,
}

trait MailboxReaderFactory {
    fn open(&self, account: &AccountId) -> Result<Box<dyn MailboxReader>, OpenFailure>;
}

struct ProductionMailboxReaderFactory;

impl MailboxReaderFactory for ProductionMailboxReaderFactory {
    fn open(&self, account: &AccountId) -> Result<Box<dyn MailboxReader>, OpenFailure> {
        #[cfg(target_os = "macos")]
        {
            tersa_keychain_macos::open_default_read_only_mailbox(account)
                .map(|reader| Box::new(reader) as Box<dyn MailboxReader>)
                .map_err(|error| match error {
                    tersa_keychain_macos::ReadOnlyMailboxOpenError::KeyAccess => {
                        OpenFailure::KeyAccess
                    }
                    tersa_keychain_macos::ReadOnlyMailboxOpenError::ProfileUnavailable => {
                        OpenFailure::Profile
                    }
                    tersa_keychain_macos::ReadOnlyMailboxOpenError::MailboxCorrupted => {
                        OpenFailure::Corrupted
                    }
                })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _unused = account;
            Err(OpenFailure::Operation)
        }
    }
}

/// Runs `mailctl` with caller-controlled process streams.
///
/// The production factory is fixed and provides no runtime key, profile, or
/// database-path override. Caller-controlled streams exist only to make the
/// process contract deterministic and testable.
pub fn run<I, O, E>(arguments: I, stdout: &mut O, stderr: &mut E) -> u8
where
    I: IntoIterator<Item = OsString>,
    O: Write,
    E: Write,
{
    run_with_factory(arguments, stdout, stderr, &ProductionMailboxReaderFactory)
}

fn run_with_factory<I, O, E>(
    arguments: I,
    stdout: &mut O,
    stderr: &mut E,
    factory: &dyn MailboxReaderFactory,
) -> u8
where
    I: IntoIterator<Item = OsString>,
    O: Write,
    E: Write,
{
    let exit = match parse(arguments) {
        Ok(invocation) => execute(&invocation, stdout, factory),
        Err(()) => Exit::Invocation,
    };
    if let Some(line) = exit.stderr() {
        let _ignored = stderr.write_all(line.as_bytes());
        let _ignored = stderr.flush();
    }
    exit as u8
}

fn parse<I>(arguments: I) -> Result<Invocation, ()>
where
    I: IntoIterator<Item = OsString>,
{
    let mut values = arguments.into_iter();
    let command = values
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(())?;
    let is_thread = match command.as_str() {
        "inbox" => false,
        "thread" => true,
        _ => return Err(()),
    };
    let mut account = None;
    let mut thread = None;
    let mut limit = None;
    while let Some(flag) = values.next() {
        let flag = flag.into_string().map_err(|_non_utf8| ())?;
        let value = values
            .next()
            .ok_or(())?
            .into_string()
            .map_err(|_non_utf8| ())?;
        match flag.as_str() {
            "--account" if account.is_none() => {
                account = Some(AccountId::new(value).map_err(|_invalid| ())?);
            }
            "--thread" if thread.is_none() => {
                thread = Some(ThreadId::new(value).map_err(|_invalid| ())?);
            }
            "--limit" if limit.is_none() => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(());
                }
                let value = value.parse::<u16>().map_err(|_overflow| ())?;
                limit = Some(StoreLimit::new(value).map_err(|_invalid| ())?);
            }
            _ => return Err(()),
        }
    }
    let account = account.ok_or(())?;
    let limit = match limit {
        Some(limit) => limit,
        None => StoreLimit::new(DEFAULT_LIMIT).map_err(|_invalid| ())?,
    };
    match (is_thread, thread) {
        (false, None) => Ok(Invocation {
            command: Command::Inbox,
            account,
            limit,
        }),
        (true, Some(thread)) => Ok(Invocation {
            command: Command::Thread(thread),
            account,
            limit,
        }),
        _ => Err(()),
    }
}

fn execute(
    invocation: &Invocation,
    stdout: &mut impl Write,
    factory: &dyn MailboxReaderFactory,
) -> Exit {
    let reader = match factory.open(&invocation.account) {
        Ok(reader) => reader,
        Err(OpenFailure::KeyAccess) => return Exit::KeyAccess,
        Err(OpenFailure::Profile) => return Exit::Profile,
        Err(OpenFailure::Corrupted) => return Exit::Corrupted,
        Err(OpenFailure::Operation) => return Exit::Operation,
    };
    let future = match invocation.command {
        Command::Inbox => inbox_metadata(&*reader, &invocation.account, invocation.limit),
        Command::Thread(ref thread) => {
            thread_metadata(&*reader, &invocation.account, thread, invocation.limit)
        }
    };
    let document = match poll_once(future) {
        Ok(Ok(document)) => document,
        Ok(Err(MailboxStoreError::Storage)) => return Exit::Profile,
        Ok(Err(MailboxStoreError::Corrupted)) => return Exit::Corrupted,
        Ok(Err(_)) | Err(()) => return Exit::Operation,
    };
    if matches!(invocation.command, Command::Thread(_)) && document.messages().is_empty() {
        return Exit::MissingThread;
    }
    let Ok(serialized) = render(&document) else {
        return Exit::Operation;
    };
    write_once(stdout, &serialized)
}

fn poll_once<T>(
    mut future: std::pin::Pin<Box<dyn Future<Output = T> + Send + '_>>,
) -> Result<T, ()> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => Ok(value),
        Poll::Pending => Err(()),
    }
}

fn render(document: &MailboxMetadataDocument) -> Result<Vec<u8>, ()> {
    let mut output = String::from("{\"schema_version\":");
    write!(&mut output, "{}", document.schema_version()).map_err(|_format| ())?;
    output.push_str(",\"command\":");
    json_string(&mut output, document.command().as_str()).map_err(|_format| ())?;
    output.push_str(",\"account_id\":");
    json_string(&mut output, document.account_id().as_str()).map_err(|_format| ())?;
    output.push_str(",\"limit\":");
    write!(&mut output, "{}", document.limit().get()).map_err(|_format| ())?;
    output.push_str(",\"messages\":[");
    for (index, message) in document.messages().iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"message_id\":");
        json_string(&mut output, message.message_id().as_str()).map_err(|_format| ())?;
        output.push_str(",\"thread_id\":");
        json_string(&mut output, message.thread_id().as_str()).map_err(|_format| ())?;
        output.push_str(",\"from\":");
        json_string(&mut output, message.from().as_str()).map_err(|_format| ())?;
        output.push_str(",\"subject\":");
        json_string(&mut output, message.subject().as_str()).map_err(|_format| ())?;
        output.push_str(",\"received_at_millis\":");
        write!(&mut output, "{}", message.received_at().as_millis()).map_err(|_format| ())?;
        output.push_str(",\"unread\":");
        output.push_str(if message.is_unread() { "true" } else { "false" });
        output.push('}');
    }
    output.push_str("]}");
    Ok(output.into_bytes())
}

fn json_string(output: &mut String, value: &str) -> std::fmt::Result {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            character
                if character <= '\u{001F}' || ('\u{007F}'..='\u{009F}').contains(&character) =>
            {
                write!(output, "\\u{:04X}", u32::from(character))?;
            }
            character => output.push(character),
        }
    }
    output.push('"');
    Ok(())
}

fn write_once(output: &mut impl Write, bytes: &[u8]) -> Exit {
    match output.write(bytes) {
        Ok(written) if written == bytes.len() => {}
        _ => return Exit::Operation,
    }
    if output.flush().is_err() {
        return Exit::Operation;
    }
    Exit::Success
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Test fixtures use valid literals and fail immediately on unexpected results."
)]
mod tests {
    use std::future::{Pending, Ready, pending, ready};
    use std::io;

    use tersa_application::mailbox::BoxFuture;
    use tersa_domain::mailbox::{HeaderText, MessageEnvelope, MessageId, UnixTimestampMillis};

    use super::*;

    #[derive(Clone)]
    enum QueryResult {
        Ready(Result<Vec<MessageEnvelope>, MailboxStoreError>),
        Pending,
    }

    impl QueryResult {
        fn future(&self) -> BoxFuture<'static, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            match self {
                Self::Ready(result) => {
                    let future: Ready<_> = ready(result.clone());
                    Box::pin(future)
                }
                Self::Pending => {
                    let future: Pending<_> = pending();
                    Box::pin(future)
                }
            }
        }
    }

    struct FakeReader {
        inbox: QueryResult,
        thread: QueryResult,
    }

    impl MailboxReader for FakeReader {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            self.inbox.future()
        }

        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            self.thread.future()
        }
    }

    struct FakeFactory {
        open: Result<(QueryResult, QueryResult), OpenFailure>,
    }

    impl MailboxReaderFactory for FakeFactory {
        fn open(&self, _account: &AccountId) -> Result<Box<dyn MailboxReader>, OpenFailure> {
            self.open.clone().map(|(inbox, thread)| {
                Box::new(FakeReader { inbox, thread }) as Box<dyn MailboxReader>
            })
        }
    }

    fn envelope(id: &str, thread: &str, timestamp: i64) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new(id).unwrap(),
            ThreadId::new(thread).unwrap(),
            HeaderText::new(format!("from-{id}")).unwrap(),
            HeaderText::new(format!("subject-{id}")).unwrap(),
            HeaderText::new(format!("preview-secret-{id}")).unwrap(),
            UnixTimestampMillis::new(timestamp).unwrap(),
            true,
        )
    }

    fn successful_factory(messages: Vec<MessageEnvelope>) -> FakeFactory {
        FakeFactory {
            open: Ok((
                QueryResult::Ready(Ok(messages.clone())),
                QueryResult::Ready(Ok(messages)),
            )),
        }
    }

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn invoke(arguments: &[&str], factory: &FakeFactory) -> (u8, Vec<u8>, Vec<u8>) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_with_factory(args(arguments), &mut stdout, &mut stderr, factory);
        (exit, stdout, stderr)
    }

    #[test]
    fn renders_inbox_golden_json_with_exact_fields_and_order() {
        let factory = successful_factory(vec![
            envelope("newest", "thread-a", 20),
            envelope("older", "thread-b", 10),
        ]);
        let (exit, stdout, stderr) = invoke(&["inbox", "--account", "account-1"], &factory);

        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            "{\"schema_version\":1,\"command\":\"inbox\",\"account_id\":\"account-1\",\"limit\":50,\"messages\":[{\"message_id\":\"newest\",\"thread_id\":\"thread-a\",\"from\":\"from-newest\",\"subject\":\"subject-newest\",\"received_at_millis\":20,\"unread\":true},{\"message_id\":\"older\",\"thread_id\":\"thread-b\",\"from\":\"from-older\",\"subject\":\"subject-older\",\"received_at_millis\":10,\"unread\":true}]}"
        );
    }

    #[test]
    fn renders_thread_golden_json_and_excludes_preview() {
        let factory = successful_factory(vec![envelope("message-1", "thread-a", 10)]);
        let (exit, stdout, stderr) = invoke(
            &[
                "thread",
                "--thread",
                "thread-a",
                "--limit",
                "1",
                "--account",
                "account-1",
            ],
            &factory,
        );

        let stdout = String::from_utf8(stdout).unwrap();
        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        assert_eq!(
            stdout,
            "{\"schema_version\":1,\"command\":\"thread\",\"account_id\":\"account-1\",\"limit\":1,\"messages\":[{\"message_id\":\"message-1\",\"thread_id\":\"thread-a\",\"from\":\"from-message-1\",\"subject\":\"subject-message-1\",\"received_at_millis\":10,\"unread\":true}]}"
        );
        assert!(!stdout.contains("preview-secret"));
    }

    #[test]
    fn parser_applies_default_and_accepts_exact_limit_bounds() {
        let default = parse(args(&["inbox", "--account", "account-1"])).unwrap();
        let minimum = parse(args(&["inbox", "--limit", "1", "--account", "account-1"])).unwrap();
        let maximum = parse(args(&[
            "inbox",
            "--account",
            "account-1",
            "--limit",
            "10000",
        ]))
        .unwrap();

        assert_eq!(default.limit.get(), 50);
        assert_eq!(minimum.limit.get(), 1);
        assert_eq!(maximum.limit.get(), 10_000);
    }

    #[test]
    fn parser_rejects_every_invalid_invocation_class() {
        let invalid = [
            vec![],
            vec!["unknown"],
            vec!["--help"],
            vec!["--version"],
            vec!["inbox"],
            vec!["inbox", "--account"],
            vec!["inbox", "--account", "account-1", "extra"],
            vec!["inbox", "--unknown", "value", "--account", "account-1"],
            vec!["inbox", "--account", "account-1", "--account", "account-2"],
            vec!["inbox", "--account", "person@example.com"],
            vec!["inbox", "--account", "account-1", "--thread", "thread-1"],
            vec!["thread", "--account", "account-1"],
            vec!["thread", "--account", "account-1", "--thread", ""],
            vec!["inbox", "--account", "account-1", "--limit", ""],
            vec!["inbox", "--account", "account-1", "--limit", "+1"],
            vec!["inbox", "--account", "account-1", "--limit", "0"],
            vec!["inbox", "--account", "account-1", "--limit", "10001"],
            vec!["inbox", "--account", "account-1", "--limit", "65536"],
            vec![
                "inbox",
                "--account",
                "account-1",
                "--limit",
                "1",
                "--limit",
                "2",
            ],
        ];
        let factory = successful_factory(Vec::new());
        for invocation in invalid {
            let (exit, stdout, stderr) = invoke(&invocation, &factory);
            assert_eq!(exit, 2, "unexpected acceptance for {invocation:?}");
            assert!(stdout.is_empty());
            assert_eq!(stderr, b"mailctl: invalid invocation\n");
        }
    }

    #[cfg(unix)]
    #[test]
    fn parser_rejects_non_utf8_arguments() {
        use std::os::unix::ffi::OsStringExt;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let factory = successful_factory(Vec::new());
        let exit = run_with_factory(
            [
                OsString::from("inbox"),
                OsString::from("--account"),
                OsString::from_vec(vec![0xFF]),
            ],
            &mut stdout,
            &mut stderr,
            &factory,
        );
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"mailctl: invalid invocation\n");
    }

    #[test]
    fn empty_inbox_succeeds_but_empty_thread_is_not_found() {
        let factory = successful_factory(Vec::new());
        let (inbox_exit, inbox_stdout, inbox_stderr) =
            invoke(&["inbox", "--account", "account-1"], &factory);
        let (thread_exit, thread_stdout, thread_stderr) = invoke(
            &["thread", "--account", "account-1", "--thread", "thread-1"],
            &factory,
        );

        assert_eq!(inbox_exit, 0);
        assert!(
            String::from_utf8(inbox_stdout)
                .unwrap()
                .ends_with("\"messages\":[]}")
        );
        assert!(inbox_stderr.is_empty());
        assert_eq!(thread_exit, 5);
        assert!(thread_stdout.is_empty());
        assert_eq!(thread_stderr, b"mailctl: mailbox item was not found\n");
    }

    #[test]
    fn open_and_query_failures_use_the_closed_exit_table() {
        for (failure, exit, line) in [
            (OpenFailure::KeyAccess, 3, "mailctl: key access failed\n"),
            (
                OpenFailure::Profile,
                4,
                "mailctl: local profile is unavailable\n",
            ),
            (
                OpenFailure::Corrupted,
                6,
                "mailctl: local mailbox is corrupted\n",
            ),
            (OpenFailure::Operation, 7, "mailctl: operation failed\n"),
        ] {
            let factory = FakeFactory { open: Err(failure) };
            let (actual, stdout, stderr) = invoke(&["inbox", "--account", "account-1"], &factory);
            assert_eq!(actual, exit);
            assert!(stdout.is_empty());
            assert_eq!(stderr, line.as_bytes());
        }

        for (error, exit, line) in [
            (
                MailboxStoreError::Storage,
                4,
                "mailctl: local profile is unavailable\n",
            ),
            (
                MailboxStoreError::Corrupted,
                6,
                "mailctl: local mailbox is corrupted\n",
            ),
        ] {
            let factory = FakeFactory {
                open: Ok((
                    QueryResult::Ready(Err(error)),
                    QueryResult::Ready(Err(error)),
                )),
            };
            let (actual, stdout, stderr) = invoke(&["inbox", "--account", "account-1"], &factory);
            assert_eq!(actual, exit);
            assert!(stdout.is_empty());
            assert_eq!(stderr, line.as_bytes());
        }
    }

    #[test]
    fn pending_reader_future_fails_without_panicking_or_writing_stdout() {
        let factory = FakeFactory {
            open: Ok((QueryResult::Pending, QueryResult::Pending)),
        };
        let (exit, stdout, stderr) = invoke(&["inbox", "--account", "account-1"], &factory);
        assert_eq!(exit, 7);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"mailctl: operation failed\n");
    }

    #[test]
    fn terminal_escaping_covers_every_c0_del_and_c1_scalar() {
        let controls = (0_u32..=0x1F)
            .chain(0x7F..=0x9F)
            .map(|value| char::from_u32(value).unwrap())
            .collect::<String>();
        let mut encoded = String::new();
        json_string(&mut encoded, &controls).unwrap();
        let expected =
            (0_u32..=0x1F)
                .chain(0x7F..=0x9F)
                .fold(String::from("\""), |mut output, value| {
                    write!(&mut output, "\\u{value:04X}").unwrap();
                    output
                })
                + "\"";
        assert_eq!(encoded, expected);

        let mut ordinary = String::new();
        json_string(&mut ordinary, "quote=\" slash=\\ snow=雪").unwrap();
        assert_eq!(ordinary, "\"quote=\\\" slash=\\\\ snow=雪\"");
    }

    struct RecordingWriter {
        calls: usize,
        bytes: Vec<u8>,
        maximum: usize,
        fail: bool,
        fail_flush: bool,
        require_complete_document: bool,
    }

    impl RecordingWriter {
        fn complete() -> Self {
            Self {
                calls: 0,
                bytes: Vec::new(),
                maximum: usize::MAX,
                fail: false,
                fail_flush: false,
                require_complete_document: false,
            }
        }
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.require_complete_document {
                assert!(buffer.starts_with(b"{\"schema_version\":"));
                assert!(buffer.ends_with(b"]}"));
            }
            if self.fail {
                return Err(io::Error::other("intentional writer failure"));
            }
            let accepted = buffer.len().min(self.maximum);
            self.bytes.extend_from_slice(&buffer[..accepted]);
            Ok(accepted)
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("intentional flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn stdout_is_serialized_first_and_written_exactly_once() {
        let factory = successful_factory(vec![envelope("message-1", "thread-1", 1)]);
        let mut stdout = RecordingWriter {
            require_complete_document: true,
            ..RecordingWriter::complete()
        };
        let mut stderr = Vec::new();

        let exit = run_with_factory(
            args(&["inbox", "--account", "account-1"]),
            &mut stdout,
            &mut stderr,
            &factory,
        );
        assert_eq!(exit, 0);
        assert_eq!(stdout.calls, 1);
        assert!(stderr.is_empty());
    }

    #[test]
    fn short_error_and_flush_failures_never_retry_stdout() {
        let factory = successful_factory(vec![envelope("message-1", "thread-1", 1)]);
        for mut stdout in [
            RecordingWriter {
                maximum: 7,
                ..RecordingWriter::complete()
            },
            RecordingWriter {
                fail: true,
                ..RecordingWriter::complete()
            },
            RecordingWriter {
                fail_flush: true,
                ..RecordingWriter::complete()
            },
        ] {
            let mut stderr = Vec::new();
            let exit = run_with_factory(
                args(&["inbox", "--account", "account-1"]),
                &mut stdout,
                &mut stderr,
                &factory,
            );
            assert_eq!(exit, 7);
            assert_eq!(stdout.calls, 1);
            assert_eq!(stderr, b"mailctl: operation failed\n");
        }
    }

    #[test]
    fn stderr_failure_does_not_change_the_selected_exit() {
        let factory = FakeFactory {
            open: Err(OpenFailure::KeyAccess),
        };
        let mut stdout = Vec::new();
        let mut stderr = RecordingWriter {
            fail: true,
            ..RecordingWriter::complete()
        };
        let exit = run_with_factory(
            args(&["inbox", "--account", "account-1"]),
            &mut stdout,
            &mut stderr,
            &factory,
        );
        assert_eq!(exit, 3);
        assert!(stdout.is_empty());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn production_factory_fails_closed_off_macos() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            args(&["inbox", "--account", "account-1"]),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 7);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"mailctl: operation failed\n");
    }
}
