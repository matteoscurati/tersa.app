// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The full-screen interface (ADR 0031, T2).
//!
//! State and key handling live in [`app`] and drawing in [`view`]; this module
//! only owns the terminal and the event loop, so the rest is testable with
//! ratatui's test backend.

mod app;
mod view;
mod wrap;

use std::collections::HashSet;
use std::io::IsTerminal;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use tersa_application::mailbox::MessageId;
use tersa_presentation::terminal::SafeText;

pub use app::Row;
use app::{App, Request, SyncState};

/// Where the interface reads cached mail from.
pub trait MailSource {
    /// The cached rows, newest first.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the local store cannot be read.
    fn rows(&self) -> Result<Vec<Row>, ()>;

    /// The cached raw message `id`; `Ok(None)` when only the envelope is
    /// cached.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the local store cannot be read.
    fn message(&self, id: &MessageId) -> Result<Option<Vec<u8>>, ()>;
}

/// Work that finishes later, on the network thread.
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + 'a>>;

/// Talks to Gmail on the network thread, so the interface stays responsive
/// while the network is slow. Downloads and syncs may run at the same time.
pub trait Remote: Send + 'static {
    /// Downloads, caches, and returns the raw message `id`; fails with a
    /// short reason for the reader.
    fn fetch<'a>(&'a self, id: &'a MessageId) -> Pending<'a, Vec<u8>>;

    /// Syncs recent mail into the cache; fails with a short reason for the
    /// reader.
    fn sync(&self) -> Pending<'_, ()>;
}

/// How often the loop checks for finished work while idle.
const TICK: Duration = Duration::from_millis(100);

/// How often the account syncs on its own.
const SYNC_EVERY: Duration = Duration::from_secs(5 * 60);

/// Runs the interface until the user quits.
///
/// # Errors
///
/// Returns a message when standard input or output is not a terminal, the
/// cache cannot be read, or the terminal fails.
pub fn run(
    account: SafeText,
    source: &dyn MailSource,
    remote: Option<Box<dyn Remote>>,
) -> Result<(), String> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("the interface needs a terminal; `tersa inbox` prints plain output".to_owned());
    }
    let rows = source
        .rows()
        .map_err(|()| "could not read the local mailbox".to_owned())?;
    let mut app = App::new(account, rows);
    let worker = remote.map(Worker::start);
    // Installs a panic hook that restores the terminal before reporting.
    let mut terminal = ratatui::try_init().map_err(terminal_error)?;
    let result = event_loop(&mut terminal, &mut app, source, worker);
    ratatui::restore();
    result
}

/// One piece of network work.
enum Job {
    Fetch(MessageId),
    Sync,
}

/// A finished piece of network work.
enum Done {
    Fetched(MessageId, Result<Vec<u8>, String>),
    Synced(Result<(), String>),
}

/// The network thread's channels. Each job runs as its own task on one
/// single-threaded runtime, so a download never waits for a sync. Dropping
/// this ends the thread and cancels unfinished jobs; the process does not
/// wait for it.
struct Worker {
    jobs: tokio::sync::mpsc::UnboundedSender<Job>,
    done: Receiver<Done>,
    fetching: HashSet<MessageId>,
    syncing: bool,
    last_sync: Option<Instant>,
}

/// At most this many downloads run at once; more wait their turn.
const PARALLEL_FETCHES: usize = 4;

impl Worker {
    fn start(remote: Box<dyn Remote>) -> Self {
        let (jobs, mut incoming) = tokio::sync::mpsc::unbounded_channel::<Job>();
        let (outgoing, done) = mpsc::channel();
        std::thread::spawn(move || {
            let Ok(executor) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                // Dropping the channels reports every job as failed.
                return;
            };
            let remote: Rc<dyn Remote> = Rc::from(remote);
            let fetches = Rc::new(tokio::sync::Semaphore::new(PARALLEL_FETCHES));
            tokio::task::LocalSet::new().block_on(&executor, async move {
                while let Some(job) = incoming.recv().await {
                    let remote = Rc::clone(&remote);
                    let fetches = Rc::clone(&fetches);
                    let outgoing = outgoing.clone();
                    tokio::task::spawn_local(async move {
                        let finished = match job {
                            Job::Fetch(id) => {
                                let _turn = fetches.acquire().await;
                                let result = remote.fetch(&id).await;
                                Done::Fetched(id, result)
                            }
                            Job::Sync => Done::Synced(remote.sync().await),
                        };
                        let _ = outgoing.send(finished);
                    });
                }
            });
        });
        Self {
            jobs,
            done,
            fetching: HashSet::new(),
            syncing: false,
            last_sync: None,
        }
    }

    /// Asks for message `id`; returns false when the thread is gone.
    fn fetch(&mut self, id: &MessageId) -> bool {
        if self.fetching.contains(id) {
            return true;
        }
        let sent = self.jobs.send(Job::Fetch(id.clone())).is_ok();
        if sent {
            self.fetching.insert(id.clone());
        }
        sent
    }

    /// Asks for a sync unless one is running; returns false when the thread
    /// is gone.
    fn sync(&mut self) -> bool {
        self.last_sync = Some(Instant::now());
        if self.syncing {
            return true;
        }
        self.syncing = self.jobs.send(Job::Sync).is_ok();
        self.syncing
    }

    fn sync_due(&self) -> bool {
        !self.syncing
            && self
                .last_sync
                .is_none_or(|last| last.elapsed() >= SYNC_EVERY)
    }
}

const WORKER_GONE: &str = "the network worker stopped";

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    source: &dyn MailSource,
    mut worker: Option<Worker>,
) -> Result<(), String> {
    loop {
        let now = now_millis();
        if let Some(worker) = &mut worker {
            finish_work(worker, app, source, now);
            if worker.sync_due() {
                start_sync(worker, app, now);
            }
        }
        if std::mem::take(&mut app.repaint) {
            // Repaint every cell when the screen changes, so any drift
            // between the terminal and ratatui's model cannot linger.
            terminal.clear().map_err(terminal_error)?;
        }
        terminal
            .draw(|frame| view::draw(frame, app, now))
            .map_err(terminal_error)?;
        if app.quit {
            return Ok(());
        }
        if !event::poll(TICK).map_err(terminal_error)? {
            continue;
        }
        let Event::Key(key) = event::read().map_err(terminal_error)? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match app.key(key) {
            Some(Request::OpenMessage(id)) => {
                let raw = source.message(&id);
                let missing = matches!(raw, Ok(None));
                app.show_message(id.clone(), raw);
                if missing && worker.as_mut().is_some_and(|worker| worker.fetch(&id)) {
                    app.downloading(&id);
                }
            }
            Some(Request::Sync) => match &mut worker {
                Some(worker) => start_sync(worker, app, now),
                None => {
                    app.status = Some(
                        "Syncing needs the Google OAuth client; see `tersa doctor`.".to_owned(),
                    );
                }
            },
            None => {}
        }
    }
}

fn start_sync(worker: &mut Worker, app: &mut App, now: i64) {
    if worker.sync() {
        app.sync = SyncState::Running;
    } else {
        app.synced(Err(WORKER_GONE.to_owned()), now);
    }
}

/// Applies finished downloads and syncs.
fn finish_work(worker: &mut Worker, app: &mut App, source: &dyn MailSource, now: i64) {
    while let Ok(done) = worker.done.try_recv() {
        match done {
            Done::Fetched(id, result) => {
                worker.fetching.remove(&id);
                app.downloaded(id, result);
            }
            Done::Synced(result) => {
                worker.syncing = false;
                let reloaded = result.and_then(|()| {
                    source
                        .rows()
                        .map_err(|()| "could not read the local mailbox".to_owned())
                });
                match reloaded {
                    Ok(rows) => {
                        app.reload(rows);
                        app.synced(Ok(()), now);
                    }
                    Err(error) => app.synced(Err(error), now),
                }
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value, reason = "used as a map_err adapter")]
fn terminal_error(error: std::io::Error) -> String {
    format!("the terminal failed: {error}")
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::mpsc::{self, Sender};
    use std::time::Duration;

    use tersa_application::mailbox::MessageId;

    use super::{Done, Pending, Remote, Worker};

    /// Records the order work finishes in; syncs wait for the test.
    struct Recorder {
        log: Sender<String>,
        release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    impl Remote for Recorder {
        fn fetch<'a>(&'a self, id: &'a MessageId) -> Pending<'a, Vec<u8>> {
            Box::pin(async move {
                let _ = self.log.send(format!("fetch {}", id.as_str()));
                Ok(Vec::new())
            })
        }

        fn sync(&self) -> Pending<'_, ()> {
            let release = self.release.lock().expect("lock").take();
            Box::pin(async move {
                if let Some(release) = release {
                    let _ = release.await;
                }
                let _ = self.log.send("sync".to_owned());
                Err("offline".to_owned())
            })
        }
    }

    fn id(text: &str) -> MessageId {
        MessageId::new(text).expect("id")
    }

    #[test]
    fn downloads_finish_while_a_sync_is_still_running() {
        let (log, entries) = mpsc::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let mut worker = Worker::start(Box::new(Recorder {
            log,
            release: Mutex::new(Some(released)),
        }));
        let next = || {
            entries
                .recv_timeout(Duration::from_secs(5))
                .expect("work finishes")
        };
        assert!(worker.sync());
        assert!(worker.sync(), "a second request joins the running sync");
        assert!(worker.fetch(&id("a")));
        assert!(worker.fetch(&id("a")), "a repeat is merged");
        assert!(worker.fetch(&id("b")));
        assert_eq!([next(), next()], ["fetch a", "fetch b"]);
        release.send(()).expect("release");
        assert_eq!(next(), "sync");
        let mut fetched = 0;
        let mut synced = 0;
        for _ in 0..3 {
            match worker.done.recv_timeout(Duration::from_secs(5)) {
                Ok(Done::Fetched(_, Ok(_))) => fetched += 1,
                Ok(Done::Synced(Err(error))) if error == "offline" => synced += 1,
                _ => panic!("unexpected result"),
            }
        }
        assert_eq!((fetched, synced), (2, 1));
        assert!(
            entries.recv_timeout(Duration::from_millis(100)).is_err(),
            "nothing ran twice"
        );
        assert!(!worker.sync_due(), "a sync was just asked for");
    }
}
