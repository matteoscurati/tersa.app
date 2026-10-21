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

use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use tersa_presentation::terminal::SafeText;

pub use app::Row;
use app::{App, Request};

/// Where the interface reads cached mail from.
pub trait MailSource {
    /// The cached raw message for the row at `index`; `Ok(None)` when only
    /// the envelope is cached.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the local store cannot be read.
    fn message(&self, index: usize) -> Result<Option<Vec<u8>>, ()>;
}

/// Runs the interface until the user quits.
///
/// # Errors
///
/// Returns a message when standard input or output is not a terminal, or the
/// terminal fails.
pub fn run(account: SafeText, rows: Vec<Row>, source: &dyn MailSource) -> Result<(), String> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("the interface needs a terminal; `tersa inbox` prints plain output".to_owned());
    }
    let mut app = App::new(account, rows);
    // Installs a panic hook that restores the terminal before reporting.
    let mut terminal = ratatui::try_init().map_err(terminal_error)?;
    let result = event_loop(&mut terminal, &mut app, source);
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    source: &dyn MailSource,
) -> Result<(), String> {
    loop {
        let now = now_millis();
        terminal
            .draw(|frame| view::draw(frame, app, now))
            .map_err(terminal_error)?;
        if app.quit {
            return Ok(());
        }
        if let Event::Key(key) = event::read().map_err(terminal_error)? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if let Some(Request::OpenMessage(index)) = app.key(key) {
                let raw = source.message(index);
                app.show_message(index, raw);
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
