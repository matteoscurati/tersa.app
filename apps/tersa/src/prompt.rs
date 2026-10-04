// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Passphrase prompts on the controlling terminal with echo disabled.
//!
//! Passphrases are read only from `/dev/tty`, never from arguments or the
//! environment, where other processes could observe them.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};

use rustix::termios::{self, LocalModes, OptionalActions};
use zeroize::Zeroizing;

const MAX_PASSPHRASE: usize = 1024;

/// Reads one passphrase from the terminal without echo.
pub fn passphrase(prompt: &str) -> io::Result<Zeroizing<String>> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;

    let original = termios::tcgetattr(&tty)?;
    let mut silent = original.clone();
    silent.local_modes.remove(LocalModes::ECHO);
    silent.local_modes.insert(LocalModes::ECHONL);
    termios::tcsetattr(&tty, OptionalActions::Flush, &silent)?;
    let read = read_line(&tty);
    let restored = termios::tcsetattr(&tty, OptionalActions::Flush, &original);
    let line = read?;
    restored?;
    Ok(line)
}

/// Asks for a new passphrase twice and requires a match.
pub fn new_passphrase() -> io::Result<Zeroizing<String>> {
    loop {
        let first = passphrase("New passphrase: ")?;
        if first.is_empty() {
            eprintln!("The passphrase must not be empty.");
            continue;
        }
        let second = passphrase("Repeat passphrase: ")?;
        if *first == *second {
            return Ok(first);
        }
        eprintln!("The passphrases do not match; try again.");
    }
}

fn read_line(tty: &File) -> io::Result<Zeroizing<String>> {
    let mut reader =
        BufReader::new(tty).take(u64::try_from(MAX_PASSPHRASE + 2).unwrap_or(u64::MAX));
    let mut line = Zeroizing::new(String::new());
    reader.read_line(&mut line)?;
    if line.len() > MAX_PASSPHRASE + 1 {
        return Err(io::Error::other("the passphrase is too long"));
    }
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(line)
}
