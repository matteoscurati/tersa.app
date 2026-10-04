// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Passphrase prompts on the controlling terminal with echo disabled.
//!
//! Passphrases are read only from `/dev/tty`, never from arguments or the
//! environment, where other processes could observe them. While reading, the
//! terminal is in non-canonical mode with echo and signal keys off, so Ctrl-C
//! arrives as a byte that cancels the prompt and the original settings are
//! always restored. Bytes go straight into zeroizing storage; no intermediate
//! buffer keeps a copy.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use rustix::termios::{self, LocalModes, OptionalActions, SpecialCodeIndex};
use zeroize::{Zeroize, Zeroizing};

const MAX_PASSPHRASE: usize = 1024;
const CTRL_C: u8 = 0x03;
const CTRL_D: u8 = 0x04;
const BACKSPACE: u8 = 0x08;
const DELETE: u8 = 0x7f;

/// Reads one passphrase from the terminal without echo.
pub fn passphrase(prompt: &str) -> io::Result<Zeroizing<String>> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;

    let original = termios::tcgetattr(&tty)?;
    let mut silent = original.clone();
    silent
        .local_modes
        .remove(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG);
    silent.special_codes[SpecialCodeIndex::VMIN] = 1;
    silent.special_codes[SpecialCodeIndex::VTIME] = 0;
    termios::tcsetattr(&tty, OptionalActions::Flush, &silent)?;
    let read = read_secret(&tty);
    let restored = termios::tcsetattr(&tty, OptionalActions::Flush, &original);
    let _ = tty.write_all(b"\n");
    let secret = read?;
    restored?;
    Ok(secret)
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

fn read_secret(tty: &File) -> io::Result<Zeroizing<String>> {
    let mut reader = tty;
    // Full capacity up front: growth would reallocate and leave unwiped
    // copies of the typed prefix in freed memory.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE));
    let mut byte = [0_u8; 1];
    loop {
        if reader.read(&mut byte)? == 0 {
            break;
        }
        match byte[0] {
            b'\r' | b'\n' => break,
            CTRL_C => return Err(cancelled()),
            CTRL_D if bytes.is_empty() => return Err(cancelled()),
            BACKSPACE | DELETE => {
                // Drop one whole UTF-8 character.
                while let Some(removed) = bytes.pop() {
                    if removed & 0xc0 != 0x80 {
                        break;
                    }
                }
            }
            other => {
                if bytes.len() >= MAX_PASSPHRASE {
                    byte.zeroize();
                    return Err(io::Error::other("the passphrase is too long"));
                }
                bytes.push(other);
            }
        }
    }
    byte.zeroize();
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            error.into_bytes().zeroize();
            Err(io::Error::other("the passphrase is not valid UTF-8"))
        }
    }
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "cancelled")
}
