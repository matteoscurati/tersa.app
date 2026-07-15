// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Proves the bounded chunked-AEAD blob feasibility contract.

#![forbid(unsafe_code)]

mod format;

#[cfg(unix)]
mod diagnostic;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match diagnostic::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(stage) => {
            eprintln!("Blob feasibility failed ({stage})");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() {
    println!("Chunked AEAD blob diagnostic is unavailable on this target.");
}

// Rust guideline compliant 1.0.
