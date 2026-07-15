// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runs the bounded Apple encrypted-search feasibility diagnostic.

#![forbid(unsafe_code)]

// Rust guideline compliant 1.0.

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod diagnostic;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod directory;

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() {
    if let Err(error) = diagnostic::run() {
        if std::env::var_os("TERSA_SEARCH_DIAGNOSTIC_DEBUG").is_some() {
            eprintln!("Encrypted search feasibility failed: {error:#}");
        } else {
            eprintln!("Encrypted search feasibility failed.");
        }
        std::process::exit(1);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {
    println!("Encrypted search diagnostic is Apple-only.");
}
