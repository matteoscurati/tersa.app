// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runs the signed macOS sandbox network entitlement probe.

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    if tersa_apple_bridge::tersa_oauth_macos_entitlement_probe() == 1 {
        println!("OAuth sandbox network entitlement probe passed.");
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("OAuth sandbox network entitlement probe failed.");
        std::process::ExitCode::FAILURE
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("The OAuth sandbox entitlement probe requires macOS.");
    std::process::ExitCode::FAILURE
}

// Rust guideline compliant 1.0.
