// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! C-compatible bootstrap surface for the Apple application targets.

#![deny(unsafe_code)]

/// Confirms that the Apple application linked the Rust static library.
#[expect(
    unsafe_code,
    reason = "a stable unmangled symbol is required by the C-compatible Apple bridge"
)]
#[unsafe(no_mangle)]
pub extern "C" fn tersa_apple_bridge_version() -> u32 {
    tersa_presentation::presentation_protocol_version()
}

// Rust guideline compliant 1.0.
