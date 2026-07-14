// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Compiles the Apple-only diagnostic Slint markup.

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() -> Result<(), slint_build::CompileError> {
    slint_build::compile("ui/tersa.slint")
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {}

// Rust guideline compliant 1.0.
