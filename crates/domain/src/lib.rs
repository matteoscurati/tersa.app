// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Platform-independent domain types and invariants for tersa.app.

#![forbid(unsafe_code)]

/// Shared mailbox identifiers, envelopes, and redacted message content.
pub mod mailbox;

// Rust guideline compliant 1.0.
