// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Trusted macOS OAuth token-lifecycle and bounded Gmail sync composition.
//!
//! This crate is the sole executor of Step 3's network-and-write composition:
//! it forwards the validated OAuth grant into the token exchange, refreshes the
//! access token proactively, gates account identity, and drives the bounded
//! recent sync into the encrypted store. It loads the refresh token from the
//! `tersa-keychain-macos` store, drives the `tersa-gmail-rest-macos` token
//! transport and read adapter, and reconciles through the validated
//! `SQLCipher` write path — all on a pinned current-thread `tokio` runtime.
//!
//! It is the only macOS crate besides the Gmail adapter that reaches the
//! network (reqwest, transitively through `tersa-gmail-rest-macos`); the
//! retrieval-only CLI never depends on it, so the CLI stays network-free.
//!
//! This is the 3d-1 scaffold: it establishes the crate, its dependency edges,
//! and the runtime. The connect / sync / disconnect behaviour lands in 3d-2 and
//! 3d-3.

#![forbid(unsafe_code)]

/// Builds the pinned current-thread `tokio` runtime that will drive the
/// connect-time token exchange and the bounded sync worker.
///
/// A dedicated current-thread runtime keeps the composition's async network
/// work off the main thread and out of every other crate; the retrieval-only
/// CLI never constructs it.
///
/// # Errors
///
/// Returns the `tokio` build error when the runtime cannot be created.
#[cfg(target_os = "macos")]
pub fn build_sync_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

// Rust guideline compliant 1.0.
