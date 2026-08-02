// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Portable token-broker lifecycle core (ADR-0024, pass A).
//!
//! This crate is the runtime-agnostic composition the separately signed macOS
//! token-broker process will host: it owns OAuth code exchange, refresh,
//! refresh-token persistence, rotation, deletion, and provider revoke over
//! generic ports, and never exposes a refresh token, PKCE verifier, state, or
//! authorization code across its API. It deliberately contains no
//! Keychain/Security.framework code, no C ABI, and no IPC: pass B binds these
//! ports to the macOS Keychain and the closed XPC protocol.
//!
//! Security invariants enforced here:
//!
//! - `begin_authorization` accepts only an exact root-form literal IPv4
//!   loopback redirect with an explicit ephemeral port.
//! - Pending authorization sessions live in a bounded registry with an
//!   absolute TTL, deterministic reaping, no live-entry eviction, and
//!   poisoned-lock fail-closed wiping; a completion claims its session
//!   atomically BEFORE any callback validation, so every callback is terminal.
//! - Token mutations serialize per validated subject through bounded
//!   single-flight permits released by RAII guards (cancellation-safe); no
//!   mutex guard is held across an `.await`.
//! - Success values carry only a zeroizing access token, a zeroizing subject,
//!   and a bounded positive expiry; every `Debug`/`Display` redacts
//!   account-identifying and secret-bearing values.

#![forbid(unsafe_code)]

mod broker;
mod error;
mod handle;
mod permits;
mod ports;
mod registry;
mod subject;

pub use broker::{BrokerCore, BrokerToken, PendingAuthorization};
pub use error::BrokerError;
pub use handle::{SESSION_HANDLE_BYTES, SessionHandle};
pub use ports::{
    GetRandomEntropy, RefreshTokenStore, RefreshTokenStoreError, SessionHandleEntropy,
};
pub use subject::ValidatedSubject;

// Rust guideline compliant 1.0.
