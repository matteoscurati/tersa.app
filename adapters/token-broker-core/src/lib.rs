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
//!   Session handles are held in zeroizing memory everywhere, including the
//!   registry's owned key copies, so no removal path leaves handle bytes in
//!   freed heap.
//! - Token mutations serialize per validated subject through bounded
//!   single-flight permits released by RAII guards (cancellation-safe); no
//!   mutex guard is held across an `.await`. A completion claims its
//!   account's permit immediately after subject validation, before any
//!   store read or write.
//! - A granted exchange snapshots the stored credential under the permit
//!   before replacing it; a stranded post-exchange grant is revoked
//!   best-effort only when that snapshot is definitively empty, because
//!   Google revocation is grant-wide and a prior credential could be the
//!   working connection. An unreadable snapshot fails closed as
//!   `PersistenceFailed` before any store write or revoke.
//! - An explicitly under-scoped completion carries no validated identity and
//!   the XPC-shaped begin operation supplies no account identity, so no
//!   subject-keyed snapshot is possible: it fails safe and non-destructively
//!   (nothing persisted, nothing revoked). This can leave a first-connect
//!   under-scoped grant active at the provider, and this API cannot offer an
//!   in-app manual revoke for it — the minted tokens were dropped and there
//!   is no validated subject or stored credential to revoke against. The
//!   point-3 UI must surface the failure, offer retain-or-retry recovery,
//!   and direct the user to their Google account-permissions page for manual
//!   revocation.
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
