// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Application commands, queries, and use-case orchestration for tersa.app.

#![forbid(unsafe_code)]

/// Shared inward mailbox ports and pagination contracts.
pub mod mailbox;
/// Body-free metadata projections for explicit output adapters.
pub mod mailbox_metadata;
/// Bounded metadata-only mailbox search projections.
pub mod mailbox_search;
pub mod oauth;
/// Bounded recent-snapshot mailbox synchronization and cache orchestration.
pub mod sync;

// Rust guideline compliant 1.0.
