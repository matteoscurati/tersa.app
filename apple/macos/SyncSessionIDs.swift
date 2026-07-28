// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// The bridge-issued id of one OAuth authorization session
/// (`tersa_oauth_macos_begin`). A lookup key, never a capability.
struct OAuthSessionID: Equatable {
    let rawValue: UInt64
}

/// The FFI-issued id of one mailbox sync, connect, or disconnect session
/// (`tersa_mailbox_macos_*_begin`, polled via `tersa_mailbox_macos_sync_poll`).
///
/// Distinct from `OAuthSessionID` so the two id domains can never be swapped
/// at a call site: a connect consumes the OAuth session id and yields a sync
/// session id, and only the sync id may be polled.
struct SyncSessionID: Equatable {
    let rawValue: UInt64
}
