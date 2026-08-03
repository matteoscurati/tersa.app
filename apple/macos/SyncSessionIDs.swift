// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// The FFI-issued id of one broker-fed mailbox sync or broker disconnect
/// finalize session. Opaque to the caller: a lookup key the mailbox worker
/// polls via `tersa_mailbox_macos_sync_poll`, never a capability.
struct SyncSessionID: Equatable {
    let rawValue: UInt64
}
