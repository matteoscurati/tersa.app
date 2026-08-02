// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// A content-free outer journal for destructive disconnect intent.
///
/// The SQLCipher lifecycle row remains the authoritative detailed projection,
/// but it cannot protect a relaunch when that store cannot be opened. This
/// journal records only the opaque local account alias before the Rust teardown
/// begins and is cleared only after a successful terminal result.
struct DisconnectIntentStore {
    private static let pendingAccountKey = "TersaPendingDisconnectAccount"

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func pendingAccountIdentifier() -> String? {
        guard let identifier = defaults.string(forKey: Self.pendingAccountKey),
              !identifier.isEmpty
        else {
            return nil
        }
        return identifier
    }

    /// Persists and verifies intent before any destructive FFI begin.
    @discardableResult
    func markPending(accountIdentifier: String) -> Bool {
        guard !accountIdentifier.isEmpty else {
            return false
        }
        defaults.set(accountIdentifier, forKey: Self.pendingAccountKey)
        return defaults.synchronize()
            && defaults.string(forKey: Self.pendingAccountKey) == accountIdentifier
    }

    /// Clears and verifies the outer journal after a successful Rust terminal.
    @discardableResult
    func clearPending() -> Bool {
        defaults.removeObject(forKey: Self.pendingAccountKey)
        return defaults.synchronize()
            && defaults.object(forKey: Self.pendingAccountKey) == nil
    }
}
