// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit
import Combine
import Foundation

/// Owns the account-connection UI state. Product bootstrap starts only from
/// the reviewed `connect` user-intent entry below; nothing here runs at app
/// launch or view construction time.
@MainActor
final class AccountConnectionViewModel: ObservableObject {
    @Published private(set) var state: ConnectionState = .notConnected
    @Published private(set) var connectedAccountIdentifier: Data?
    @Published var accountIdentifier: String = ""

    var isConnectDisabled: Bool {
        accountIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// The single reviewed user-intent entry into product bootstrap.
    func connect() {
        let trimmedIdentifier = accountIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedIdentifier.isEmpty, state != .connecting else {
            return
        }
        state = .connecting
        let accountIdentifierData = Data(trimmedIdentifier.utf8)
        let completion: @MainActor (ProductBootstrapStatus) -> Void = { [weak self] status in
            let newState = ConnectionState(status: status)
            if newState == .connected {
                self?.connectedAccountIdentifier = accountIdentifierData
            }
            self?.state = newState
        }
        (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(
            accountIdentifier: accountIdentifierData,
            completion: completion
        )
    }

    /// Returns to the not-connected state and re-runs the connection attempt.
    func retry() {
        state = .notConnected
        connect()
    }
}
