// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit

@main
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let oauthAuthorizationSession = OAuthAuthorizationSession()
    private let bootstrapWorker = BootstrapWorker()

    func applicationDidFinishLaunching(_ notification: Notification) {
        _ = tersa_apple_bridge_version()
    }

    /// Receives opaque bytes only from the future owning product flow.
    func establishOwnedAccountProfile(
        accountIdentifier: Data,
        completion: @escaping @MainActor (ProductBootstrapStatus) -> Void
    ) {
        bootstrapWorker.submit(accountIdentifier: accountIdentifier, completion: completion)
    }

    func startOAuthAuthorization() -> Bool {
        oauthAuthorizationSession.start()
    }
}
