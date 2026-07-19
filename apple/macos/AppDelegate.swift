// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit
import SwiftUI

@main
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let oauthAuthorizationSession = OAuthAuthorizationSession()
    private let bootstrapWorker = BootstrapWorker()
    private var mainWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        _ = tersa_apple_bridge_version()
        MainMenu.install()
        presentMainWindow()
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

    private func presentMainWindow() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 420),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Tersa"
        window.contentViewController = NSHostingController(rootView: RootView())
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate()
        mainWindow = window
    }
}
