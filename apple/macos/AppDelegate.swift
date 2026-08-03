// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// The app-held broker authorization session the view model drives
    /// (start, and the unconditional cancel before a disconnect).
    let tokenBrokerAuthorizationSession = TokenBrokerAuthorizationSession()
    private let bootstrapWorker = BootstrapWorker()
    private var mainWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        _ = tersa_apple_bridge_version()
        MainMenu.install()
        presentMainWindow()
    }

    /// Receives opaque bytes only from the reviewed view-model intent entry.
    func establishOwnedAccountProfile(
        accountIdentifier: Data,
        completion: @escaping @MainActor (ProductBootstrapStatus) -> Void
    ) {
        bootstrapWorker.submit(accountIdentifier: accountIdentifier, completion: completion)
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

@main
@MainActor
private enum TersaApplication {
    private static let delegate = AppDelegate()

    static func main() {
        // Exact opt-in Keychain isolation probe: read-only, no bootstrap, exits
        // before any normal app behavior. Without this single argument the app
        // launches exactly as before.
        if KeychainIsolationProbe.isProbeRequest(CommandLine.arguments) {
            KeychainIsolationProbe.runAsPrincipal(.mainApp)
        }
        let application = NSApplication.shared
        application.delegate = delegate
        application.run()
    }
}
