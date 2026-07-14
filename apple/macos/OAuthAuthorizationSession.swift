// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit

@MainActor
final class OAuthAuthorizationSession {
    private static let pendingStatus: Int32 = 0
    private static let succeededStatus: Int32 = 1

    private var sessionID: UInt64?
    private var pollTimer: Timer?

    func start() -> Bool {
        guard sessionID == nil,
              let clientID = Bundle.main.object(forInfoDictionaryKey: "TersaOAuthClientID") as? String,
              !clientID.isEmpty,
              clientID.range(of: "UNCONFIGURED", options: .caseInsensitive) == nil
        else {
            return false
        }

        var newSessionID: UInt64 = 0
        var authorizationURLLength = 0
        var authorizationURLBytes = [UInt8](repeating: 0, count: 4_096)
        defer {
            authorizationURLBytes.withUnsafeMutableBufferPointer { buffer in
                buffer.initialize(repeating: 0)
            }
        }
        let clientIDBytes = Array(clientID.utf8)
        let status = clientIDBytes.withUnsafeBufferPointer { clientBuffer in
            authorizationURLBytes.withUnsafeMutableBufferPointer { urlBuffer in
                tersa_oauth_macos_begin(
                    clientBuffer.baseAddress,
                    clientBuffer.count,
                    &newSessionID,
                    urlBuffer.baseAddress,
                    urlBuffer.count,
                    &authorizationURLLength
                )
            }
        }
        guard status == Self.pendingStatus,
              authorizationURLLength <= authorizationURLBytes.count,
              let authorizationURL = URL(
                  string: String(decoding: authorizationURLBytes.prefix(authorizationURLLength), as: UTF8.self)
              ),
              NSWorkspace.shared.open(authorizationURL)
        else {
            if newSessionID != 0 {
                _ = tersa_oauth_cancel(newSessionID)
            }
            return false
        }

        sessionID = newSessionID
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.poll()
            }
        }
        return true
    }

    func cancel() {
        guard let sessionID else {
            return
        }
        _ = tersa_oauth_cancel(sessionID)
        finishLocally()
    }

    private func poll() {
        guard let sessionID else {
            return
        }
        let status = tersa_oauth_macos_poll(sessionID)
        if status != Self.pendingStatus {
            _ = status == Self.succeededStatus
            finishLocally()
        }
    }

    private func finishLocally() {
        pollTimer?.invalidate()
        pollTimer = nil
        sessionID = nil
    }
}
