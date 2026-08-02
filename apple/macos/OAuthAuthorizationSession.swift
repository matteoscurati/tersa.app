// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit

/// The terminal outcome of one OAuth authorization session. A success
/// carries the bridge-issued OAuth session id the connect flow claims the
/// grant with.
enum OAuthOutcome {
    case succeeded(OAuthSessionID)
    case cancelled
    case permissionRequired
    case failed
}

@MainActor
final class OAuthAuthorizationSession {
    private static let pendingStatus: Int32 = 0
    private static let succeededStatus: Int32 = 1
    private static let insufficientScopeStatus: Int32 = -8

    private var sessionID: UInt64?
    private var pollTimer: Timer?
    private var onOutcome: (@MainActor (OAuthOutcome) -> Void)?

    /// Begins one authorization session and reports its terminal outcome
    /// exactly once. Returns `false` when the pre-flight fails —
    /// `TersaOAuthClientID` missing, empty, or UNCONFIGURED, a session
    /// already in flight, a begin failure, or an authorization URL the
    /// workspace would not open; 3e-2c renders that `false` as the failed
    /// state, so `onOutcome` fires only for a session that actually started.
    ///
    /// The client id this begin reads is the SAME `TersaOAuthClientID`
    /// Info.plist key the caller passes downstream to
    /// `tersa_mailbox_macos_sync_begin`, so the client_id↔grant pairing
    /// holds by construction — no extra plumbing.
    func start(onOutcome: @escaping @MainActor (OAuthOutcome) -> Void) -> Bool {
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
        self.onOutcome = onOutcome
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
        // Capture the callback, clear all state, THEN deliver — so a callback
        // that reentrantly calls cancel()/start() sees no live session and the
        // outcome is delivered exactly once.
        let callback = onOutcome
        finishLocally()
        callback?(.cancelled)
    }

    private func poll() {
        guard let sessionID else {
            return
        }
        let status = tersa_oauth_macos_poll(sessionID)
        if status != Self.pendingStatus {
            // Capture the outcome (with the session id, before it is cleared)
            // AND the callback, clear all state, THEN deliver: the callback runs
            // against cleared state, so a reentrant cancel()/start() sees no live
            // session and the terminal outcome is delivered exactly once. A
            // success still hands the connect flow the OAuth session id it
            // claims the grant with.
            let outcome: OAuthOutcome
            if status == Self.succeededStatus {
                outcome = .succeeded(OAuthSessionID(rawValue: sessionID))
            } else if status == Self.insufficientScopeStatus {
                outcome = .permissionRequired
            } else {
                outcome = .failed
            }
            let callback = onOutcome
            finishLocally()
            callback?(outcome)
        }
    }

    private func finishLocally() {
        pollTimer?.invalidate()
        pollTimer = nil
        sessionID = nil
        onOutcome = nil
    }
}
