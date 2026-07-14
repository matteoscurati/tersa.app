// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AuthenticationServices
import UIKit

@MainActor
final class OAuthAuthorizationSession: NSObject, ASWebAuthenticationPresentationContextProviding {
    private static let pendingStatus: Int32 = 0
    private static let succeededStatus: Int32 = 1

    private var browserSession: ASWebAuthenticationSession?
    private var sessionID: UInt64?
    private var redirectScheme: String?

    func start() -> Bool {
        guard browserSession == nil,
              let clientID = Bundle.main.object(forInfoDictionaryKey: "TersaOAuthClientID") as? String,
              let redirectScheme = Bundle.main.object(
                  forInfoDictionaryKey: "TersaOAuthRedirectScheme"
              ) as? String,
              !clientID.isEmpty,
              !redirectScheme.isEmpty,
              clientID.range(of: "UNCONFIGURED", options: .caseInsensitive) == nil,
              redirectScheme.range(of: "UNCONFIGURED", options: .caseInsensitive) == nil
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
        let redirectSchemeBytes = Array(redirectScheme.utf8)
        let status = clientIDBytes.withUnsafeBufferPointer { clientBuffer in
            redirectSchemeBytes.withUnsafeBufferPointer { schemeBuffer in
                authorizationURLBytes.withUnsafeMutableBufferPointer { urlBuffer in
                    tersa_oauth_ios_begin(
                        clientBuffer.baseAddress,
                        clientBuffer.count,
                        schemeBuffer.baseAddress,
                        schemeBuffer.count,
                        &newSessionID,
                        urlBuffer.baseAddress,
                        urlBuffer.count,
                        &authorizationURLLength
                    )
                }
            }
        }
        guard status == Self.pendingStatus,
              authorizationURLLength <= authorizationURLBytes.count,
              let authorizationURL = URL(
                  string: String(decoding: authorizationURLBytes.prefix(authorizationURLLength), as: UTF8.self)
              )
        else {
            if newSessionID != 0 {
                _ = tersa_oauth_cancel(newSessionID)
            }
            return false
        }

        let browserSession = ASWebAuthenticationSession(
            url: authorizationURL,
            callbackURLScheme: redirectScheme
        ) { [weak self] callbackURL, _ in
            Task { @MainActor in
                self?.complete(callbackURL: callbackURL)
            }
        }
        browserSession.presentationContextProvider = self
        browserSession.prefersEphemeralWebBrowserSession = true
        guard browserSession.start() else {
            _ = tersa_oauth_cancel(newSessionID)
            return false
        }

        self.browserSession = browserSession
        sessionID = newSessionID
        self.redirectScheme = redirectScheme
        return true
    }

    func cancel() {
        browserSession?.cancel()
        if let sessionID {
            _ = tersa_oauth_cancel(sessionID)
        }
        finishLocally()
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
    }

    private func complete(callbackURL: URL?) {
        guard let sessionID,
              let redirectScheme,
              let callbackURL,
              callbackURL.scheme?.caseInsensitiveCompare(redirectScheme) == .orderedSame
        else {
            if let sessionID {
                _ = tersa_oauth_cancel(sessionID)
            }
            finishLocally()
            return
        }

        var callbackBytes = Array(callbackURL.absoluteString.utf8)
        defer {
            callbackBytes.withUnsafeMutableBufferPointer { buffer in
                buffer.initialize(repeating: 0)
            }
        }
        let status = callbackBytes.withUnsafeBufferPointer { callbackBuffer in
            tersa_oauth_ios_finish(sessionID, callbackBuffer.baseAddress, callbackBuffer.count)
        }
        _ = status == Self.succeededStatus
        finishLocally()
    }

    private func finishLocally() {
        browserSession = nil
        sessionID = nil
        redirectScheme = nil
    }
}
