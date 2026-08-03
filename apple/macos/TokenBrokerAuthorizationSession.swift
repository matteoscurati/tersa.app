// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit
import Foundation
import Network

/// Terminal outcome of one broker-backed authorization session.
///
/// Point 3 provides the operational client and mapping surface. Production
/// cutover of the main connect ladder remains point 4 work: this type does not
/// replace the legacy in-process OAuth path.
enum TokenBrokerAuthorizationOutcome: Equatable, Sendable {
    case succeeded(accessToken: String, subject: String, expiresInSeconds: Int)
    case cancelled
    case failed(TokenBrokerStatusMapping.Recovery)
}

/// Broker-backed OAuth authorization session owned by the main app.
///
/// The main app binds an IPv4 ephemeral loopback listener, asks the broker to
/// begin with that redirect, opens the returned authorization URL, forwards the
/// exact callback URL with the opaque session handle, and maps terminal statuses
/// into the closed UI recovery set. PKCE verifier, refresh token, and client
/// secret never cross XPC into this process as broker authority.
///
/// Pre-flight never blocks the MainActor: listener bind and broker begin complete
/// on a private queue / XPC callback, then hop back to MainActor for browser open
/// and outcome delivery. Completions fire exactly once.
@MainActor
final class TokenBrokerAuthorizationSession {
    private var client: TokenBrokerClient?
    private var listener: NWListener?
    private var sessionHandle: String?
    private var onOutcome: (@MainActor (TokenBrokerAuthorizationOutcome) -> Void)?
    private var isFinished = false
    /// True after the first `.ready` has been accepted so a repeated ready
    /// notification cannot start a second broker begin.
    private var hasAcceptedListenerReady = false
    private let listenerQueue = DispatchQueue(
        label: "app.tersa.macos.token-broker.loopback"
    )

    /// Begins one broker-backed authorization session.
    ///
    /// Returns `false` only when a session is already active or the loopback
    /// listener cannot be created. Bind, broker begin, and browser-open failures
    /// after arming deliver `.failed` through `onOutcome` exactly once.
    func start(
        onOutcome: @escaping @MainActor (TokenBrokerAuthorizationOutcome) -> Void
    ) -> Bool {
        guard client == nil, !isFinished else {
            return false
        }

        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host("127.0.0.1"),
            port: .any
        )
        guard let listener = try? NWListener(using: parameters) else {
            return false
        }

        self.onOutcome = onOutcome
        self.listener = listener
        let client = TokenBrokerClient()
        self.client = client

        listener.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self else {
                    return
                }
                switch state {
                case .ready:
                    self.handleListenerReady(listener: listener, client: client)
                case .failed, .cancelled:
                    self.failPreflight(recovery: .unavailable)
                default:
                    break
                }
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            Task { @MainActor in
                self?.handleLoopbackConnection(connection)
            }
        }
        listener.start(queue: listenerQueue)
        return true
    }

    /// Cancels the session and delivers `.cancelled` exactly once when live.
    func cancel() {
        guard !isFinished else {
            return
        }
        finish(.cancelled)
    }

    private func handleListenerReady(listener: NWListener, client: TokenBrokerClient) {
        guard !isFinished, !hasAcceptedListenerReady else {
            return
        }
        hasAcceptedListenerReady = true
        guard let port = listener.port, Self.isAcceptedLoopbackPort(port.rawValue) else {
            failPreflight(recovery: .unavailable)
            return
        }

        // Inventory forbids string interpolation; keep the exact root redirect
        // shape `http://127.0.0.1:<port>/` via concatenation.
        let redirectURI = "http://127.0.0.1:" + String(port.rawValue) + "/"
        client.beginAuthorizationSession(redirectURI: redirectURI) { [weak self] result in
            Task { @MainActor in
                guard let self, !self.isFinished, self.sessionHandle == nil else {
                    return
                }
                switch result {
                case .success(let pending):
                    guard NSWorkspace.shared.open(pending.authorizationURL) else {
                        self.failPreflight(recovery: .unavailable)
                        return
                    }
                    self.sessionHandle = pending.sessionHandle
                case .failure(let error):
                    self.failPreflight(
                        recovery: TokenBrokerStatusMapping.recovery(
                            for: error,
                            operation: .beginAuthorization
                        )
                    )
                }
            }
        }
    }

    private func handleLoopbackConnection(_ connection: NWConnection) {
        guard !isFinished, let sessionHandle else {
            connection.cancel()
            return
        }
        connection.start(queue: .main)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8_192) {
            [weak self] data,
            _,
            _,
            error in
            Task { @MainActor in
                guard let self else {
                    connection.cancel()
                    return
                }
                defer { connection.cancel() }
                guard error == nil,
                      let data,
                      let callbackURL = Self.callbackURL(from: data)
                else {
                    self.finish(
                        .failed(
                            TokenBrokerStatusMapping.recovery(
                                for: .status(.invalidRequest),
                                operation: .completeAuthorization
                            )
                        )
                    )
                    return
                }
                self.complete(sessionHandle: sessionHandle, callbackURL: callbackURL)
            }
        }
    }

    private func complete(sessionHandle: String, callbackURL: String) {
        guard let client, !isFinished else {
            return
        }
        client.completeAuthorizationSession(
            sessionHandle: sessionHandle,
            callbackURL: callbackURL
        ) { [weak self] result in
            Task { @MainActor in
                guard let self, !self.isFinished else {
                    return
                }
                switch result {
                case .success(let token):
                    self.finish(
                        .succeeded(
                            accessToken: token.accessToken,
                            subject: token.subject,
                            expiresInSeconds: token.expiresInSeconds
                        )
                    )
                case .failure(let error):
                    self.finish(
                        .failed(
                            TokenBrokerStatusMapping.recovery(
                                for: error,
                                operation: .completeAuthorization
                            )
                        )
                    )
                }
            }
        }
    }

    private func failPreflight(recovery: TokenBrokerStatusMapping.Recovery) {
        guard !isFinished else {
            return
        }
        finish(.failed(recovery))
    }

    private func finish(_ outcome: TokenBrokerAuthorizationOutcome) {
        guard !isFinished else {
            return
        }
        isFinished = true
        hasAcceptedListenerReady = true
        let callback = onOutcome
        onOutcome = nil
        listener?.cancel()
        listener = nil
        sessionHandle = nil
        client?.cancel()
        client = nil
        callback?(outcome)
    }

    /// Parses a minimal HTTP request line into the exact callback URL the
    /// loopback peer requested. Rejects oversized or malformed requests.
    ///
    /// The returned string is the exact request target under the loopback host.
    /// Callers must not log it: the query can carry an authorization code.
    nonisolated static func callbackURL(from request: Data) -> String? {
        guard request.count <= 8_192,
              let text = String(data: request, encoding: .utf8)
        else {
            return nil
        }
        let lines = text.split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let requestLine = lines.first else {
            return nil
        }
        let parts = requestLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2, parts[0] == "GET" else {
            return nil
        }
        let target = String(parts[1])
        guard target.hasPrefix("/"),
              let hostHeader = lines.first(where: { $0.lowercased().hasPrefix("host:") })
        else {
            return nil
        }
        let host = hostHeader.dropFirst(5).trimmingCharacters(in: .whitespaces)
        guard isExactLoopbackHostHeader(host) else {
            return nil
        }
        // Inventory forbids string interpolation; forward the exact validated
        // host and request target without logging the callback query/code.
        return "http://" + host + target
    }

    /// Accepts only the literal IPv4 loopback host with an explicit decimal
    /// port that matches the listener/callback contract (`127.0.0.1:<port>`,
    /// port in `1024...65535`, no leading zeros, no suffix).
    ///
    /// Prefix checks are intentionally rejected: `127.0.0.1.attacker` and
    /// `127.0.0.1:54321.evil` must not pass.
    nonisolated static func isExactLoopbackHostHeader(_ host: String) -> Bool {
        let prefix = "127.0.0.1:"
        guard host.hasPrefix(prefix) else {
            return false
        }
        let portText = String(host.dropFirst(prefix.count))
        guard !portText.isEmpty,
              portText.utf8.allSatisfy({ byte in
                  byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9")
              }),
              let port = UInt16(portText),
              isAcceptedLoopbackPort(port),
              String(port) == portText
        else {
            return false
        }
        return true
    }

    /// Ephemeral loopback ports only; matches the listener ready-path gate.
    nonisolated static func isAcceptedLoopbackPort(_ port: UInt16) -> Bool {
        port >= 1024
    }
}
