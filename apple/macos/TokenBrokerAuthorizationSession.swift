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

/// Pure decision for one loopback receive accumulation step.
enum TokenBrokerLoopbackReceiveDecision: Equatable, Sendable {
    /// Headers are incomplete and more bytes may still arrive.
    case needMore
    /// Headers terminated with CRLFCRLF within the byte cap; parse next.
    case ready(Data)
    /// Empty, partial (peer closed), oversize, or transport-error request.
    /// Callers must cancel only that connection and keep the listener alive.
    case rejectConnection
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
    /// Maximum HTTP request bytes accepted from one loopback peer (8 KiB).
    nonisolated static let maxRequestBytes = 8_192
    /// Bounds how many accepted TCP connections one session will process.
    /// Excess peers are cancelled without completing the session; the session
    /// deadline still ends a flow that never receives a valid callback.
    nonisolated static let maxAcceptedConnections = 8
    /// Hard upper bound for one authorization session (matches broker session
    /// TTL). Prevents stray connections from keeping the flow alive forever.
    nonisolated static let sessionTimeout: TimeInterval = 600

    private var client: TokenBrokerClient?
    private var listener: NWListener?
    private var sessionHandle: String?
    private var onOutcome: (@MainActor (TokenBrokerAuthorizationOutcome) -> Void)?
    private var isFinished = false
    /// True after the first `.ready` has been accepted so a repeated ready
    /// notification cannot start a second broker begin.
    private var hasAcceptedListenerReady = false
    /// Single-shot latch: only the first parseable callback may call complete.
    /// Concurrent or second connections cannot double-complete the session.
    private var hasForwardedCallback = false
    /// Count of accepted TCP connections processed this session.
    private var acceptedConnectionCount = 0
    private var sessionDeadlineTimer: Timer?
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
        acceptedConnectionCount = 0
        hasForwardedCallback = false
        armSessionDeadline()

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

    private func armSessionDeadline() {
        sessionDeadlineTimer?.invalidate()
        sessionDeadlineTimer = Timer.scheduledTimer(
            withTimeInterval: Self.sessionTimeout,
            repeats: false
        ) { [weak self] _ in
            Task { @MainActor in
                self?.handleSessionDeadline()
            }
        }
    }

    private func handleSessionDeadline() {
        guard !isFinished else {
            return
        }
        finish(
            .failed(
                TokenBrokerStatusMapping.recovery(
                    for: .status(.unavailable),
                    operation: .beginAuthorization
                )
            )
        )
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
        guard !isFinished, sessionHandle != nil else {
            connection.cancel()
            return
        }
        acceptedConnectionCount += 1
        guard acceptedConnectionCount <= Self.maxAcceptedConnections else {
            // Bound accepted work; cancel the excess peer only. The session
            // deadline still terminates a flow that never gets a valid callback.
            connection.cancel()
            return
        }
        connection.start(queue: .main)
        receiveLoopbackBytes(connection: connection, accumulated: Data())
    }

    private func receiveLoopbackBytes(connection: NWConnection, accumulated: Data) {
        guard !isFinished else {
            connection.cancel()
            return
        }
        let remaining = Self.maxRequestBytes - accumulated.count
        guard remaining > 0 else {
            connection.cancel()
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) {
            [weak self] data,
            _,
            isComplete,
            error in
            Task { @MainActor in
                guard let self else {
                    connection.cancel()
                    return
                }
                guard !self.isFinished else {
                    connection.cancel()
                    return
                }
                var buffer = accumulated
                let decision = Self.accumulateLoopbackReceive(
                    buffer: &buffer,
                    chunk: data,
                    isComplete: isComplete,
                    hadError: error != nil
                )
                switch decision {
                case .needMore:
                    self.receiveLoopbackBytes(connection: connection, accumulated: buffer)
                case .rejectConnection:
                    // Empty, partial, oversize, or errored peer: drop only this
                    // connection and leave the listener ready for a real callback.
                    connection.cancel()
                case .ready(let request):
                    connection.cancel()
                    guard let callbackURL = Self.callbackURL(from: request) else {
                        // Unparseable request: keep the session alive.
                        return
                    }
                    guard Self.claimForwardedCallback(
                        isFinished: self.isFinished,
                        hasForwardedCallback: &self.hasForwardedCallback
                    ) else {
                        return
                    }
                    guard let sessionHandle = self.sessionHandle else {
                        return
                    }
                    self.complete(sessionHandle: sessionHandle, callbackURL: callbackURL)
                }
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
        hasForwardedCallback = true
        sessionDeadlineTimer?.invalidate()
        sessionDeadlineTimer = nil
        let callback = onOutcome
        onOutcome = nil
        listener?.cancel()
        listener = nil
        sessionHandle = nil
        client?.cancel()
        client = nil
        callback?(outcome)
    }

    /// Claims the single-shot forwarded-callback latch.
    ///
    /// Returns `true` only when the session is still live and no prior
    /// connection has already claimed the latch. Concurrent or second
    /// connections observe `false` and must not call `complete`.
    nonisolated static func claimForwardedCallback(
        isFinished: Bool,
        hasForwardedCallback: inout Bool
    ) -> Bool {
        guard !isFinished, !hasForwardedCallback else {
            return false
        }
        hasForwardedCallback = true
        return true
    }

    /// Whether one more accepted connection may be processed.
    ///
    /// Pure gate used by the accept path and unit tests. Excess peers are
    /// cancelled without completing the session.
    nonisolated static func shouldProcessAcceptedConnection(
        isFinished: Bool,
        hasSessionHandle: Bool,
        acceptedConnectionCount: Int,
        maxAcceptedConnections: Int = maxAcceptedConnections
    ) -> Bool {
        !isFinished
            && hasSessionHandle
            && acceptedConnectionCount < maxAcceptedConnections
    }

    /// Accumulates one receive into the loopback request buffer.
    ///
    /// Continues until CRLFCRLF is observed or the 8 KiB cap is hit. Empty,
    /// partial (peer closed without headers), oversize, and transport-error
    /// outcomes reject only the connection.
    nonisolated static func accumulateLoopbackReceive(
        buffer: inout Data,
        chunk: Data?,
        isComplete: Bool,
        hadError: Bool
    ) -> TokenBrokerLoopbackReceiveDecision {
        if hadError {
            return .rejectConnection
        }
        if let chunk, !chunk.isEmpty {
            if buffer.count > maxRequestBytes - chunk.count {
                return .rejectConnection
            }
            buffer.append(chunk)
        }
        if requestHeadersAreComplete(buffer) {
            return .ready(buffer)
        }
        if buffer.count >= maxRequestBytes {
            return .rejectConnection
        }
        if isComplete {
            // Peer closed without a complete header block (empty or partial).
            return .rejectConnection
        }
        return .needMore
    }

    /// True when the buffer contains the HTTP header terminator CRLFCRLF.
    nonisolated static func requestHeadersAreComplete(_ buffer: Data) -> Bool {
        guard buffer.count >= 4 else {
            return false
        }
        let cr: UInt8 = 0x0d
        let lf: UInt8 = 0x0a
        var index = 0
        let bytes = buffer
        let end = bytes.count - 3
        while index <= end {
            if bytes[index] == cr,
               bytes[index + 1] == lf,
               bytes[index + 2] == cr,
               bytes[index + 3] == lf
            {
                return true
            }
            index += 1
        }
        return false
    }

    /// Parses a minimal HTTP request line into the exact callback URL the
    /// loopback peer requested. Rejects oversized or malformed requests.
    ///
    /// The returned string is the exact request target under the loopback host.
    /// Callers must not log it: the query can carry an authorization code.
    nonisolated static func callbackURL(from request: Data) -> String? {
        guard request.count <= maxRequestBytes,
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
