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

/// Holds cancelable loopback/XPC resources for MainActor-safe abandoned cleanup.
///
/// `TokenBrokerAuthorizationSession` is `@MainActor`; `deinit` is not. This bag
/// is `@unchecked Sendable` and cancels its timer, listener, and XPC client from
/// `release()` / `deinit` so an abandoned session still tears those endpoints
/// down without actor-isolated access from `deinit`. `release()` is idempotent
/// and preserves exactly-once session completion (completion stays in `finish`).
final class TokenBrokerSessionResourceBag: @unchecked Sendable {
    private let lock = NSLock()
    private var client: TokenBrokerClient?
    private var listener: NWListener?
    private var timer: Timer?

    func install(client: TokenBrokerClient, listener: NWListener) {
        lock.lock()
        self.client = client
        self.listener = listener
        lock.unlock()
    }

    func storeTimer(_ timer: Timer) {
        lock.lock()
        self.timer?.invalidate()
        self.timer = timer
        lock.unlock()
    }

    func borrowClient() -> TokenBrokerClient? {
        lock.lock()
        defer { lock.unlock() }
        return client
    }

    /// Cancels timer, loopback listener, and XPC client. Idempotent.
    func release() {
        lock.lock()
        let pendingTimer = timer
        let pendingListener = listener
        let pendingClient = client
        timer = nil
        listener = nil
        client = nil
        lock.unlock()
        pendingTimer?.invalidate()
        pendingListener?.cancel()
        pendingClient?.cancel()
    }

    /// Testable idempotent release of optional cancel closures (no live XPC/NW).
    ///
    /// Models the bag's clear-then-cancel order: a second call is a no-op
    /// because the closures are nilled before invocation.
    nonisolated static func releaseCancelClosures(
        clientCancel: inout (() -> Void)?,
        listenerCancel: inout (() -> Void)?
    ) {
        let client = clientCancel
        let listener = listenerCancel
        clientCancel = nil
        listenerCancel = nil
        client?()
        listener?()
    }

    deinit {
        release()
    }
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

    private let resources = TokenBrokerSessionResourceBag()
    private var sessionHandle: String?
    /// Exact IPv4 loopback port bound for this session. Host headers must match
    /// `127.0.0.1:<boundLoopbackPort>` exactly; any other nonprivileged port is
    /// treated as a stray peer and must not burn the session latch.
    private var boundLoopbackPort: UInt16?
    private var onOutcome: (@MainActor (TokenBrokerAuthorizationOutcome) -> Void)?
    private var isFinished = false
    /// True after the first `.ready` has been accepted so a repeated ready
    /// notification cannot start a second broker begin.
    private var hasAcceptedListenerReady = false
    /// Single-shot latch: only the first provider-outcome callback may call
    /// complete. Concurrent or second connections cannot double-complete the
    /// session. Stray parseable peers must never claim this latch.
    private var hasForwardedCallback = false
    /// Count of accepted TCP connections processed this session.
    private var acceptedConnectionCount = 0
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
        guard resources.borrowClient() == nil, !isFinished else {
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
        let client = TokenBrokerClient()
        resources.install(client: client, listener: listener)
        acceptedConnectionCount = 0
        hasForwardedCallback = false
        boundLoopbackPort = nil
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
        let timer = Timer.scheduledTimer(
            withTimeInterval: Self.sessionTimeout,
            repeats: false
        ) { [weak self] _ in
            Task { @MainActor in
                self?.handleSessionDeadline()
            }
        }
        resources.storeTimer(timer)
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
        // Capture the actual bound port: Host headers and redirect must match
        // this exact port, not merely any nonprivileged loopback port.
        boundLoopbackPort = port.rawValue

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
                    guard let boundPort = self.boundLoopbackPort,
                          let callbackURL = Self.callbackURL(
                            from: request,
                            boundPort: boundPort
                          )
                    else {
                        // Stray or non-outcome request: keep the session alive.
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
        guard let client = resources.borrowClient(), !isFinished else {
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
        boundLoopbackPort = nil
        let callback = onOutcome
        onOutcome = nil
        sessionHandle = nil
        // Release listener + XPC client (and timer) before delivering outcome.
        resources.release()
        callback?(outcome)
    }

    /// Claims the single-shot forwarded-callback latch.
    ///
    /// Returns `true` only when the session is still live and no prior
    /// connection has already claimed the latch. Concurrent or second
    /// connections observe `false` and must not call `complete`. Callers must
    /// only claim after the request is a bound-port provider outcome.
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
    ///
    /// Scans with `withUnsafeBytes` so `Data` slices with a non-zero
    /// `startIndex` and arbitrary storage are safe. The last legal window
    /// start is `count - 4` so a buffer ending `CR LF CR` cannot read past
    /// the end (the prior `count - 3` end allowed `index + 3 == count`).
    nonisolated static func requestHeadersAreComplete(_ buffer: Data) -> Bool {
        guard buffer.count >= 4 else {
            return false
        }
        return buffer.withUnsafeBytes { rawBuffer -> Bool in
            let bytes = rawBuffer.bindMemory(to: UInt8.self)
            let count = bytes.count
            guard count >= 4 else {
                return false
            }
            let cr: UInt8 = 0x0d
            let lf: UInt8 = 0x0a
            // Inclusive last start index for a four-byte window.
            let lastStart = count - 4
            var index = 0
            while index <= lastStart {
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
    }

    /// Parses a minimal HTTP request into the exact callback URL only when the
    /// Host matches the bound loopback port and the target represents a
    /// provider outcome (`code` XOR `error`). Stray peers return `nil` so the
    /// session latch stays unclaimed.
    ///
    /// The returned string is the exact request target under the loopback host.
    /// Callers must not log it: the query can carry an authorization code.
    /// State validation remains broker-side.
    nonisolated static func callbackURL(from request: Data, boundPort: UInt16) -> String? {
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
        guard isExactLoopbackHostHeader(host, boundPort: boundPort) else {
            return nil
        }
        guard representsProviderCallbackOutcome(target: target) else {
            return nil
        }
        // Inventory forbids string interpolation; forward the exact validated
        // host and request target without logging the callback query/code.
        return "http://" + host + target
    }

    /// True when the HTTP request-target is a root-path provider outcome
    /// compatible with the broker core's eventual callback validation:
    /// unique query parameters, no fragment, and exactly one of a non-empty
    /// authorization `code` or a provider `error` (never both, never neither).
    ///
    /// Bare `/`, irrelevant queries, duplicates, conflicts, and malformed
    /// encodings return `false` so the peer is dropped without claiming the
    /// session latch. Does not log the target or code.
    nonisolated static func representsProviderCallbackOutcome(target: String) -> Bool {
        // Fragments never appear on a well-formed OAuth loopback target; reject
        // them before any query work so the broker session cannot be burned by
        // a fragment-bearing peer.
        guard !target.contains("#") else {
            return false
        }
        guard target == "/" || target.hasPrefix("/?") else {
            return false
        }
        if target == "/" {
            return false
        }
        let query = String(target.dropFirst(2))
        guard !query.isEmpty else {
            return false
        }
        // Malformed percent-encoding must fail closed before any outcome claim.
        guard percentEncodingIsWellFormed(query) else {
            return false
        }
        // Parse via URLComponents so percent-decoding matches Foundation URL
        // behavior used elsewhere.
        var components = URLComponents()
        components.percentEncodedQuery = query
        guard let items = components.queryItems, !items.isEmpty else {
            return false
        }
        var seenNames = Set<String>()
        var codeValue: String?
        var sawError = false
        for item in items {
            // Empty parameter names are not a provider outcome.
            guard !item.name.isEmpty else {
                return false
            }
            guard seenNames.insert(item.name).inserted else {
                // Duplicate parameter name: core would reject as
                // DuplicateParameter and consume the session — drop the peer.
                return false
            }
            if item.name == "code" {
                codeValue = item.value ?? ""
            } else if item.name == "error" {
                sawError = true
            }
        }
        switch (codeValue, sawError) {
        case (let code?, false):
            // Non-empty authorization code without a provider error.
            return !code.isEmpty
        case (nil, true):
            // Provider error outcome (value may be empty; core still maps it).
            return true
        default:
            // Both present (conflict), neither present, or empty code alone.
            return false
        }
    }

    /// Accepts only the literal IPv4 loopback host with the session's exact
    /// bound port (`127.0.0.1:<boundPort>`). Prefix/suffix lookalikes and any
    /// other port — including other nonprivileged ports — are rejected.
    nonisolated static func isExactLoopbackHostHeader(
        _ host: String,
        boundPort: UInt16
    ) -> Bool {
        let expected = "127.0.0.1:" + String(boundPort)
        return host == expected
    }

    /// Ephemeral loopback ports only; matches the listener ready-path gate.
    nonisolated static func isAcceptedLoopbackPort(_ port: UInt16) -> Bool {
        port >= 1024
    }

    /// True when every `%` in `text` is followed by two hexadecimal digits.
    nonisolated static func percentEncodingIsWellFormed(_ text: String) -> Bool {
        var index = text.startIndex
        while index < text.endIndex {
            if text[index] == "%" {
                let first = text.index(after: index)
                guard first < text.endIndex else {
                    return false
                }
                let second = text.index(after: first)
                guard second < text.endIndex else {
                    return false
                }
                let firstByte = text[first].utf8.first ?? 0
                let secondByte = text[second].utf8.first ?? 0
                guard isHexDigit(firstByte), isHexDigit(secondByte) else {
                    return false
                }
                index = text.index(after: second)
            } else {
                index = text.index(after: index)
            }
        }
        return true
    }

    nonisolated private static func isHexDigit(_ byte: UInt8) -> Bool {
        (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "F"))
            || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
    }
}
