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

/// Concurrent live-peer admission for one loopback authorization session.
///
/// Counts concurrent live peers, not cumulative lifetime accepts. Each admit
/// pairs with exactly one successful `release`; double-release is a no-op so
/// timeout/send/error races cannot underflow.
struct TokenBrokerLoopbackPeerBudget: Equatable, Sendable {
    private(set) var livePeerIDs: Set<ObjectIdentifier>
    let maxConcurrent: Int

    var liveCount: Int { livePeerIDs.count }

    init(maxConcurrent: Int = TokenBrokerAuthorizationSession.maxAcceptedConnections) {
        self.livePeerIDs = []
        self.maxConcurrent = maxConcurrent
    }

    /// Admits a peer when under budget and not already live.
    mutating func admit(_ id: ObjectIdentifier) -> Bool {
        guard !livePeerIDs.contains(id), livePeerIDs.count < maxConcurrent else {
            return false
        }
        livePeerIDs.insert(id)
        return true
    }

    /// Idempotent release. Returns `true` only on the first release of `id`.
    @discardableResult
    mutating func release(_ id: ObjectIdentifier) -> Bool {
        livePeerIDs.remove(id) != nil
    }
}

/// Holds cancelable loopback/XPC resources for MainActor-safe abandoned cleanup.
///
/// `TokenBrokerAuthorizationSession` is `@MainActor`; `deinit` is not. This bag
/// is `@unchecked Sendable` and cancels its deadline source, listener, and XPC
/// client from `release()` / `deinit` so an abandoned session still tears those
/// endpoints down without actor-isolated access from `deinit`. `release()` is
/// idempotent and preserves exactly-once session completion (completion stays
/// in `finish`). The session deadline uses `DispatchSourceTimer` on `.main` so
/// cancellation is safe from any thread (unlike Foundation `Timer.invalidate`,
/// which must run on the scheduling run loop).
final class TokenBrokerSessionResourceBag: @unchecked Sendable {
    private let lock = NSLock()
    private var client: TokenBrokerClient?
    private var listener: NWListener?
    private var deadlineSource: DispatchSourceTimer?

    func install(client: TokenBrokerClient, listener: NWListener) {
        lock.lock()
        self.client = client
        self.listener = listener
        lock.unlock()
    }

    /// Stores the session deadline source. Cancels any previous source.
    /// Caller must `activate()` the source exactly once after this returns.
    func storeDeadlineSource(_ source: DispatchSourceTimer) {
        lock.lock()
        let previous = deadlineSource
        deadlineSource = source
        lock.unlock()
        previous?.cancel()
    }

    func borrowClient() -> TokenBrokerClient? {
        lock.lock()
        defer { lock.unlock() }
        return client
    }

    /// Cancels deadline source, loopback listener, and XPC client. Idempotent.
    /// `DispatchSource.cancel` is thread-safe; safe from `deinit` or any queue.
    func release() {
        lock.lock()
        let pendingSource = deadlineSource
        let pendingListener = listener
        let pendingClient = client
        deadlineSource = nil
        listener = nil
        client = nil
        lock.unlock()
        pendingSource?.cancel()
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
    /// Maximum concurrent live TCP peers one session will process at once.
    /// Excess peers are cancelled without completing the session; finished
    /// peers release their slot so later callbacks can still be admitted. The
    /// session deadline still ends a flow that never receives a valid callback.
    nonisolated static let maxAcceptedConnections = 8
    /// Per-connection read lifetime matching the legacy loopback receiver.
    /// A silent or partial peer is cancelled individually after this deadline.
    nonisolated static let connectionReadLifetime: TimeInterval = 2
    /// Hard upper bound for one authorization session (matches broker session
    /// TTL). Prevents stray connections from keeping the flow alive forever.
    nonisolated static let sessionTimeout: TimeInterval = 600

    /// Fixed HTTP 200 for a validated provider callback. Static bytes only —
    /// never interpolate callback/code. Body length is 55 UTF-8 bytes.
    nonisolated static let httpSuccessResponse: Data = Data(
        (
            "HTTP/1.1 200 OK\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: 55\r\n"
                + "Connection: close\r\n"
                + "Cache-Control: no-store\r\n"
                + "\r\n"
                + "Authorization received. Return to the tersa.app window."
        ).utf8
    )
    /// Fixed HTTP 400 for a complete but rejected/malformed request. Static
    /// bytes only — no reflected input. Body length is 55 UTF-8 bytes.
    nonisolated static let httpBadRequestResponse: Data = Data(
        (
            "HTTP/1.1 400 Bad Request\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: 55\r\n"
                + "Connection: close\r\n"
                + "Cache-Control: no-store\r\n"
                + "\r\n"
                + "Authorization rejected. Return to the tersa.app window."
        ).utf8
    )

    private final class LivePeer {
        let connection: NWConnection
        let deadlineWork: DispatchWorkItem
        /// True once a complete-header finish has begun (HTTP response path).
        /// Prevents timeout/ready races from double-sending while the peer still
        /// occupies the concurrent budget until contentProcessed.
        var isFinishing = false

        init(connection: NWConnection, deadlineWork: DispatchWorkItem) {
            self.connection = connection
            self.deadlineWork = deadlineWork
        }
    }

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
    /// Concurrent live peers keyed by `ObjectIdentifier`. Finish removes and
    /// cancels the per-peer deadline exactly once (reject, parse failure, send
    /// completion, timeout, session finish, or transport error).
    private var livePeers: [ObjectIdentifier: LivePeer] = [:]
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
        livePeers = [:]
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
        // DispatchSourceTimer on .main: cancel is thread-safe from any queue
        // (resource-bag deinit / release), unlike Foundation Timer.invalidate.
        let source = DispatchSource.makeTimerSource(queue: .main)
        source.schedule(
            deadline: .now() + Self.sessionTimeout,
            repeating: .never,
            leeway: .seconds(1)
        )
        source.setEventHandler { [weak self] in
            Task { @MainActor in
                self?.handleSessionDeadline()
            }
        }
        // Store before activate so release can cancel; activate exactly once.
        resources.storeDeadlineSource(source)
        source.activate()
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
        let id = ObjectIdentifier(connection)
        // Concurrent live budget: reject only when eight peers are in flight.
        // Finished peers release their slot so a later valid callback can enter.
        guard livePeers.count < Self.maxAcceptedConnections, livePeers[id] == nil else {
            connection.cancel()
            return
        }
        let deadlineWork = DispatchWorkItem { [weak self, weak connection] in
            guard let connection else {
                return
            }
            Task { @MainActor in
                self?.handlePeerReadDeadline(connection)
            }
        }
        livePeers[id] = LivePeer(connection: connection, deadlineWork: deadlineWork)
        DispatchQueue.main.asyncAfter(
            deadline: .now() + Self.connectionReadLifetime,
            execute: deadlineWork
        )
        connection.start(queue: .main)
        receiveLoopbackBytes(connection: connection, accumulated: Data())
    }

    private func receiveLoopbackBytes(connection: NWConnection, accumulated: Data) {
        guard !isFinished else {
            releasePeerImmediate(connection)
            return
        }
        // Peer already finished (timeout/session end) — stop receiving.
        guard livePeers[ObjectIdentifier(connection)] != nil else {
            return
        }
        let remaining = Self.maxRequestBytes - accumulated.count
        guard remaining > 0 else {
            releasePeerImmediate(connection)
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
                    self.releasePeerImmediate(connection)
                    return
                }
                // Drop work for peers already released (timeout race).
                guard self.livePeers[ObjectIdentifier(connection)] != nil else {
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
                    // connection (no HTTP body) and leave the listener ready.
                    self.releasePeerImmediate(connection)
                case .ready(let request):
                    self.handleReadyLoopbackRequest(connection: connection, request: request)
                }
            }
        }
    }

    /// Handles a complete header block: validated provider outcome claims the
    /// latch and completes the broker once after queuing a fixed 200; complete
    /// but rejected/malformed requests get a fixed 400. Incomplete peers never
    /// reach this path. Budget release and TCP cancel run in contentProcessed.
    private func handleReadyLoopbackRequest(connection: NWConnection, request: Data) {
        let id = ObjectIdentifier(connection)
        // Claim exclusive finish: cancel the read deadline and prevent a second
        // ready/timeout path from admitting the same peer again.
        guard let peer = livePeers[id], !peer.isFinishing else {
            return
        }
        peer.deadlineWork.cancel()
        peer.isFinishing = true

        guard !isFinished else {
            // Force-release: isFinishing would make releasePeerImmediate a no-op.
            livePeers.removeValue(forKey: id)
            connection.cancel()
            return
        }

        guard let boundPort = boundLoopbackPort,
              let callbackURL = Self.callbackURL(from: request, boundPort: boundPort)
        else {
            // Complete headers but not a bound-port provider outcome.
            sendFixedHTTPResponseAndRelease(connection, response: Self.httpBadRequestResponse)
            return
        }
        guard Self.claimForwardedCallback(
            isFinished: isFinished,
            hasForwardedCallback: &hasForwardedCallback
        ) else {
            sendFixedHTTPResponseAndRelease(connection, response: Self.httpBadRequestResponse)
            return
        }
        guard let sessionHandle else {
            sendFixedHTTPResponseAndRelease(connection, response: Self.httpBadRequestResponse)
            return
        }
        // Broker complete once; browser gets the fixed 200. Cancel/release of
        // the TCP peer and concurrent budget slot happen only in contentProcessed.
        complete(sessionHandle: sessionHandle, callbackURL: callbackURL)
        sendFixedHTTPResponseAndRelease(connection, response: Self.httpSuccessResponse)
    }

    /// 2-second per-peer read deadline: cancel only this silent/partial peer.
    private func handlePeerReadDeadline(_ connection: NWConnection) {
        releasePeerImmediate(connection)
    }

    /// Idempotent immediate finish for incomplete/timeout/transport paths:
    /// cancel deadline, free the concurrent slot, cancel TCP. No HTTP body.
    /// No-op when the HTTP response path already owns the peer (`isFinishing`);
    /// that path releases only in `.contentProcessed`. Session teardown still
    /// drains every peer via `cancelAllLivePeers`.
    private func releasePeerImmediate(_ connection: NWConnection) {
        let id = ObjectIdentifier(connection)
        guard let peer = livePeers[id], !peer.isFinishing else {
            return
        }
        livePeers.removeValue(forKey: id)
        peer.deadlineWork.cancel()
        connection.cancel()
    }

    /// Sends a pinned static HTTP response; releases the concurrent budget and
    /// cancels the connection only in `.contentProcessed`. Never interpolates
    /// callback/code.
    private func sendFixedHTTPResponseAndRelease(_ connection: NWConnection, response: Data) {
        let id = ObjectIdentifier(connection)
        // Deadline is already cancelled; registry entry remains until send
        // completion so the concurrent budget counts this peer as live.
        livePeers[id]?.deadlineWork.cancel()
        livePeers[id]?.isFinishing = true
        connection.send(
            content: response,
            contentContext: .defaultMessage,
            isComplete: true,
            completion: .contentProcessed { [weak self] _ in
                Task { @MainActor in
                    if let peer = self?.livePeers.removeValue(forKey: id) {
                        peer.deadlineWork.cancel()
                    }
                    connection.cancel()
                }
            }
        )
    }

    /// Cancels every live peer deadline and connection. Idempotent per peer
    /// because the map is drained once.
    private func cancelAllLivePeers() {
        let peers = livePeers
        livePeers.removeAll()
        for (_, peer) in peers {
            peer.deadlineWork.cancel()
            peer.connection.cancel()
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
        // Drop live peers (deadline + TCP) before listener/XPC teardown.
        cancelAllLivePeers()
        // Release listener + XPC client (and deadline source) before outcome.
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

    /// Whether one more concurrent live peer may be admitted.
    ///
    /// Pure gate used by the accept path and unit tests. `liveCount` is the
    /// number of peers currently in flight, not cumulative lifetime accepts.
    /// Excess simultaneous peers are cancelled without completing the session.
    nonisolated static func shouldProcessAcceptedConnection(
        isFinished: Bool,
        hasSessionHandle: Bool,
        acceptedConnectionCount liveCount: Int,
        maxAcceptedConnections: Int = maxAcceptedConnections
    ) -> Bool {
        !isFinished
            && hasSessionHandle
            && liveCount < maxAcceptedConnections
    }

    /// Pure peer read-deadline check (elapsed >= lifetime).
    nonisolated static func peerReadDeadlineExpired(
        elapsed: TimeInterval,
        lifetime: TimeInterval = connectionReadLifetime
    ) -> Bool {
        elapsed >= lifetime
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

    /// True when every UTF-8 byte is in the RFC 3986 query allowed set and
    /// every `%` is followed by two hex digits.
    ///
    /// Allowed set: ASCII alphanumeric plus `-._~!$&'()*+,;=:@/?`, with `%`
    /// only as a well-formed percent-escape. Rejects raw `|`, `<`, `[`, `^`,
    /// spaces, backticks, and every non-ASCII byte so assigning the string to
    /// `URLComponents.percentEncodedQuery` cannot Foundation-fatalError.
    nonisolated static func percentEncodingIsWellFormed(_ text: String) -> Bool {
        let utf8 = text.utf8
        var index = utf8.startIndex
        while index < utf8.endIndex {
            let byte = utf8[index]
            if byte == UInt8(ascii: "%") {
                let first = utf8.index(after: index)
                guard first < utf8.endIndex else {
                    return false
                }
                let second = utf8.index(after: first)
                guard second < utf8.endIndex else {
                    return false
                }
                guard isHexDigit(utf8[first]), isHexDigit(utf8[second]) else {
                    return false
                }
                index = utf8.index(after: second)
            } else if isAllowedRFC3986QueryByte(byte) {
                index = utf8.index(after: index)
            } else {
                return false
            }
        }
        return true
    }

    /// RFC 3986 query characters excluding `%` (handled as an escape lead).
    /// unreserved / sub-delims / ":" / "@" / "/" / "?".
    nonisolated private static func isAllowedRFC3986QueryByte(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"),
             UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"):
            return true
        case UInt8(ascii: "-"),
             UInt8(ascii: "."),
             UInt8(ascii: "_"),
             UInt8(ascii: "~"),
             UInt8(ascii: "!"),
             UInt8(ascii: "$"),
             UInt8(ascii: "&"),
             UInt8(ascii: "'"),
             UInt8(ascii: "("),
             UInt8(ascii: ")"),
             UInt8(ascii: "*"),
             UInt8(ascii: "+"),
             UInt8(ascii: ","),
             UInt8(ascii: ";"),
             UInt8(ascii: "="),
             UInt8(ascii: ":"),
             UInt8(ascii: "@"),
             UInt8(ascii: "/"),
             UInt8(ascii: "?"):
            return true
        default:
            return false
        }
    }

    nonisolated private static func isHexDigit(_ byte: UInt8) -> Bool {
        (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "F"))
            || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
    }
}
