// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// Bounded success value returned by exchange or refresh. Carries only a
/// short-lived access token, validated subject, and expiry.
struct TokenBrokerAccessToken: Sendable {
    let accessToken: String
    let subject: String
    let expiresInSeconds: Int
}

/// Bounded begin-authorization success value.
struct TokenBrokerPendingAuthorization: Sendable {
    let authorizationURL: URL
    let sessionHandle: String
}

/// Closed client failure after status validation and operation-aware mapping.
enum TokenBrokerClientError: Error, Equatable, Sendable {
    case status(TokenBrokerStatus)
    case malformedReply
    case interrupted
    case invalidated
    case rejectedPeer
}

/// Connects only to the embedded token-broker XPC service and never falls back
/// to the legacy in-process token path.
///
/// Fail-closed on interruption or invalidation. Each completion fires exactly
/// once. Success reply shapes are validated and bounded before delivery.
///
/// Lifecycle ownership is explicit: there is no `deinit` invalidation. The
/// owner (for example `TokenBrokerAuthorizationSession.finish`) must call
/// `cancel()` on every terminal path. Dropping the client without `cancel()`
/// leaves the XPC connection live until process exit.
final class TokenBrokerClient: @unchecked Sendable {
    static let serviceBundleIdentifier = "app.tersa.mac.token-broker"

    private static let maxAuthorizationURLBytes = 4_096
    private static let maxSessionHandleBytes = 64
    private static let maxAccessTokenBytes = 4_096
    private static let maxSubjectBytes = 255
    private static let maxExpiresInSeconds = 86_400

    private let connection: NSXPCConnection
    private let lock = NSLock()
    private var isFailed = false

    init() {
        let connection = NSXPCConnection(serviceName: Self.serviceBundleIdentifier)
        connection.remoteObjectInterface = NSXPCInterface(with: TersaMacTokenBrokerProtocolV1.self)
        self.connection = connection
        // Interruption and invalidation fail closed. In-flight proxy calls also
        // complete exactly once via `remoteObjectProxyWithErrorHandler`.
        connection.interruptionHandler = { [weak self] in
            self?.failClosed()
        }
        connection.invalidationHandler = { [weak self] in
            self?.failClosed()
        }
        connection.resume()
    }

    /// Cancels the connection deterministically and idempotently.
    ///
    /// Marks the client failed before invalidation so concurrent method calls
    /// observe `.invalidated` rather than racing a live proxy. Does not deliver
    /// completions itself: in-flight proxy error handlers and `OnceCompletion`
    /// preserve exact-once delivery (no duplicate completions on repeated
    /// `cancel()`, interruption, or invalidation). Safe to call multiple times.
    func cancel() {
        failClosed()
        connection.invalidate()
    }

    func beginAuthorizationSession(
        redirectURI: String,
        completion: @escaping @Sendable (Result<TokenBrokerPendingAuthorization, TokenBrokerClientError>) -> Void
    ) {
        let once = OnceCompletion(completion)
        guard let proxy = remoteProxy(once: once) else {
            return
        }
        proxy.beginAuthorizationSession(redirectURI: redirectURI) { authorizationURL, sessionHandle, status in
            once.finish {
                Self.mapBeginReply(
                    authorizationURL: authorizationURL,
                    sessionHandle: sessionHandle,
                    status: status
                )
            }
        }
    }

    func completeAuthorizationSession(
        sessionHandle: String,
        callbackURL: String,
        completion: @escaping @Sendable (Result<TokenBrokerAccessToken, TokenBrokerClientError>) -> Void
    ) {
        let once = OnceCompletion(completion)
        guard let proxy = remoteProxy(once: once) else {
            return
        }
        proxy.completeAuthorizationSession(
            sessionHandle: sessionHandle,
            callbackURL: callbackURL
        ) { accessToken, subject, expiresInSeconds, status in
            once.finish {
                Self.mapTokenReply(
                    accessToken: accessToken,
                    subject: subject,
                    expiresInSeconds: expiresInSeconds,
                    status: status
                )
            }
        }
    }

    func refreshAccessToken(
        accountSubject: String,
        completion: @escaping @Sendable (Result<TokenBrokerAccessToken, TokenBrokerClientError>) -> Void
    ) {
        let once = OnceCompletion(completion)
        guard let proxy = remoteProxy(once: once) else {
            return
        }
        proxy.refreshAccessToken(accountSubject: accountSubject) {
            accessToken,
            subject,
            expiresInSeconds,
            status in
            once.finish {
                Self.mapTokenReply(
                    accessToken: accessToken,
                    subject: subject,
                    expiresInSeconds: expiresInSeconds,
                    status: status
                )
            }
        }
    }

    func revokeProviderGrant(
        accountSubject: String,
        completion: @escaping @Sendable (Result<Void, TokenBrokerClientError>) -> Void
    ) {
        let once = OnceCompletion(completion)
        guard let proxy = remoteProxy(once: once) else {
            return
        }
        proxy.revokeProviderGrant(accountSubject: accountSubject) { status in
            once.finish {
                Self.mapStatusOnlyReply(
                    status: status,
                    operation: .revokeProviderGrant
                )
            }
        }
    }

    func deleteStoredTokens(
        accountSubject: String,
        completion: @escaping @Sendable (Result<Void, TokenBrokerClientError>) -> Void
    ) {
        let once = OnceCompletion(completion)
        guard let proxy = remoteProxy(once: once) else {
            return
        }
        proxy.deleteStoredTokens(accountSubject: accountSubject) { status in
            once.finish {
                Self.mapStatusOnlyReply(
                    status: status,
                    operation: .deleteStoredTokens
                )
            }
        }
    }

    private func remoteProxy<T>(once: OnceCompletion<T>) -> TersaMacTokenBrokerProtocolV1? {
        lock.lock()
        let failed = isFailed
        lock.unlock()
        if failed {
            once.finish { .failure(.invalidated) }
            return nil
        }
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
            once.finish { .failure(.interrupted) }
        }
        guard let typed = proxy as? TersaMacTokenBrokerProtocolV1 else {
            once.finish { .failure(.rejectedPeer) }
            return nil
        }
        return typed
    }

    private func failClosed() {
        lock.lock()
        isFailed = true
        lock.unlock()
    }

    static func mapBeginReply(
        authorizationURL: String?,
        sessionHandle: String?,
        status: Int
    ) -> Result<TokenBrokerPendingAuthorization, TokenBrokerClientError> {
        guard let validated = TokenBrokerStatus.validated(status) else {
            return .failure(.malformedReply)
        }
        guard validated == .success else {
            return .failure(.status(validated))
        }
        guard let authorizationURL,
              authorizationURL.utf8.count <= maxAuthorizationURLBytes,
              !authorizationURL.isEmpty,
              let url = URL(string: authorizationURL),
              isAcceptedAuthorizationURL(url),
              let sessionHandle,
              sessionHandle.utf8.count <= maxSessionHandleBytes,
              !sessionHandle.isEmpty
        else {
            return .failure(.malformedReply)
        }
        return .success(
            TokenBrokerPendingAuthorization(
                authorizationURL: url,
                sessionHandle: sessionHandle
            )
        )
    }

    /// Accepts only HTTPS authorization URLs whose host is exactly
    /// `accounts.google.com` before `NSWorkspace.open`.
    ///
    /// Rejects HTTP, file, custom schemes, and any non-exact host (including
    /// suffix/prefix lookalikes such as `accounts.google.com.evil`).
    static func isAcceptedAuthorizationURL(_ url: URL) -> Bool {
        guard let scheme = url.scheme,
              scheme.caseInsensitiveCompare("https") == .orderedSame,
              let host = url.host,
              host == "accounts.google.com"
        else {
            return false
        }
        return true
    }

    static func mapTokenReply(
        accessToken: String?,
        subject: String?,
        expiresInSeconds: Int,
        status: Int
    ) -> Result<TokenBrokerAccessToken, TokenBrokerClientError> {
        guard let validated = TokenBrokerStatus.validated(status) else {
            return .failure(.malformedReply)
        }
        guard validated == .success else {
            return .failure(.status(validated))
        }
        guard let accessToken,
              accessToken.utf8.count <= maxAccessTokenBytes,
              !accessToken.isEmpty,
              let subject,
              subject.utf8.count <= maxSubjectBytes,
              !subject.isEmpty,
              expiresInSeconds > 0,
              expiresInSeconds <= maxExpiresInSeconds
        else {
            return .failure(.malformedReply)
        }
        return .success(
            TokenBrokerAccessToken(
                accessToken: accessToken,
                subject: subject,
                expiresInSeconds: expiresInSeconds
            )
        )
    }

    static func mapStatusOnlyReply(
        status: Int,
        operation: TokenBrokerOperation
    ) -> Result<Void, TokenBrokerClientError> {
        _ = operation
        guard let validated = TokenBrokerStatus.validated(status) else {
            return .failure(.malformedReply)
        }
        guard validated == .success else {
            return .failure(.status(validated))
        }
        return .success(())
    }
}

/// Delivers a completion exactly once under concurrent reply/error races.
private final class OnceCompletion<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Result<T, TokenBrokerClientError>) -> Void)?

    init(_ completion: @escaping (Result<T, TokenBrokerClientError>) -> Void) {
        self.completion = completion
    }

    func finish(_ body: () -> Result<T, TokenBrokerClientError>) {
        lock.lock()
        let pending = completion
        completion = nil
        lock.unlock()
        pending?(body())
    }
}
