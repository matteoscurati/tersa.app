// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import XCTest

/// Deterministic mapping tests for the closed broker status surface.
///
/// No live XPC, network, or Keychain. Fixtures carry no credentials, subjects,
/// codes, or provider bodies.
final class TokenBrokerStatusMappingTests: XCTestCase {
    func testAllStatusesMapForCompleteAuthorization() {
        let operation = TokenBrokerOperation.completeAuthorization
        let expected: [(TokenBrokerStatus, TokenBrokerStatusMapping.Recovery)] = [
            (.success, .succeeded),
            (.authorizationCodeRejected, .signInExpired),
            (.providerRejected, .providerRejected),
            (.insufficientScope, .permissionRequired(
                manualRevokeURL: TokenBrokerStatusMapping.googleAccountPermissionsURL
            )),
            (.missingRefreshToken, .needsReconnect),
            (.consentRevoked, .needsReconnect),
            (.revokeUnconfirmed, .revokeUnconfirmed),
            (.persistenceFailed, .unavailable),
            (.invalidRequest, .invalidRequest),
            (.invalidConfiguration, .invalidConfiguration),
            (.unavailable, .unavailable),
            (.busy, .busy),
            (.sessionUnknown, .sessionUnknown),
            (.transport, .transport),
            (.malformedResponse, .malformedResponse),
            (.identityUnverified, .identityUnverified),
            (.identityMismatch, .identityMismatch),
            (.rejectedClient, .rejectedClient),
            (.notImplemented, .notImplemented),
            (.notProvisioned, .notProvisioned),
        ]
        for (status, recovery) in expected {
            XCTAssertEqual(
                TokenBrokerStatusMapping.recovery(for: status, operation: operation),
                recovery,
                "status \(status.rawValue)"
            )
        }
    }

    func testAuthorizationCodeRejectedIsNeverProviderOrConsent() {
        let recovery = TokenBrokerStatusMapping.recovery(
            for: .authorizationCodeRejected,
            operation: .completeAuthorization
        )
        XCTAssertEqual(recovery, .signInExpired)
        XCTAssertNotEqual(
            recovery,
            TokenBrokerStatusMapping.recovery(
                for: .providerRejected,
                operation: .completeAuthorization
            )
        )
        XCTAssertNotEqual(
            recovery,
            TokenBrokerStatusMapping.recovery(
                for: .consentRevoked,
                operation: .completeAuthorization
            )
        )
        XCTAssertEqual(
            TokenBrokerStatusMapping.connectionFailure(for: recovery),
            .signInExpired
        )
    }

    func testPersistenceFailedIsOperationAware() {
        XCTAssertEqual(
            TokenBrokerStatusMapping.recovery(
                for: .persistenceFailed,
                operation: .revokeProviderGrant
            ),
            .revokeUnconfirmed
        )
        XCTAssertEqual(
            TokenBrokerStatusMapping.recovery(
                for: .persistenceFailed,
                operation: .deleteStoredTokens
            ),
            .incompleteLocalTeardown
        )
        XCTAssertEqual(
            TokenBrokerStatusMapping.connectionFailure(for: .incompleteLocalTeardown),
            .disconnectIncomplete
        )
        // Incomplete teardown must never look like a clean success.
        XCTAssertNotNil(
            TokenBrokerStatusMapping.connectionFailure(for: .incompleteLocalTeardown)
        )
    }

    func testInsufficientScopeKeepsManualRevokeRecovery() {
        let recovery = TokenBrokerStatusMapping.recovery(
            for: .insufficientScope,
            operation: .completeAuthorization
        )
        guard case .permissionRequired(let url) = recovery else {
            return XCTFail("insufficient scope must keep permission recovery")
        }
        XCTAssertEqual(url, TokenBrokerStatusMapping.googleAccountPermissionsURL)
        XCTAssertEqual(url.host, "myaccount.google.com")
        XCTAssertFalse(url.absoluteString.contains("token"))
        XCTAssertEqual(
            TokenBrokerStatusMapping.connectionFailure(for: recovery),
            .permissionRequired
        )
    }

    func testMissingAndRevokedConsentRouteToReconnect() {
        for status: TokenBrokerStatus in [.missingRefreshToken, .consentRevoked] {
            let recovery = TokenBrokerStatusMapping.recovery(
                for: status,
                operation: .refreshAccessToken
            )
            XCTAssertEqual(recovery, .needsReconnect)
            XCTAssertEqual(
                TokenBrokerStatusMapping.connectionFailure(for: recovery),
                .signInExpired
            )
        }
    }

    func testClientErrorsMapWithoutOpenPayloads() {
        XCTAssertEqual(
            TokenBrokerStatusMapping.recovery(
                for: .malformedReply,
                operation: .completeAuthorization
            ),
            .malformedResponse
        )
        XCTAssertEqual(
            TokenBrokerStatusMapping.recovery(
                for: .interrupted,
                operation: .refreshAccessToken
            ),
            .unavailable
        )
        XCTAssertEqual(
            TokenBrokerStatusMapping.recovery(
                for: .invalidated,
                operation: .beginAuthorization
            ),
            .unavailable
        )
        XCTAssertEqual(
            TokenBrokerStatusMapping.recovery(
                for: .rejectedPeer,
                operation: .beginAuthorization
            ),
            .rejectedClient
        )
    }

    func testMalformedAndOversizedBeginRepliesFailClosed() {
        XCTAssertEqual(
            TokenBrokerClient.mapBeginReply(
                authorizationURL: nil,
                sessionHandle: "handle",
                status: TokenBrokerStatus.success.rawValue
            ).isFailure,
            true
        )
        XCTAssertEqual(
            TokenBrokerClient.mapBeginReply(
                authorizationURL: "http://example.invalid/",
                sessionHandle: nil,
                status: TokenBrokerStatus.success.rawValue
            ).isFailure,
            true
        )
        let oversizedURL = "https://example.invalid/" + String(repeating: "a", count: 5_000)
        XCTAssertEqual(
            TokenBrokerClient.mapBeginReply(
                authorizationURL: oversizedURL,
                sessionHandle: "handle",
                status: TokenBrokerStatus.success.rawValue
            ).isFailure,
            true
        )
        XCTAssertEqual(
            TokenBrokerClient.mapBeginReply(
                authorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
                sessionHandle: "opaque-handle-22chars!",
                status: 9_999
            ).isFailure,
            true
        )
    }

    func testMalformedAndOversizedTokenRepliesFailClosed() {
        XCTAssertEqual(
            TokenBrokerClient.mapTokenReply(
                accessToken: nil,
                subject: "subject",
                expiresInSeconds: 3600,
                status: TokenBrokerStatus.success.rawValue
            ).isFailure,
            true
        )
        XCTAssertEqual(
            TokenBrokerClient.mapTokenReply(
                accessToken: "token",
                subject: "subject",
                expiresInSeconds: 0,
                status: TokenBrokerStatus.success.rawValue
            ).isFailure,
            true
        )
        XCTAssertEqual(
            TokenBrokerClient.mapTokenReply(
                accessToken: "token",
                subject: "subject",
                expiresInSeconds: 200_000,
                status: TokenBrokerStatus.success.rawValue
            ).isFailure,
            true
        )
        let oversizedToken = String(repeating: "t", count: 5_000)
        XCTAssertEqual(
            TokenBrokerClient.mapTokenReply(
                accessToken: oversizedToken,
                subject: "subject",
                expiresInSeconds: 3600,
                status: TokenBrokerStatus.success.rawValue
            ).isFailure,
            true
        )
    }

    func testStatusOnlySuccessAndUnknownStatus() {
        XCTAssertTrue(
            TokenBrokerClient.mapStatusOnlyReply(
                status: TokenBrokerStatus.success.rawValue,
                operation: .deleteStoredTokens
            ).isSuccess
        )
        XCTAssertEqual(
            TokenBrokerClient.mapStatusOnlyReply(
                status: 42_000,
                operation: .deleteStoredTokens
            ).isFailure,
            true
        )
    }

    func testValidatedStatusRejectsUnknownIntegers() {
        XCTAssertNil(TokenBrokerStatus.validated(-1))
        XCTAssertNil(TokenBrokerStatus.validated(20))
        XCTAssertEqual(TokenBrokerStatus.validated(0), .success)
        XCTAssertEqual(TokenBrokerStatus.validated(5), .authorizationCodeRejected)
    }

    func testLoopbackCallbackParsingIsBounded() {
        let valid = Data(
            "GET /?code=redacted&state=redacted HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n"
                .utf8
        )
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.callbackURL(from: valid),
            "http://127.0.0.1:54321/?code=redacted&state=redacted"
        )
        let nonLoopback = Data(
            "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n".utf8
        )
        XCTAssertNil(TokenBrokerAuthorizationSession.callbackURL(from: nonLoopback))
        // Prefix-only host checks must not accept dotted suffixes.
        let attackerSuffix = Data(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1.attacker\r\n\r\n".utf8
        )
        XCTAssertNil(TokenBrokerAuthorizationSession.callbackURL(from: attackerSuffix))
        let missingPort = Data(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".utf8
        )
        XCTAssertNil(TokenBrokerAuthorizationSession.callbackURL(from: missingPort))
        let privilegedPort = Data(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n".utf8
        )
        XCTAssertNil(TokenBrokerAuthorizationSession.callbackURL(from: privilegedPort))
        let leadingZeroPort = Data(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:054321\r\n\r\n".utf8
        )
        XCTAssertNil(TokenBrokerAuthorizationSession.callbackURL(from: leadingZeroPort))
        let oversized = Data(repeating: 0x41, count: 9_000)
        XCTAssertNil(TokenBrokerAuthorizationSession.callbackURL(from: oversized))
    }

    func testSegmentedLoopbackReceiveAccumulatesUntilHeadersComplete() {
        var buffer = Data()
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.accumulateLoopbackReceive(
                buffer: &buffer,
                chunk: Data("GET /?code=redacted HTTP/1.1\r\n".utf8),
                isComplete: false,
                hadError: false
            ),
            .needMore
        )
        XCTAssertFalse(TokenBrokerAuthorizationSession.requestHeadersAreComplete(buffer))
        let second = TokenBrokerAuthorizationSession.accumulateLoopbackReceive(
            buffer: &buffer,
            chunk: Data("Host: 127.0.0.1:54321\r\n\r\n".utf8),
            isComplete: false,
            hadError: false
        )
        guard case .ready(let request) = second else {
            XCTFail("segmented receive must become ready after CRLFCRLF")
            return
        }
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.callbackURL(from: request),
            "http://127.0.0.1:54321/?code=redacted"
        )
    }

    func testStrayLoopbackConnectionsRejectWithoutSessionCompletionSignal() {
        // Empty peer close, partial headers, transport error, and oversize all
        // reject only the connection (no parseable callback URL).
        var empty = Data()
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.accumulateLoopbackReceive(
                buffer: &empty,
                chunk: nil,
                isComplete: true,
                hadError: false
            ),
            .rejectConnection
        )
        var partial = Data()
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.accumulateLoopbackReceive(
                buffer: &partial,
                chunk: Data("GET / HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n".utf8),
                isComplete: true,
                hadError: false
            ),
            .rejectConnection
        )
        var errored = Data()
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.accumulateLoopbackReceive(
                buffer: &errored,
                chunk: Data("GET / HTTP/1.1\r\n".utf8),
                isComplete: false,
                hadError: true
            ),
            .rejectConnection
        )
        var oversize = Data()
        let chunk = Data(
            repeating: 0x41,
            count: TokenBrokerAuthorizationSession.maxRequestBytes + 1
        )
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.accumulateLoopbackReceive(
                buffer: &oversize,
                chunk: chunk,
                isComplete: false,
                hadError: false
            ),
            .rejectConnection
        )
        // Unparseable complete headers must not yield a callback URL.
        let badHost = Data("GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n".utf8)
        XCTAssertNil(TokenBrokerAuthorizationSession.callbackURL(from: badHost))
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.shouldProcessAcceptedConnection(
                isFinished: false,
                hasSessionHandle: true,
                acceptedConnectionCount: TokenBrokerAuthorizationSession.maxAcceptedConnections
            )
        )
        XCTAssertTrue(
            TokenBrokerAuthorizationSession.shouldProcessAcceptedConnection(
                isFinished: false,
                hasSessionHandle: true,
                acceptedConnectionCount: 0
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.shouldProcessAcceptedConnection(
                isFinished: true,
                hasSessionHandle: true,
                acceptedConnectionCount: 0
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.shouldProcessAcceptedConnection(
                isFinished: false,
                hasSessionHandle: false,
                acceptedConnectionCount: 0
            )
        )
    }

    func testDuplicateCallbackLatchIsSingleShot() {
        var hasForwardedCallback = false
        XCTAssertTrue(
            TokenBrokerAuthorizationSession.claimForwardedCallback(
                isFinished: false,
                hasForwardedCallback: &hasForwardedCallback
            )
        )
        XCTAssertTrue(hasForwardedCallback)
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.claimForwardedCallback(
                isFinished: false,
                hasForwardedCallback: &hasForwardedCallback
            )
        )
        var finishedLatch = false
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.claimForwardedCallback(
                isFinished: true,
                hasForwardedCallback: &finishedLatch
            )
        )
        XCTAssertFalse(finishedLatch)
    }

    func testExactLoopbackHostHeaderContract() {
        XCTAssertTrue(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader("127.0.0.1:54321")
        )
        XCTAssertTrue(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader("127.0.0.1:1024")
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader("127.0.0.1.attacker")
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader("127.0.0.1")
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader("127.0.0.1:80")
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader("127.0.0.1:054321")
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader("127.0.0.1:54321.evil")
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader("localhost:54321")
        )
    }

    func testPermissionRequiredCopyMentionsManualRevoke() {
        let message = ConnectionFailure.permissionRequired.message
        XCTAssertTrue(message.contains("Gmail read access"))
        XCTAssertTrue(message.contains("Google Account permissions"))
    }
}

private extension Result {
    var isFailure: Bool {
        if case .failure = self { return true }
        return false
    }

    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }
}
