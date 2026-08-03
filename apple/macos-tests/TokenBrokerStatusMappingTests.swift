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
        let boundPort: UInt16 = 54_321
        let valid = Data(
            "GET /?code=redacted&state=redacted HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n"
                .utf8
        )
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.callbackURL(from: valid, boundPort: boundPort),
            "http://127.0.0.1:54321/?code=redacted&state=redacted"
        )
        let nonLoopback = Data(
            "GET /?code=redacted HTTP/1.1\r\nHost: example.invalid\r\n\r\n".utf8
        )
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(from: nonLoopback, boundPort: boundPort)
        )
        // Prefix-only host checks must not accept dotted suffixes.
        let attackerSuffix = Data(
            "GET /?code=redacted HTTP/1.1\r\nHost: 127.0.0.1.attacker\r\n\r\n".utf8
        )
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(from: attackerSuffix, boundPort: boundPort)
        )
        let missingPort = Data(
            "GET /?code=redacted HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".utf8
        )
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(from: missingPort, boundPort: boundPort)
        )
        let privilegedPort = Data(
            "GET /?code=redacted HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n".utf8
        )
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(from: privilegedPort, boundPort: boundPort)
        )
        let leadingZeroPort = Data(
            "GET /?code=redacted HTTP/1.1\r\nHost: 127.0.0.1:054321\r\n\r\n".utf8
        )
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(from: leadingZeroPort, boundPort: boundPort)
        )
        let oversized = Data(repeating: 0x41, count: 9_000)
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(from: oversized, boundPort: boundPort)
        )
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
            TokenBrokerAuthorizationSession.callbackURL(from: request, boundPort: 54_321),
            "http://127.0.0.1:54321/?code=redacted"
        )
    }

    func testHeaderTerminatorScanIsSafeForPartialCRLFAndDataSlices() {
        // Buffer ending CR LF CR must not SIGTRAP: last legal window is count-4.
        let endsCRLFCR = Data([0x41, 0x0d, 0x0a, 0x0d])
        XCTAssertFalse(TokenBrokerAuthorizationSession.requestHeadersAreComplete(endsCRLFCR))

        // Terminator split after each of the four bytes still completes.
        let prefix = Data("GET / HTTP/1.1\r\nHost: 127.0.0.1:54321".utf8)
        let terminator: [UInt8] = [0x0d, 0x0a, 0x0d, 0x0a]
        for splitAfter in 0...4 {
            var buffer = prefix
            if splitAfter > 0 {
                buffer.append(contentsOf: terminator.prefix(splitAfter))
            }
            let completeAfterPrefix = splitAfter >= 4
            XCTAssertEqual(
                TokenBrokerAuthorizationSession.requestHeadersAreComplete(buffer),
                completeAfterPrefix,
                "splitAfter \(splitAfter) before final chunk"
            )
            if splitAfter < 4 {
                buffer.append(contentsOf: terminator.suffix(from: splitAfter))
                XCTAssertTrue(
                    TokenBrokerAuthorizationSession.requestHeadersAreComplete(buffer),
                    "splitAfter \(splitAfter) must complete once remainder arrives"
                )
            }
        }

        // Data slice with non-zero startIndex must scan relative to the slice
        // without reindexing (withUnsafeBytes, not integer base-0 Data subscripts).
        let padded = Data("xxGET / HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n".utf8)
        let slice = padded.dropFirst(2)
        XCTAssertEqual(slice.startIndex, 2)
        XCTAssertTrue(TokenBrokerAuthorizationSession.requestHeadersAreComplete(slice))
        // Incomplete slice ending mid-terminator must stay false.
        let incompletePadded = Data("xxGET / HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r".utf8)
        let incompleteSlice = incompletePadded.dropFirst(2)
        XCTAssertEqual(incompleteSlice.startIndex, 2)
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.requestHeadersAreComplete(incompleteSlice)
        )
    }

    func testProviderOutcomeGateRejectsStraysAndAcceptsCodeOrError() {
        let boundPort: UInt16 = 54_321
        // Valid bound port with authorization code.
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.callbackURL(
                from: Data(
                    "GET /?code=redacted&state=redacted HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n"
                        .utf8
                ),
                boundPort: boundPort
            ),
            "http://127.0.0.1:54321/?code=redacted&state=redacted"
        )
        // Valid bound port with provider error.
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.callbackURL(
                from: Data(
                    "GET /?error=access_denied&state=redacted HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n"
                        .utf8
                ),
                boundPort: boundPort
            ),
            "http://127.0.0.1:54321/?error=access_denied&state=redacted"
        )
        // Wrong bound port (other nonprivileged port) must not claim the latch.
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(
                from: Data(
                    "GET /?code=redacted&state=redacted HTTP/1.1\r\nHost: 127.0.0.1:54322\r\n\r\n"
                        .utf8
                ),
                boundPort: boundPort
            )
        )
        // Bare GET /
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(
                from: Data("GET / HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n".utf8),
                boundPort: boundPort
            )
        )
        // Irrelevant query (no code/error).
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(
                from: Data(
                    "GET /?state=redacted&scope=email HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n"
                        .utf8
                ),
                boundPort: boundPort
            )
        )
        // Duplicate code parameter.
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(
                from: Data(
                    "GET /?code=one&code=two&state=redacted HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n"
                        .utf8
                ),
                boundPort: boundPort
            )
        )
        // Conflicting code + error.
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(
                from: Data(
                    "GET /?code=redacted&error=access_denied&state=redacted HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n"
                        .utf8
                ),
                boundPort: boundPort
            )
        )
        // Fragment / malformed encoding.
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(
                from: Data(
                    "GET /?code=redacted#frag HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n".utf8
                ),
                boundPort: boundPort
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.representsProviderCallbackOutcome(
                target: "/?code=%ZZ"
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.representsProviderCallbackOutcome(target: "/")
        )
        XCTAssertTrue(
            TokenBrokerAuthorizationSession.representsProviderCallbackOutcome(
                target: "/?code=redacted&state=redacted"
            )
        )
        XCTAssertTrue(
            TokenBrokerAuthorizationSession.representsProviderCallbackOutcome(
                target: "/?error=access_denied&state=redacted"
            )
        )

        // Valid callback after a stray: latch stays free for the first outcome.
        var hasForwardedCallback = false
        let stray = TokenBrokerAuthorizationSession.callbackURL(
            from: Data("GET / HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n".utf8),
            boundPort: boundPort
        )
        XCTAssertNil(stray)
        // Stray must not claim the latch.
        XCTAssertFalse(hasForwardedCallback)
        let validAfterStray = TokenBrokerAuthorizationSession.callbackURL(
            from: Data(
                "GET /?code=redacted&state=redacted HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n"
                    .utf8
            ),
            boundPort: boundPort
        )
        XCTAssertNotNil(validAfterStray)
        XCTAssertTrue(
            TokenBrokerAuthorizationSession.claimForwardedCallback(
                isFinished: false,
                hasForwardedCallback: &hasForwardedCallback
            )
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
        let badHost = Data("GET /?code=x HTTP/1.1\r\nHost: example.invalid\r\n\r\n".utf8)
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(from: badHost, boundPort: 54_321)
        )
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
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader(
                "127.0.0.1:54321",
                boundPort: 54_321
            )
        )
        XCTAssertTrue(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader(
                "127.0.0.1:1024",
                boundPort: 1_024
            )
        )
        // Any other nonprivileged port is wrong for this session.
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader(
                "127.0.0.1:54322",
                boundPort: 54_321
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader(
                "127.0.0.1.attacker",
                boundPort: 54_321
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader(
                "127.0.0.1",
                boundPort: 54_321
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader(
                "127.0.0.1:80",
                boundPort: 54_321
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader(
                "127.0.0.1:054321",
                boundPort: 54_321
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader(
                "127.0.0.1:54321.evil",
                boundPort: 54_321
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.isExactLoopbackHostHeader(
                "localhost:54321",
                boundPort: 54_321
            )
        )
    }

    func testAbandonedSessionResourceReleaseIsIdempotent() {
        var clientCancels = 0
        var listenerCancels = 0
        var clientCancel: (() -> Void)? = { clientCancels += 1 }
        var listenerCancel: (() -> Void)? = { listenerCancels += 1 }
        TokenBrokerSessionResourceBag.releaseCancelClosures(
            clientCancel: &clientCancel,
            listenerCancel: &listenerCancel
        )
        XCTAssertEqual(clientCancels, 1)
        XCTAssertEqual(listenerCancels, 1)
        XCTAssertNil(clientCancel)
        XCTAssertNil(listenerCancel)
        // Second release must not double-cancel (exactly-once endpoint teardown).
        TokenBrokerSessionResourceBag.releaseCancelClosures(
            clientCancel: &clientCancel,
            listenerCancel: &listenerCancel
        )
        XCTAssertEqual(clientCancels, 1)
        XCTAssertEqual(listenerCancels, 1)
    }

    func testWireStatusRawValuesAreClosedZeroThroughNineteen() {
        let expected: [(TokenBrokerStatus, Int)] = [
            (.success, 0),
            (.notImplemented, 1),
            (.notProvisioned, 2),
            (.invalidRequest, 3),
            (.rejectedClient, 4),
            (.authorizationCodeRejected, 5),
            (.providerRejected, 6),
            (.insufficientScope, 7),
            (.missingRefreshToken, 8),
            (.consentRevoked, 9),
            (.revokeUnconfirmed, 10),
            (.persistenceFailed, 11),
            (.invalidConfiguration, 12),
            (.unavailable, 13),
            (.busy, 14),
            (.sessionUnknown, 15),
            (.transport, 16),
            (.malformedResponse, 17),
            (.identityUnverified, 18),
            (.identityMismatch, 19),
        ]
        XCTAssertEqual(expected.count, 20)
        for (status, raw) in expected {
            XCTAssertEqual(status.rawValue, raw, "\(status)")
            XCTAssertEqual(TokenBrokerStatus.validated(raw), status)
        }
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
