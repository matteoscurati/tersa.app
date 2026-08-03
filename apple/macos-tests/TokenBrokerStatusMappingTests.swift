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
        // Illegal raw query bytes must fail closed without Foundation SIGTRAP
        // on percentEncodedQuery (raw | < [ ^ and non-ASCII).
        let illegalTargets = [
            "/?code=a|b",
            "/?code=a<b",
            "/?code=a[b",
            "/?code=a^b",
            "/?code=x\u{00E9}",
            "/?code=\u{00E9}",
            "/?code=a b",
            "/?code=a`b",
        ]
        for target in illegalTargets {
            XCTAssertFalse(
                TokenBrokerAuthorizationSession.representsProviderCallbackOutcome(
                    target: target
                ),
                "must reject without trapping: \(target)"
            )
            XCTAssertFalse(
                TokenBrokerAuthorizationSession.percentEncodingIsWellFormed(
                    String(target.dropFirst(2))
                ),
                "query bytes must be rejected: \(target)"
            )
        }

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
        // Unparsable complete headers must not yield a callback URL.
        let badHost = Data("GET /?code=x HTTP/1.1\r\nHost: example.invalid\r\n\r\n".utf8)
        XCTAssertNil(
            TokenBrokerAuthorizationSession.callbackURL(from: badHost, boundPort: 54_321)
        )
    }

    func testConcurrentPeerRegistryBudgetAndFinishingGuards() {
        // Production path: admit → (timeout) releaseImmediate OR beginFinishing
        // → take on send completion / force. Tests must fail if finishing no
        // longer blocks immediate release or if duplicate IDs are re-admitted.
        final class PeerToken: NSObject {}
        struct DummyPeer {
            let label: Int
        }

        var registry = TokenBrokerLoopbackPeerRegistry<DummyPeer>(maxConcurrent: 8)
        let firstWave = (0..<8).map { index -> (PeerToken, DummyPeer) in
            (PeerToken(), DummyPeer(label: index))
        }
        for (token, peer) in firstWave {
            XCTAssertTrue(registry.admit(ObjectIdentifier(token), peer: peer))
        }
        XCTAssertEqual(registry.liveCount, 8)
        let ninth = PeerToken()
        XCTAssertFalse(registry.admit(ObjectIdentifier(ninth), peer: DummyPeer(label: 8)))
        XCTAssertEqual(registry.liveCount, 8)

        // Release all reading peers (timeout/reject path); slots free.
        for (token, _) in firstWave {
            let id = ObjectIdentifier(token)
            XCTAssertNotNil(registry.releaseImmediate(id))
            // Double immediate release is a no-op (exactly-once).
            XCTAssertNil(registry.releaseImmediate(id))
        }
        XCTAssertEqual(registry.liveCount, 0)

        let later = PeerToken()
        XCTAssertTrue(registry.admit(ObjectIdentifier(later), peer: DummyPeer(label: 9)))
        XCTAssertEqual(registry.liveCount, 1)

        // Duplicate-ID rejection while still live.
        XCTAssertFalse(registry.admit(ObjectIdentifier(later), peer: DummyPeer(label: 10)))
        XCTAssertEqual(registry.liveCount, 1)

        // beginFinishing: immediate release becomes a no-op; take frees the slot.
        let finishingToken = PeerToken()
        let finishingID = ObjectIdentifier(finishingToken)
        XCTAssertTrue(
            registry.admit(finishingID, peer: DummyPeer(label: 11))
        )
        XCTAssertEqual(registry.phase(of: finishingID), .reading)
        XCTAssertEqual(registry.beginFinishing(finishingID)?.label, 11)
        XCTAssertEqual(registry.phase(of: finishingID), .finishing)
        // Second beginFinishing is rejected (ready/timeout race).
        XCTAssertNil(registry.beginFinishing(finishingID))
        // Immediate release prohibited while finishing (HTTP path owns peer).
        XCTAssertNil(registry.releaseImmediate(finishingID))
        XCTAssertTrue(registry.contains(finishingID))
        XCTAssertEqual(registry.liveCount, 2)
        // Send-completion / force take releases exactly once.
        XCTAssertEqual(registry.take(finishingID)?.label, 11)
        XCTAssertNil(registry.take(finishingID))
        XCTAssertFalse(registry.contains(finishingID))

        // Nine simultaneous admits: only eight succeed.
        var simultaneous = TokenBrokerLoopbackPeerRegistry<DummyPeer>(maxConcurrent: 8)
        let nine = (0..<9).map { index -> (PeerToken, DummyPeer) in
            (PeerToken(), DummyPeer(label: index))
        }
        var admitted = 0
        for (token, peer) in nine {
            if simultaneous.admit(ObjectIdentifier(token), peer: peer) {
                admitted += 1
            }
        }
        XCTAssertEqual(admitted, 8)
        XCTAssertEqual(simultaneous.liveCount, 8)

        // Drain tears down every remaining peer once (session finish).
        let drained = simultaneous.drainAll()
        XCTAssertEqual(drained.count, 8)
        XCTAssertEqual(simultaneous.liveCount, 0)
        XCTAssertTrue(simultaneous.drainAll().isEmpty)
    }

    func testConnectionReadDeadlineIsTwoSeconds() {
        // Production schedules DispatchWorkItem with connectionReadLifetime;
        // pin the constant. No separate pure elapsed helper — deadline expiry
        // is the work-item firing into releaseImmediate on the registry.
        XCTAssertEqual(TokenBrokerAuthorizationSession.connectionReadLifetime, 2)
        XCTAssertEqual(TokenBrokerAuthorizationSession.sessionTimeout, 600)
    }

    func testLoopbackHTTPResponsesArePinnedStaticBytes() {
        let successBody = "Authorization received. Return to the tersa.app window."
        let errorBody = "Authorization rejected. Return to the tersa.app window."
        XCTAssertEqual(successBody.utf8.count, 55)
        XCTAssertEqual(errorBody.utf8.count, 55)

        let expectedSuccess = Data(
            (
                "HTTP/1.1 200 OK\r\n"
                    + "Content-Type: text/plain; charset=utf-8\r\n"
                    + "Content-Length: 55\r\n"
                    + "Connection: close\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "\r\n"
                    + successBody
            ).utf8
        )
        let expectedError = Data(
            (
                "HTTP/1.1 400 Bad Request\r\n"
                    + "Content-Type: text/plain; charset=utf-8\r\n"
                    + "Content-Length: 55\r\n"
                    + "Connection: close\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "\r\n"
                    + errorBody
            ).utf8
        )
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.httpSuccessResponse,
            expectedSuccess
        )
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.httpBadRequestResponse,
            expectedError
        )
        // Pin absolute wire lengths (headers + 55-byte body).
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.httpSuccessResponse.count,
            expectedSuccess.count
        )
        XCTAssertEqual(
            TokenBrokerAuthorizationSession.httpBadRequestResponse.count,
            expectedError.count
        )
        XCTAssertEqual(expectedSuccess.count, 179)
        XCTAssertEqual(expectedError.count, 188)

        let successText = String(
            decoding: TokenBrokerAuthorizationSession.httpSuccessResponse,
            as: UTF8.self
        )
        let errorText = String(
            decoding: TokenBrokerAuthorizationSession.httpBadRequestResponse,
            as: UTF8.self
        )
        // No reflected callback/code and fixed close/no-store discipline.
        XCTAssertFalse(successText.contains("code="))
        XCTAssertFalse(errorText.contains("code="))
        XCTAssertTrue(successText.contains("Connection: close"))
        XCTAssertTrue(errorText.contains("Connection: close"))
        XCTAssertTrue(successText.contains("Cache-Control: no-store"))
        XCTAssertTrue(errorText.contains("Cache-Control: no-store"))
    }

    func testCompletePathCallbackWipeZerosTheSameAllocation() {
        // Calls the exact production helper used by deliverTokenOperation's
        // complete path. Immutable XPC Strings are not zeroizable; this proves
        // only the process-owned byte buffer wipe on the shared allocation.
        let plaintext = Array("callback-secret-code".utf8)
        var addressDuringRead: UInt?
        var snapshotDuringRead: [UInt8] = []
        var addressAfterWipe: UInt?
        var zerosAfterWipe = false

        let simulatedStatus = TokenBrokerOwnedCallbackUTF8.withMutableBufferWipedAfter(
            plaintext,
            body: { buffer -> Int32 in
                if let base = buffer.baseAddress {
                    addressDuringRead = UInt(bitPattern: base)
                    // Simulated const FFI read of uniquely referenced storage.
                    snapshotDuringRead = Array(
                        UnsafeBufferPointer(start: UnsafePointer(base), count: buffer.count)
                    )
                }
                return 0
            },
            afterWipe: { buffer in
                if let base = buffer.baseAddress {
                    addressAfterWipe = UInt(bitPattern: base)
                    zerosAfterWipe = UnsafeBufferPointer(start: base, count: buffer.count)
                        .allSatisfy { $0 == 0 }
                }
            }
        )

        XCTAssertEqual(simulatedStatus, 0)
        XCTAssertEqual(snapshotDuringRead, plaintext)
        XCTAssertNotNil(addressDuringRead)
        XCTAssertEqual(addressDuringRead, addressAfterWipe)
        XCTAssertTrue(zerosAfterWipe)
    }

    func testCompletePathCallbackWipeZerosTheSameAllocationOnThrow() {
        // rethrows must still wipe: a throwing body must not leave plaintext in
        // the process-owned allocation. afterWipe observes the same base.
        enum SentinelError: Error {
            case expected
        }

        let plaintext = Array("callback-secret-code".utf8)
        var addressDuringRead: UInt?
        var snapshotDuringRead: [UInt8] = []
        var addressAfterWipe: UInt?
        var zerosAfterWipe = false
        var observedError: Error?

        do {
            _ = try TokenBrokerOwnedCallbackUTF8.withMutableBufferWipedAfter(
                plaintext,
                body: { buffer -> Int32 in
                    if let base = buffer.baseAddress {
                        addressDuringRead = UInt(bitPattern: base)
                        snapshotDuringRead = Array(
                            UnsafeBufferPointer(start: UnsafePointer(base), count: buffer.count)
                        )
                    }
                    throw SentinelError.expected
                },
                afterWipe: { buffer in
                    if let base = buffer.baseAddress {
                        addressAfterWipe = UInt(bitPattern: base)
                        zerosAfterWipe = UnsafeBufferPointer(start: base, count: buffer.count)
                            .allSatisfy { $0 == 0 }
                    }
                }
            )
            XCTFail("expected SentinelError.expected to propagate")
        } catch {
            observedError = error
        }

        XCTAssertEqual(snapshotDuringRead, plaintext)
        XCTAssertNotNil(addressDuringRead)
        XCTAssertEqual(addressDuringRead, addressAfterWipe)
        XCTAssertTrue(zerosAfterWipe)
        guard let observedError else {
            XCTFail("sentinel error must propagate after wipe")
            return
        }
        XCTAssertTrue(
            observedError is SentinelError,
            "expected SentinelError, got \(observedError)"
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
        // Same clear-then-cancel helper production release() invokes for
        // deadline source, listener, and XPC client.
        var deadlineCancels = 0
        var clientCancels = 0
        var listenerCancels = 0
        var deadlineCancel: (() -> Void)? = { deadlineCancels += 1 }
        var clientCancel: (() -> Void)? = { clientCancels += 1 }
        var listenerCancel: (() -> Void)? = { listenerCancels += 1 }
        TokenBrokerSessionResourceBag.releaseCancelClosures(
            deadlineCancel: &deadlineCancel,
            listenerCancel: &listenerCancel,
            clientCancel: &clientCancel
        )
        XCTAssertEqual(deadlineCancels, 1)
        XCTAssertEqual(clientCancels, 1)
        XCTAssertEqual(listenerCancels, 1)
        XCTAssertNil(deadlineCancel)
        XCTAssertNil(clientCancel)
        XCTAssertNil(listenerCancel)
        // Second release must not double-cancel (exactly-once endpoint teardown).
        TokenBrokerSessionResourceBag.releaseCancelClosures(
            deadlineCancel: &deadlineCancel,
            listenerCancel: &listenerCancel,
            clientCancel: &clientCancel
        )
        XCTAssertEqual(deadlineCancels, 1)
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

    func testBrokerDisconnectSubjectRoutingConvergesCrashRecoveryOnlyForAbsent() {
        // Crash between Rust disconnect finalization and clearing the Swift
        // outer intent journal: on relaunch prepare succeeds, but the prior
        // teardown already purged the broker subject, so the read returns
        // `.absent`. The policy must converge by finalizing directly — never
        // by preserving the outer intent forever. The route carries no
        // payload because it is invariantly revoke-unconfirmed.
        XCTAssertEqual(
            TokenBrokerStatusMapping.brokerDisconnectRouting(for: .absent),
            .finalizeCrashRecovery
        )

        // A transport/storage read failure stays fail-closed: proven absence
        // and failure must never be conflated.
        XCTAssertEqual(
            TokenBrokerStatusMapping.brokerDisconnectRouting(for: .failure),
            .failClosed
        )
        XCTAssertNotEqual(
            TokenBrokerStatusMapping.brokerDisconnectRouting(for: .failure),
            .finalizeCrashRecovery
        )

        // A found subject still routes to the revoke/delete/finalize path.
        XCTAssertEqual(
            TokenBrokerStatusMapping.brokerDisconnectRouting(for: .found("subject")),
            .revokeThenDelete(subject: "subject")
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
