// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import XCTest

/// Deterministic exactly-once / fail-closed shape tests for client reply mapping.
///
/// Does not open a live XPC connection or perform network/Keychain work.
/// Live connection lifecycle is owner-driven: callers must invoke `cancel()`
/// (or an owning-session finish path) explicitly; there is no `deinit` cleanup.
final class TokenBrokerClientOnceTests: XCTestCase {
    func testServiceBundleIdentifierIsExactEmbeddedBroker() {
        XCTAssertEqual(
            TokenBrokerClient.serviceBundleIdentifier,
            "app.tersa.mac.token-broker"
        )
    }

    func testSuccessfulBeginReplyShape() {
        let result = TokenBrokerClient.mapBeginReply(
            authorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
            sessionHandle: "ABCDEFGHIJKLMNOPQRSTUV",
            status: TokenBrokerStatus.success.rawValue
        )
        switch result {
        case .success(let pending):
            XCTAssertEqual(
                pending.authorizationURL.absoluteString,
                "https://accounts.google.com/o/oauth2/v2/auth"
            )
            XCTAssertEqual(pending.sessionHandle, "ABCDEFGHIJKLMNOPQRSTUV")
        case .failure:
            XCTFail("valid begin reply must succeed")
        }
    }

    func testSuccessfulTokenReplyShape() {
        let result = TokenBrokerClient.mapTokenReply(
            accessToken: "access-token-fixture",
            subject: "110169484474386276334",
            expiresInSeconds: 3600,
            status: TokenBrokerStatus.success.rawValue
        )
        switch result {
        case .success(let token):
            XCTAssertEqual(token.expiresInSeconds, 3600)
            XCTAssertFalse(token.accessToken.isEmpty)
            XCTAssertFalse(token.subject.isEmpty)
        case .failure:
            XCTFail("valid token reply must succeed")
        }
    }

    func testNonSuccessStatusNeverReturnsSuccessPayload() {
        let statuses: [TokenBrokerStatus] = [
            .authorizationCodeRejected,
            .providerRejected,
            .insufficientScope,
            .missingRefreshToken,
            .consentRevoked,
            .revokeUnconfirmed,
            .persistenceFailed,
            .unavailable,
            .busy,
            .sessionUnknown,
            .transport,
            .malformedResponse,
            .identityUnverified,
            .identityMismatch,
            .rejectedClient,
            .invalidRequest,
            .invalidConfiguration,
            .notImplemented,
            .notProvisioned,
        ]
        for status in statuses {
            let begin = TokenBrokerClient.mapBeginReply(
                authorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
                sessionHandle: "ABCDEFGHIJKLMNOPQRSTUV",
                status: status.rawValue
            )
            if case .success = begin {
                XCTFail("non-success status \(status.rawValue) must not succeed begin")
            }
            let token = TokenBrokerClient.mapTokenReply(
                accessToken: "access-token-fixture",
                subject: "110169484474386276334",
                expiresInSeconds: 3600,
                status: status.rawValue
            )
            if case .success = token {
                XCTFail("non-success status \(status.rawValue) must not succeed token")
            }
        }
    }

    func testAuthorizationURLValidationAcceptsOnlyExactGoogleHTTPS() {
        let accepted = URL(string: "https://accounts.google.com/o/oauth2/v2/auth")!
        XCTAssertTrue(TokenBrokerClient.isAcceptedAuthorizationURL(accepted))

        let rejected: [String] = [
            "http://accounts.google.com/o/oauth2/v2/auth",
            "file:///tmp/oauth.html",
            "tersa://oauth/callback",
            "https://evil.example/accounts.google.com",
            "https://accounts.google.com.evil/o/oauth2/v2/auth",
            "https://attacker.accounts.google.com/o/oauth2/v2/auth",
            "https://accounts.google.com.attacker/path",
        ]
        for raw in rejected {
            let url = URL(string: raw)!
            XCTAssertFalse(
                TokenBrokerClient.isAcceptedAuthorizationURL(url),
                "must reject \(raw)"
            )
            let mapped = TokenBrokerClient.mapBeginReply(
                authorizationURL: raw,
                sessionHandle: "ABCDEFGHIJKLMNOPQRSTUV",
                status: TokenBrokerStatus.success.rawValue
            )
            if case .success = mapped {
                XCTFail("mapBeginReply must reject unauthorized URL \(raw)")
            }
        }

        let good = TokenBrokerClient.mapBeginReply(
            authorizationURL: "https://accounts.google.com/o/oauth2/v2/auth?client_id=public",
            sessionHandle: "ABCDEFGHIJKLMNOPQRSTUV",
            status: TokenBrokerStatus.success.rawValue
        )
        if case .failure = good {
            XCTFail("expected Google HTTPS authorization URL must succeed")
        }
    }
}
