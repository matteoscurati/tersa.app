// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// Client-side mirror of the closed version-1 token-broker wire status set.
///
/// Integer values must match the service and Rust FFI exactly. No open-ended
/// string or dictionary error channel exists.
enum TokenBrokerStatus: Int, Equatable, Sendable {
    case success = 0
    case notImplemented = 1
    case notProvisioned = 2
    case invalidRequest = 3
    case rejectedClient = 4
    case authorizationCodeRejected = 5
    case providerRejected = 6
    case insufficientScope = 7
    case missingRefreshToken = 8
    case consentRevoked = 9
    case revokeUnconfirmed = 10
    case persistenceFailed = 11
    case invalidConfiguration = 12
    case unavailable = 13
    case busy = 14
    case sessionUnknown = 15
    case transport = 16
    case malformedResponse = 17
    case identityUnverified = 18
    case identityMismatch = 19

    /// Validates a raw XPC status integer against the closed set.
    static func validated(_ raw: Int) -> TokenBrokerStatus? {
        TokenBrokerStatus(rawValue: raw)
    }
}

/// The five closed protocol operations. Mapping is operation-aware so a single
/// wire `persistenceFailed` retains distinct recovery by call site.
enum TokenBrokerOperation: Equatable, Sendable {
    case beginAuthorization
    case completeAuthorization
    case refreshAccessToken
    case revokeProviderGrant
    case deleteStoredTokens
}

/// Client-side Objective-C protocol matching the embedded XPC service.
///
/// Declared only so the main app can configure `NSXPCInterface` against the
/// exact v1 surface. Parameter labels and reply shapes must stay byte-identical
/// to the service declaration.
@objc(TersaMacTokenBrokerProtocolV1)
protocol TersaMacTokenBrokerProtocolV1 {
    func beginAuthorizationSession(
        redirectURI: String,
        withReply reply: @escaping (_ authorizationURL: String?, _ sessionHandle: String?, _ status: Int) -> Void
    )

    func completeAuthorizationSession(
        sessionHandle: String,
        callbackURL: String,
        withReply reply: @escaping (
            _ accessToken: String?,
            _ subject: String?,
            _ expiresInSeconds: Int,
            _ status: Int
        ) -> Void
    )

    func refreshAccessToken(
        accountSubject: String,
        withReply reply: @escaping (
            _ accessToken: String?,
            _ subject: String?,
            _ expiresInSeconds: Int,
            _ status: Int
        ) -> Void
    )

    func revokeProviderGrant(
        accountSubject: String,
        withReply reply: @escaping (_ status: Int) -> Void
    )

    func deleteStoredTokens(
        accountSubject: String,
        withReply reply: @escaping (_ status: Int) -> Void
    )
}
