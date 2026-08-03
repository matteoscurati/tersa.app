// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// Bounded status codes for the version-1 token-broker protocol.
///
/// Closed operational set (ADR-0024 point 3). Integer values are stable wire
/// contracts shared with the Rust FFI; no strings, dictionaries, or generic
/// error payloads ever ride this enum.
@objc
enum TersaTokenBrokerStatusV1: Int {
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
}

/// Explicit wire version for the closed NSXPC protocol surface.
///
/// Always `1` while the exported interface is
/// `TersaMacTokenBrokerProtocolV1`. A version bump requires a new versioned
/// Objective-C protocol name and inventory review; it must not widen this
/// surface in place.
enum TersaMacTokenBrokerProtocolVersion {
    static let value: Int = 1
}

/// Closed, versioned NSXPC protocol for the macOS token broker (ADR-0024).
///
/// Allowed operations match only the broker's planned authority: begin and
/// complete authorization, refresh a short-lived access token, provider
/// revoke, and local token deletion. The protocol never carries refresh
/// tokens, PKCE verifiers, generic `Data` RPC bodies, or arbitrary Keychain
/// commands.
@objc(TersaMacTokenBrokerProtocolV1)
protocol TersaMacTokenBrokerProtocolV1 {
    /// Starts an authorization session for the supplied redirect URI.
    ///
    /// On success the broker returns only the provider authorization URL
    /// and an opaque session handle. The PKCE verifier remains broker-local.
    func beginAuthorizationSession(
        redirectURI: String,
        withReply reply: @escaping @Sendable (_ authorizationURL: String?, _ sessionHandle: String?, _ status: Int) -> Void
    )

    /// Completes an authorization session after the main app forwards the
    /// callback URL. A success reply may carry only the short-lived access
    /// token, validated subject, and expiry; never a refresh token.
    func completeAuthorizationSession(
        sessionHandle: String,
        callbackURL: String,
        withReply reply: @escaping @Sendable (
            _ accessToken: String?,
            _ subject: String?,
            _ expiresInSeconds: Int,
            _ status: Int
        ) -> Void
    )

    /// Refreshes a short-lived access token for the given account subject.
    /// A success reply may carry only the access token, subject, and expiry.
    func refreshAccessToken(
        accountSubject: String,
        withReply reply: @escaping @Sendable (
            _ accessToken: String?,
            _ subject: String?,
            _ expiresInSeconds: Int,
            _ status: Int
        ) -> Void
    )

    /// Asks the broker to revoke the provider grant for the account subject.
    func revokeProviderGrant(
        accountSubject: String,
        withReply reply: @escaping @Sendable (_ status: Int) -> Void
    )

    /// Asks the broker to delete locally stored refresh-token material for the
    /// account subject. Token bytes never cross this interface.
    func deleteStoredTokens(
        accountSubject: String,
        withReply reply: @escaping @Sendable (_ status: Int) -> Void
    )
}
