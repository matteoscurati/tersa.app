// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// Fail-closed token-broker service for the packaging skeleton.
///
/// This object exports only `TersaMacTokenBrokerProtocolV1`. It performs no
/// Security.framework, Keychain, network, Rust FFI, or OAuth work. Token
/// authority remains in-process in `TersaMac` until a later ADR-0024 point
/// provisions and activates isolation.
final class TokenBrokerService: NSObject, TersaMacTokenBrokerProtocolV1 {
    func beginAuthorizationSession(
        redirectURI: String,
        withReply reply: @escaping (String?, String?, Int) -> Void
    ) {
        _ = redirectURI
        reply(nil, nil, TersaTokenBrokerStatusV1.notProvisioned.rawValue)
    }

    func completeAuthorizationSession(
        sessionHandle: String,
        callbackURL: String,
        withReply reply: @escaping (String?, String?, Int, Int) -> Void
    ) {
        _ = sessionHandle
        _ = callbackURL
        reply(nil, nil, 0, TersaTokenBrokerStatusV1.notProvisioned.rawValue)
    }

    func refreshAccessToken(
        accountSubject: String,
        withReply reply: @escaping (String?, String?, Int, Int) -> Void
    ) {
        _ = accountSubject
        reply(nil, nil, 0, TersaTokenBrokerStatusV1.notProvisioned.rawValue)
    }

    func revokeProviderGrant(
        accountSubject: String,
        withReply reply: @escaping (Int) -> Void
    ) {
        _ = accountSubject
        reply(TersaTokenBrokerStatusV1.notProvisioned.rawValue)
    }

    func deleteStoredTokens(
        accountSubject: String,
        withReply reply: @escaping (Int) -> Void
    ) {
        _ = accountSubject
        reply(TersaTokenBrokerStatusV1.notProvisioned.rawValue)
    }
}
