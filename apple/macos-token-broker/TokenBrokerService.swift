// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// Operational token-broker service for ADR-0024 point 3.
///
/// Exports only `TersaMacTokenBrokerProtocolV1` and forwards each operation to
/// the dedicated Rust static archive. Input limits and loopback constraints are
/// re-validated at the Rust service boundary. No generic RPC, no Keychain
/// calls from Swift, and no secret-bearing logging.
///
/// All Rust FFI work runs on a single serial queue so the process-owned
/// current-thread broker runtime is never driven from the XPC listener thread
/// and concurrent connections cannot overlap broker mutation unsafely.
final class TokenBrokerService: NSObject, TersaMacTokenBrokerProtocolV1 {
    private static let maxRedirectURIBytes = 256
    private static let maxCallbackURLBytes = 4_096
    private static let maxSessionHandleBytes = 64
    private static let maxSubjectBytes = 255
    private static let maxAuthorizationURLBytes = 4_096
    private static let maxAccessTokenBytes = 4_096

    /// Serializes every broker FFI call for the process. Distinct from the XPC
    /// listener queue: replies may complete from this queue without blocking
    /// connection acceptance.
    private static let workQueue = DispatchQueue(
        label: "app.tersa.mac.token-broker.service",
        qos: .userInitiated
    )

    func beginAuthorizationSession(
        redirectURI: String,
        withReply reply: @escaping @Sendable (String?, String?, Int) -> Void
    ) {
        let redirectBytes = Array(redirectURI.utf8)
        guard !redirectBytes.isEmpty,
              redirectBytes.count <= Self.maxRedirectURIBytes
        else {
            reply(nil, nil, TersaTokenBrokerStatusV1.invalidRequest.rawValue)
            return
        }

        Self.workQueue.async {
            var authorizationURLBytes = [UInt8](repeating: 0, count: Self.maxAuthorizationURLBytes)
            var authorizationURLLength = 0
            var sessionHandleBytes = [UInt8](repeating: 0, count: Self.maxSessionHandleBytes)
            var sessionHandleLength = 0
            defer {
                authorizationURLBytes.withUnsafeMutableBufferPointer { buffer in
                    buffer.initialize(repeating: 0)
                }
                sessionHandleBytes.withUnsafeMutableBufferPointer { buffer in
                    buffer.initialize(repeating: 0)
                }
            }

            let status = redirectBytes.withUnsafeBufferPointer { redirectBuffer in
                authorizationURLBytes.withUnsafeMutableBufferPointer { urlBuffer in
                    sessionHandleBytes.withUnsafeMutableBufferPointer { handleBuffer in
                        tersa_token_broker_begin_authorization(
                            redirectBuffer.baseAddress,
                            redirectBuffer.count,
                            urlBuffer.baseAddress,
                            urlBuffer.count,
                            &authorizationURLLength,
                            handleBuffer.baseAddress,
                            handleBuffer.count,
                            &sessionHandleLength
                        )
                    }
                }
            }

            guard status == TersaTokenBrokerStatusV1.success.rawValue,
                  authorizationURLLength > 0,
                  authorizationURLLength <= authorizationURLBytes.count,
                  sessionHandleLength > 0,
                  sessionHandleLength <= sessionHandleBytes.count
            else {
                // FFI success with an invalid payload shape is not success on
                // the wire; preserve every non-success FFI status as-is.
                let wireStatus =
                    status == TersaTokenBrokerStatusV1.success.rawValue
                    ? TersaTokenBrokerStatusV1.malformedResponse.rawValue
                    : Int(status)
                reply(nil, nil, wireStatus)
                return
            }

            let authorizationURL = String(
                decoding: authorizationURLBytes.prefix(authorizationURLLength),
                as: UTF8.self
            )
            let sessionHandle = String(
                decoding: sessionHandleBytes.prefix(sessionHandleLength),
                as: UTF8.self
            )
            reply(authorizationURL, sessionHandle, TersaTokenBrokerStatusV1.success.rawValue)
        }
    }

    func completeAuthorizationSession(
        sessionHandle: String,
        callbackURL: String,
        withReply reply: @escaping @Sendable (String?, String?, Int, Int) -> Void
    ) {
        let handleBytes = Array(sessionHandle.utf8)
        let callbackBytes = Array(callbackURL.utf8)
        guard !handleBytes.isEmpty,
              handleBytes.count <= Self.maxSessionHandleBytes,
              !callbackBytes.isEmpty,
              callbackBytes.count <= Self.maxCallbackURLBytes
        else {
            reply(nil, nil, 0, TersaTokenBrokerStatusV1.invalidRequest.rawValue)
            return
        }

        deliverTokenOperation(
            subjectOrHandle: handleBytes,
            secondary: callbackBytes,
            isComplete: true,
            reply: reply
        )
    }

    func refreshAccessToken(
        accountSubject: String,
        withReply reply: @escaping @Sendable (String?, String?, Int, Int) -> Void
    ) {
        let subjectBytes = Array(accountSubject.utf8)
        guard !subjectBytes.isEmpty,
              subjectBytes.count <= Self.maxSubjectBytes
        else {
            reply(nil, nil, 0, TersaTokenBrokerStatusV1.invalidRequest.rawValue)
            return
        }

        deliverTokenOperation(
            subjectOrHandle: subjectBytes,
            secondary: [],
            isComplete: false,
            reply: reply
        )
    }

    func revokeProviderGrant(
        accountSubject: String,
        withReply reply: @escaping @Sendable (Int) -> Void
    ) {
        let subjectBytes = Array(accountSubject.utf8)
        guard !subjectBytes.isEmpty,
              subjectBytes.count <= Self.maxSubjectBytes
        else {
            reply(TersaTokenBrokerStatusV1.invalidRequest.rawValue)
            return
        }
        Self.workQueue.async {
            let status = subjectBytes.withUnsafeBufferPointer { buffer in
                tersa_token_broker_revoke_provider_grant(buffer.baseAddress, buffer.count)
            }
            reply(Int(status))
        }
    }

    func deleteStoredTokens(
        accountSubject: String,
        withReply reply: @escaping @Sendable (Int) -> Void
    ) {
        let subjectBytes = Array(accountSubject.utf8)
        guard !subjectBytes.isEmpty,
              subjectBytes.count <= Self.maxSubjectBytes
        else {
            reply(TersaTokenBrokerStatusV1.invalidRequest.rawValue)
            return
        }
        Self.workQueue.async {
            let status = subjectBytes.withUnsafeBufferPointer { buffer in
                tersa_token_broker_delete_stored_tokens(buffer.baseAddress, buffer.count)
            }
            reply(Int(status))
        }
    }

    private func deliverTokenOperation(
        subjectOrHandle: [UInt8],
        secondary: [UInt8],
        isComplete: Bool,
        reply: @escaping @Sendable (String?, String?, Int, Int) -> Void
    ) {
        Self.workQueue.async {
            // Mutable copy so the complete path can zero the callback/code
            // bytes after the FFI call. Refresh passes an empty secondary and
            // does not need that wipe. Immutable Swift `String` values received
            // over XPC cannot be zeroized; this UTF-8 buffer is the
            // secret-bearing copy this process owns for the FFI call.
            //
            // The complete path uniquely references this storage via
            // `withUnsafeMutableBufferPointer` before the FFI read so the
            // defer wipe zeros the same allocation the FFI observed (COW-
            // safe). Do not use the immutable buffer view for that read.
            var secondaryBytes = secondary
            var accessTokenBytes = [UInt8](repeating: 0, count: Self.maxAccessTokenBytes)
            var accessTokenLength = 0
            var subjectBytes = [UInt8](repeating: 0, count: Self.maxSubjectBytes)
            var subjectLength = 0
            var expiresInSeconds: Int64 = 0
            defer {
                accessTokenBytes.withUnsafeMutableBufferPointer { buffer in
                    buffer.initialize(repeating: 0)
                }
                subjectBytes.withUnsafeMutableBufferPointer { buffer in
                    buffer.initialize(repeating: 0)
                }
                if isComplete {
                    secondaryBytes.withUnsafeMutableBufferPointer { buffer in
                        buffer.initialize(repeating: 0)
                    }
                }
            }

            let status: Int32 = subjectOrHandle.withUnsafeBufferPointer { primaryBuffer in
                accessTokenBytes.withUnsafeMutableBufferPointer { tokenBuffer in
                    subjectBytes.withUnsafeMutableBufferPointer { subjectBuffer in
                        if isComplete {
                            return secondaryBytes.withUnsafeMutableBufferPointer { callbackBuffer in
                                // Pass the uniquely referenced storage as a
                                // read-only pointer; no second plaintext copy.
                                let callbackPointer = callbackBuffer.baseAddress
                                    .map { UnsafePointer($0) }
                                return tersa_token_broker_complete_authorization(
                                    primaryBuffer.baseAddress,
                                    primaryBuffer.count,
                                    callbackPointer,
                                    callbackBuffer.count,
                                    tokenBuffer.baseAddress,
                                    tokenBuffer.count,
                                    &accessTokenLength,
                                    subjectBuffer.baseAddress,
                                    subjectBuffer.count,
                                    &subjectLength,
                                    &expiresInSeconds
                                )
                            }
                        }
                        return tersa_token_broker_refresh_access_token(
                            primaryBuffer.baseAddress,
                            primaryBuffer.count,
                            tokenBuffer.baseAddress,
                            tokenBuffer.count,
                            &accessTokenLength,
                            subjectBuffer.baseAddress,
                            subjectBuffer.count,
                            &subjectLength,
                            &expiresInSeconds
                        )
                    }
                }
            }

            guard status == TersaTokenBrokerStatusV1.success.rawValue,
                  accessTokenLength > 0,
                  accessTokenLength <= accessTokenBytes.count,
                  subjectLength > 0,
                  subjectLength <= subjectBytes.count,
                  expiresInSeconds > 0,
                  expiresInSeconds <= 86_400
            else {
                // FFI success with an invalid payload shape is not success on
                // the wire; preserve every non-success FFI status as-is.
                let wireStatus =
                    status == TersaTokenBrokerStatusV1.success.rawValue
                    ? TersaTokenBrokerStatusV1.malformedResponse.rawValue
                    : Int(status)
                reply(nil, nil, 0, wireStatus)
                return
            }

            let accessToken = String(
                decoding: accessTokenBytes.prefix(accessTokenLength),
                as: UTF8.self
            )
            let subject = String(
                decoding: subjectBytes.prefix(subjectLength),
                as: UTF8.self
            )
            reply(
                accessToken,
                subject,
                Int(expiresInSeconds),
                TersaTokenBrokerStatusV1.success.rawValue
            )
        }
    }

    /// Testable complete-path wipe invariant.
    ///
    /// Uniquely references a mutable UTF-8 buffer, performs a simulated const
    /// FFI read of that storage, zeros the same allocation, and returns whether
    /// the buffer the read observed is all zeros afterward (same address when
    /// storage is stable). Immutable XPC `String` values are not zeroizable;
    /// this models only the process-owned callback byte buffer.
    static func completePathCallbackWipeLeavesZeros(_ plaintext: [UInt8]) -> Bool {
        var secondaryBytes = plaintext
        var addressDuringRead: UInt?
        var lengthDuringRead = 0
        var snapshotDuringRead: [UInt8] = []

        // Uniquely reference before the simulated const FFI read.
        secondaryBytes.withUnsafeMutableBufferPointer { buffer in
            if let base = buffer.baseAddress {
                addressDuringRead = UInt(bitPattern: base)
                lengthDuringRead = buffer.count
                let constView = UnsafePointer(base)
                snapshotDuringRead = Array(
                    UnsafeBufferPointer(start: constView, count: buffer.count)
                )
            }
        }

        guard snapshotDuringRead == plaintext, lengthDuringRead == plaintext.count else {
            return false
        }

        // Defer-style wipe of the same uniquely referenced allocation.
        var wipedSameAddress = false
        secondaryBytes.withUnsafeMutableBufferPointer { buffer in
            buffer.initialize(repeating: 0)
            if let base = buffer.baseAddress,
               UInt(bitPattern: base) == addressDuringRead,
               buffer.count == lengthDuringRead
            {
                wipedSameAddress = UnsafeBufferPointer(start: base, count: buffer.count)
                    .allSatisfy { $0 == 0 }
            }
        }

        guard secondaryBytes.allSatisfy({ $0 == 0 }),
              secondaryBytes.count == plaintext.count
        else {
            return false
        }
        return wipedSameAddress
    }
}
