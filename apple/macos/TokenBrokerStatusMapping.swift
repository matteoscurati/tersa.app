// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// Closed result of the broker routing subject read. The subject is the
/// account-identifying BROKER ROUTING value — never an OAuth credential and
/// never mailbox content — and is never logged or displayed. A raw status of
/// zero with a malformed payload (a length outside 1...255 or invalid UTF-8)
/// is `.failure`, never `.absent`: `.absent` is reserved for the FFI's
/// explicit no-subject-stored code (-6).
enum BrokerSubjectReadResult: Equatable {
    /// A stored subject was read and validated.
    case found(String)
    /// No subject is stored for the account (raw status -6).
    case absent
    /// Any other status, or a malformed success payload.
    case failure
}

/// Operation-aware mapping from closed broker statuses into existing UI recovery.
///
/// Preserves ADR-0024 recovery invariants:
/// - `authorizationCodeRejected` → `signInExpired` (never ordinary provider
///   rejection, never consent revoked, never claims a stored credential was
///   deleted).
/// - `insufficientScope` keeps Gmail-specific recovery and exposes the manual
///   Google Account permissions action because the under-scoped grant cannot
///   be revoked in-app.
/// - `consentRevoked` / `missingRefreshToken` route to reconnect.
/// - `persistenceFailed` while loading during revoke is unconfirmed revoke;
///   during delete it is incomplete local teardown and never looks clean.
///
/// Also owns the disconnect-ladder routing for the post-prepare broker
/// subject read (`brokerDisconnectRouting`), including the crash-recovery
/// convergence for a proven-absent subject.
enum TokenBrokerStatusMapping {
    /// Where the insufficient-scope recovery sends the user to revoke a
    /// stranded first-connect grant manually. Safe, stable, non-secret URL.
    static let googleAccountPermissionsURL = URL(
        string: "https://myaccount.google.com/permissions"
    )!

    /// Closed UI recovery after a broker terminal. Distinct cases keep the
    /// four end-to-end recovery semantics from collapsing.
    enum Recovery: Equatable, Sendable {
        case succeeded
        case signInExpired
        case providerRejected
        case permissionRequired(manualRevokeURL: URL)
        case needsReconnect
        case revokeUnconfirmed
        case incompleteLocalTeardown
        case invalidRequest
        case unavailable
        case busy
        case sessionUnknown
        case transport
        case malformedResponse
        case identityUnverified
        case identityMismatch
        case rejectedClient
        case notImplemented
        case notProvisioned
        case invalidConfiguration
        case failed
    }

    /// Maps a validated broker status for a known operation.
    static func recovery(
        for status: TokenBrokerStatus,
        operation: TokenBrokerOperation
    ) -> Recovery {
        switch status {
        case .success:
            return .succeeded
        case .authorizationCodeRejected:
            // Exchange-time code rejection: sign-in lapsed. Never provider
            // rejection, never consent revoked, never a deletion claim.
            return .signInExpired
        case .providerRejected:
            return .providerRejected
        case .insufficientScope:
            return .permissionRequired(manualRevokeURL: googleAccountPermissionsURL)
        case .missingRefreshToken, .consentRevoked:
            return .needsReconnect
        case .revokeUnconfirmed:
            return .revokeUnconfirmed
        case .persistenceFailed:
            return persistenceRecovery(for: operation)
        case .invalidRequest:
            return .invalidRequest
        case .invalidConfiguration:
            return .invalidConfiguration
        case .unavailable:
            return .unavailable
        case .busy:
            return .busy
        case .sessionUnknown:
            return .sessionUnknown
        case .transport:
            return .transport
        case .malformedResponse:
            return .malformedResponse
        case .identityUnverified:
            return .identityUnverified
        case .identityMismatch:
            return .identityMismatch
        case .rejectedClient:
            return .rejectedClient
        case .notImplemented:
            return .notImplemented
        case .notProvisioned:
            return .notProvisioned
        }
    }

    /// Routing for the broker disconnect ladder once the Rust prepare has
    /// succeeded and the broker routing subject read has completed.
    enum BrokerDisconnectRouting: Equatable, Sendable {
        /// A stored subject exists: run the revoke → delete → finalize path.
        case revokeThenDelete(subject: String)
        /// The subject is proven ABSENT while the durable outer intent still
        /// stands: a previous run finalized the Rust teardown (which purges
        /// the subject) but crashed before the Swift outer intent journal was
        /// cleared. Converge by finalizing directly — Rust finalization is
        /// idempotent and its poll terminal clears the outer intent through
        /// the existing terminal handling. This route carries no payload
        /// because it is invariantly revoke-unconfirmed: the crashed run's
        /// provider-revoke outcome is unknowable, so the unconfirmed-revoke
        /// warning must show.
        case finalizeCrashRecovery
        /// The subject read FAILED (transport/storage): fail closed as
        /// `.disconnectIncomplete`; a read failure is never conflated with
        /// proven absence.
        case failClosed
    }

    /// Maps the disconnect-time broker subject read into the ladder routing.
    /// Only `.absent` (the FFI's explicit no-subject-stored code) converges;
    /// `.failure` stays fail-closed so a wedged intent is re-issued by the
    /// retry path rather than silently finalized.
    static func brokerDisconnectRouting(
        for result: BrokerSubjectReadResult
    ) -> BrokerDisconnectRouting {
        switch result {
        case .found(let subject):
            return .revokeThenDelete(subject: subject)
        case .absent:
            return .finalizeCrashRecovery
        case .failure:
            return .failClosed
        }
    }

    /// Maps a client transport/shape failure into recovery without inventing
    /// an open error channel.
    static func recovery(for error: TokenBrokerClientError, operation: TokenBrokerOperation) -> Recovery {
        switch error {
        case .status(let status):
            return recovery(for: status, operation: operation)
        case .malformedReply:
            return .malformedResponse
        case .interrupted, .invalidated:
            return .unavailable
        case .rejectedPeer:
            return .rejectedClient
        }
    }

    /// Maps a recovery into the existing closed `ConnectionFailure` set where
    /// a direct correspondence exists. Returns nil for success.
    static func connectionFailure(for recovery: Recovery) -> ConnectionFailure? {
        switch recovery {
        case .succeeded:
            return nil
        case .signInExpired:
            return .signInExpired
        case .providerRejected, .transport, .malformedResponse, .failed:
            return .signInFailed
        case .permissionRequired:
            return .permissionRequired
        case .needsReconnect:
            return .signInExpired
        case .revokeUnconfirmed:
            // Disconnect ladder (point 4) owns presentation of unconfirmed
            // revoke; authorization-session mapping surfaces it as failed
            // sign-in rather than a clean outcome.
            return .signInFailed
        case .incompleteLocalTeardown:
            return .disconnectIncomplete
        case .invalidRequest, .invalidConfiguration, .rejectedClient, .notImplemented, .notProvisioned:
            return .signInUnavailable
        case .unavailable, .busy, .sessionUnknown, .identityUnverified, .identityMismatch:
            return .unavailable
        }
    }

    private static func persistenceRecovery(for operation: TokenBrokerOperation) -> Recovery {
        switch operation {
        case .revokeProviderGrant:
            // PersistenceFailed while loading during revoke: revoke is
            // unconfirmed; the caller must still be able to attempt local delete.
            return .revokeUnconfirmed
        case .deleteStoredTokens:
            // PersistenceFailed from delete: incomplete local teardown; never
            // looks clean.
            return .incompleteLocalTeardown
        case .beginAuthorization, .completeAuthorization, .refreshAccessToken:
            return .unavailable
        }
    }
}
