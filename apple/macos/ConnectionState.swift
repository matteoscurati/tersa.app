// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Closed product-bootstrap status integers shared with the Rust bridge.
enum ProductBootstrapStatus: Int32 {
    case ready = 0
    case invalidAccountIdentifier = 1
    case invalidExecutionContext = 2
    case busyOrUnavailable = 3
    case rootMissingWithExistingProfile = 4
    case unavailable = 5
}

/// A non-ready account-connection outcome, phrased for the person using the
/// app. Carries no internal identifiers and no secrets.
enum ConnectionFailure: Equatable {
    case invalidAccountIdentifier
    case invalidExecutionContext
    case busyOrUnavailable
    case rootMissingWithExistingProfile
    case unavailable
    /// The stored grant could not be claimed even right after a successful
    /// re-consent: the sign-in itself lapsed.
    case signInExpired
    /// The browser sign-in flow started but did not complete.
    case signInFailed
    /// A PRE-FLIGHT refusal: the sign-in page never opened (missing/
    /// unconfigured client id, a session already running, or no browser). NOT
    /// a browser sign-in failure — a different remedy applies.
    case signInUnavailable
    /// Google sign-in completed without granting Gmail read access.
    ///
    /// The first-connect under-scoped grant can be stranded at Google and
    /// cannot be revoked in-app (ADR-0024). UI recovery must offer
    /// retain-or-retry and a safe link to Google Account permissions
    /// (`TokenBrokerStatusMapping.googleAccountPermissionsURL`).
    case permissionRequired
    /// A connect or stored-credential sync did not complete within its bounded
    /// client-side deadline. The non-cancellable original callback remains
    /// authoritative and prevents a second begin.
    case connectionTimedOut
    /// The browser authorization did not return within its bounded deadline.
    case authorizationTimedOut
    /// Disconnect has exceeded its presentation deadline. Rust teardown keeps
    /// running and its late terminal remains authoritative.
    case disconnectTimedOut
    /// The durable local account lifecycle projection could not be read. The
    /// connect ladder must not proceed without knowing whether teardown is due.
    case accountStateUnavailable
    /// The disconnect teardown did not converge; the Rust slot stays fenced
    /// against sync and connect until a disconnect does. Its retry re-issues
    /// the disconnect, never the connect ladder.
    case disconnectIncomplete

    var message: String {
        switch self {
        case .invalidAccountIdentifier:
            return "That account identifier is not valid. Check it and try again."
        case .invalidExecutionContext:
            return "The app could not prepare a secure place for the account. Restart the app and try again."
        case .busyOrUnavailable:
            return "The account service is busy. Try again in a moment."
        case .rootMissingWithExistingProfile:
            return "The existing profile cannot be unlocked on this Mac. Reinstall the app only after contacting support."
        case .unavailable:
            return "The account service is unavailable. Try again later."
        case .signInExpired:
            return "Your sign-in expired. Sign in again."
        case .signInFailed:
            return "The sign-in didn't complete. Sign in again."
        case .signInUnavailable:
            return "Tersa couldn't open the sign-in page in your browser. Check that a default browser is set, then try again."
        case .permissionRequired:
            return "Gmail read access wasn't granted. Sign in again and allow Tersa to read your email — or open your Google Account permissions to remove Tersa if this Mac should not keep access."
        case .connectionTimedOut:
            return "Connection is still finishing. Keep Tersa open; it will update when complete."
        case .authorizationTimedOut:
            return "Sign-in took too long. Return to Tersa and sign in again."
        case .disconnectTimedOut:
            return "Disconnect is still finishing. Keep Tersa open; it will confirm when access and local mail are removed."
        case .accountStateUnavailable:
            return "Tersa couldn't verify this account's local recovery state. Try again before connecting."
        case .disconnectIncomplete:
            return "Tersa couldn't finish disconnecting. This account stays unavailable until it does. Try again — or remove Tersa from your Google Account to revoke its access now."
        }
    }

    /// The failure's operation-aware headline, shared by the failure view and
    /// its VoiceOver value so the two never drift.
    var title: String {
        switch self {
        case .connectionTimedOut:
            return "Connection delayed"
        case .disconnectIncomplete:
            return "Disconnect failed"
        case .disconnectTimedOut:
            return "Disconnect delayed"
        case .accountStateUnavailable:
            return "Account unavailable"
        default:
            return "Connection failed"
        }
    }
}

/// The closed set of account-connection states the UI can render.
enum ConnectionState: Equatable {
    case notConnected
    case connecting
    /// The OAuth consent page is open in the browser; the user can cancel it.
    case authorizing
    case connected
    case disconnecting
    case failed(ConnectionFailure)

    init(status: ProductBootstrapStatus) {
        switch status {
        case .ready:
            self = .connected
        case .invalidAccountIdentifier:
            self = .failed(.invalidAccountIdentifier)
        case .invalidExecutionContext:
            self = .failed(.invalidExecutionContext)
        case .busyOrUnavailable:
            self = .failed(.busyOrUnavailable)
        case .rootMissingWithExistingProfile:
            self = .failed(.rootMissingWithExistingProfile)
        case .unavailable:
            self = .failed(.unavailable)
        }
    }

    /// Short state text exposed to assistive technologies as a value.
    var accessibilityValue: String {
        switch self {
        case .notConnected:
            return "Not connected"
        case .connecting:
            return "Connecting"
        case .authorizing:
            return "Waiting for sign-in"
        case .connected:
            return "Connected"
        case .disconnecting:
            return "Disconnecting"
        case .failed(let failure):
            return failure.title
        }
    }

    /// Spoken text announced on every state transition.
    var announcement: String {
        switch self {
        case .notConnected:
            return "Not connected"
        case .connecting:
            return "Connecting account"
        case .authorizing:
            return "Sign-in opened in the browser"
        case .connected:
            return "Account connected"
        case .disconnecting:
            return "Disconnecting account"
        case .failed(let failure):
            return failure.message
        }
    }
}
