// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// A non-ready product bootstrap outcome, phrased for the person using the
/// app. Carries no internal identifiers and no secrets.
enum ConnectionFailure: Equatable {
    case invalidAccountIdentifier
    case invalidExecutionContext
    case busyOrUnavailable
    case rootMissingWithExistingProfile
    case unavailable

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
        }
    }
}

/// The closed set of account-connection states the UI can render.
enum ConnectionState: Equatable {
    case notConnected
    case connecting
    case connected
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
        case .connected:
            return "Connected"
        case .failed:
            return "Connection failed"
        }
    }

    /// Spoken text announced on every state transition.
    var announcement: String {
        switch self {
        case .notConnected:
            return "Not connected"
        case .connecting:
            return "Connecting account"
        case .connected:
            return "Account connected"
        case .failed(let failure):
            return failure.message
        }
    }
}
