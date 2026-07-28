// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit
import Combine
import Foundation

/// Owns the account-connection UI state. Product bootstrap starts only from
/// the reviewed `connect` user-intent entry below; nothing here runs at app
/// launch or view construction time.
///
/// `connect` runs a ladder, never an unconditional OAuth (the connection
/// state is in-memory only, so re-consenting on every launch would open the
/// browser each time): bootstrap the profile, sync with the stored
/// credential, and climb to browser re-consent ONLY when the sync reports
/// `.needsReconnect`.
@MainActor
final class AccountConnectionViewModel: ObservableObject {
    @Published private(set) var state: ConnectionState = .notConnected
    @Published private(set) var connectedAccountIdentifier: Data?
    /// The M2 WARNING banner shown after a disconnect whose provider-side
    /// revoke could not be confirmed — the account may still be authorized at
    /// Google. Separate from the state machine AND from the plain-success
    /// confirmation: its presence MEANS "revoke unconfirmed". A `.succeeded`
    /// disconnect leaves it nil, and it never renders as a failure.
    @Published private(set) var disconnectNotice: String?
    /// The neutral confirmation shown after a CLEAN disconnect (revoke
    /// confirmed): a successful consent withdrawal must be acknowledged, not
    /// announced identically to a cancel. Distinct from `disconnectNotice` so
    /// "notice present ⇒ revoke unconfirmed" stays true.
    @Published private(set) var disconnectConfirmation: String?
    @Published var accountIdentifier: String = ""

    private let syncWorker = MailboxSyncWorker()

    /// The M2 warning copy for a disconnect that returned
    /// `.succeededRevokeUnconfirmed`: fact → what we can't confirm → the
    /// actionable remedy (the banner pairs it with a link to Google's
    /// connections page). One voice ("Tersa").
    private static let revokeUnconfirmedNotice = "Disconnected on this Mac. Tersa couldn't confirm that Google revoked its access — open your Google Account and remove Tersa to be sure."
    /// The clean-disconnect confirmation copy.
    private static let disconnectConfirmed = "Disconnected. Tersa's access to your Google Account was removed and mail stored on this Mac was deleted."
    /// Where the M2 banner sends the user to revoke access themselves.
    static let googleConnectionsURL = URL(string: "https://myaccount.google.com/connections")!

    /// The OAuth client id handed to the sync and connect begins: the SAME
    /// `TersaOAuthClientID` Info.plist key `OAuthAuthorizationSession` reads,
    /// so the client_id↔grant pairing holds by construction — no second,
    /// unchecked path.
    private static var oauthClientID: String {
        Bundle.main.object(forInfoDictionaryKey: "TersaOAuthClientID") as? String ?? ""
    }

    var isConnectDisabled: Bool {
        accountIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// The single reviewed user-intent entry into product bootstrap, and the
    /// first ladder rung: bootstrap the profile, then sync with the stored
    /// credential. A non-ready bootstrap surfaces as its mapped failure —
    /// never as a browser re-consent.
    func connect() {
        let trimmedIdentifier = accountIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedIdentifier.isEmpty,
              state != .connecting,
              state != .authorizing,
              state != .disconnecting
        else {
            return
        }
        // A new connect supersedes any prior disconnect banner: a revoke-
        // unconfirmed warning or a clean-disconnect confirmation is stale the
        // moment the user reconnects (and the warning's "remove Tersa from
        // Google" advice would break the connection they are making now).
        disconnectNotice = nil
        disconnectConfirmation = nil
        state = .connecting
        let accountIdentifierData = Data(trimmedIdentifier.utf8)
        let completion: @MainActor (ProductBootstrapStatus) -> Void = { [weak self] status in
            guard let self else {
                return
            }
            guard status == .ready else {
                self.state = ConnectionState(status: status)
                return
            }
            self.syncWithStoredCredential(accountIdentifier: accountIdentifierData)
        }
        (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(
            accountIdentifier: accountIdentifierData,
            completion: completion
        )
    }

    /// Returns to the not-connected state and re-runs the whole ladder; a
    /// stored token lets the sync rung succeed without re-consent.
    func retry() {
        state = .notConnected
        connect()
    }

    /// Routes a failure's retry. A failed DISCONNECT must re-issue the
    /// disconnect — the Rust account slot stays fenced against sync and
    /// connect until a disconnect converges, so re-running the connect ladder
    /// would dead-loop — while every other failure retries the ladder.
    func retryAfterFailure(_ failure: ConnectionFailure) {
        if failure == .disconnectIncomplete {
            state = .notConnected
            disconnect()
        } else {
            retry()
        }
    }

    /// Disconnects the connected account (consent withdrawal + local
    /// teardown). Any in-flight OAuth is cancelled FIRST and unconditionally:
    /// a pending grant landing within the bridge's authorization lifetime
    /// after a successful disconnect would silently re-connect the account,
    /// and the disconnect cannot tombstone it.
    func disconnect() {
        (NSApp.delegate as? AppDelegate)?.oauthAuthorizationSession.cancel()
        guard let accountIdentifier = connectedAccountIdentifier, state != .disconnecting else {
            return
        }
        // This disconnect earns its own banner: clear any prior one before we
        // start, so a stale warning can never render over a new teardown.
        disconnectNotice = nil
        disconnectConfirmation = nil
        state = .disconnecting
        syncWorker.beginDisconnect(accountIdentifier: accountIdentifier) { [weak self] status in
            guard let self else {
                return
            }
            switch status {
            case .succeeded:
                self.state = .notConnected
                self.disconnectConfirmation = Self.disconnectConfirmed
                self.connectedAccountIdentifier = nil
            case .succeededRevokeUnconfirmed:
                self.state = .notConnected
                self.disconnectNotice = Self.revokeUnconfirmedNotice
                self.connectedAccountIdentifier = nil
            case .cancelled, .gateBlocked, .syncFailed, .internalError, .needsReconnect,
                 .unknownSession, .unrecognized, .running:
                // Fail closed: the fence stays set in Rust until a disconnect
                // converges, so this failure's retry re-issues the DISCONNECT
                // (see retryAfterFailure) rather than the connect ladder. The
                // worker coalesces a busy disconnect-begin onto the running
                // teardown; the UI never re-issues in a loop.
                self.state = .failed(.disconnectIncomplete)
            }
        }
    }

    /// Cancels the in-flight browser sign-in; the session delivers
    /// `.cancelled`, landing the ladder back at not-connected.
    func cancelAuthorization() {
        guard state == .authorizing else {
            return
        }
        (NSApp.delegate as? AppDelegate)?.oauthAuthorizationSession.cancel()
    }

    /// Dismisses the disconnect banner (the M2 revoke warning or the clean
    /// confirmation — only one is shown at a time).
    func dismissDisconnectNotice() {
        disconnectNotice = nil
        disconnectConfirmation = nil
    }

    /// The second rung: sync with the STORED credential. ONLY a
    /// `.needsReconnect` climbs to browser re-consent (the stored credential
    /// is gone or never existed); a network or gate problem maps straight to
    /// a failure and never re-prompts OAuth.
    private func syncWithStoredCredential(accountIdentifier: Data) {
        syncWorker.beginSync(
            clientID: Self.oauthClientID,
            accountIdentifier: accountIdentifier
        ) { [weak self] status in
            guard let self else {
                return
            }
            switch status {
            case .succeeded, .succeededRevokeUnconfirmed:
                self.connectedAccountIdentifier = accountIdentifier
                self.state = .connected
            case .needsReconnect:
                self.authorizeAndConnect(accountIdentifier: accountIdentifier)
            case .cancelled:
                // A disconnect dropped the in-flight sync; land neutral —
                // not a failure, and never rendered as "disconnected".
                self.state = .notConnected
            case .gateBlocked, .syncFailed, .internalError, .unknownSession, .unrecognized,
                 .running:
                self.state = .failed(Self.terminalFailure(status))
            }
        }
    }

    /// The third rung: re-consent in the browser. The state moves to
    /// `.authorizing` only once the session actually started (its Cancel
    /// affordance targets that session); a pre-flight refusal is the
    /// missing-configuration failure.
    private func authorizeAndConnect(accountIdentifier: Data) {
        guard let session = (NSApp.delegate as? AppDelegate)?.oauthAuthorizationSession else {
            state = .failed(.signInUnavailable)
            return
        }
        let started = session.start { [weak self] outcome in
            guard let self else {
                return
            }
            switch outcome {
            case .succeeded(let oauthSession):
                self.state = .connecting
                self.connectWithGrant(accountIdentifier: accountIdentifier, oauthSession: oauthSession)
            case .cancelled:
                // Sign-in cancelled: land neutral — not a failure, and a
                // cancelled re-connect never renders as "disconnected".
                self.state = .notConnected
            case .failed:
                self.state = .failed(.signInFailed)
            }
        }
        guard started else {
            // A PRE-FLIGHT refusal — the sign-in page never opened (missing/
            // unconfigured client id, a session already in flight, or the
            // browser wouldn't open the URL). NOT a browser sign-in failure.
            state = .failed(.signInUnavailable)
            return
        }
        state = .authorizing
    }

    /// The final rung: claim the finished OAuth grant with a connect-begin. A
    /// `.needsReconnect` here means the grant lapsed between consent and
    /// claim — the sign-in expired — so it surfaces as a failure and never
    /// loops back into another browser prompt.
    private func connectWithGrant(accountIdentifier: Data, oauthSession: OAuthSessionID) {
        syncWorker.beginConnect(
            accountIdentifier: accountIdentifier,
            oauthSession: oauthSession
        ) { [weak self] status in
            guard let self else {
                return
            }
            switch status {
            case .succeeded, .succeededRevokeUnconfirmed:
                self.connectedAccountIdentifier = accountIdentifier
                self.state = .connected
            case .needsReconnect:
                self.state = .failed(.signInExpired)
            case .cancelled:
                self.state = .notConnected
            case .gateBlocked, .syncFailed, .internalError, .unknownSession, .unrecognized,
                 .running:
                self.state = .failed(Self.terminalFailure(status))
            }
        }
    }

    /// Maps a terminal poll that can never climb to OAuth to its failure:
    /// gate contention is transient, everything else is a plain failure. The
    /// worker only ever delivers terminals, so a `.running` here is
    /// coalesced fail-closed rather than trusted.
    private static func terminalFailure(_ status: MailboxPollStatus) -> ConnectionFailure {
        status == .gateBlocked ? .busyOrUnavailable : .unavailable
    }
}
