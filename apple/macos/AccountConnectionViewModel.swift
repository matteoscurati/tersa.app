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
    /// A finished browser authorization may arrive while Chrome is still the
    /// foreground app. `WhenUnlockedThisDeviceOnly` Data Protection Keychain
    /// operations can then fail with `errSecInteractionNotAllowed`; retain the
    /// one activation handoff until AppKit confirms Tersa is active, and only
    /// then let the Rust connect worker claim and persist the grant.
    private var activationPending = false
    private var activationObserver: NSObjectProtocol?
    private var activationTimeout: Timer?

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
    /// so the client_id↔grant pairing holds by construction. `connect()` applies
    /// the SAME empty/`UNCONFIGURED` pre-flight `start()` does, so a bad id fails
    /// fast with the configuration message rather than surfacing downstream as a
    /// misleading "unavailable".
    private static var oauthClientID: String {
        Bundle.main.object(forInfoDictionaryKey: "TersaOAuthClientID") as? String ?? ""
    }

    /// Mirrors `OAuthAuthorizationSession.start()`'s pre-flight: an empty or
    /// still-`UNCONFIGURED` client id cannot drive the sync/connect begins.
    private static var oauthClientIDIsUsable: Bool {
        let id = oauthClientID
        return !id.isEmpty && id.range(of: "UNCONFIGURED", options: .caseInsensitive) == nil
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
        // Fail fast on a missing/unconfigured client id with the config-specific
        // message, rather than letting a bad id reach the sync rung and surface
        // as a misleading permanent "unavailable".
        guard Self.oauthClientIDIsUsable else {
            state = .failed(.signInUnavailable)
            return
        }
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
        // Only a genuine failure retries. `retry()`/`disconnect()` reset the
        // state, so without this a double-tap before the failure view is
        // dismissed would slip a SECOND concurrent ladder past their re-entry
        // guards; the second tap now sees a non-failed state and no-ops.
        guard case .failed = state else {
            return
        }
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
                // (see retryAfterFailure) rather than the connect ladder. Only
                // one disconnect is ever in flight: `disconnect()`'s
                // `state != .disconnecting` guard and `retryAfterFailure`'s
                // `case .failed` guard keep the UI single-issue, so the worker's
                // second-slot behavior is never exercised from here.
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
            case .syncFailed:
                // A returning user reaches their locally-synced inbox even when
                // the network refresh can't complete (the offline case: the
                // stored-credential refresh dies with a transport error ->
                // SYNC_FAILED, never reaching the gate). Safe on THIS rung not
                // because the gate passed — SYNC_FAILED means the gate did not
                // BLOCK, which includes it never running — but because the
                // mailbox store only ever holds the last-COMMITTED identity's
                // data: writes happen solely through the post-gate SyncCoordinator,
                // and a mismatched re-consent clears the store (ClearAndRecord).
                // The pre-gate SYNC_FAILED sub-cases here (refresh transport,
                // setup, session) mutate nothing, so they show last-verified
                // data. No NEW identity can be introduced on this rung (it uses
                // the STORED credential); the fresh-consent handoff lives on the
                // connect rung, which deliberately does NOT land connected here.
                self.connectedAccountIdentifier = accountIdentifier
                self.state = .connected
            case .needsReconnect:
                self.authorizeAndConnect(accountIdentifier: accountIdentifier)
            case .cancelled:
                // A disconnect dropped the in-flight sync; land neutral —
                // not a failure, and never rendered as "disconnected".
                self.state = .notConnected
            case .gateBlocked, .internalError, .unknownSession, .unrecognized,
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
                self.connectAfterApplicationActivation(
                    accountIdentifier: accountIdentifier,
                    oauthSession: oauthSession
                )
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

    /// Returns focus from the browser before the connect worker touches the
    /// `WhenUnlockedThisDeviceOnly` refresh-token item. Registering the
    /// activation observer before `activate()` closes the synchronous-notice
    /// race; the post-activate `isActive` check closes the opposite race.
    private func connectAfterApplicationActivation(
        accountIdentifier: Data,
        oauthSession: OAuthSessionID
    ) {
        guard !activationPending else {
            _ = tersa_oauth_cancel(oauthSession.rawValue)
            state = .failed(.unavailable)
            return
        }
        activationPending = true

        if NSApp.isActive {
            finishApplicationActivation(
                accountIdentifier: accountIdentifier,
                oauthSession: oauthSession
            )
            return
        }

        activationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: NSApp,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.finishApplicationActivation(
                    accountIdentifier: accountIdentifier,
                    oauthSession: oauthSession
                )
            }
        }
        activationTimeout = Timer.scheduledTimer(withTimeInterval: 5, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.activationPending else {
                    return
                }
                self.clearApplicationActivation()
                _ = tersa_oauth_cancel(oauthSession.rawValue)
                self.state = .failed(.unavailable)
            }
        }
        NSApp.activate()
        if NSApp.isActive {
            finishApplicationActivation(
                accountIdentifier: accountIdentifier,
                oauthSession: oauthSession
            )
        }
    }

    /// Delivers the finished grant exactly once after AppKit confirms Tersa is
    /// foreground-active. Clearing observer/timer state before the worker begins
    /// makes a duplicate activation notification harmless.
    private func finishApplicationActivation(
        accountIdentifier: Data,
        oauthSession: OAuthSessionID
    ) {
        guard activationPending else {
            return
        }
        clearApplicationActivation()
        guard state == .connecting else {
            _ = tersa_oauth_cancel(oauthSession.rawValue)
            return
        }
        connectWithGrant(accountIdentifier: accountIdentifier, oauthSession: oauthSession)
    }

    private func clearApplicationActivation() {
        activationPending = false
        if let activationObserver {
            NotificationCenter.default.removeObserver(activationObserver)
        }
        activationObserver = nil
        activationTimeout?.invalidate()
        activationTimeout = nil
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
                // On the CONNECT rung, .syncFailed must NOT land connected: after
                // a fresh browser consent, SYNC_FAILED covers pre-gate failures
                // (a bad exchange, an UNVERIFIED id_token, no token stored) where
                // the gate never ran — landing connected would show the PREVIOUS
                // identity's cached mailbox to the newly-consenting one, defeating
                // the identity gate at the account-handoff moment. Recovery is
                // one tap: retry() -> the stored-credential rung, which is where a
                // genuinely-stored token gets the gate. (The offline regression is
                // fully fixed on that rung; this rung is unreachable offline.)
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
