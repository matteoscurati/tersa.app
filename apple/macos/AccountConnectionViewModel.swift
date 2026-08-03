// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit
import Combine
import Foundation

/// Owns the account-connection UI state. Product bootstrap starts only from
/// the reviewed `connect` user-intent entry below. Launch performs only a
/// content-free lifecycle read for the last opaque local account alias so a
/// durable disconnect warning survives relaunch; it never starts OAuth or sync.
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
    /// Aggregate freshness only; no mailbox content or provider identity is
    /// retained in the Swift presentation state.
    @Published private(set) var mailboxFreshness: MailboxFreshnessState = .unknown
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
    private let operationDeadline = ConnectionOperationDeadline()
    private let disconnectIntentStore = DisconnectIntentStore()
    private var operationTimer: Timer?
    private static let connectAndSyncTimeout: TimeInterval = 45
    private static let authorizationTimeout: TimeInterval = 5 * 60
    private static let disconnectTimeout: TimeInterval = 45
    private static let lastAccountIdentifierKey = "TersaLastAccountIdentifier"
    /// A finished browser authorization may arrive while Chrome is still the
    /// foreground app. `WhenUnlockedThisDeviceOnly` Data Protection Keychain
    /// operations can then fail with `errSecInteractionNotAllowed`; retain the
    /// one activation handoff until AppKit confirms Tersa is active, and only
    /// then let the Rust connect worker claim and persist the grant.
    private var activationPending = false
    private var activationObserver: NSObjectProtocol?
    private var activationTimeout: Timer?
    private var didRestorePersistedLifecycle = false
    private var launchLifecycleRestoreFence = MailboxLifecycleRestoreFence()
    /// The single token-broker client this view model currently owns, or nil.
    /// Ownership is exclusive: a client is installed only while this is nil and
    /// is released (cleared here, then cancelled exactly once) by the same path
    /// that ends its operation. A completion arriving after release finds this
    /// nil — or a DIFFERENT instance — and must not touch the slot, so a late
    /// terminal can never cancel a replacement client. MainActor-confined like
    /// every property on this class, so install/finish/cancel are race-free.
    private var activeTokenBrokerClient: TokenBrokerClient?

    /// The M2 warning copy for a disconnect that returned
    /// `.succeededRevokeUnconfirmed`: fact → what we can't confirm → the
    /// actionable remedy (the banner pairs it with a link to Google's
    /// connections page). One voice ("Tersa").
    private static let revokeUnconfirmedNotice = "Disconnected on this Mac. Tersa couldn't confirm that Google revoked its access — open your Google Account and remove Tersa to be sure."
    /// The clean-disconnect confirmation copy.
    private static let disconnectConfirmed = "Disconnected. Tersa's access to your Google Account was removed and mail stored on this Mac was deleted."
    /// Where the M2 banner sends the user to revoke access themselves.
    static let googleConnectionsURL = URL(string: "https://myaccount.google.com/connections")!

    /// Restores the content-free lifecycle projection once when the root view
    /// appears. Keeping this separate from initialization preserves the
    /// source-enforced rule that construction never enters product bootstrap.
    func restorePersistedLifecycleOnLaunch() {
        guard !didRestorePersistedLifecycle else {
            return
        }
        didRestorePersistedLifecycle = true
        if let pendingIdentifier = disconnectIntentStore.pendingAccountIdentifier() {
            let pendingAccount = Data(pendingIdentifier.utf8)
            accountIdentifier = pendingIdentifier
            connectedAccountIdentifier = pendingAccount
            state = .failed(.disconnectIncomplete)
            return
        }
        guard let savedIdentifier = UserDefaults.standard.string(
            forKey: Self.lastAccountIdentifierKey
        ), !savedIdentifier.isEmpty else {
            return
        }
        accountIdentifier = savedIdentifier
        let savedAccount = Data(savedIdentifier.utf8)
        let restoreToken = launchLifecycleRestoreFence.begin(accountIdentifier: savedAccount)
        restorePersistedLifecycle(
            accountIdentifier: savedAccount,
            restoreToken: restoreToken
        )
    }

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

    /// Starts a monotonic deadline and replaces any previous UI-only deadline.
    /// The underlying Rust worker is not cancelled by this replacement; its
    /// callback is generation-fenced by `operationDeadline` below.
    private func beginOperation(
        _ kind: ConnectionOperationKind,
        timeout: TimeInterval
    ) -> ConnectionOperationToken {
        operationTimer?.invalidate()
        let token = operationDeadline.start(kind: kind, timeout: timeout)
        operationTimer = Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.handleOperationTimeout(token)
            }
        }
        return token
    }

    private func finishOperation(_ token: ConnectionOperationToken) -> Bool {
        guard operationDeadline.finish(token) else {
            return false
        }
        operationTimer?.invalidate()
        operationTimer = nil
        return true
    }

    private func renewTimedOutOperation(
        _ kind: ConnectionOperationKind,
        timeout: TimeInterval,
        state renewedState: ConnectionState
    ) {
        guard let token = operationDeadline.renewTimedOut(kind: kind, timeout: timeout) else {
            return
        }
        operationTimer?.invalidate()
        operationTimer = Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.handleOperationTimeout(token)
            }
        }
        state = renewedState
    }

    /// A normal timeout invalidates its callback generation. Disconnect is the
    /// exception: its Rust teardown has already begun, so the late terminal is
    /// still allowed to settle the UI and no connect may start in between.
    private func handleOperationTimeout(_ token: ConnectionOperationToken) {
        switch token.kind {
        case .connectAndSync:
            guard operationDeadline.timeOut(token, keepAlive: true) else { return }
            operationTimer = nil
            state = .failed(.connectionTimedOut)
        case .authorization:
            guard operationDeadline.timeOut(token, keepAlive: false) else { return }
            operationTimer = nil
            (NSApp.delegate as? AppDelegate)?.oauthAuthorizationSession.cancel()
            state = .failed(.authorizationTimedOut)
        case .disconnect:
            guard operationDeadline.timeOut(token, keepAlive: true) else { return }
            operationTimer = nil
            state = .failed(.disconnectTimedOut)
        }
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
              state != .disconnecting,
              !operationDeadline.hasActiveOperation
        else {
            return
        }
        launchLifecycleRestoreFence.invalidate()
        // A new connect supersedes only a clean-disconnect confirmation. A
        // durable revoke-unconfirmed warning remains visible until the next
        // disconnect converges or the user dismisses it explicitly.
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
        let token = beginOperation(.connectAndSync, timeout: Self.connectAndSyncTimeout)
        let completion: @MainActor (ProductBootstrapStatus) -> Void = { [weak self] status in
            guard let self else {
                return
            }
            guard self.operationDeadline.accepts(token) else {
                return
            }
            guard status == .ready else {
                _ = self.finishOperation(token)
                self.state = ConnectionState(status: status)
                return
            }
            UserDefaults.standard.set(trimmedIdentifier, forKey: Self.lastAccountIdentifierKey)
            self.inspectLifecycleBeforeSync(
                accountIdentifier: accountIdentifierData,
                token: token
            )
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
    /// would dead-loop. A timed-out non-cancellable operation only returns to
    /// progress while its original terminal remains authoritative; other
    /// failures retry the ladder.
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
        } else if failure == .connectionTimedOut, operationDeadline.connectIsActive {
            // Token exchange, credential persistence, or bounded sync may
            // already be in flight and cannot be abandoned safely. Re-enter
            // progress without issuing a second begin; its terminal remains
            // authoritative.
            renewTimedOutOperation(
                .connectAndSync,
                timeout: Self.connectAndSyncTimeout,
                state: .connecting
            )
        } else if failure == .disconnectTimedOut, operationDeadline.disconnectIsActive {
            // The destructive worker is still live. Re-enter progress without
            // issuing a second begin; its late terminal remains authoritative.
            renewTimedOutOperation(
                .disconnect,
                timeout: Self.disconnectTimeout,
                state: .disconnecting
            )
        } else {
            retry()
        }
    }

    /// Disconnects the connected account (consent withdrawal + local
    /// teardown). Any in-flight OAuth is cancelled FIRST and unconditionally:
    /// a pending grant landing within the bridge's authorization lifetime
    /// after a successful disconnect would silently re-connect the account.
    /// The content-free outer intent journal is durably verified before the
    /// destructive Rust begin and cleared only after a successful terminal.
    func disconnect() {
        (NSApp.delegate as? AppDelegate)?.oauthAuthorizationSession.cancel()
        guard let accountIdentifier = connectedAccountIdentifier, state != .disconnecting else {
            return
        }
        guard let pendingIdentifier = String(data: accountIdentifier, encoding: .utf8),
              disconnectIntentStore.markPending(accountIdentifier: pendingIdentifier)
        else {
            state = .failed(.disconnectIncomplete)
            return
        }
        // This disconnect earns its own banner: clear any prior one before we
        // start, so a stale warning can never render over a new teardown.
        disconnectNotice = nil
        disconnectConfirmation = nil
        state = .disconnecting
        let token = beginOperation(.disconnect, timeout: Self.disconnectTimeout)
        syncWorker.beginDisconnect(accountIdentifier: accountIdentifier) { [weak self] status in
            guard let self else {
                return
            }
            guard self.operationDeadline.accepts(token) else {
                return
            }
            _ = self.finishOperation(token)
            switch status {
            case .succeeded:
                guard self.disconnectIntentStore.clearPending() else {
                    self.state = .failed(.disconnectIncomplete)
                    return
                }
                self.state = .notConnected
                self.disconnectConfirmation = Self.disconnectConfirmed
                self.connectedAccountIdentifier = nil
                self.mailboxFreshness = .unknown
                UserDefaults.standard.removeObject(forKey: Self.lastAccountIdentifierKey)
            case .succeededRevokeUnconfirmed:
                guard self.disconnectIntentStore.clearPending() else {
                    self.state = .failed(.disconnectIncomplete)
                    return
                }
                self.state = .notConnected
                self.disconnectNotice = Self.revokeUnconfirmedNotice
                self.connectedAccountIdentifier = nil
            case .cancelled, .gateBlocked, .syncFailed, .internalError, .needsReconnect,
                 .permissionRequired, .unknownSession, .unrecognized, .running:
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

    /// The second rung: sync with the STORED credential through the token
    /// broker. Reads the account's broker routing subject from local account
    /// state without opening a mailbox store; ONLY `.absent` (no subject
    /// persisted — the stored credential is gone or never existed) climbs to
    /// browser re-consent; a local subject read failure maps straight to
    /// `.accountStateUnavailable` and never re-prompts OAuth; a found subject
    /// hands the SAME operation to the broker refresh ladder.
    private func syncWithStoredCredential(
        accountIdentifier: Data,
        token: ConnectionOperationToken
    ) {
        syncWorker.readBrokerSubject(accountIdentifier: accountIdentifier) { [weak self] result in
            guard let self, self.operationDeadline.accepts(token) else {
                return
            }
            switch result {
            case .absent:
                _ = self.finishOperation(token)
                self.authorizeAndConnect(accountIdentifier: accountIdentifier)
            case .failure:
                _ = self.finishOperation(token)
                self.state = .failed(.accountStateUnavailable)
            case .found(let subject):
                self.refreshStoredBrokerCredential(
                    subject: subject,
                    accountIdentifier: accountIdentifier,
                    token: token
                )
            }
        }
    }

    /// The broker-backed stored-credential rung: refresh the STORED grant
    /// through the one broker client this view model owns, then feed the
    /// returned access token into the broker sync. Only a `.needsReconnect`
    /// climbs to browser re-consent; a transport failure lands connected
    /// offline (the same offline semantics as the stored-credential rung's
    /// SYNC_FAILED); every other failure maps to its closed connection
    /// failure and never re-prompts OAuth.
    private func refreshStoredBrokerCredential(
        subject: String,
        accountIdentifier: Data,
        token: ConnectionOperationToken
    ) {
        guard let client = installTokenBrokerClient() else {
            // A broker client is already active: fail closed as busy rather
            // than racing a second refresh against the owned one.
            _ = finishOperation(token)
            state = .failed(.busyOrUnavailable)
            return
        }
        client.refreshAccessToken(accountSubject: subject) { [weak self] result in
            Task { @MainActor in
                guard let self else {
                    // The owner is gone, so no finish path can release the
                    // client; cancel the captured instance directly, exactly
                    // once (the completion fires at most once).
                    client.cancel()
                    return
                }
                // Releases the client exactly once; a stale completion from an
                // already-released client observes a foreign/empty slot and
                // must not touch the state.
                guard self.finishTokenBrokerClient(client) else {
                    return
                }
                guard self.operationDeadline.accepts(token) else {
                    return
                }
                switch result {
                case .success(let refreshedToken):
                    // The refreshed grant must still belong to the STORED
                    // identity; a mismatched subject must never feed another
                    // identity's access token into the sync.
                    guard refreshedToken.subject == subject else {
                        _ = self.finishOperation(token)
                        self.state = .failed(.unavailable)
                        return
                    }
                    self.syncWorker.beginBrokerSync(
                        accountIdentifier: accountIdentifier,
                        token: refreshedToken
                    ) { [weak self] status in
                        guard let self, self.operationDeadline.accepts(token) else {
                            return
                        }
                        self.finishStoredBrokerSync(
                            status: status,
                            accountIdentifier: accountIdentifier,
                            token: token
                        )
                    }
                case .failure(let error):
                    let recovery = TokenBrokerStatusMapping.recovery(
                        for: error,
                        operation: .refreshAccessToken
                    )
                    switch recovery {
                    case .needsReconnect:
                        // The stored grant is gone or revoked: climb the ladder.
                        _ = self.finishOperation(token)
                        self.authorizeAndConnect(accountIdentifier: accountIdentifier)
                    case .permissionRequired:
                        _ = self.finishOperation(token)
                        self.state = .failed(.permissionRequired)
                    case .transport:
                        // The refresh died in transit; land connected on the
                        // last-committed mailbox, offline — the stored-credential
                        // rung's SYNC_FAILED semantics.
                        self.completeConnected(
                            accountIdentifier: accountIdentifier,
                            token: token,
                            offline: true
                        )
                    default:
                        _ = self.finishOperation(token)
                        self.state = .failed(
                            TokenBrokerStatusMapping.connectionFailure(for: recovery) ?? .unavailable
                        )
                    }
                }
            }
        }
    }

    /// The terminal mapping for a broker sync begun from
    /// `refreshStoredBrokerCredential`: identical to the stored-credential
    /// rung's poll-terminal semantics. The deadline must already have been
    /// checked by the caller.
    private func finishStoredBrokerSync(
        status: MailboxPollStatus,
        accountIdentifier: Data,
        token: ConnectionOperationToken
    ) {
        switch status {
        case .succeeded, .succeededRevokeUnconfirmed:
            completeConnected(
                accountIdentifier: accountIdentifier,
                token: token,
                offline: false
            )
        case .syncFailed:
            // Offline case, as on the stored-credential rung: the gate did not
            // BLOCK, and the mailbox store only ever holds the last-COMMITTED
            // identity's data, so last-verified data may be shown.
            completeConnected(
                accountIdentifier: accountIdentifier,
                token: token,
                offline: true
            )
        case .needsReconnect, .permissionRequired:
            _ = finishOperation(token)
            authorizeAndConnect(accountIdentifier: accountIdentifier)
        case .cancelled:
            // A disconnect dropped the in-flight sync; land neutral.
            _ = finishOperation(token)
            state = .notConnected
        case .gateBlocked, .internalError, .unknownSession, .unrecognized,
             .running:
            _ = finishOperation(token)
            state = .failed(Self.terminalFailure(status))
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
        let token = beginOperation(.authorization, timeout: Self.authorizationTimeout)
        let started = session.start { [weak self] outcome in
            guard let self else {
                return
            }
            guard self.operationDeadline.accepts(token) else {
                return
            }
            switch outcome {
            case .succeeded(let oauthSession):
                _ = self.finishOperation(token)
                self.state = .connecting
                let connectToken = self.beginOperation(.connectAndSync, timeout: Self.connectAndSyncTimeout)
                self.connectAfterApplicationActivation(
                    accountIdentifier: accountIdentifier,
                    oauthSession: oauthSession,
                    token: connectToken
                )
            case .cancelled:
                // Sign-in cancelled: land neutral — not a failure, and a
                // cancelled re-connect never renders as "disconnected".
                _ = self.finishOperation(token)
                self.state = .notConnected
            case .permissionRequired:
                _ = self.finishOperation(token)
                self.state = .failed(.permissionRequired)
            case .failed:
                _ = self.finishOperation(token)
                self.state = .failed(.signInFailed)
            }
        }
        guard started else {
            // A PRE-FLIGHT refusal — the sign-in page never opened (missing/
            // unconfigured client id, a session already in flight, or the
            // browser wouldn't open the URL). NOT a browser sign-in failure.
            _ = finishOperation(token)
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
        oauthSession: OAuthSessionID,
        token: ConnectionOperationToken
    ) {
        guard operationDeadline.accepts(token), !activationPending else {
            _ = tersa_oauth_cancel(oauthSession.rawValue)
            if operationDeadline.accepts(token) {
                _ = finishOperation(token)
                state = .failed(.unavailable)
            }
            return
        }
        activationPending = true

        if NSApp.isActive {
            finishApplicationActivation(
                accountIdentifier: accountIdentifier,
                oauthSession: oauthSession,
                token: token
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
                    oauthSession: oauthSession,
                    token: token
                )
            }
        }
        activationTimeout = Timer.scheduledTimer(withTimeInterval: 5, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.activationPending else {
                    return
                }
                self.clearApplicationActivation()
                guard self.operationDeadline.accepts(token) else {
                    _ = tersa_oauth_cancel(oauthSession.rawValue)
                    return
                }
                _ = tersa_oauth_cancel(oauthSession.rawValue)
                _ = self.finishOperation(token)
                self.state = .failed(.unavailable)
            }
        }
        NSApp.activate()
        if NSApp.isActive {
            finishApplicationActivation(
                accountIdentifier: accountIdentifier,
                oauthSession: oauthSession,
                token: token
            )
        }
    }

    /// Delivers the finished grant exactly once after AppKit confirms Tersa is
    /// foreground-active. Clearing observer/timer state before the worker begins
    /// makes a duplicate activation notification harmless.
    private func finishApplicationActivation(
        accountIdentifier: Data,
        oauthSession: OAuthSessionID,
        token: ConnectionOperationToken
    ) {
        guard activationPending else {
            return
        }
        guard operationDeadline.accepts(token) else {
            clearApplicationActivation()
            _ = tersa_oauth_cancel(oauthSession.rawValue)
            return
        }
        clearApplicationActivation()
        guard state == .connecting else {
            _ = tersa_oauth_cancel(oauthSession.rawValue)
            return
        }
        connectWithGrant(accountIdentifier: accountIdentifier, oauthSession: oauthSession, token: token)
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

    /// The broker-grant twin of `connectAfterApplicationActivation`: after
    /// browser consent, Tersa must be foreground-active before
    /// `storeBrokerSubject` opens the root/store Keychain/SQLCipher state —
    /// the same `WhenUnlockedThisDeviceOnly` interaction constraint the
    /// legacy grant claim sequences around. The observer-before-`activate()`
    /// ordering and the post-activate `isActive` check mirror the legacy
    /// sequencing and close the same two races on the SAME shared
    /// activationPending/observer/timer state. Every failure path here
    /// cleans up through `cleanupFreshBrokerGrant` — the legacy OAuth FFI is
    /// never touched on this rung.
    private func connectBrokerGrantAfterApplicationActivation(
        accountIdentifier: Data,
        brokerToken: TokenBrokerAccessToken,
        token: ConnectionOperationToken
    ) {
        guard operationDeadline.accepts(token), !activationPending else {
            cleanupFreshBrokerGrant(subject: brokerToken.subject, token: token)
            return
        }
        activationPending = true

        if NSApp.isActive {
            finishBrokerGrantApplicationActivation(
                accountIdentifier: accountIdentifier,
                brokerToken: brokerToken,
                token: token
            )
            return
        }

        activationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: NSApp,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.finishBrokerGrantApplicationActivation(
                    accountIdentifier: accountIdentifier,
                    brokerToken: brokerToken,
                    token: token
                )
            }
        }
        activationTimeout = Timer.scheduledTimer(withTimeInterval: 5, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.activationPending else {
                    return
                }
                self.clearApplicationActivation()
                // The cleanup must run even when the operation went stale
                // waiting for activation: the broker grant still exists and
                // must not be orphaned by a deadline that lapsed first.
                self.cleanupFreshBrokerGrant(subject: brokerToken.subject, token: token)
            }
        }
        NSApp.activate()
        if NSApp.isActive {
            finishBrokerGrantApplicationActivation(
                accountIdentifier: accountIdentifier,
                brokerToken: brokerToken,
                token: token
            )
        }
    }

    /// Delivers the freshly-consented broker grant exactly once after AppKit
    /// confirms Tersa is foreground-active: persist the account's routing
    /// subject, then feed the access token into the broker sync. Clearing
    /// observer/timer state before the worker begins makes a duplicate
    /// activation notification harmless. A subject may remain locally if the
    /// operation goes stale just after a successful persist; the cleanup
    /// still deletes the broker-stored tokens, and the next
    /// stored-credential refresh safely routes the missing token to
    /// re-consent.
    private func finishBrokerGrantApplicationActivation(
        accountIdentifier: Data,
        brokerToken: TokenBrokerAccessToken,
        token: ConnectionOperationToken
    ) {
        guard activationPending else {
            return
        }
        guard operationDeadline.accepts(token) else {
            clearApplicationActivation()
            cleanupFreshBrokerGrant(subject: brokerToken.subject, token: token)
            return
        }
        clearApplicationActivation()
        guard state == .connecting else {
            cleanupFreshBrokerGrant(subject: brokerToken.subject, token: token)
            return
        }
        syncWorker.storeBrokerSubject(
            accountIdentifier: accountIdentifier,
            subject: brokerToken.subject
        ) { [weak self] persisted in
            guard let self else {
                return
            }
            guard self.operationDeadline.accepts(token), persisted else {
                self.cleanupFreshBrokerGrant(subject: brokerToken.subject, token: token)
                return
            }
            self.connectWithBrokerGrant(
                accountIdentifier: accountIdentifier,
                brokerToken: brokerToken,
                token: token
            )
        }
    }

    /// Installs a new token-broker client as the one this view model owns.
    /// Returns nil WITHOUT constructing when one is already active, so a
    /// re-entrant begin can never leak a second client or orphan the first.
    /// The caller owns the returned instance only through this property: it
    /// must be released via `finishTokenBrokerClient(_:)` or
    /// `cancelActiveTokenBrokerClient()`, never cancelled directly.
    private func installTokenBrokerClient() -> TokenBrokerClient? {
        guard activeTokenBrokerClient == nil else {
            return nil
        }
        let client = TokenBrokerClient()
        activeTokenBrokerClient = client
        return client
    }

    /// Releases `client` if it is STILL the active instance: clears the
    /// property first, then cancels exactly once, and returns true. Returns
    /// false — and never cancels — when the slot is empty or holds a different
    /// instance, so a late completion from an already-released client cannot
    /// cancel its successor. Clearing before `cancel()` keeps the exact-once
    /// guarantee even if `cancel()`'s invalidation reenters this actor: the
    /// reentrant path observes a nil slot and takes the false branch.
    private func finishTokenBrokerClient(_ client: TokenBrokerClient) -> Bool {
        guard activeTokenBrokerClient === client else {
            return false
        }
        activeTokenBrokerClient = nil
        client.cancel()
        return true
    }

    /// Releases whatever client is currently active: takes and clears the
    /// property first, then cancels it exactly once. Repeated calls — and
    /// calls racing a `finishTokenBrokerClient(_:)` that already released the
    /// instance — observe a nil slot and no-op, so the owned client can never
    /// be cancelled twice from this view model.
    private func cancelActiveTokenBrokerClient() {
        guard let client = activeTokenBrokerClient else {
            return
        }
        activeTokenBrokerClient = nil
        client.cancel()
    }

    /// Best-effort cleanup of a broker refresh token that consent already
    /// persisted but the main app could not safely adopt: revoke the provider
    /// grant, then ALWAYS delete the broker-stored tokens through the same
    /// client — the delete attempt is mandatory regardless of the revoke
    /// result. Neither outcome changes the visible state: the operation
    /// closes as the requested failure and never claims the cleanup
    /// succeeded. The revoke completion deliberately captures no self so the
    /// delete still goes out on the captured client even if the view model
    /// disappeared in between.
    private func cleanupFreshBrokerGrant(
        subject: String,
        token: ConnectionOperationToken,
        failure: ConnectionFailure = .unavailable
    ) {
        guard let client = installTokenBrokerClient() else {
            // A broker client is already active: fail closed rather than
            // racing the cleanup against the owned one.
            guard operationDeadline.accepts(token) else {
                return
            }
            _ = finishOperation(token)
            state = .failed(failure)
            return
        }
        client.revokeProviderGrant(accountSubject: subject) { _ in
            // The revoke result never gates the delete: the stored tokens
            // must be removed either way, on the SAME client.
            client.deleteStoredTokens(accountSubject: subject) { _ in
                Task { @MainActor [weak self] in
                    guard let self else {
                        // The owner is gone, so no finish path can release
                        // the client; cancel the captured instance directly,
                        // exactly once (the completion fires at most once).
                        client.cancel()
                        return
                    }
                    // Releases the client exactly once; a stale completion
                    // from an already-released client observes a foreign/
                    // empty slot and must not touch the state.
                    guard self.finishTokenBrokerClient(client) else {
                        return
                    }
                    guard self.operationDeadline.accepts(token) else {
                        return
                    }
                    // Delete success and failure land identically: a closed
                    // failure, never a cleanup-success claim.
                    _ = self.finishOperation(token)
                    self.state = .failed(failure)
                }
            }
        }
    }

    /// The final rung: claim the finished OAuth grant with a connect-begin. A
    /// `.needsReconnect` here means the grant lapsed between consent and
    /// claim — the sign-in expired — so it surfaces as a failure and never
    /// loops back into another browser prompt.
    private func connectWithGrant(
        accountIdentifier: Data,
        oauthSession: OAuthSessionID,
        token: ConnectionOperationToken
    ) {
        syncWorker.beginConnect(
            accountIdentifier: accountIdentifier,
            oauthSession: oauthSession
        ) { [weak self] status in
            guard let self else {
                return
            }
            guard self.operationDeadline.accepts(token) else {
                return
            }
            switch status {
            case .succeeded, .succeededRevokeUnconfirmed:
                self.completeConnected(
                    accountIdentifier: accountIdentifier,
                    token: token,
                    offline: false
                )
            case .needsReconnect:
                _ = self.finishOperation(token)
                self.state = .failed(.signInExpired)
            case .permissionRequired:
                _ = self.finishOperation(token)
                self.state = .failed(.permissionRequired)
            case .cancelled:
                _ = self.finishOperation(token)
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
                _ = self.finishOperation(token)
                self.state = .failed(Self.terminalFailure(status))
            }
        }
    }

    /// The broker-backed fresh-consent rung: feed an access token the broker
    /// vends for a NEWLY-consented grant straight into the broker sync. The
    /// terminal semantics match `connectWithGrant` exactly: a `.syncFailed`
    /// here covers pre-gate failures after a fresh consent, so it must never
    /// land connected — not even offline, which would show the PREVIOUS
    /// identity's cached mailbox to the newly-consenting one. A
    /// `.needsReconnect` means the grant lapsed between consent and claim and
    /// surfaces as `.signInExpired`, never looping back into another browser
    /// prompt.
    private func connectWithBrokerGrant(
        accountIdentifier: Data,
        brokerToken: TokenBrokerAccessToken,
        token: ConnectionOperationToken
    ) {
        syncWorker.beginBrokerSync(
            accountIdentifier: accountIdentifier,
            token: brokerToken
        ) { [weak self] status in
            guard let self else {
                return
            }
            guard self.operationDeadline.accepts(token) else {
                return
            }
            switch status {
            case .succeeded, .succeededRevokeUnconfirmed:
                self.completeConnected(
                    accountIdentifier: accountIdentifier,
                    token: token,
                    offline: false
                )
            case .needsReconnect:
                _ = self.finishOperation(token)
                self.state = .failed(.signInExpired)
            case .permissionRequired:
                _ = self.finishOperation(token)
                self.state = .failed(.permissionRequired)
            case .cancelled:
                _ = self.finishOperation(token)
                self.state = .notConnected
            case .gateBlocked, .syncFailed, .internalError, .unknownSession, .unrecognized,
                 .running:
                // Fresh consent must NEVER land connected offline: on this
                // rung .syncFailed covers pre-gate failures (no token stored,
                // an UNVERIFIED id_token), so it fails closed through the
                // same terminal mapping as `connectWithGrant`.
                _ = self.finishOperation(token)
                self.state = .failed(Self.terminalFailure(status))
            }
        }
    }

    /// Restores a durable disconnect warning as soon as the one remembered,
    /// opaque local account alias is available. This reads only the bounded
    /// lifecycle projection; it never starts OAuth or a mailbox sync at launch.
    private func restorePersistedLifecycle(
        accountIdentifier: Data,
        restoreToken: MailboxLifecycleRestoreToken
    ) {
        syncWorker.readLifecycle(accountIdentifier: accountIdentifier) { [weak self] result in
            guard let self,
                  self.state == .notConnected,
                  self.launchLifecycleRestoreFence.finish(
                      restoreToken,
                      currentAccountIdentifier: Data(self.accountIdentifier.utf8)
                  )
            else {
                return
            }
            switch result.launchProjection {
            case .unavailable:
                self.state = .failed(.accountStateUnavailable)
            case .recovery(let recovery):
                switch recovery {
                case .disconnectIncomplete:
                    self.connectedAccountIdentifier = accountIdentifier
                    self.state = .failed(.disconnectIncomplete)
                case .revokeUnconfirmed:
                    self.disconnectNotice = Self.revokeUnconfirmedNotice
                case .none:
                    break
                }
            }
        }
    }

    /// Checks recovery before the stored-credential rung. An incomplete local
    /// teardown must converge before reconnecting; a revoke-unconfirmed marker
    /// remains visible but does not prevent an explicit new consent attempt.
    private func inspectLifecycleBeforeSync(
        accountIdentifier: Data,
        token: ConnectionOperationToken
    ) {
        syncWorker.readLifecycle(accountIdentifier: accountIdentifier) { [weak self] result in
            guard let self, self.operationDeadline.accepts(token) else {
                return
            }
            guard case .success(let snapshot) = result else {
                _ = self.finishOperation(token)
                self.state = .failed(.accountStateUnavailable)
                return
            }
            switch snapshot.recoveryPresentation {
            case .disconnectIncomplete:
                _ = self.finishOperation(token)
                self.connectedAccountIdentifier = accountIdentifier
                self.state = .failed(.disconnectIncomplete)
                return
            case .revokeUnconfirmed:
                self.disconnectNotice = Self.revokeUnconfirmedNotice
            case .none:
                break
            }
            self.syncWithStoredCredential(accountIdentifier: accountIdentifier, token: token)
        }
    }

    /// Projects the aggregate timestamp after the worker terminal, then makes
    /// cached mail visible. A metadata read failure never invents a time.
    private func completeConnected(
        accountIdentifier: Data,
        token: ConnectionOperationToken,
        offline: Bool
    ) {
        syncWorker.readLifecycle(accountIdentifier: accountIdentifier) { [weak self] result in
            guard let self, self.operationDeadline.accepts(token) else {
                return
            }
            let snapshot: MailboxLifecycleSnapshot? = switch result {
            case .success(let snapshot): snapshot
            case .failure: nil
            }
            self.mailboxFreshness = .afterSync(snapshot: snapshot, offline: offline)
            self.disconnectNotice = nil
            _ = self.finishOperation(token)
            self.connectedAccountIdentifier = accountIdentifier
            self.state = .connected
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
