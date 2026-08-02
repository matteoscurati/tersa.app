// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// The `tersa_mailbox_macos_{sync,connect,disconnect}_begin` return domain.
/// Raw values mirror `adapters/mailbox-sync-ffi-macos/src/lib.rs`
/// (`STATUS_STARTED`, `STATUS_SYNC_BUSY`, `STATUS_INTERNAL`,
/// `STATUS_INVALID_INPUT`).
///
/// Distinct from `MailboxPollStatus`: the two domains ALIAS numerically — a
/// begin's started (0) is a poll's running, and busy (2) is a begin-only
/// refusal that is NEVER a poll terminal — so one shared enum would silently
/// swap them. `STATUS_UNKNOWN_SESSION` (-8) is poll-only and deliberately
/// absent here.
enum MailboxBeginStatus {
    /// A worker was spawned; the out session id was written. Poll it.
    case started
    /// The account slot already has a whole cycle in flight; no worker was
    /// spawned and no session id was written.
    case busy
    /// A registry, session-id allocation, or configuration fault.
    case internalError
    /// A null, empty, oversized, or non-UTF-8 input, or a null out pointer.
    case invalidInput
    /// A begin returned a code this build does not know.
    case unrecognized

    init(rawValue: Int32) {
        switch rawValue {
        case 0:
            self = .started
        case 2:
            self = .busy
        case -5:
            self = .internalError
        case -7:
            self = .invalidInput
        default:
            // An unknown begin code maps to `.unrecognized` HERE, so no caller
            // can forget to coalesce and force-unwrap a nil into a crash.
            self = .unrecognized
        }
    }

    /// The poll-domain terminal a begin REFUSAL is surfaced as, so the
    /// worker's single completion type stays `MailboxPollStatus`. Explicit
    /// and one-way, keeping the two domains distinct: `.busy` — begin-only,
    /// never a poll terminal — renders as `.gateBlocked` ("another cycle
    /// owns the slot"), and the remaining refusals collapse to terminals of
    /// matching severity. `.started` never reaches here: it drives the poll
    /// loop instead.
    var refusalTerminal: MailboxPollStatus {
        switch self {
        case .busy:
            return .gateBlocked
        case .started, .invalidInput, .internalError:
            return .internalError
        case .unrecognized:
            return .unrecognized
        }
    }
}

/// The `tersa_mailbox_macos_sync_poll` terminal domain; the SAME poll serves
/// sync, connect, AND disconnect sessions. Raw values mirror
/// `adapters/oauth-sync-macos/src/worker.rs` plus the FFI's own
/// `STATUS_UNKNOWN_SESSION` (-8).
enum MailboxPollStatus {
    /// The worker is live and its cycle is in flight. NOT terminal.
    case running
    /// The cycle completed.
    case succeeded
    /// The disconnect teardown completed locally but the provider /revoke
    /// could not be confirmed. A SUCCESS — the success family sibling of
    /// `.succeeded`, not a failure — and only ever reported by a DISCONNECT
    /// poll: a sync or connect poll never reports it.
    case succeededRevokeUnconfirmed
    /// A disconnect dropped the in-flight sync.
    case cancelled
    /// The account-identity gate blocked the sync.
    case gateBlocked
    /// The bounded sync failed.
    case syncFailed
    /// The worker could not build its runtime, or hit an internal anomaly.
    case internalError
    /// No refresh token is stored for the account: it must be reconnected
    /// (re-consent) rather than retried.
    case needsReconnect
    /// Google explicitly omitted Gmail read access from the granted scopes.
    case permissionRequired
    /// The poll named an unregistered or already-reaped session id.
    case unknownSession
    /// A poll returned a code this build does not know. Terminal
    /// (fail-closed); reserved headroom for future codes.
    case unrecognized

    init(rawValue: Int32) {
        switch rawValue {
        case 0:
            self = .running
        case 1:
            self = .succeeded
        case 3:
            self = .succeededRevokeUnconfirmed
        case -2:
            self = .cancelled
        case -3:
            self = .gateBlocked
        case -4:
            self = .syncFailed
        case -5:
            self = .internalError
        case -6:
            self = .needsReconnect
        case -9:
            self = .permissionRequired
        case -8:
            self = .unknownSession
        default:
            // An unknown poll code maps to `.unrecognized` HERE (terminal), so
            // no caller can forget to coalesce and force-unwrap a nil.
            self = .unrecognized
        }
    }

    /// Success is the FAMILY { `.succeeded`, `.succeededRevokeUnconfirmed` } —
    /// never a raw-value shortcut: `raw == 1` would drop the
    /// revoke-unconfirmed success, and `raw >= 0` would count `.running`
    /// (and the begin-only busy code 2, which never reaches a poll).
    var isSuccess: Bool {
        switch self {
        case .succeeded, .succeededRevokeUnconfirmed:
            return true
        default:
            return false
        }
    }
}

/// Serializes the mailbox connect, disconnect, and sync begins — and their
/// ONE shared FFI poll loop — away from the AppKit main thread. One active
/// session at a time: the UI cannot legally run two flows, and the Rust
/// whole-cycle permit and disconnect fence backstop that. The concurrency
/// guard mirrors the bootstrap worker exactly: an `NSLock`-guarded
/// running/pending single slot, and a second queued request rejected
/// immediately.
final class MailboxSyncWorker: @unchecked Sendable {
    private static let pollInterval: DispatchTimeInterval = .milliseconds(100)

    /// One queued begin: a connect, a disconnect, or a plain sync.
    private enum BeginRequest {
        case connect(Data, OAuthSessionID)
        case disconnect(Data)
        case sync(String, Data)
    }

    private let queue = DispatchQueue(label: "app.tersa.macos.mailbox-sync", qos: .utility)
    private let state = NSLock()
    private var running = false
    private var pending: (() -> Void)?

    /// Queues one connect-begin for a finished OAuth session. A second queued
    /// request is rejected immediately.
    func beginConnect(
        accountIdentifier: Data,
        oauthSession: OAuthSessionID,
        completion: @escaping @MainActor (MailboxPollStatus) -> Void
    ) {
        enqueueBegin(.connect(accountIdentifier, oauthSession), completion: completion)
    }

    /// Queues one disconnect-begin (consent withdrawal + local teardown). A
    /// second queued request is rejected immediately.
    func beginDisconnect(
        accountIdentifier: Data,
        completion: @escaping @MainActor (MailboxPollStatus) -> Void
    ) {
        enqueueBegin(.disconnect(accountIdentifier), completion: completion)
    }

    /// Queues one bounded sync-begin. A second queued request is rejected
    /// immediately.
    func beginSync(
        clientID: String,
        accountIdentifier: Data,
        completion: @escaping @MainActor (MailboxPollStatus) -> Void
    ) {
        enqueueBegin(.sync(clientID, accountIdentifier), completion: completion)
    }

    private func enqueueBegin(
        _ request: BeginRequest,
        completion: @escaping @MainActor (MailboxPollStatus) -> Void
    ) {
        let operation = { [queue] in
            queue.async {
                let (rawStatus, sessionID) = self.performBegin(request)
                let beginStatus = MailboxBeginStatus(rawValue: rawStatus)
                guard beginStatus == .started else {
                    let refusal = beginStatus.refusalTerminal
                    DispatchQueue.main.async { completion(refusal) }
                    self.finish()
                    return
                }
                self.poll(session: SyncSessionID(rawValue: sessionID), completion: completion)
            }
        }
        state.lock()
        defer { state.unlock() }
        if !running {
            running = true
            operation()
        } else if pending == nil {
            pending = operation
        } else {
            // The single-slot rejection surfaces as the same terminal a
            // begin-busy refusal maps to.
            DispatchQueue.main.async { completion(.gateBlocked) }
        }
    }

    /// Invokes the matching C ABI begin once, on the worker queue. The out
    /// session id is meaningful only when the returned status maps to
    /// `MailboxBeginStatus.started`.
    private func performBegin(_ request: BeginRequest) -> (status: Int32, sessionID: UInt64) {
        var sessionID: UInt64 = 0
        let status: Int32
        switch request {
        case .connect(let accountIdentifier, let oauthSession):
            status = Array(accountIdentifier).withUnsafeBufferPointer { accountBuffer in
                tersa_mailbox_macos_connect_begin(
                    accountBuffer.baseAddress,
                    accountBuffer.count,
                    oauthSession.rawValue,
                    &sessionID
                )
            }
        case .disconnect(let accountIdentifier):
            status = Array(accountIdentifier).withUnsafeBufferPointer { accountBuffer in
                tersa_mailbox_macos_disconnect_begin(
                    accountBuffer.baseAddress,
                    accountBuffer.count,
                    &sessionID
                )
            }
        case .sync(let clientID, let accountIdentifier):
            let clientIDBytes = Array(clientID.utf8)
            status = clientIDBytes.withUnsafeBufferPointer { clientBuffer in
                Array(accountIdentifier).withUnsafeBufferPointer { accountBuffer in
                    tersa_mailbox_macos_sync_begin(
                        clientBuffer.baseAddress,
                        clientBuffer.count,
                        accountBuffer.baseAddress,
                        accountBuffer.count,
                        &sessionID
                    )
                }
            }
        }
        return (status, sessionID)
    }

    /// Drives the shared FFI poll on the worker queue until the session
    /// reports a non-running status, then hops the terminal completion to the
    /// main actor. `.running` is the ONLY non-terminal; an unrecognized code
    /// is terminal (fail-closed).
    private func poll(
        session: SyncSessionID,
        completion: @escaping @MainActor (MailboxPollStatus) -> Void
    ) {
        let rawStatus = tersa_mailbox_macos_sync_poll(session.rawValue)
        let status = MailboxPollStatus(rawValue: rawStatus)
        guard status != .running else {
            queue.asyncAfter(deadline: .now() + Self.pollInterval) {
                self.poll(session: session, completion: completion)
            }
            return
        }
        DispatchQueue.main.async { completion(status) }
        finish()
    }

    private func finish() {
        state.lock()
        let next = pending
        pending = nil
        if next == nil { running = false }
        state.unlock()
        next?()
    }
}
