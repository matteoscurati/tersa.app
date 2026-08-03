// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// The `tersa_mailbox_macos_broker_sync_begin` and
/// `tersa_mailbox_macos_broker_disconnect_finalize` return domain.
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
/// broker sync AND broker disconnect finalize sessions. Raw values mirror
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
    /// poll: a sync poll never reports it.
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

/// Closed result of the synchronous broker disconnect prepare. Raw values
/// mirror the `tersa_mailbox_macos_broker_disconnect_prepare` return domain:
/// raw 1 means the Rust fence was set and any in-flight sync was cancelled,
/// raw 2 means the account slot is busy and nothing was prepared, and every
/// other value is a failure.
enum BrokerDisconnectPrepareResult: Equatable {
    /// The disconnect fence is set and the in-flight sync was cancelled; the
    /// caller may proceed to the broker revoke.
    case prepared
    /// The account slot is busy; nothing was prepared.
    case busy
    /// Any other status.
    case failure
}

/// Serializes the mailbox broker sync and broker disconnect finalize begins
/// — and their ONE shared FFI poll loop — away from the AppKit main thread. One active
/// session at a time: the UI cannot legally run two flows, and the Rust
/// whole-cycle permit and disconnect fence backstop that. The concurrency
/// guard mirrors the bootstrap worker exactly: an `NSLock`-guarded
/// running/pending single slot, and a second queued request rejected
/// immediately.
final class MailboxSyncWorker: @unchecked Sendable {
    private static let pollInterval: DispatchTimeInterval = .milliseconds(100)
    /// The FFI's `MAX_SUBJECT_BYTES`: a broker subject is 1...255 UTF-8 bytes.
    private static let brokerSubjectCapacity = 255

    /// Reference-type box holding the two broker-fed secrets of ONE queued
    /// broker sync begin as mutable UTF-8 byte arrays. Reference semantics are
    /// the point: a `BeginRequest.brokerSync` payload may be copied (enum
    /// value semantics), but every copy shares this one box, so an in-place
    /// wipe here cannot leave a copy-on-write source copy retained by the
    /// enum. Confinement: the box is created on the caller's thread, handed to
    /// the worker queue exactly once via `enqueueBegin`, and afterwards
    /// touched only on that serial queue — never concurrently — hence
    /// `@unchecked Sendable`. Neither buffer is ever printed, formatted, or
    /// logged.
    private final class BrokerSyncSecrets: @unchecked Sendable {
        private var accessToken: [UInt8]
        private var subject: [UInt8]
        private var wiped = false

        init(token: TokenBrokerAccessToken) {
            accessToken = Array(token.accessToken.utf8)
            subject = Array(token.subject.utf8)
        }

        /// Invokes the broker sync begin FFI once, on the worker queue, and
        /// wipes BOTH secret buffers in a defer immediately after the call
        /// returns — on the started path AND on every refusal — so no secret
        /// outlives the FFI hand-off. The account identifier is not a secret
        /// and is not wiped.
        func begin(accountIdentifier: Data) -> (status: Int32, sessionID: UInt64) {
            var sessionID: UInt64 = 0
            defer { wipe() }
            let status = accessToken.withUnsafeBufferPointer { tokenBuffer in
                subject.withUnsafeBufferPointer { subjectBuffer in
                    Array(accountIdentifier).withUnsafeBufferPointer { accountBuffer in
                        tersa_mailbox_macos_broker_sync_begin(
                            accountBuffer.baseAddress,
                            accountBuffer.count,
                            tokenBuffer.baseAddress,
                            tokenBuffer.count,
                            subjectBuffer.baseAddress,
                            subjectBuffer.count,
                            &sessionID
                        )
                    }
                }
            }
            return (status, sessionID)
        }

        /// Covers a box that was NEVER begun: a queued request rejected by the
        /// full pending slot (or otherwise abandoned) releases the box without
        /// a begin, and deinit guarantees its secrets do not linger in freed
        /// memory. Idempotent against the post-FFI defer wipe via `wiped`.
        deinit {
            wipe()
        }

        /// In-place zeroing via `withUnsafeMutableBytes`: mutating through
        /// subscripts could trigger copy-on-write if a buffer were ever
        /// shared, while this mutates the box-owned storage directly.
        private func wipe() {
            guard !wiped else { return }
            wiped = true
            accessToken.withUnsafeMutableBytes { bytes in
                bytes.initializeMemory(as: UInt8.self, repeating: 0)
            }
            subject.withUnsafeMutableBytes { bytes in
                bytes.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }
    }

    /// One queued begin: a broker-fed sync or a broker disconnect finalize.
    private enum BeginRequest {
        case brokerSync(Data, BrokerSyncSecrets)
        case brokerDisconnectFinalize(Data, Bool)
    }

    private let queue = DispatchQueue(label: "app.tersa.macos.mailbox-sync", qos: .utility)
    private let state = NSLock()
    private var running = false
    private var pending: (() -> Void)?

    /// Queues one broker-fed sync-begin. The token's access token and subject
    /// are copied into a `BrokerSyncSecrets` box IMMEDIATELY, before any queue
    /// hop, so the caller may release its `TokenBrokerAccessToken` at once. A
    /// second queued request is rejected immediately; the rejected box is then
    /// released without a begin and its deinit wipes both secrets.
    func beginBrokerSync(
        accountIdentifier: Data,
        token: TokenBrokerAccessToken,
        completion: @escaping @MainActor (MailboxPollStatus) -> Void
    ) {
        let secrets = BrokerSyncSecrets(token: token)
        enqueueBegin(.brokerSync(accountIdentifier, secrets), completion: completion)
    }

    /// Runs the SYNCHRONOUS broker disconnect prepare on the worker queue. It
    /// is deliberately NOT routed through `enqueueBegin`: the prepare must set
    /// the Rust disconnect fence and cancel the in-flight sync BEFORE the
    /// broker revoke, ahead of any queued begin. Raw 1 maps to `.prepared`,
    /// raw 2 to `.busy`, and every other status to `.failure`; the result is
    /// delivered on the main actor.
    func prepareBrokerDisconnect(
        accountIdentifier: Data,
        completion: @escaping @MainActor (BrokerDisconnectPrepareResult) -> Void
    ) {
        queue.async {
            let status = Array(accountIdentifier).withUnsafeBufferPointer { accountBuffer in
                tersa_mailbox_macos_broker_disconnect_prepare(
                    accountBuffer.baseAddress,
                    accountBuffer.count
                )
            }
            let result: BrokerDisconnectPrepareResult
            switch status {
            case 1:
                result = .prepared
            case 2:
                result = .busy
            default:
                result = .failure
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    /// Queues one broker disconnect finalize-begin (local teardown after the
    /// broker revoke; `revokeUnconfirmed` records whether the revoke could not
    /// be confirmed). A second queued request is rejected immediately.
    func beginBrokerDisconnectFinalize(
        accountIdentifier: Data,
        revokeUnconfirmed: Bool,
        completion: @escaping @MainActor (MailboxPollStatus) -> Void
    ) {
        enqueueBegin(.brokerDisconnectFinalize(accountIdentifier, revokeUnconfirmed), completion: completion)
    }

    /// Reads only disconnect recovery and last-successful-sync metadata on the
    /// worker queue. It never creates a mailbox store and never returns account
    /// identity, OAuth material, or mailbox content.
    func readLifecycle(
        accountIdentifier: Data,
        completion: @escaping @MainActor (MailboxLifecycleReadResult) -> Void
    ) {
        queue.async {
            var recovery: Int32 = 0
            var lastSuccessfulSync: Int64 = -1
            let status = Array(accountIdentifier).withUnsafeBufferPointer { accountBuffer in
                tersa_mailbox_macos_lifecycle_get(
                    accountBuffer.baseAddress,
                    accountBuffer.count,
                    &recovery,
                    &lastSuccessfulSync
                )
            }
            let result: MailboxLifecycleReadResult
            if status == 0,
               recovery == 0 || MailboxLifecycleSnapshot.DisconnectRecovery(rawValue: recovery) != nil,
               lastSuccessfulSync >= -1 {
                let date = lastSuccessfulSync >= 0
                    ? Date(timeIntervalSince1970: Double(lastSuccessfulSync) / 1_000)
                    : nil
                result = .success(MailboxLifecycleSnapshot(
                    disconnectRecovery: MailboxLifecycleSnapshot.DisconnectRecovery(rawValue: recovery),
                    lastSuccessfulSync: date
                ))
            } else {
                result = .failure
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    /// Persists the account's broker routing subject on the worker queue. The
    /// subject is never logged or displayed, and its UTF-8 bytes are wiped
    /// before the queue closure returns. The completion reports true only for
    /// raw status 0; every refusal (internal, invalid input, unrecognized) is
    /// false.
    func storeBrokerSubject(
        accountIdentifier: Data,
        subject: String,
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        queue.async {
            var subjectBytes = Array(subject.utf8)
            let status = subjectBytes.withUnsafeMutableBufferPointer { subjectBuffer in
                Array(accountIdentifier).withUnsafeBufferPointer { accountBuffer in
                    tersa_mailbox_macos_broker_subject_store(
                        accountBuffer.baseAddress,
                        accountBuffer.count,
                        subjectBuffer.baseAddress,
                        subjectBuffer.count
                    )
                }
            }
            subjectBytes.withUnsafeMutableBytes { bytes in
                bytes.initializeMemory(as: UInt8.self, repeating: 0)
            }
            DispatchQueue.main.async { completion(status == 0) }
        }
    }

    /// Reads the account's broker routing subject on the worker queue without
    /// ever creating a mailbox store. The subject is never logged or
    /// displayed, and the full 255-byte output buffer is wiped on every path
    /// before the queue closure returns. Raw 0 requires a 1...255 byte valid
    /// UTF-8 payload (`.found`, else `.failure`); raw -6 is `.absent`; every
    /// other status is `.failure`.
    func readBrokerSubject(
        accountIdentifier: Data,
        completion: @escaping @MainActor (BrokerSubjectReadResult) -> Void
    ) {
        queue.async {
            var output = [UInt8](repeating: 0, count: Self.brokerSubjectCapacity)
            // Sentinel: a raw-0 return that leaves the length unwritten fails
            // the 1...255 window below instead of fabricating an empty subject.
            var outputLength: Int = .max
            let status = output.withUnsafeMutableBufferPointer { outputBuffer in
                Array(accountIdentifier).withUnsafeBufferPointer { accountBuffer in
                    tersa_mailbox_macos_broker_subject_get(
                        accountBuffer.baseAddress,
                        accountBuffer.count,
                        outputBuffer.baseAddress,
                        outputBuffer.count,
                        &outputLength
                    )
                }
            }
            let result: BrokerSubjectReadResult
            if status == 0 {
                if (1...Self.brokerSubjectCapacity).contains(outputLength),
                   let subject = String(bytes: output.prefix(outputLength), encoding: .utf8) {
                    result = .found(subject)
                } else {
                    result = .failure
                }
            } else if status == -6 {
                result = .absent
            } else {
                result = .failure
            }
            output.withUnsafeMutableBytes { bytes in
                bytes.initializeMemory(as: UInt8.self, repeating: 0)
            }
            DispatchQueue.main.async { completion(result) }
        }
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
        case .brokerSync(let accountIdentifier, let secrets):
            // The box wipes both secret buffers in a defer inside `begin`,
            // before this case returns — started or refused alike.
            let result = secrets.begin(accountIdentifier: accountIdentifier)
            status = result.status
            sessionID = result.sessionID
        case .brokerDisconnectFinalize(let accountIdentifier, let revokeUnconfirmed):
            status = Array(accountIdentifier).withUnsafeBufferPointer { accountBuffer in
                tersa_mailbox_macos_broker_disconnect_finalize(
                    accountBuffer.baseAddress,
                    accountBuffer.count,
                    revokeUnconfirmed ? 1 : 0,
                    &sessionID
                )
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
