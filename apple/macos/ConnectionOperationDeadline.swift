// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// An operation whose completion may change the account-connection surface.
/// Each kind receives an independent deadline and a generation fence.
enum ConnectionOperationKind: Equatable {
    case connectAndSync
    case authorization
    case disconnect
}

/// The opaque identity of one connection attempt. A callback can change UI
/// only while this token remains current.
struct ConnectionOperationToken: Equatable {
    fileprivate let generation: UInt64
    let kind: ConnectionOperationKind
}

/// Main-actor monotonic deadline and generation-fence coordinator.
///
/// It deliberately does not own I/O. Callers use `accepts(_:)` before every
/// asynchronous callback, and use `timeOut(_:keepAlive:)` to distinguish a
/// cancellable browser authorization from a connect or destructive disconnect
/// which must keep accepting its eventual terminal result.
@MainActor
final class ConnectionOperationDeadline {
    typealias MonotonicNow = @MainActor () -> UInt64

    private struct ActiveOperation {
        let token: ConnectionOperationToken
        var deadline: UInt64
        var timedOut = false
    }

    private let now: MonotonicNow
    private var generation: UInt64 = 0
    private var active: ActiveOperation?

    /// True from disconnect begin until its terminal callback. A presentation
    /// timeout deliberately leaves this true so no new connect or teardown can
    /// supersede the destructive worker.
    var disconnectIsActive: Bool {
        active?.token.kind == .disconnect
    }

    /// A timed-out non-cancellable connect remains active until its terminal
    /// callback, just like a destructive disconnect.
    var connectIsActive: Bool {
        active?.token.kind == .connectAndSync
    }

    var hasActiveOperation: Bool {
        active != nil
    }

    init(now: @escaping MonotonicNow = { DispatchTime.now().uptimeNanoseconds }) {
        self.now = now
    }

    /// Starts a fresh attempt. The previous attempt becomes stale immediately.
    func start(kind: ConnectionOperationKind, timeout: TimeInterval) -> ConnectionOperationToken {
        generation &+= 1
        let token = ConnectionOperationToken(generation: generation, kind: kind)
        let timeoutNanoseconds = UInt64(max(0, timeout) * 1_000_000_000)
        let start = now()
        active = ActiveOperation(
            token: token,
            deadline: start.addingReportingOverflow(timeoutNanoseconds).partialValue
        )
        return token
    }

    /// Returns true only for the operation that is still allowed to mutate UI.
    func accepts(_ token: ConnectionOperationToken) -> Bool {
        active?.token == token
    }

    /// Completes the active operation. A stale callback cannot complete a newer
    /// attempt.
    @discardableResult
    func finish(_ token: ConnectionOperationToken) -> Bool {
        guard accepts(token) else {
            return false
        }
        active = nil
        return true
    }

    /// Marks the active operation timed out only after its monotonic deadline.
    /// For a non-cancellable connect or destructive disconnect, `keepAlive`
    /// preserves the generation so a late Rust terminal can still update the
    /// UI; it does not start another operation or permit a competing begin.
    @discardableResult
    func timeOut(_ token: ConnectionOperationToken, keepAlive: Bool) -> Bool {
        guard var active, active.token == token, now() >= active.deadline, !active.timedOut else {
            return false
        }
        active.timedOut = true
        self.active = keepAlive ? active : nil
        return true
    }

    /// Renews only the presentation deadline of an already timed-out,
    /// non-cancellable operation. The generation does not change, so the
    /// original terminal callback remains authoritative.
    func renewTimedOut(
        kind: ConnectionOperationKind,
        timeout: TimeInterval
    ) -> ConnectionOperationToken? {
        guard var active, active.token.kind == kind, active.timedOut else {
            return nil
        }
        let timeoutNanoseconds = UInt64(max(0, timeout) * 1_000_000_000)
        active.deadline = now().addingReportingOverflow(timeoutNanoseconds).partialValue
        active.timedOut = false
        self.active = active
        return active.token
    }
}
