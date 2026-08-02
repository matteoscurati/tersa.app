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
/// cancellable connect/authorization from a destructive disconnect which must
/// keep accepting its eventual terminal result.
@MainActor
final class ConnectionOperationDeadline {
    typealias MonotonicNow = @MainActor () -> UInt64

    private struct ActiveOperation {
        let token: ConnectionOperationToken
        let deadline: UInt64
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
    /// For a destructive disconnect, `keepAlive` preserves the generation so a
    /// late Rust terminal can still update the UI; it does not start another
    /// operation or permit reconnect.
    @discardableResult
    func timeOut(_ token: ConnectionOperationToken, keepAlive: Bool) -> Bool {
        guard var active, active.token == token, now() >= active.deadline, !active.timedOut else {
            return false
        }
        active.timedOut = true
        self.active = keepAlive ? active : nil
        return true
    }

    /// Cancels a non-destructive attempt locally. Its callback becomes stale.
    func invalidate(_ token: ConnectionOperationToken) {
        guard accepts(token) else {
            return
        }
        active = nil
    }
}
