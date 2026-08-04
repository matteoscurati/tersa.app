// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// The content-free lifecycle projection returned by the Rust mailbox owner.
struct MailboxLifecycleSnapshot: Equatable {
    enum DisconnectRecovery: Int32, Equatable {
        case incompleteTeardown = 1
        case revokeUnconfirmed = 2
    }

    let disconnectRecovery: DisconnectRecovery?
    let lastSuccessfulSync: Date?

    var recoveryPresentation: MailboxLifecycleRecoveryPresentation {
        switch disconnectRecovery {
        case .incompleteTeardown:
            return .disconnectIncomplete
        case .revokeUnconfirmed:
            return .revokeUnconfirmed
        case .none:
            return .none
        }
    }
}

/// Closed result of the privacy-safe lifecycle metadata query.
enum MailboxLifecycleReadResult {
    case success(MailboxLifecycleSnapshot)
    case failure

    var launchProjection: MailboxLifecycleLaunchProjection {
        switch self {
        case .success(let snapshot):
            return .recovery(snapshot.recoveryPresentation)
        case .failure:
            return .unavailable
        }
    }
}

enum MailboxLifecycleLaunchProjection: Equatable {
    case recovery(MailboxLifecycleRecoveryPresentation)
    case unavailable
}

struct MailboxLifecycleRestoreToken: Equatable {
    fileprivate let generation: UInt64
    fileprivate let accountIdentifier: Data
}

/// Generation fence for the launch-only lifecycle read. User intent
/// invalidates the pending token without borrowing the connection deadline.
struct MailboxLifecycleRestoreFence {
    private var generation: UInt64 = 0
    private var active: MailboxLifecycleRestoreToken?

    mutating func begin(accountIdentifier: Data) -> MailboxLifecycleRestoreToken {
        generation &+= 1
        let token = MailboxLifecycleRestoreToken(
            generation: generation,
            accountIdentifier: accountIdentifier
        )
        active = token
        return token
    }

    mutating func invalidate() {
        active = nil
    }

    mutating func finish(
        _ token: MailboxLifecycleRestoreToken,
        currentAccountIdentifier: Data
    ) -> Bool {
        guard active == token, token.accountIdentifier == currentAccountIdentifier else {
            return false
        }
        active = nil
        return true
    }
}

/// Content-free launch presentation restored from the durable lifecycle row.
enum MailboxLifecycleRecoveryPresentation: Equatable {
    case none
    case disconnectIncomplete
    case revokeUnconfirmed
}

/// Freshness presented alongside cached mailbox content.
enum MailboxFreshnessState: Equatable {
    case unknown
    case fresh(lastSuccessfulSync: Date?)
    case offline(lastSuccessfulSync: Date?)

    var isVisible: Bool {
        self != .unknown
    }

    var accessibilityLabel: String {
        switch self {
        case .unknown:
            return "Mailbox freshness unavailable"
        case .fresh:
            return "Mailbox is up to date"
        case .offline:
            return "Offline cached mailbox"
        }
    }

    static func afterSync(snapshot: MailboxLifecycleSnapshot?, offline: Bool) -> Self {
        let lastSuccessfulSync = snapshot?.lastSuccessfulSync
        return offline
            ? .offline(lastSuccessfulSync: lastSuccessfulSync)
            : .fresh(lastSuccessfulSync: lastSuccessfulSync)
    }

    func message(formatDate: (Date) -> String = MailboxFreshnessState.formatDate) -> String {
        switch self {
        case .unknown:
            return ""
        case .fresh(.some(let date)):
            return "Last updated " + formatDate(date) + "."
        case .fresh(.none):
            return "Sync complete. Last-updated time is unavailable."
        case .offline(.some(let date)):
            return "Offline. Showing cached mail last updated " + formatDate(date) + "."
        case .offline(.none):
            return "Offline. Showing cached mail; no successful sync time is available."
        }
    }

    private static func formatDate(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .shortened)
    }
}

/// Main-actor presentation fence for an Inbox-initiated refresh. It holds no
/// credential, mailbox content, or network state; the connection coordinator
/// owns those concerns. A successful terminal advances the local-read revision
/// exactly once, while disconnect and stale callbacks are ignored.
struct MailboxRefreshToken: Equatable {
    fileprivate let generation: UInt64
    fileprivate let accountIdentifier: Data
}

/// The Inbox-only result of a refresh attempt. It is deliberately separate
/// from connection state: refreshing cached mail must not replace the Inbox
/// with an OAuth or generic connection surface.
enum MailboxRefreshNotice: Equatable {
    case offline
    case reconnectRequired
    case unavailable

    var message: String {
        switch self {
        case .offline:
            return "Refresh could not reach Gmail. Showing cached mail."
        case .reconnectRequired:
            return "Reconnect is required before Tersa can refresh this inbox."
        case .unavailable:
            return "Refresh could not complete. Showing cached mail."
        }
    }

    var accessibilityLabel: String {
        switch self {
        case .offline:
            return "Inbox refresh is offline"
        case .reconnectRequired:
            return "Inbox reconnect is required"
        case .unavailable:
            return "Inbox refresh failed"
        }
    }

    var requiresExplicitReconnect: Bool {
        self == .reconnectRequired
    }
}

/// Pure policy for the Inbox-only refresh origin. It prevents broker recovery
/// outcomes from borrowing the ordinary connect ladder until the person taps
/// the explicit Reconnect action.
enum MailboxRefreshTerminal: Equatable {
    case reconnect
    case transport
    case syncFailure
    case unavailable
}

enum MailboxCredentialRecoveryOrigin: Equatable {
    case ordinaryConnection
    case automaticRefresh
    case explicitReconnect
}

enum MailboxCredentialRecoveryEvent: Equatable {
    case missingStoredCredential
    case brokerReconnect
    case brokerPermissionRequired
    case syncReconnect
    case syncPermissionRequired
}

enum MailboxCredentialRecoveryRoute: Equatable {
    case authorizeFromConnectionLadder
    case startExplicitReconnectLadder
    case presentRefreshReconnect
    case failConnectionPermission
}

enum MailboxRefreshTimeoutAction: Equatable {
    case cancelOwnedBrokerClient
    case finishAndFence(MailboxRefreshTerminal)
}

enum MailboxRefreshPolicy {
    static func route(
        origin: MailboxCredentialRecoveryOrigin,
        event: MailboxCredentialRecoveryEvent
    ) -> MailboxCredentialRecoveryRoute {
        switch origin {
        case .automaticRefresh:
            return .presentRefreshReconnect
        case .explicitReconnect:
            return .startExplicitReconnectLadder
        case .ordinaryConnection:
            switch event {
            case .brokerPermissionRequired:
                return .failConnectionPermission
            case .missingStoredCredential, .brokerReconnect, .syncReconnect, .syncPermissionRequired:
                return .authorizeFromConnectionLadder
            }
        }
    }

    static let timeoutActions: [MailboxRefreshTimeoutAction] = [
        .cancelOwnedBrokerClient,
        .finishAndFence(.transport)
    ]
}

enum MailboxRefreshPresentationPolicy {
    static func notice(for terminal: MailboxRefreshTerminal) -> MailboxRefreshNotice {
        switch terminal {
        case .reconnect:
            return .reconnectRequired
        case .transport, .syncFailure:
            return .offline
        case .unavailable:
            return .unavailable
        }
    }

}

struct MailboxRefreshPresentation {
    private var generation: UInt64 = 0
    private var active: MailboxRefreshToken?
    private(set) var reloadGeneration: UInt64 = 0
    private(set) var notice: MailboxRefreshNotice?

    var isRefreshing: Bool { active != nil }
    var activeToken: MailboxRefreshToken? { active }

    mutating func begin(accountIdentifier: Data) -> MailboxRefreshToken? {
        guard active == nil else { return nil }
        notice = nil
        generation &+= 1
        let token = MailboxRefreshToken(
            generation: generation,
            accountIdentifier: accountIdentifier
        )
        active = token
        return token
    }

    mutating func finish(_ token: MailboxRefreshToken, succeeded: Bool) -> Bool {
        guard active == token else { return false }
        active = nil
        if succeeded {
            reloadGeneration &+= 1
        }
        return true
    }

    mutating func present(_ notice: MailboxRefreshNotice) {
        self.notice = notice
    }

    mutating func invalidate() {
        active = nil
    }
}
