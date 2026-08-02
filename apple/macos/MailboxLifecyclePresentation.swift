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
            return "Last updated \(formatDate(date))."
        case .fresh(.none):
            return "Sync complete. Last-updated time is unavailable."
        case .offline(.some(let date)):
            return "Offline. Showing cached mail last updated \(formatDate(date))."
        case .offline(.none):
            return "Offline. Showing cached mail; no successful sync time is available."
        }
    }

    private static func formatDate(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .shortened)
    }
}
