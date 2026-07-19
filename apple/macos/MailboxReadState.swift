// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// The closed status set returned by the 2b mailbox read C ABI.
enum MailboxReadStatus: Int32 {
    case ok = 0
    case invalidInput = 1
    case invalidExecutionContext = 2
    case unavailable = 3
    case corrupted = 4
    case bufferTooSmall = 5
}

/// A non-ok mailbox read outcome, phrased for the person using the app.
/// Carries no internal identifiers and no secrets.
enum MailboxReadFailure: Equatable {
    case invalidInput
    case invalidExecutionContext
    case unavailable
    case corrupted

    var message: String {
        switch self {
        case .invalidInput:
            return "The account details are not valid."
        case .invalidExecutionContext:
            return "Restart the app and try again."
        case .unavailable:
            return "The mailbox is unavailable. Try again."
        case .corrupted:
            return "The mailbox could not be read."
        }
    }

    /// Maps a raw C ABI status to user-facing copy. A post-retry
    /// `bufferTooSmall` and any unknown code collapse to `unavailable`;
    /// `ok` never reaches a failure render.
    static func fromStatus(_ status: Int32) -> MailboxReadFailure {
        guard let mapped = MailboxReadStatus(rawValue: status) else {
            return .unavailable
        }
        switch mapped {
        case .invalidInput:
            return .invalidInput
        case .invalidExecutionContext:
            return .invalidExecutionContext
        case .corrupted:
            return .corrupted
        case .ok, .unavailable, .bufferTooSmall:
            return .unavailable
        }
    }
}

/// The closed set of mailbox read outcomes the UI can render.
enum MailboxReadOutcome: Equatable {
    case content([MessageRow])
    case empty
    case failure(MailboxReadFailure)

    /// Short state text exposed to assistive technologies as a value.
    var accessibilityValue: String {
        switch self {
        case .content(let rows):
            return String(rows.count) + (rows.count == 1 ? " message" : " messages")
        case .empty:
            return "No messages"
        case .failure:
            return "Mailbox read failed"
        }
    }

    /// Spoken text announced when a read finishes loading or fails.
    var announcement: String {
        switch self {
        case .content(let rows):
            return "Loaded " + String(rows.count) + (rows.count == 1 ? " message." : " messages.")
        case .empty:
            return "No messages"
        case .failure(let failure):
            return failure.message
        }
    }
}
