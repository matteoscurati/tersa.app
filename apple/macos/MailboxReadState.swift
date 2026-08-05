// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

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

/// What the search screen does with a completed search whose field may have
/// been edited while the search was in flight.
enum SearchCompletionDecision: Equatable {
    /// The field still shows the submitted query; the result matches it.
    case displayResult
    /// The field text changed mid-flight, so the result is stale and must be
    /// dropped. The UI must say so — a dropped result must not fall silent.
    case discardStale
}

/// Pure stale-result guard for the submit-only search. The decision compares
/// the submitted query with the field text at completion time; the status copy
/// is a fixed string that never carries query text or message content.
enum SearchCompletionGuard {
    /// Fixed status shown and announced when a stale result is discarded.
    static let staleEditStatus = "Search text changed. Press Return to search again."

    static func decision(completedQuery: String, currentFieldText: String) -> SearchCompletionDecision {
        let trimmed = currentFieldText.trimmingCharacters(in: .whitespacesAndNewlines)
        return completedQuery == trimmed ? .displayResult : .discardStale
    }
}

/// What the search screen does with a submit attempt.
enum SearchSubmitDecision: Equatable {
    /// No search is in flight; validate and submit the current field.
    case submitField
    /// A search is already in flight; the resubmit is rejected. The UI must
    /// say so with fixed query-free copy — a rejected resubmit must not fall
    /// silent.
    case rejectInFlight
}

/// Pure serialization guard for the submit-only search. The worker serves
/// one request at a time, so a resubmit while a search is in flight is
/// rejected; the copy is a fixed string that never carries query text or
/// message content.
enum SearchSubmitGuard {
    /// Fixed status announced when a resubmit arrives mid-search.
    static let inProgressStatus = "Search already in progress."

    static func decision(searching: Bool) -> SearchSubmitDecision {
        searching ? .rejectInFlight : .submitField
    }
}

/// What the search screen does with the current search field text. Both the
/// Return submit path and the Try again retry route through this decision, so
/// a retry always uses the user's current field text — the field is never
/// silently rewritten to an earlier query.
enum SearchFieldDecision: Equatable {
    /// The trimmed field is a valid query; the search runs with it.
    case validatedQuery(String)
    /// The trimmed field is empty; show and announce the fixed empty-field
    /// message — an empty submit or retry must not fall silent.
    case emptyField
    /// The field is invalid; show and announce the fixed message. The
    /// messages are fixed copy and never carry query text.
    case invalid(String)
}

/// Pure field validation for the submit-only search. Length and control
/// characters are checked inline before any ABI call — the Rust side
/// re-validates authoritatively — and all messages are fixed copy.
enum SearchFieldValidator {
    static let maximumQueryByteCount = 256
    /// Fixed copy shown and announced when the trimmed field is empty. It
    /// never carries query text.
    static let emptyFieldMessage = "Enter search text, then press Return."
    static let tooLongMessage = "Search text is limited to 256 bytes. Shorten it and try again."
    static let controlCharacterMessage = "Search text cannot contain control characters."

    static func decision(forFieldText fieldText: String) -> SearchFieldDecision {
        let trimmed = fieldText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .emptyField
        }
        guard trimmed.utf8.count <= maximumQueryByteCount else {
            return .invalid(tooLongMessage)
        }
        guard !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            return .invalid(controlCharacterMessage)
        }
        return .validatedQuery(trimmed)
    }
}
