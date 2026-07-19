// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// One message row in the 2b bridge wire shape.
struct MessageRow: Decodable, Identifiable, Equatable {
    let messageId: String
    let threadId: String
    let from: String
    let subject: String
    let receivedAtMillis: Int64
    let unread: Bool

    var id: String {
        messageId
    }

    /// The received instant derived from the wire milliseconds.
    var receivedDate: Date {
        Date(timeIntervalSince1970: TimeInterval(receivedAtMillis) / 1_000)
    }

    enum CodingKeys: String, CodingKey {
        case messageId = "message_id"
        case threadId = "thread_id"
        case from
        case subject
        case receivedAtMillis = "received_at_millis"
        case unread
    }
}

/// The inbox document in the 2b bridge wire shape.
struct InboxDocument: Decodable {
    let schemaVersion: Int
    let command: String
    let accountId: String
    let limit: Int
    let messages: [MessageRow]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case command
        case accountId = "account_id"
        case limit
        case messages
    }
}

/// The thread document in the 2b bridge wire shape.
struct ThreadDocument: Decodable {
    let schemaVersion: Int
    let command: String
    let accountId: String
    let threadId: String
    let limit: Int
    let messages: [MessageRow]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case command
        case accountId = "account_id"
        case threadId = "thread_id"
        case limit
        case messages
    }
}

/// The search document in the 2b bridge wire shape.
struct SearchDocument: Decodable {
    let schemaVersion: Int
    let command: String
    let accountId: String
    let query: String
    let limit: Int
    let messages: [MessageRow]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case command
        case accountId = "account_id"
        case query
        case limit
        case messages
    }
}

/// Decodes bridge read payloads. Fails closed: a wrong schema version, a
/// wrong command, or a decoding error yields a failure outcome and never a
/// partial render.
enum MailboxDocumentDecoder {
    private static let supportedSchemaVersion = 1
    private static let inboxCommand = "inbox"
    private static let threadCommand = "thread"
    private static let searchCommand = "search"

    static func decodeInbox(_ payload: Data) -> MailboxReadOutcome {
        guard let document = try? JSONDecoder().decode(InboxDocument.self, from: payload),
              document.schemaVersion == supportedSchemaVersion,
              document.command == inboxCommand
        else {
            return .failure(.corrupted)
        }
        return document.messages.isEmpty ? .empty : .content(document.messages)
    }

    static func decodeThread(_ payload: Data) -> MailboxReadOutcome {
        guard let document = try? JSONDecoder().decode(ThreadDocument.self, from: payload),
              document.schemaVersion == supportedSchemaVersion,
              document.command == threadCommand
        else {
            return .failure(.corrupted)
        }
        return document.messages.isEmpty ? .empty : .content(document.messages)
    }

    static func decodeSearch(_ payload: Data) -> MailboxReadOutcome {
        guard let document = try? JSONDecoder().decode(SearchDocument.self, from: payload),
              document.schemaVersion == supportedSchemaVersion,
              document.command == searchCommand
        else {
            return .failure(.corrupted)
        }
        return document.messages.isEmpty ? .empty : .content(document.messages)
    }
}
