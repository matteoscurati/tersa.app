// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// One mailbox message row — unread indicator, sender, subject, received date —
/// shared by the inbox and thread lists and exposed to assistive technology as a
/// single combined element whose label is built by concatenation.
@MainActor
struct MailboxMessageRowView: View {
    let row: MessageRow

    var body: some View {
        HStack(spacing: 8) {
            if row.unread {
                Circle()
                    .fill(Color.accentColor)
                    .frame(width: 8, height: 8)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(row.from)
                    .font(.headline)
                    .lineLimit(1)
                Text(row.subject)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text(row.receivedDate, format: .dateTime.month(.abbreviated).day().hour().minute())
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(rowAccessibilityLabel)
    }

    private var rowAccessibilityLabel: String {
        let unreadText = row.unread ? "Unread, " : ""
        let dateText = row.receivedDate.formatted(
            .dateTime.month(.abbreviated).day().hour().minute()
        )
        return unreadText + row.from + ", " + row.subject + ", " + dateText
    }
}
