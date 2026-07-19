// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// First-class empty state for the inbox. `InboxView` renders it when a live
/// mailbox read over the 2b read C ABI returns zero rows, which is every read
/// until Step 3 sync fills the store; no demo data is involved.
@MainActor
struct InboxEmptyStateView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "tray")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Inbox is empty")
                .font(.title2)
            Text("New messages will appear here when they arrive.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Inbox is empty")
        .accessibilityValue("No messages")
        .accessibilityHint("New messages will appear here when they arrive.")
    }
}
