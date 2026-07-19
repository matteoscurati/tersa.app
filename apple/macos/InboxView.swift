// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// Live inbox over the 2b read C ABI. The store is empty until Step 3 sync,
/// so a real read currently returns zero rows and renders the empty state;
/// the list and thread navigation render once data exists.
@MainActor
struct InboxView: View {
    let accountIdentifier: Data

    @State private var worker = MailboxReadWorker()
    @State private var outcome: MailboxReadOutcome?

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Inbox")
                .navigationDestination(for: String.self) { threadId in
                    ThreadView(
                        accountIdentifier: accountIdentifier,
                        threadIdentifier: Data(threadId.utf8)
                    )
                }
        }
        .onAppear(perform: loadInbox)
        .onChange(of: outcome) { _, newOutcome in
            announceOutcome(newOutcome)
        }
    }

    @ViewBuilder
    private var content: some View {
        switch outcome {
        case .none:
            loadingContent
        case .some(.empty):
            InboxEmptyStateView()
        case .some(.content(let rows)):
            inboxList(rows)
        case .some(.failure(let failure)):
            inboxFailure(failure)
        }
    }

    private var loadingContent: some View {
        ProgressView()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .accessibilityLabel("Loading inbox")
            .accessibilityValue("In progress")
    }

    private func inboxList(_ rows: [MessageRow]) -> some View {
        List(rows) { row in
            NavigationLink(value: row.threadId) {
                MailboxMessageRowView(row: row)
            }
        }
        .accessibilityLabel("Inbox")
        .accessibilityValue(String(rows.count) + (rows.count == 1 ? " message" : " messages"))
    }

    private func inboxFailure(_ failure: MailboxReadFailure) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 48))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("The inbox could not be loaded")
                .font(.title2)
            Text(failure.message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Try again", action: handleReloadTapped)
                .keyboardShortcut(.defaultAction)
                .accessibilityLabel("Try again")
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func loadInbox() {
        worker.enqueueRead(accountIdentifier: accountIdentifier) { result in
            self.outcome = result
        }
    }

    private func reloadInbox() {
        outcome = nil
        loadInbox()
    }

    private func handleReloadTapped() {
        reloadInbox()
    }

    private func announceOutcome(_ newOutcome: MailboxReadOutcome?) {
        guard let newOutcome else {
            return
        }
        AccessibilityNotification.Announcement(newOutcome.announcement).post()
    }
}
