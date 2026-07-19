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
    @State private var selectedMessageId: String?
    @State private var navigationPath = NavigationPath()

    var body: some View {
        NavigationStack(path: $navigationPath) {
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
        .onChange(of: selectedMessageId) { _, messageId in
            handleThreadSelected(messageId)
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

    private var loadedRows: [MessageRow] {
        guard case .some(.content(let rows)) = outcome else {
            return []
        }
        return rows
    }

    private func inboxList(_ rows: [MessageRow]) -> some View {
        List(rows, selection: $selectedMessageId) { row in
            inboxRow(row)
        }
        .accessibilityLabel("Inbox")
        .accessibilityValue(String(rows.count) + (rows.count == 1 ? " message" : " messages"))
    }

    private func inboxRow(_ row: MessageRow) -> some View {
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
        .accessibilityLabel(rowLabel(row))
    }

    private func rowLabel(_ row: MessageRow) -> String {
        let unreadText = row.unread ? "Unread, " : ""
        let dateText = row.receivedDate.formatted(.dateTime.month(.abbreviated).day().hour().minute())
        return unreadText + row.from + ", " + row.subject + ", " + dateText
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
        .accessibilityLabel("The inbox could not be loaded")
        .accessibilityValue(failure.message)
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

    private func handleThreadSelected(_ messageId: String?) {
        guard let messageId,
              let row = loadedRows.first(where: { $0.id == messageId })
        else {
            return
        }
        openThread(row.threadId)
    }

    private func openThread(_ threadId: String) {
        navigationPath.append(threadId)
    }

    private func announceOutcome(_ newOutcome: MailboxReadOutcome?) {
        guard let newOutcome else {
            return
        }
        AccessibilityNotification.Announcement(newOutcome.announcement).post()
    }
}
