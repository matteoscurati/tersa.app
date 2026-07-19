// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// One thread over the 2b read C ABI, opened from the inbox list. Exercised
/// only once the store holds data; the loading, empty, and failure states
/// mirror the inbox.
@MainActor
struct ThreadView: View {
    let accountIdentifier: Data
    let threadIdentifier: Data

    @State private var worker = MailboxReadWorker()
    @State private var outcome: MailboxReadOutcome?

    var body: some View {
        content
            .navigationTitle("Thread")
            .onAppear(perform: loadThread)
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
            threadEmpty
        case .some(.content(let rows)):
            threadList(rows)
        case .some(.failure(let failure)):
            threadFailure(failure)
        }
    }

    private var loadingContent: some View {
        ProgressView()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .accessibilityLabel("Loading thread")
            .accessibilityValue("In progress")
    }

    private var threadEmpty: some View {
        VStack(spacing: 16) {
            Image(systemName: "tray")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("No messages in this thread")
                .font(.title2)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("No messages in this thread")
    }

    private func threadList(_ rows: [MessageRow]) -> some View {
        List(rows) { row in
            threadRow(row)
        }
        .accessibilityLabel("Thread")
        .accessibilityValue(String(rows.count) + (rows.count == 1 ? " message" : " messages"))
    }

    private func threadRow(_ row: MessageRow) -> some View {
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

    private func threadFailure(_ failure: MailboxReadFailure) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 48))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("The thread could not be loaded")
                .font(.title2)
            Text(failure.message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Try again", action: handleThreadReloadTapped)
                .keyboardShortcut(.defaultAction)
                .accessibilityLabel("Try again")
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityLabel("The thread could not be loaded")
        .accessibilityValue(failure.message)
    }

    private func loadThread() {
        worker.enqueueRead(
            accountIdentifier: accountIdentifier,
            threadIdentifier: threadIdentifier
        ) { result in
            self.outcome = result
        }
    }

    private func reloadThread() {
        outcome = nil
        loadThread()
    }

    private func handleThreadReloadTapped() {
        reloadThread()
    }

    private func announceOutcome(_ newOutcome: MailboxReadOutcome?) {
        guard let newOutcome else {
            return
        }
        AccessibilityNotification.Announcement(newOutcome.announcement).post()
    }
}
