// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// Live inbox over the 2b read C ABI. The store is empty until Step 3 sync,
/// so a real read currently returns zero rows and renders the empty state;
/// the list and thread navigation render once data exists. The toolbar opens
/// the submit-only search screen and the read-only composer entry, and holds
/// the confirmation-gated disconnect control.
@MainActor
struct InboxView: View {
    let accountIdentifier: Data
    let freshness: MailboxFreshnessState
    let isRefreshing: Bool
    let reloadGeneration: UInt64
    let refreshNotice: MailboxRefreshNotice?
    let onRefresh: () -> Void
    let onReconnect: () -> Void
    let onDisconnect: () -> Void

    @State private var worker = MailboxReadWorker()
    @State private var outcome: MailboxReadOutcome?
    @State private var showingSearch = false
    @State private var showingComposer = false
    @State private var showingDisconnectConfirmation = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if freshness.isVisible {
                    freshnessBanner
                }
                if let refreshNotice {
                    refreshNoticeBanner(refreshNotice)
                }
                content
            }
                .navigationTitle("Inbox")
                .navigationDestination(for: String.self) { threadId in
                    ThreadView(
                        accountIdentifier: accountIdentifier,
                        threadIdentifier: Data(threadId.utf8)
                    )
                }
                .navigationDestination(isPresented: $showingSearch) {
                    SearchView(accountIdentifier: accountIdentifier)
                }
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Button(action: onRefresh) {
                            if isRefreshing {
                                ProgressView()
                                    .controlSize(.small)
                            } else {
                                Label("Refresh", systemImage: "arrow.clockwise")
                            }
                        }
                        .disabled(isRefreshing)
                        .accessibilityLabel("Refresh inbox")
                        .accessibilityValue(isRefreshing ? "Refreshing" : "Ready")
                        .accessibilityHint(isRefreshing ? "Inbox refresh is in progress." : "Refreshes mail using the connected account.")
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Button("Search", action: handleSearchTapped)
                            .accessibilityLabel("Search")
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Button("New Message", action: handleComposeTapped)
                            .keyboardShortcut("n", modifiers: .command)
                            .accessibilityLabel("New message")
                    }
                    // A rare, destructive account action belongs off the
                    // primary row: an overflow menu, one step from the
                    // high-frequency controls, behind its confirmation.
                    ToolbarItem(placement: .automatic) {
                        Menu {
                            Button("Disconnect Account…", action: handleDisconnectTapped)
                        } label: {
                            Image(systemName: "ellipsis.circle")
                        }
                        .accessibilityLabel("Account actions")
                    }
                }
        }
        .confirmationDialog(
            "Disconnect this account?",
            isPresented: $showingDisconnectConfirmation,
            titleVisibility: .visible
        ) {
            Button("Disconnect", role: .destructive, action: onDisconnect)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Tersa will stop having access to your Google Account, and mail stored on this Mac will be deleted. Your mail in Gmail is not affected.")
        }
        .sheet(isPresented: $showingComposer) {
            ComposerView()
        }
        .onAppear(perform: loadInbox)
        .onChange(of: reloadGeneration) { _, _ in
            reloadInbox()
        }
        .onChange(of: outcome) { _, newOutcome in
            announceOutcome(newOutcome)
        }
    }

    private var freshnessBanner: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: freshnessIcon)
                .foregroundStyle(freshnessColor)
                .accessibilityHidden(true)
            Text(freshness.message())
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
        .background(freshnessColor.opacity(0.12))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(freshness.accessibilityLabel)
        .accessibilityValue(freshness.message())
    }

    private func refreshNoticeBanner(_ notice: MailboxRefreshNotice) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text(notice.message)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            if notice.requiresExplicitReconnect {
                Button("Reconnect", action: onReconnect)
                    .accessibilityLabel("Reconnect account")
            }
            Spacer(minLength: 8)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
        .background(Color.orange.opacity(0.12))
        .accessibilityElement(children: .contain)
        .accessibilityLabel(notice.accessibilityLabel)
    }

    private var freshnessIcon: String {
        switch freshness {
        case .offline:
            return "wifi.slash"
        case .fresh, .unknown:
            return "checkmark.circle"
        }
    }

    private var freshnessColor: Color {
        switch freshness {
        case .offline:
            return .orange
        case .fresh, .unknown:
            return .secondary
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

    private func handleSearchTapped() {
        showingSearch = true
    }

    private func handleDisconnectTapped() {
        showingDisconnectConfirmation = true
    }

    private func handleComposeTapped() {
        showingComposer = true
    }

    private func announceOutcome(_ newOutcome: MailboxReadOutcome?) {
        guard let newOutcome else {
            return
        }
        AccessibilityNotification.Announcement(newOutcome.announcement).post()
    }
}
