// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// Live inbox over the 2b read C ABI. The store is empty until Step 3 sync,
/// so a real read currently returns zero rows and renders the empty state;
/// the list and thread navigation render once data exists. The visible inbox
/// action row opens the submit-only search screen and the read-only composer
/// entry, and holds the confirmation-gated disconnect control.
@MainActor
struct InboxView: View {
    private enum PresentedSheet: String, Identifiable {
        case search
        case composer

        var id: String { rawValue }
    }

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
    @State private var presentedSheet: PresentedSheet?
    @State private var showingDisconnectConfirmation = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                inboxActionBar
                Divider()
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
                    threadDestination(for: threadId)
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
        .sheet(item: $presentedSheet) { sheet in
            switch sheet {
            case .search:
                NavigationStack {
                    SearchView(
                        accountIdentifier: accountIdentifier,
                        onClose: { presentedSheet = nil }
                    )
                        .navigationDestination(for: String.self) { threadId in
                            threadDestination(for: threadId)
                        }
                }
                .frame(minWidth: 480, minHeight: 360)
            case .composer:
                ComposerView()
            }
        }
        .onAppear(perform: loadInbox)
        .onChange(of: reloadGeneration) { _, _ in
            reloadInbox()
        }
        .onChange(of: outcome) { _, newOutcome in
            announceOutcome(newOutcome)
        }
    }

    /// A content-level action row stays visible when `InboxView` is hosted by
    /// AppKit's `NSHostingController`, where scene-owned SwiftUI toolbars are
    /// not materialized. These are the primary inbox controls, not a duplicate
    /// fallback toolbar.
    private var inboxActionBar: some View {
        HStack(spacing: 10) {
            Button(action: onRefresh) {
                Label {
                    Text("Refresh")
                } icon: {
                    if isRefreshing {
                        ProgressView()
                            .controlSize(.small)
                            .frame(width: 16, height: 16)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .frame(width: 16, height: 16)
                    }
                }
            }
            .disabled(isRefreshing)
            .accessibilityLabel("Refresh inbox")
            .accessibilityValue(isRefreshing ? "Refreshing" : "Ready")
            .accessibilityHint(
                isRefreshing
                    ? "Inbox refresh is in progress."
                    : "Refreshes mail using the connected account."
            )

            Button(action: handleSearchTapped) {
                Image(systemName: "magnifyingglass")
            }
            .accessibilityLabel("Search")
            .help("Search")

            Button(action: handleComposeTapped) {
                Image(systemName: "square.and.pencil")
            }
            .accessibilityLabel("New message")
            .help("New message")

            Spacer(minLength: 8)

            // Keep the rare destructive account action away from the primary
            // controls, one step behind an overflow menu and its confirmation.
            Menu {
                Button("Disconnect Account…", action: handleDisconnectTapped)
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .accessibilityLabel("Account actions")
            .help("Account actions")
        }
        .buttonStyle(.bordered)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
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
        presentedSheet = .search
    }

    private func handleDisconnectTapped() {
        // Let NSMenu finish dismissing before presenting the confirmation;
        // presenting synchronously from its action can be swallowed on macOS.
        Task { @MainActor in
            await Task.yield()
            showingDisconnectConfirmation = true
        }
    }

    private func handleComposeTapped() {
        presentedSheet = .composer
    }

    private func threadDestination(for threadId: String) -> some View {
        ThreadView(
            accountIdentifier: accountIdentifier,
            threadIdentifier: Data(threadId.utf8)
        )
    }

    private func announceOutcome(_ newOutcome: MailboxReadOutcome?) {
        guard let newOutcome else {
            return
        }
        AccessibilityNotification.Announcement(newOutcome.announcement).post()
    }
}
