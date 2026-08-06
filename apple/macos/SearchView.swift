// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation
import SwiftUI

/// Submit-only mailbox search over the 2b read C ABI. Each submit runs one
/// full open-read-scan-close through the worker; there is no live
/// per-keystroke search. The field validates length and control characters
/// inline before any ABI call — the Rust side re-validates authoritatively —
/// and every state change is announced to VoiceOver with strings built by
/// concatenation.
@MainActor
struct SearchView: View {
    let accountIdentifier: Data
    let onClose: () -> Void

    @State private var worker = MailboxReadWorker()
    @State private var outcome: MailboxReadOutcome?
    @State private var queryText = ""
    @State private var searching = false
    @State private var validationMessage: String?
    @State private var staleEditNoticeVisible = false
    @State private var didHandleInitialAppearance = false
    @FocusState private var searchFieldFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            searchHeader
            Divider()
            searchField
            if let validationMessage {
                validationBanner(validationMessage)
            }
            if staleEditNoticeVisible {
                staleEditBanner
            }
            content
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Search")
        .onChange(of: outcome) { _, newOutcome in
            announceSearchOutcome(newOutcome)
        }
        .onChange(of: searching) { _, isSearching in
            announceSearching(isSearching)
        }
        .onChange(of: queryText) { _, _ in
            validationMessage = nil
        }
        .onAppear(perform: handleSearchAppear)
    }

    private var searchHeader: some View {
        HStack {
            Text("Search")
                .font(.title2)
                .accessibilityAddTraits(.isHeader)
                .accessibilityHeading(.h1)
            Spacer()
            Button("Close", action: onClose)
                .keyboardShortcut(.cancelAction)
                .accessibilityLabel("Close search")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var searchField: some View {
        HStack(spacing: 10) {
            TextField("Search sender or subject", text: $queryText)
                .textFieldStyle(.roundedBorder)
                .onSubmit(handleSearchSubmit)
                .accessibilityLabel("Search sender or subject")
                .accessibilityAddTraits(.isSearchField)
                .focused($searchFieldFocused)
            Button("Search", action: handleSearchSubmit)
                .disabled(searching)
                .accessibilityLabel("Search mailbox")
        }
        .padding(16)
    }

    @ViewBuilder
    private var content: some View {
        if searching {
            loadingContent
        } else {
            switch outcome {
            case .none:
                idleContent
            case .some(.empty):
                noResultsContent
            case .some(.content(let rows)):
                resultsList(rows)
            case .some(.failure(let failure)):
                searchFailure(failure)
            }
        }
    }

    private var loadingContent: some View {
        ProgressView()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .accessibilityLabel("Searching")
            .accessibilityValue("In progress")
    }

    private var idleContent: some View {
        VStack(spacing: 16) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Search your mailbox")
                .font(.title2)
                .accessibilityAddTraits(.isHeader)
                .accessibilityHeading(.h1)
            Text("Type a sender or subject, then press Return to search.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
    }

    private var noResultsContent: some View {
        VStack(spacing: 16) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("No results")
                .font(.title2)
                .accessibilityAddTraits(.isHeader)
                .accessibilityHeading(.h1)
            Text("No messages match this search.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
    }

    private func resultsList(_ rows: [MessageRow]) -> some View {
        List(rows) { row in
            NavigationLink(value: row.threadId) {
                MailboxMessageRowView(row: row)
            }
        }
        .accessibilityLabel("Search results")
        .accessibilityValue(String(rows.count) + (rows.count == 1 ? " result" : " results"))
    }

    private func searchFailure(_ failure: MailboxReadFailure) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 48))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("The search could not be completed")
                .font(.title2)
                .accessibilityAddTraits(.isHeader)
                .accessibilityHeading(.h1)
            Text(failure.message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Try again", action: handleSearchReloadTapped)
                .keyboardShortcut(.defaultAction)
                .accessibilityLabel("Try again")
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func validationBanner(_ message: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text(message)
                .font(.callout)
                .multilineTextAlignment(.center)
        }
        .padding(12)
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(message)
    }

    /// The deterministic status for a discarded stale result: the field was
    /// edited mid-search, the dropped result stays suppressed, and the user is
    /// told that Return searches again. Fixed copy — it never names the query.
    private var staleEditBanner: some View {
        HStack(spacing: 6) {
            Image(systemName: "info.circle.fill")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(SearchCompletionGuard.staleEditStatus)
                .font(.callout)
                .multilineTextAlignment(.center)
        }
        .padding(12)
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(SearchCompletionGuard.staleEditStatus)
    }

    /// Validates the field, then enqueues one bounded search. A resubmit while
    /// a search is in flight is rejected with one fixed announced status —
    /// never silently. An empty or invalid field sets an inline banner and
    /// posts one direct announcement per submit, and never reaches the ABI.
    private func handleSearchSubmit() {
        switch SearchSubmitGuard.decision(searching: searching) {
        case .rejectInFlight:
            AccessibilityNotification.Announcement(SearchSubmitGuard.inProgressStatus).post()
            return
        case .submitField:
            break
        }
        validationMessage = nil
        staleEditNoticeVisible = false
        switch SearchFieldValidator.decision(forFieldText: queryText) {
        case .emptyField:
            validationMessage = SearchFieldValidator.emptyFieldMessage
            AccessibilityNotification.Announcement(SearchFieldValidator.emptyFieldMessage).post()
            return
        case .invalid(let message):
            validationMessage = message
            AccessibilityNotification.Announcement(message).post()
            return
        case .validatedQuery(let query):
            runSearch(query)
        }
    }

    /// Try again uses the same current-field validation and submit path as
    /// Return. The field is never rewritten to an earlier query.
    private func handleSearchReloadTapped() {
        handleSearchSubmit()
    }

    private func runSearch(_ query: String) {
        searching = true
        outcome = nil
        worker.enqueueSearch(accountIdentifier: accountIdentifier, query: Data(query.utf8)) { result in
            self.searching = false
            // Display the result only if the field still shows the query it was
            // for. If the user edited the field while the search was in flight,
            // drop the mismatched result — but never silently.
            switch SearchCompletionGuard.decision(
                completedQuery: query,
                currentFieldText: self.queryText
            ) {
            case .displayResult:
                self.staleEditNoticeVisible = false
                self.outcome = result
            case .discardStale:
                self.staleEditNoticeVisible = true
                AccessibilityNotification.Announcement(SearchCompletionGuard.staleEditStatus).post()
            }
        }
    }

    private func announceSearching(_ isSearching: Bool) {
        guard isSearching else {
            return
        }
        AccessibilityNotification.Announcement("Searching").post()
    }

    private func handleSearchAppear() {
        guard !didHandleInitialAppearance else {
            return
        }
        didHandleInitialAppearance = true
        searchFieldFocused = true
        AccessibilityNotification.Announcement("Search opened").post()
    }

    private func announceSearchOutcome(_ newOutcome: MailboxReadOutcome?) {
        guard let newOutcome else {
            return
        }
        AccessibilityNotification.Announcement(searchAnnouncement(for: newOutcome)).post()
    }

    /// Spoken text for a finished search. Distinct from the inbox read
    /// announcement: an empty search says "No results", not "No messages".
    private func searchAnnouncement(for outcome: MailboxReadOutcome) -> String {
        switch outcome {
        case .content(let rows):
            return String(rows.count) + (rows.count == 1 ? " result" : " results")
        case .empty:
            return "No results"
        case .failure(let failure):
            return failure.message
        }
    }
}
