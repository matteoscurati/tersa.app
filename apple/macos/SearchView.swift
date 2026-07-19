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
    private static let maximumQueryByteCount = 256

    let accountIdentifier: Data

    @State private var worker = MailboxReadWorker()
    @State private var outcome: MailboxReadOutcome?
    @State private var queryText = ""
    @State private var submittedQuery = ""
    @State private var searching = false
    @State private var validationMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            if let validationMessage {
                validationBanner(validationMessage)
            }
            content
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Search")
        .searchable(text: $queryText, prompt: "Search sender or subject")
        .onSubmit(of: .search) {
            handleSearchSubmit()
        }
        .onChange(of: outcome) { _, newOutcome in
            announceSearchOutcome(newOutcome)
        }
        .onChange(of: searching) { _, isSearching in
            announceSearching(isSearching)
        }
        .onChange(of: validationMessage) { _, newMessage in
            announceValidationMessage(newMessage)
        }
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

    /// Validates the field, then enqueues one bounded search. An empty field
    /// does nothing; an over-limit or control-character field sets an inline
    /// message and never reaches the ABI.
    private func handleSearchSubmit() {
        // Serialize submits: the worker serves one request at a time, so a
        // resubmit while a search is in flight is ignored to avoid displaying an
        // earlier query's results under the current text.
        guard !searching else {
            return
        }
        validationMessage = nil
        let trimmed = queryText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return
        }
        guard trimmed.utf8.count <= Self.maximumQueryByteCount else {
            validationMessage = "Search text is limited to 256 bytes. Shorten it and try again."
            return
        }
        guard !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            validationMessage = "Search text cannot contain control characters."
            return
        }
        submittedQuery = trimmed
        runSearch(trimmed)
    }

    private func handleSearchReloadTapped() {
        // Restore the field to the query being retried so its completed result
        // is not dropped by the field-match guard below.
        queryText = submittedQuery
        runSearch(submittedQuery)
    }

    private func runSearch(_ query: String) {
        searching = true
        outcome = nil
        worker.enqueueSearch(accountIdentifier: accountIdentifier, query: Data(query.utf8)) { result in
            self.searching = false
            // Display the result only if the field still shows the query it was
            // for. If the user edited the field while the search was in flight,
            // the earlier query's result would be mismatched, so drop it — the
            // view returns to the idle prompt and the new query can be submitted.
            guard query == self.queryText.trimmingCharacters(in: .whitespacesAndNewlines) else {
                return
            }
            self.outcome = result
        }
    }

    private func announceSearching(_ isSearching: Bool) {
        guard isSearching else {
            return
        }
        AccessibilityNotification.Announcement("Searching").post()
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

    private func announceValidationMessage(_ message: String?) {
        guard let message else {
            return
        }
        AccessibilityNotification.Announcement(message).post()
    }
}
