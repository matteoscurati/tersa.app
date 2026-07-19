// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// Composer entry presented as a sheet from the inbox toolbar. Phase 1 has no
/// send symbol, no network, and no write surface, so the sheet offers fields
/// and an honest notice instead of any send control. All text is in-memory
/// view state and is discarded when the sheet is dismissed.
@MainActor
struct ComposerView: View {
    private enum ComposerField: Hashable {
        case recipient
        case subject
        case body
    }

    @Environment(\.dismiss) private var dismiss
    @State private var recipientText = ""
    @State private var subjectText = ""
    @State private var bodyText = ""
    @FocusState private var focusedField: ComposerField?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("New Message")
                .font(.title2)
                .accessibilityAddTraits(.isHeader)
            unavailableNotice
            composerForm
            HStack {
                Spacer()
                Button("Close", action: handleClose)
                    .keyboardShortcut(.cancelAction)
                    .accessibilityLabel("Close composer")
            }
        }
        .padding(24)
        .frame(minWidth: 480, minHeight: 420)
        .onAppear(perform: handleComposerAppear)
    }

    private var unavailableNotice: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "info.circle")
                .accessibilityHidden(true)
            Text("Sending is not available in this version. Anything you type here is discarded when you close this composer.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Sending is not available in this version. Anything you type here is discarded when you close this composer.")
    }

    private var composerForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("To")
                .font(.callout)
                .accessibilityHidden(true)
            TextField("To", text: $recipientText)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel("To")
                .focused($focusedField, equals: .recipient)
            Text("Subject")
                .font(.callout)
                .accessibilityHidden(true)
            TextField("Subject", text: $subjectText)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel("Subject")
                .focused($focusedField, equals: .subject)
            Text("Body")
                .font(.callout)
                .accessibilityHidden(true)
            TextEditor(text: $bodyText)
                .frame(minHeight: 160)
                .overlay(
                    RoundedRectangle(cornerRadius: 4)
                        .stroke(Color.secondary.opacity(0.4), lineWidth: 1)
                )
                .accessibilityLabel("Body")
                .focused($focusedField, equals: .body)
        }
    }

    private func handleClose() {
        dismiss()
    }

    /// Moves focus to the To field and announces the sheet, including the
    /// unavailable-send notice, to VoiceOver.
    private func handleComposerAppear() {
        focusedField = .recipient
        AccessibilityNotification.Announcement(
            "New message. Sending is not available in this version."
        ).post()
    }
}
