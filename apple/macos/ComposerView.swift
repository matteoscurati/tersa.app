// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit
import SwiftUI

/// Fixed presentation copy for the composer sheet. The announcement is a
/// compile-time constant: it never interpolates recipient, subject, or body
/// text, so no draft content can reach an accessibility announcement.
enum ComposerPresentation {
    /// Announced when the composer sheet appears.
    static let presentationAnnouncement = "New message. Sending is not available in this version."
}

/// What the composer does with an intercepted body-editor key.
enum ComposerBodyKeyAction: Equatable {
    /// Forward Tab with Full Keyboard Access on: leave the editor for the
    /// next control (the Close button), which accepts key focus only then.
    case focusNextControl
    /// Forward Tab with Full Keyboard Access off: the Close button is not a
    /// valid key-focus destination, so wrap to the first field instead.
    case focusFirstField
    /// Backward traversal: leave the editor for the previous field (Subject).
    case focusPreviousField
    /// Escape: close the composer.
    case closeComposer
}

/// Pure focus-traversal decision for the composer body editor. A multiline
/// editor must not become a Full Keyboard Access trap: Tab and Shift-Tab move
/// focus out in logical order instead of inserting a tab character, and
/// Escape closes the composer. Shift-Tab may arrive either as Tab with the
/// Shift modifier or as the back-tab character U+0019; both map to backward
/// traversal. Every other key maps to no action, so ordinary text entry —
/// including IME and dead-key input — is unchanged.
enum ComposerFocusTraversal {
    /// The exact key set the body editor intercepts; all other keys reach the
    /// editor untouched. Pinned here so production and tests share one list.
    static let interceptedKeys: Set<KeyEquivalent> = [.tab, KeyEquivalent("\u{19}"), .escape]

    /// Maps an intercepted key to a composer action, or nil when the key is
    /// not one the body editor handles.
    static func action(
        for key: KeyEquivalent,
        shiftPressed: Bool,
        fullKeyboardAccessEnabled: Bool
    ) -> ComposerBodyKeyAction? {
        switch key {
        case .tab:
            if shiftPressed {
                return .focusPreviousField
            }
            // A Button is a key-focus destination only when macOS Full
            // Keyboard Access (all-controls navigation) is enabled. With it
            // off, forward Tab wraps to the To field, which always accepts
            // focus, instead of targeting an unfocusable control.
            return fullKeyboardAccessEnabled ? .focusNextControl : .focusFirstField
        case KeyEquivalent("\u{19}"):
            // Shift-Tab can arrive as the back-tab character U+0019 without
            // the Shift modifier retained; it is always backward traversal.
            return .focusPreviousField
        case .escape:
            return .closeComposer
        default:
            return nil
        }
    }
}

/// Composer entry presented as a sheet from the inbox action row. Phase 1 has no
/// send symbol, no network, and no write surface, so the sheet offers fields
/// and an honest notice instead of any send control. All text is in-memory
/// view state and is discarded when the sheet is dismissed.
@MainActor
struct ComposerView: View {
    private enum ComposerField: Hashable {
        case recipient
        case subject
        case body
        case close
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
                .accessibilityHeading(.h1)
            unavailableNotice
            composerForm
            HStack {
                Spacer()
                Button("Close", action: handleClose)
                    // Primary Escape path: the cancelAction shortcut. The
                    // body editor's Escape handling below is only a
                    // defense-in-depth fallback for when focus sits inside
                    // the editor, and must not justify removing this
                    // shortcut.
                    .keyboardShortcut(.cancelAction)
                    .accessibilityLabel("Close composer")
                    .focused($focusedField, equals: .close)
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
                // Full Keyboard Access must not trap inside the multiline
                // editor: only Tab, back-tab (U+0019), and Escape are
                // intercepted, on key-down only, so key repeat and ordinary
                // keys — including IME and dead-key input — never enter this
                // handler and reach the editor unchanged.
                .onKeyPress(keys: ComposerFocusTraversal.interceptedKeys, phases: .down) { press in
                    handleBodyKeyPress(press)
                }
        }
    }

    private func handleClose() {
        dismiss()
    }

    /// Applies the pure traversal decision to the focused field or the sheet.
    /// The narrow `onKeyPress` key set means only Tab, back-tab, and Escape
    /// reach this handler; the nil branch is defense in depth.
    private func handleBodyKeyPress(_ press: KeyPress) -> KeyPress.Result {
        guard let action = ComposerFocusTraversal.action(
            for: press.key,
            shiftPressed: press.modifiers.contains(.shift),
            fullKeyboardAccessEnabled: NSApplication.shared.isFullKeyboardAccessEnabled
        ) else {
            return .ignored
        }
        switch action {
        case .focusNextControl:
            focusedField = .close
            return .handled
        case .focusFirstField:
            focusedField = .recipient
            return .handled
        case .focusPreviousField:
            focusedField = .subject
            return .handled
        case .closeComposer:
            dismiss()
            return .handled
        }
    }

    /// Schedules the initial focus move and the presentation announcement as
    /// main-queue turns after `onAppear`, so the sheet can enter the
    /// responder chain before focus is written. The announcement waits one
    /// further nested turn so it is less likely to be dropped or immediately
    /// interrupted by the focus speech. This ordering is best-effort only —
    /// `DispatchQueue.main.async` does not guarantee that focus has settled
    /// or that the announcement is delivered in order. Whether the sequence
    /// is correct in practice remains to be confirmed by the owner VoiceOver
    /// walk.
    private func handleComposerAppear() {
        DispatchQueue.main.async {
            focusedField = .recipient
            DispatchQueue.main.async {
                AccessibilityNotification.Announcement(
                    ComposerPresentation.presentationAnnouncement
                ).post()
            }
        }
    }
}
