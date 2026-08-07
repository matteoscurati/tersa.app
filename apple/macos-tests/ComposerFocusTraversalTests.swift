// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI
import XCTest

final class ComposerFocusTraversalTests: XCTestCase {
    func testForwardTabLeavesTheEditorForTheCloseControlOnlyWithFullKeyboardAccess() {
        // The Close button is a valid key-focus destination only when macOS
        // Full Keyboard Access (all-controls navigation) is enabled.
        XCTAssertEqual(
            ComposerFocusTraversal.action(for: .tab, shiftPressed: false, fullKeyboardAccessEnabled: true),
            .focusNextControl
        )
    }

    func testForwardTabWrapsToTheFirstFieldWithoutFullKeyboardAccess() {
        // With Full Keyboard Access off the Close button cannot take key
        // focus, so forward Tab wraps to the To field, which always can.
        XCTAssertEqual(
            ComposerFocusTraversal.action(for: .tab, shiftPressed: false, fullKeyboardAccessEnabled: false),
            .focusFirstField
        )
    }

    func testShiftTabLeavesTheEditorForThePreviousFieldRegardlessOfFullKeyboardAccess() {
        XCTAssertEqual(
            ComposerFocusTraversal.action(for: .tab, shiftPressed: true, fullKeyboardAccessEnabled: true),
            .focusPreviousField
        )
        XCTAssertEqual(
            ComposerFocusTraversal.action(for: .tab, shiftPressed: true, fullKeyboardAccessEnabled: false),
            .focusPreviousField
        )
    }

    func testBackTabCharacterMapsToBackwardTraversalEvenWithoutShift() {
        // Shift-Tab may arrive as the back-tab character U+0019 with the
        // Shift modifier no longer set; it is still backward traversal.
        XCTAssertEqual(
            ComposerFocusTraversal.action(for: KeyEquivalent("\u{19}"), shiftPressed: false, fullKeyboardAccessEnabled: true),
            .focusPreviousField
        )
        XCTAssertEqual(
            ComposerFocusTraversal.action(for: KeyEquivalent("\u{19}"), shiftPressed: false, fullKeyboardAccessEnabled: false),
            .focusPreviousField
        )
    }

    func testEscapeClosesTheComposerWithOrWithoutShift() {
        // The production mapping returns the close action for Escape. Which
        // runtime path fires — the Close button's cancelAction shortcut or
        // the body-editor fallback handler — is not asserted here.
        XCTAssertEqual(
            ComposerFocusTraversal.action(for: .escape, shiftPressed: false, fullKeyboardAccessEnabled: true),
            .closeComposer
        )
        XCTAssertEqual(
            ComposerFocusTraversal.action(for: .escape, shiftPressed: true, fullKeyboardAccessEnabled: false),
            .closeComposer
        )
    }

    func testOrdinaryKeysMapToNoAction() {
        XCTAssertNil(
            ComposerFocusTraversal.action(for: KeyEquivalent("a"), shiftPressed: false, fullKeyboardAccessEnabled: true)
        )
        XCTAssertNil(
            ComposerFocusTraversal.action(for: .return, shiftPressed: false, fullKeyboardAccessEnabled: false)
        )
    }

    func testInterceptedKeySetIsExactlyTabBackTabAndEscape() {
        // The narrow onKeyPress key set: ordinary keys never enter the
        // handler, so IME and dead-key input reach the editor unchanged.
        XCTAssertEqual(
            ComposerFocusTraversal.interceptedKeys,
            [.tab, KeyEquivalent("\u{19}"), .escape]
        )
        XCTAssertFalse(ComposerFocusTraversal.interceptedKeys.contains(KeyEquivalent("a")))
    }

    func testPresentationAnnouncementIsFixedCopyThatNeverCarriesDraftContent() {
        let announcement = ComposerPresentation.presentationAnnouncement

        XCTAssertEqual(announcement, "New message. Sending is not available in this version.")
        // A sample of draft-shaped content must never appear in the copy.
        for sample in ["alice@example.com", "Q3 budget", "draft body text"] {
            XCTAssertFalse(announcement.contains(sample))
        }
    }
}
