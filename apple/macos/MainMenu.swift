// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit

/// The minimal programmatic main menu: an App menu with Quit, and a standard
/// Edit menu so text editing and Full Keyboard Access work.
@MainActor
enum MainMenu {
    static func install() {
        let mainMenu = NSMenu()

        let applicationMenuItem = NSMenuItem()
        mainMenu.addItem(applicationMenuItem)
        let applicationMenu = NSMenu()
        applicationMenuItem.submenu = applicationMenu
        applicationMenu.addItem(
            NSMenuItem(
                title: "Quit Tersa",
                action: #selector(NSApplication.terminate(_:)),
                keyEquivalent: "q"
            )
        )

        let editMenuItem = NSMenuItem()
        mainMenu.addItem(editMenuItem)
        let editMenu = NSMenu(title: "Edit")
        editMenuItem.submenu = editMenu
        // Undo/redo dispatch up the responder chain to the focused field
        // editor's undo manager; these are the standard AppKit action selectors.
        editMenu.addItem(
            NSMenuItem(title: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        )
        editMenu.addItem(
            NSMenuItem(title: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        )
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(
            NSMenuItem(title: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        )
        editMenu.addItem(
            NSMenuItem(title: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        )
        editMenu.addItem(
            NSMenuItem(title: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        )
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(
            NSMenuItem(title: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        )

        NSApp.mainMenu = mainMenu
    }
}
