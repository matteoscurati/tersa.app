# Apple bootstrap

This directory contains the M0 Apple bootstrap for arm64 macOS 15 and
iOS/iPadOS 18. `TersaMac` and `TersaIOS` remain intentionally minimal AppKit
and UIKit lifecycle targets with a Rust static-library link.

The additive `TersaSlintMac` and `TersaSlintIOS` schemes package the separate
`tersa-slint-spike` Rust executable using Slint's Winit and Skia path. They are
diagnostic mock UI targets, not product UI. They do not use Gmail, OAuth,
storage, networking, HTML, or WKWebView.

The additive `TersaDioxusMac` and `TersaDioxusIOS` schemes package the separate
`tersa-dioxus-spike` executable directly with locked Cargo. They do not invoke
the Dioxus CLI or Manganis. This diagnostic uses synthetic HTML in the system
WebView and Dioxus's authenticated loopback UI transport. It is not a product
UI, backend, sandbox-compatibility claim, or permission to persist mail in
WebKit.

Generate the project and use the reproducible build commands in
[Development](../docs/development.md#apple-bootstrap).

`rust-bridge` and both UI spikes are part of the root Cargo workspace so the
standard formatting, lint, test, documentation, dependency, and advisory
checks cover them. The bridge
depends on `tersa-presentation`, preserving the one-way rule that shared core
layers never depend on Apple frameworks.

The six Apple targets narrowly disable Xcode user-script sandboxing only for
their Cargo build phases because Cargo and rustup read the compiler sysroot
outside `SRCROOT`. The scripts accept fixed platform/configuration values, use
the workspace lockfile, and write intermediates only below the ignored
`apple/build` directory. No other target inherits this exception.
