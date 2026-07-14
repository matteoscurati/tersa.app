# Apple bootstrap

This directory contains the M0 Apple bootstrap for arm64 macOS 15 and
iOS/iPadOS 18. `TersaMac` and `TersaIOS` remain intentionally minimal AppKit
and UIKit lifecycle targets with a Rust static-library link.

The additive `TersaSlintMac` and `TersaSlintIOS` schemes package the separate
`tersa-slint-spike` Rust executable using Slint's Winit and Skia path. They are
diagnostic mock UI targets, not product UI. They do not use Gmail, OAuth,
storage, networking, HTML, or WKWebView.

Generate the project and use the reproducible build commands in
[Development](../docs/development.md#apple-bootstrap).

`rust-bridge` and `tersa-slint-spike` are part of the root Cargo workspace so the standard formatting,
lint, test, documentation, dependency, and advisory checks cover it. The bridge
depends on `tersa-presentation`, preserving the one-way rule that shared core
layers never depend on Apple frameworks.

The four Apple targets narrowly disable Xcode user-script sandboxing only for
their Cargo build phases because Cargo and rustup read the compiler sysroot
outside `SRCROOT`. The scripts accept fixed platform/configuration values, use
the workspace lockfile, and write intermediates only below the ignored
`apple/build` directory. No other target inherits this exception.
