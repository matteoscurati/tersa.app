# Apple bootstrap

This directory contains the M0 PR3 bootstrap for arm64 macOS 15 and
iOS/iPadOS 18. It is intentionally limited to AppKit and UIKit lifecycle
entry points, explicit metadata and entitlements, and a Rust static-library
link. It contains no product UI and no Slint integration.

Generate the project and use the reproducible build commands in
[Development](../docs/development.md#apple-bootstrap).

`rust-bridge` is part of the root Cargo workspace so the standard formatting,
lint, test, documentation, dependency, and advisory checks cover it. The bridge
depends on `tersa-presentation`, preserving the one-way rule that shared core
layers never depend on Apple frameworks.

The two Apple targets narrowly disable Xcode user-script sandboxing for their
Cargo pre-build phase because Cargo and rustup read the compiler sysroot outside
`SRCROOT`. The script accepts fixed platform/configuration values, uses the
workspace lockfile, and writes build products only below the ignored
`apple/build` directory. No other target inherits this exception.
