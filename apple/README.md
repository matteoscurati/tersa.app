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

The iOS Dioxus target also exposes an opt-in, exact-head physical-device
observation mode. Signing values are accepted only through the ignored
`apple/local.xcconfig`; the checked-in example contains placeholders. The
capture script defaults to a no-action dry run, deletes raw Apple command
output, and emits only aggregate review-required evidence. See the
[device evidence protocol](../docs/m0/dioxus-device-evidence.md). This harness
does not change any M0 gate or select Dioxus.

The additive `TersaMimeMac` and `TersaMimeIOS` schemes compile a separate native
Swift WKWebView policy around the portable `tersa-mime-spike`. The macOS host
probe uses a nonpersistent data store, disabled content JavaScript, block-all
network rules, navigation denial, an App Sandbox with a network client but no
server entitlement, and a separate in-app transport-control canary run. The iOS schemes
provide locked compile evidence only; neither target is the production message
viewer.

Generate the project and use the reproducible build commands in
[Development](../docs/development.md#apple-bootstrap).

`rust-bridge`, both UI spikes, and the MIME diagnostic are part of the root
Cargo workspace, so the standard formatting, lint, test, documentation,
dependency, and advisory checks cover them. The bridge depends inward on
`tersa-application` and
`tersa-presentation`, preserving the rule that shared core layers never depend
on Apple frameworks.

The base targets also contain the M0 OAuth Authorization Code + PKCE adapter.
Rust owns S256 material, state, expiry, callback validation, and the macOS
literal-loopback listener. macOS opens the system browser only after the
listener is bound; iOS uses an ephemeral `ASWebAuthenticationSession` with an
exact build-injected callback scheme. Neither path starts automatically. This
slice does not exchange codes, store tokens, call Gmail, or claim a real Google
authorization. Run the deterministic fake-callback and signed sandbox probe as
documented in [Development](../docs/development.md#oauth-pkce-feasibility).

The six Apple targets narrowly disable Xcode user-script sandboxing only for
their Cargo build phases because Cargo and rustup read the compiler sysroot
outside `SRCROOT`. The scripts accept fixed platform/configuration values, use
the workspace lockfile, and write intermediates only below the ignored
`apple/build` directory. No other target inherits this exception.
