# Apple bootstrap

This directory contains the Apple product targets for arm64 macOS 15 and the
deferred iOS/iPadOS 18 feasibility target. `TersaMac` is the active native
AppKit/SwiftUI product slice; `TersaIOS` is not a Phase 1 product claim.

Phase 1 product implementation is macOS-only. The current single-account slice
owns the fixed-profile bootstrap, brokered OAuth and refresh-token lifecycle,
bounded read-only Gmail snapshot synchronization, encrypted cached inbox and
thread, cached-metadata search, offline reopen, and composer entry. It does not
implement send, drafts, mailbox mutations, attachments, multi-account, Gmail
History synchronization, or public distribution. All iPhone and iPad product
work remains deferred to Phase 2.

Historical M0 MIME diagnostics were removed by ADR-0025. The active macOS UI is
now plain-text-only: it does not import WebKit, expose an HTML toggle, or decode
the bridge's `body_html` field. The core and bridge can still extract and
serialize untrusted HTML, so this is containment rather than an approved MIME
security boundary. `xtask` blocks WebKit/raw-HTML UI surfaces until a separately
approved `SafeHtml` boundary replaces that policy. See the
[threat model](../docs/security/threat-model.md).

Generate the project and use the reproducible build commands in
[Development](../docs/development.md#apple-bootstrap).

`rust-bridge` is part of the root Cargo workspace, so the standard formatting,
lint, test, documentation, dependency, and advisory checks cover it. The bridge
depends inward on `tersa-application`, `tersa-presentation`, and, on macOS only,
`tersa-keychain-macos` for the one-shot product bootstrap command. It receives
no key, database path, store, profile, or reusable storage capability,
preserving the rule that shared core layers never depend on Apple frameworks.

The macOS product flow uses Authorization Code + PKCE through the embedded
token broker. The main app owns the bounded literal-loopback listener and
system-browser handoff; the broker owns PKCE sessions, code exchange, refresh,
revocation, and refresh-token persistence. A short-lived access token crosses
back to the main app only for the bounded sync call and is then wiped from the
owning Swift buffer. The iOS feasibility path still uses the bridge's
`legacy-oauth` feature, while the product macOS archive rejects that legacy
surface through its closed contract. Product OAuth and token authority follow
[ADR 0023](../docs/architecture/adr-0023-step3-oauth-and-bounded-sync.md) and
[ADR 0024](../docs/architecture/adr-0024-macos-token-process-isolation.md). See
[Development](../docs/development.md#oauth-pkce) for local configuration
boundaries.

The Apple targets narrowly disable Xcode user-script sandboxing only for their
Cargo build phases because Cargo and rustup read the compiler sysroot outside
`SRCROOT`. The scripts accept fixed platform/configuration values, use the
workspace lockfile, and write intermediates only below the ignored
`apple/build` directory. No other target inherits this exception.

`TersaMac` also embeds the `TersaMacTokenBroker` XPC service required by
[ADR 0024](../docs/architecture/adr-0024-macos-token-process-isolation.md). The
broker target lives under `macos-token-broker`, declares only App Sandbox,
outbound network client, and the dedicated token Keychain access group, and
exports a closed fail-closed version-1 NSXPC protocol with the reviewed
operational status set. It links the dedicated
`tersa-token-broker-ffi-macos` archive (broker core + Google transport +
broker-only Keychain store) and never the main app's mailbox-sync archive.
The main app hosts the closed `TokenBrokerClient` and authorization-session
mapping surface. Source cutover is complete: the product macOS archive does not
link the legacy in-process token path. Production closure is not complete: the
dedicated account and token groups still require real team provisioning, and
the signed/notarized process-isolation and wrong-group denial evidence remains
open. Unsigned local builds prove behavior only, not principal isolation.
