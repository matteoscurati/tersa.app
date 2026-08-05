# Apple bootstrap

This directory contains the Apple bootstrap for arm64 macOS 15 and iOS/iPadOS
18. `TersaMac` and `TersaIOS` remain intentionally minimal AppKit and UIKit
lifecycle targets with a Rust static-library link.

Phase 1 product implementation is macOS-only. `TersaMac` owns the bounded
source path that submits a real opaque account identifier to the one-pending
bootstrap worker, which invokes the Keychain adapter's fixed-profile command
off the main thread. This credentialless source evidence adds no target,
entitlement, signing, package, OAuth, network, or real-account fixture. All
iPhone and iPad product work remains deferred to Phase 2; the existing mobile
targets below remain feasibility diagnostics only.

Historical note: the M0 MIME Apple diagnostic schemes and portable MIME spike
were removed by ADR-0025 housekeeping. No Apple MIME diagnostic target,
WKWebView hostile-content probe, or MIME renderer remains in this tree.
Hostile-content handling remains a product security requirement; see the
[M0 historical summary](../docs/history/m0-summary.md).

Generate the project and use the reproducible build commands in
[Development](../docs/development.md#apple-bootstrap).

`rust-bridge` is part of the root Cargo workspace, so the standard formatting,
lint, test, documentation, dependency, and advisory checks cover it. The bridge
depends inward on `tersa-application`, `tersa-presentation`, and, on macOS only,
`tersa-keychain-macos` for the one-shot product bootstrap command. It receives
no key, database path, store, profile, or reusable storage capability,
preserving the rule that shared core layers never depend on Apple frameworks.

The base targets also contain the OAuth Authorization Code + PKCE adapter. Rust
owns S256 material, state, expiry, callback validation, and the macOS
literal-loopback listener. macOS opens the system browser only after the
listener is bound; iOS uses an ephemeral `ASWebAuthenticationSession` with an
exact build-injected callback scheme. The `legacy-oauth` bridge feature remains
required for the active iOS path and still exports the legacy macOS begin/poll
surface for source completeness; the product macOS archive rejects that legacy
surface through its closed contract. Neither path starts automatically. This
slice does not exchange codes, store tokens, call Gmail, or claim a real Google
authorization. Product OAuth and token authority follow
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
mapping surface, but production cutover is **not** complete: OAuth and token
authority remain in-process in `TersaMac` until a later point, the dedicated
token group is not provisioned under the production team, and local builds
remain unsigned unless signing is configured.
