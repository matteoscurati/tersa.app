# ADR 0005: Dioxus diagnostic runtime boundary

## Status

Accepted for an M0 diagnostic spike. Rejected as the production UI baseline
until every blocking condition below is resolved and independently reviewed.

## Context

The Slint iOS accessibility gate failed, so the product plan requires a Dioxus
WebView feasibility spike. The spike must test the official 0.7 runtime without
making the core or Apple bootstrap depend on the Dioxus CLI, a backend, remote
assets, or real mail data.

Dioxus 0.7.9 uses `dioxus-desktop` and Wry for both desktop and mobile
WebViews. Its renderer opens an authenticated WebSocket listener on an
ephemeral `127.0.0.1` port. This is private in-process UI transport, not a
product backend, but it is still a listening TCP socket and must be treated as
a security and sandbox boundary.

## Decision

`tersa-dioxus-spike` pins `dioxus` and `dioxus-desktop` to exactly 0.7.9. It is
an Apple-target-only standalone executable built directly with locked Cargo.
Xcode packages the executable without `dx`, Manganis, a JavaScript build step,
or an Apple Swift lifecycle host.

The umbrella crate enables only the hooks, HTML, macro, and signals features.
`dioxus-desktop` disables default features and enables only `tokio_runtime`.
The runtime feature is required because 0.7.9 imports `tokio::sync::Notify` and
calls `tokio::task::yield_now` unconditionally in `edits.rs`; compiling with no
features fails even though `launch.rs` contains a nominal non-Tokio branch.
The `dioxus-devtools` package and transparent-window feature remain disabled.
The unsigned packages use Release under the narrow local-fork change recorded
in ADR-0008. It compiles the `dioxus-desktop` devtools handler, state, and menu
strings only under debug assertions, so feature-minimal Release omits those
calls and strings without enabling Wry's `devtools` feature or private WebKit
APIs. Debug behavior remains upstream-compatible.

The diagnostic renders 10,000 synthetic rows with a handwritten fixed-height
virtualizer. Only the visible range plus six overscan rows on either side is
materialized. It uses semantic list/listitem structure, labelled controls,
visible focus treatment, a multiline textarea, reduced-motion handling, and
CSS safe-area insets. Tao `Resumed` and `Suspended` events emit fixed diagnostic
markers without content.

The rendered diagnostic contains no anchors, remote assets, server functions,
Gmail code, or credentials, and the application does not explicitly save its
synthetic UI state. Its evidence-only mode injects synthetic URLs to exercise
the locally patched deny boundary described in ADR-0007. This is not sufficient
for untrusted production email content.

CI verifies every Apple target's resolved feature set, the absence of Manganis
and Dioxus devtools, the exact loopback bind expression, independent CSPRNG
creation and constant-time validation of the 256-byte mutual WebSocket keys,
the source navigation policy, target-specific notices, packaged resources,
linked WebKit frameworks, repeated live loopback-only listener snapshots,
lifecycle markers, screenshots, and stable OCR text.

Wry also adds 13 informational or unsoundness advisories through its non-Apple
lockfile graph. `cargo audit` cannot evaluate target reachability, so CI uses
time-bounded ignores through 2026-08-14. The Dioxus verifier independently
fails if any affected package/version becomes reachable from the macOS, iOS
device, or iOS simulator Cargo graph. The remaining Apple-reachable advisory
exceptions predate this spike and remain subject to the same repository
deadline. Notice generation runs on macOS because `cargo-about` 0.9.1 does not
produce byte-identical Apple-target output across host operating systems;
`cargo-deny` and `cargo-audit` remain independent Linux gates.

## Diagnostic outcome

The decision is **GO for continued diagnostic evaluation** and **NO-GO for
production adoption**.

Production adoption remains blocked because:

1. Wry uses the default persistent `WKWebsiteDataStore`, and Dioxus 0.7.9 does
   not expose a non-persistent store hook. This conflicts with tersa.app's rule
   that every local persistence surface is encrypted and governed.
2. External HTTP, HTTPS, and mailto navigation is opened by `webbrowser` before
   the configurable navigation handler runs. Production hostile-content policy
   needs a complete deny-by-default interception boundary.
3. The diagnostic macOS target is deliberately unsandboxed. App Sandbox would
   require testing and accepting the `com.apple.security.network.server`
   entitlement for the loopback listener, or replacing the transport. The
   single accept loop also performs each unauthenticated WebSocket handshake
   synchronously without a deadline before spawning its connection thread, so
   a local client can block startup or reconnection. Production requires a
   bounded concurrent handshake or a replacement transport.
4. The minimal runtime still creates a Tokio runtime because of the upstream
   0.7.9 build defect. The local Release-only devtools guard removes the prior
   feature-minimal Release compilation failure without enabling private WebKit
   APIs, but it proves neither signing nor production releasability. Its launch,
   memory, thread, energy, notarization, TestFlight, and App Review behavior
   remain outside the product gate.
5. Tao maps active/inactive transitions to resumed/suspended, but its iOS
   foreground/background callbacks are empty and it exposes no memory-warning
   event through this path.
6. Physical-device input, accessibility, safe-area, lifecycle, performance,
   energy, signed distribution, and App Review evidence remains open.

Any upstream patch, dependency upgrade, Wry customization, or sandbox
entitlement change invalidates this evidence and requires a new ADR and full
review.

## Consequences

The Dioxus spike remains isolated from all production crates and from the Slint
spike. Its target-specific Rust notices are generated from the locked Apple
graphs and bundled byte-for-byte in both unsigned Release diagnostic
applications. The large dependency and binary footprint is evidence to measure,
not an accepted production cost.

The M0 UI gate cannot close on CI alone. A production GO requires a new build
that resolves all six blockers, followed by the physical-device matrix in the
feasibility document and independent accessibility and security review.
