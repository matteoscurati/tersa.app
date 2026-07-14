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
The unsigned packages use Debug because a feature-minimal macOS Release build
also fails: `dioxus-desktop` unconditionally calls Wry's feature-gated
`open_devtools` and `close_devtools` methods in its desktop menu handler. Wry
exposes those methods under debug assertions, so Debug compiles, but it also
enables Web inspector support. Enabling the production `devtools` feature would
use private WebKit APIs on macOS and is not an acceptable release workaround.

The diagnostic renders 10,000 synthetic rows with a handwritten fixed-height
virtualizer. Only the visible range plus six overscan rows on either side is
materialized. It uses semantic list/listitem structure, labelled controls,
visible focus treatment, a multiline textarea, reduced-motion handling, and
CSS safe-area insets. Tao `Resumed` and `Suspended` events emit fixed diagnostic
markers without content.

The diagnostic contains no anchors, URLs, remote assets, server functions,
Gmail code, credentials, or persistence. A navigation callback rejects schemes
that Dioxus delegates to the application. Dioxus handles HTTP, HTTPS, and
mailto links before that callback and opens them in the system browser, so the
spike prevents those paths by never rendering a link. This is not sufficient
for untrusted production email content.

CI verifies the resolved feature set, the absence of Manganis and Dioxus
devtools, the exact loopback bind expression, the 256-byte mutual WebSocket
keys, the source navigation policy, target-specific notices, packaged
resources, linked WebKit frameworks, live loopback-only listeners, lifecycle
markers, screenshots, and stable OCR text.

Wry also adds 13 informational or unsoundness advisories through its GTK-only
lockfile graph. `cargo audit` cannot evaluate target reachability, so CI uses
time-bounded ignores through 2026-08-14. The Dioxus verifier independently
fails if any affected package/version becomes reachable from either the macOS
or iOS Cargo graph. The remaining Apple-reachable advisory exceptions predate
this spike and remain subject to the same repository deadline.

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
   entitlement for the loopback listener, or replacing the transport.
4. The minimal runtime still creates a Tokio runtime because of the upstream
   0.7.9 build defect. A feature-minimal macOS Release build separately fails
   on unguarded devtools calls, while Debug exposes the Web inspector. Its
   launch, memory, thread, energy, and releasability are outside the product
   gate.
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
graphs and bundled byte-for-byte in both diagnostic applications. The large
dependency and binary footprint is evidence to measure, not an accepted
production cost.

The M0 UI gate cannot close on CI alone. A production GO requires a new build
that resolves all six blockers, followed by the physical-device matrix in the
feasibility document and independent accessibility and security review.
