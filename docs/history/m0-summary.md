# M0 diagnostic program — historical summary

This is a durable historical summary of the retired M0 feasibility program. It
is not a live gate register, not a runnable runbook, and not product
documentation. Removed M0 gate IDs and statuses are historical only and are no
longer an authoritative live register.

The product path is the SwiftUI/AppKit macOS client, shared Rust core, Apple
bridge, production SQLCipher store, and the OAuth/token-broker surfaces governed
by the accepted ADRs. Active product quality and release work uses:

- [macOS acceptance protocol](../quality/macos-acceptance.md)
- [macOS performance harness](../quality/macos-performance.md)
- [Apple physical-device and distribution protocol](../release/apple-distribution.md)

## What M0 learned

### Slint

Host packaging diagnostics ran, but production selection was rejected because
the locked iOS accessibility adapter path was a no-op. Historical decisions:
[ADR 0004](../architecture/adr-0004-slint-binary-license.md),
[ADR 0006](../architecture/adr-0006-product-constraints.md).

### Dioxus

Bounded host/simulator diagnostics and local-fork evidence informed WebKit,
transport, navigation, and sandbox constraints. Production adoption remained a
no-go. Historical decisions: [ADR 0005](../architecture/adr-0005-dioxus-diagnostic-runtime.md),
[ADR 0007](../architecture/adr-0007-dioxus-local-ephemeral-fork.md),
[ADR 0008](../architecture/adr-0008-dioxus-release-diagnostic.md),
[ADR 0009](../architecture/adr-0009-dioxus-sandboxed-transport-diagnostic.md),
[ADR 0010](../architecture/adr-0010-dioxus-sandboxed-navigation-classification.md).

### OAuth / PKCE

Bounded transport design and development-signed live learning proved the
Authorization Code + PKCE shape and Apple callback transports. The old combined
evidence route and dedicated entitlement probe are retired. The current product
path is governed by
[ADR 0023](../architecture/adr-0023-step3-oauth-and-bounded-sync.md) and
[ADR 0024](../architecture/adr-0024-macos-token-process-isolation.md).

### SQLCipher

A host diagnostic informed the active production macOS encrypted store. The
diagnostic was retired; the production store remains. Historical and product
decisions: [ADR 0011](../architecture/adr-0011-sqlcipher-schema-and-migration-ownership.md),
[ADR 0014](../architecture/adr-0014-macos-production-dependency-boundaries.md),
[ADR 0017](../architecture/adr-0017-production-macos-account-store.md),
[ADR 0019](../architecture/adr-0019-macos-key-provisioning-and-readonly-cli.md).

### Search / Tantivy

A host comparison of SQLCipher FTS5 and Tantivy informed bounded product
mailbox search. The Tantivy diagnostic was retired. No device full-text claim
was established; active product search is the bounded cached-metadata path.

### Blob AEAD

A host format and crash-safety study only. No product blob implementation
exists. Historical decision:
[ADR 0012](../architecture/adr-0012-chunked-blob-format.md).

### MIME / HTML / fuzz

Bounded synthetic host diagnostics only. No active parser, sanitizer,
`SafeHtml`, restricted WKWebView, renderer, or fuzz harness remains. Hostile
MIME/HTML handling remains a future product security requirement.

### macOS UI and performance evidence

Native SwiftUI was selected and a product vertical slice exists
([ADR 0020](../architecture/adr-0020-macos-production-ui-toolkit.md),
[ADR 0021](../architecture/adr-0021-macos-ui-vertical-slice.md)). Retained
development-signed evidence snapshots did not close release or accessibility
gates. Use the active quality and release protocols above for current
acceptance work.

## Retirement

Diagnostic CI jobs, evidence artifact uploads, spike sources, and the former
M0 gate register were retired under
[ADR 0025](../architecture/adr-0025-retire-m0-diagnostic-program.md). Preserved
ADRs keep the architectural learning; this summary replaces the detailed M0
study corpus.
