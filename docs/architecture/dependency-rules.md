# Dependency rules

tersa.app uses inward-facing dependency boundaries so the shared core remains
independent of Apple frameworks, UI toolkits, storage engines, and transports.

The workspace has four shared architectural layers plus nine platform
and feasibility adapters:

| Crate | Responsibility | Allowed workspace dependencies |
|---|---|---|
| `tersa-domain` | Domain types and invariants | None |
| `tersa-application` | Commands, queries, and use cases | `tersa-domain` |
| `tersa-platform` | Operating-system capability ports | `tersa-domain` |
| `tersa-presentation` | UI-neutral view models | All three inward layers |
| `tersa-apple-bridge` | C ABI and Apple capability adapters | `tersa-application`, `tersa-presentation` |
| `tersa-slint-spike` | Apple-only diagnostic Slint executable | `tersa-presentation` |
| `tersa-dioxus-spike` | Apple-only diagnostic Dioxus executable | `tersa-presentation` |
| `tersa-sqlcipher-spike` | Apple-only diagnostic encrypted-storage executable | None |
| `tersa-search-spike` | Apple-only SQLCipher FTS5 and fixed-size-chunk Tantivy diagnostic | None |
| `tersa-mime-spike` | Portable bounded MIME and deny-by-default HTML diagnostic | None |
| `tersa-blob-spike` | Portable crash-safe chunked-AEAD blob diagnostic | None |
| `tersa-gmail-rest-macos` | macOS Gmail read-only REST adapter | `tersa-application`, `tersa-domain` |
| `tersa-store-sqlcipher-macos` | macOS account-scoped SQLCipher mailbox store | `tersa-application`, `tersa-domain` |

Executable adapters may depend on these layers, but the layers must never
depend on an executable, Apple API, or UI framework. `tersa-slint-spike` and
`tersa-dioxus-spike` are the only workspace crates allowed to depend on their
respective UI runtimes. `tersa-sqlcipher-spike`, `tersa-search-spike`, and
`tersa-store-sqlcipher-macos` are the only crates allowed to depend on
`rusqlite` or `libsqlite3-sys`; Tantivy is
exclusive to `tersa-search-spike`, pinned to 0.26.1, and may not reach
`memmap2`, `tempfile`, `lz4_flex`, or `zstd` in any resolved Apple target graph.
`mail-parser` 0.11.5 and `ammonia` 4.1.3 are pinned exactly and exclusive to
`tersa-mime-spike`. The portable MIME and blob M0 spikes are exceptions to the
Apple target gate: Linux CI exercises their deterministic tests, while Apple CI
cross-builds the same locked graphs. `chacha20poly1305` 0.10.1 and `hmac`
0.12.1 are pinned exactly and exclusive to `tersa-blob-spike` in every resolved
Apple target graph. New workspace crates must be added explicitly to the policy
in `xtask`; an unknown crate fails CI.

## macOS production account store

`tersa-store-sqlcipher-macos` is an active, macOS-only production adapter. It
may depend inward only on
`tersa-application` and `tersa-domain`. Remote mailbox and local mailbox-store
ports now exist in `tersa-application`; adapters implement those inward-defined
ports, while `tersa-application` and `tersa-domain` never depend on adapters.

The adapter must pin `rusqlite` exactly to 0.39.0 under the exact target cfg
`cfg(target_os = "macos")`, disable its default features, and select only
`bundled-sqlcipher`. Every resolved Apple graph must contain only rusqlite
0.39.0 with the exact unified feature set `bundled`, `bundled-sqlcipher`, and
`modern_sqlite`; extension-loading and hook features fail closed. Version,
feature, untargeted, iOS-only, and iOS-inclusive deviations are violations.
Blob/attachment encryption is deliberately deferred:
this adapter does not own `chacha20poly1305` or `hmac` until a real
blob/attachment port and cross-file commit protocol are accepted.

`tersa-gmail-rest-macos` is active and may depend inward only on
`tersa-application` and `tersa-domain`. `reqwest` is pinned exactly to 0.13.4,
declared only for `cfg(target_os = "macos")`, and exclusive to this adapter in
the resolved graph. Its direct feature set is exactly `native-tls`; resolved
features fail closed if defaults, cookies, compression, multipart, proxy, or an
alternate TLS backend becomes active. The adapter uses only the Gmail REST API;
it does not add a general network capability to the shared layers.

The Apple bridge may call application use cases directly when the operating
system owns the transport. The M0 OAuth adapter uses this edge for the browser
callback while keeping PKCE and callback validation in portable Rust.

## Bounded sync and cache orchestration

`tersa-application::sync` is the sole shared owner of bounded recent-snapshot
orchestration. It may use only existing application mailbox ports and
`tersa-domain`; it introduces no runtime, transport, storage, or background
dependency. `MailboxStore` implementations own atomic envelope reconciliation
and conditional body caching. This boundary does not authorize Gmail History or
cursor sync, deletion reconciliation, retry, background work, mutations,
outbox, labels, blobs, search, CLI/UI, real network or credentials tests,
mobile code, or gate-status changes. Cache budgets remain constraints rather
than evidence.

## Reserved macOS key and CLI boundaries

ADR 0019 reserves two future workspace crate names without activating them:

| Reserved crate | Planned responsibility | Maximum reserved inward dependencies |
|---|---|---|
| `tersa-keychain-macos` | Retrieval/provisioning-separated macOS Keychain root provider and versioned HKDF derivation | `tersa-platform` |
| `tersa-cli-macos` | Fixed-profile composition and metadata-only JSON rendering | `tersa-application`, `tersa-domain`, `tersa-keychain-macos`, `tersa-platform`, `tersa-store-sqlcipher-macos` |

The `RESERVED_FUTURE_POLICY` tripwire fails if either crate appears, even when
its dependency edges fit this table. The pull request that adds a crate must
replace its reservation with an explicitly reviewed active policy; it may not
silently promote a reservation. PR 30 is policy text and a tripwire only. It
adds no crate or dependency and must leave `Cargo.lock` and the resolved graph
byte-identical.

When `tersa-keychain-macos` is activated, its external dependencies are planned
as exact macOS-only pins: `security-framework =3.7.0` with default features
disabled, `hkdf =0.12.4`, `sha2 =0.10.9`, and `zeroize =1.9.0`. crates.io
metadata lists `security-framework` 3.7.0 as the current release. HKDF 0.12.4
is deliberately selected instead of current 0.13.0 because 0.12.4 uses the
already pinned `hmac =0.12.1`, while 0.13.0 moves to HMAC 0.13. The activation
pull request must verify these facts again, pin every direct dependency
exactly, restrict Apple dependencies to exact `cfg(target_os = "macos")`, and
add resolved-graph feature/ownership checks before changing a manifest.

The current `hmac =0.12.1` exclusivity to `tersa-blob-spike` remains unchanged
in PR 30. The Keychain/HKDF activation must deliberately expand the owner set
to exactly `tersa-blob-spike` and `tersa-keychain-macos`; no other crate may
reach HMAC. `tersa-keychain-macos` may not add direct application or domain
edges without separately accepted ADR reasoning. `tersa-cli-macos` receives no
general Apple-framework, SQLCipher, key export, database-path override, or
transport capability from its reservation.

The future adapter must opt every macOS Keychain operation into the Data
Protection Keychain, disable synchronization, and name the registered
application group shared by the same-team signed app and bundled `mailctl`
target. The same group owns their shared filesystem container. Neither target
may fall back to the legacy Keychain, a private sandbox container, or ordinary
Application Support when the entitlement, group, or container is unavailable.
The official CLI is the signed executable from the notarized app distribution;
a package-manager entry may point to it but may not substitute a separately
rebuilt binary.

The future store activation must keep WAL and shared-memory sidecars persistent
from the validated writer before authorizing a standalone read-only open. The
reader may coordinate through an existing `-shm`, but it may not create,
replace, delete, or repair the main database or either sidecar. Missing or
changed sidecars fail closed until the owning writer establishes a valid state.

The four reviewed changes are policy, strict read-only SQLCipher open, macOS
Keychain/HKDF provider, then the metadata-only JSON CLI. Until all four land,
Phase 1 roadmap item 7 remains open. The CLI's direct store reader is an interim
adapter composition replaceable by future `maild` IPC; it does not authorize
`maild` in the MVP. iPhone and iPad implementation remains in Phase 2, and no
reservation or macOS evidence changes a mobile gate.

Run the boundary check with:

```sh
cargo xtask architecture
```
