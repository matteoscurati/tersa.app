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

The adapter must declare `rusqlite` only under the exact target cfg
`cfg(target_os = "macos")`, disable its default features, and select only
`bundled-sqlcipher`. Untargeted, iOS-only, and iOS-inclusive declarations are
violations. Blob/attachment encryption is deliberately deferred: this adapter
does not own `chacha20poly1305` or `hmac` until a real blob/attachment port and
cross-file commit protocol are accepted.

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

Run the boundary check with:

```sh
cargo xtask architecture
```
