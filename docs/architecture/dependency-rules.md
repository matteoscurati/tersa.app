# Dependency rules

tersa.app uses inward-facing dependency boundaries so the shared core remains
independent of Apple frameworks, UI toolkits, storage engines, and transports.

The initial workspace has four shared architectural layers plus eight platform
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

Executable adapters may depend on these layers, but the layers must never
depend on an executable, Apple API, or UI framework. `tersa-slint-spike` and
`tersa-dioxus-spike` are the only workspace crates allowed to depend on their
respective UI runtimes. `tersa-sqlcipher-spike` and `tersa-search-spike` are the
only crates allowed to depend on `rusqlite` or `libsqlite3-sys`; Tantivy is
exclusive to `tersa-search-spike`, pinned to 0.26.1, and may not reach
`memmap2`, `tempfile`, `lz4_flex`, or `zstd` in any resolved Apple target graph.
`mail-parser` 0.11.5 and `ammonia` 4.1.3 are pinned exactly and exclusive to
`tersa-mime-spike`. The portable MIME and blob M0 spikes are exceptions to the
Apple target gate: Linux CI exercises their deterministic tests, while Apple CI
cross-builds the same locked graphs. `chacha20poly1305` 0.10.1 and `hmac`
0.12.1 are pinned exactly and exclusive to `tersa-blob-spike` in every resolved
Apple target graph. New workspace crates must be added explicitly to the policy
in `xtask`; an unknown crate fails CI.

## Reserved macOS production adapters

The `RESERVED_FUTURE_POLICY` table in `xtask` reserves
`tersa-store-sqlcipher-macos`; it is not an active dependency-policy entry and
the crate does not exist in this change. The architecture check fails if the
reserved name appears in workspace
membership. This is a tripwire, not pre-authorization: the crate-introducing
pull request must explicitly move its name from the reserved table to the
active policy under review.

When introduced, the store adapter may depend inward only on
`tersa-application` and `tersa-domain`. Remote mailbox and local mailbox-store
ports now exist in `tersa-application`; adapters implement those inward-defined
ports, while `tersa-application` and `tersa-domain` never depend on adapters.

The future macOS store adapter must declare `rusqlite`, `libsqlite3-sys`,
`chacha20poly1305`, and `hmac` only under the exact target cfg
`cfg(target_os = "macos")`. Untargeted, iOS-only, and iOS-inclusive declarations
are violations. It may own both SQLCipher and blob AEAD because both share one
commit and crash-safety protocol.

`tersa-gmail-rest-macos` is active and may depend inward only on
`tersa-application` and `tersa-domain`. `reqwest` is pinned exactly to 0.13.4,
declared only for `cfg(target_os = "macos")`, and exclusive to this adapter in
the resolved graph. The adapter uses only the Gmail REST API; it does not add a
general network capability to the shared layers.

The Apple bridge may call application use cases directly when the operating
system owns the transport. The M0 OAuth adapter uses this edge for the browser
callback while keeping PKCE and callback validation in portable Rust.

Run the boundary check with:

```sh
cargo xtask architecture
```
