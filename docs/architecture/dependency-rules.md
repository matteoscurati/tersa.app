# Dependency rules

tersa.app uses inward-facing dependency boundaries so the shared core remains
independent of Apple frameworks, UI toolkits, storage engines, and transports.

The workspace has four shared architectural layers plus eleven platform
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
| `tersa-keychain-macos` | macOS Data Protection Keychain root-key, fixed App Group profile, and trusted read-only store composition | `tersa-platform`, `tersa-store-sqlcipher-macos` |
| `tersa-cli-macos` | Fixed-profile metadata-only macOS CLI source adapter | `tersa-application`, `tersa-domain`, `tersa-keychain-macos` |

This table is the active workspace graph. The governance-only PR 33a.5
amendment authorizes, but does not activate, one future
`cfg(target_os = "macos")` edge from `tersa-apple-bridge` to
`tersa-keychain-macos`. The implementation pull request must add that exact
manifest edge and its exact `xtask` policy entry together. Until then, the
active bridge dependencies remain only `tersa-application` and
`tersa-presentation`; this document changes no manifest or passing gate.

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
cross-builds the same locked graphs. `chacha20poly1305` 0.10.1 is pinned exactly
and exclusive to `tersa-blob-spike`; `hmac` 0.12.1 is pinned exactly and may be
reached by `tersa-blob-spike`, `tersa-keychain-macos` through HKDF, and the
macOS-only CLI through its Keychain composition chain. New workspace crates
must be added explicitly to the policy in `xtask`; an unknown crate fails CI.

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
dependency. The envelope-only `MailboxReader` owns deterministic envelope
listing, including the existing body-derived preview field. `MailboxStore:
MailboxReader` adds atomic envelope reconciliation, conditional body caching,
complete-message access, and mutations. The strict macOS reader implements only
`MailboxReader`; metadata-only consumers must project preview away. This
boundary does not authorize Gmail History or cursor sync, deletion
reconciliation, retry, background work, mutations, outbox, labels, blobs,
search, CLI/UI, real network or credentials tests, mobile code, or gate-status
changes. Cache budgets remain constraints rather than evidence.

## Active macOS key boundary and split CLI boundary

ADR 0019 defines the active macOS Keychain and metadata-only CLI adapters:

| Crate | Responsibility | Maximum inward dependencies |
|---|---|---|
| `tersa-keychain-macos` | macOS Keychain root provisioning, private versioned HKDF derivation, App Group location, and trusted read-only database composition | `tersa-platform`, `tersa-store-sqlcipher-macos` |
| `tersa-cli-macos` | Fixed-profile metadata-only JSON process adapter | `tersa-application`, `tersa-domain`, `tersa-keychain-macos` |

Both crates are active and have exact `xtask` policy entries. The CLI
reservation is removed only for this reviewed metadata-only source slice.

The active Keychain adapter uses direct exact pins: `security-framework-sys =2.17.0`
with default features disabled and only `OSX_10_15`,
`core-foundation =0.10.1`, `objc2-foundation =0.3.2` with default features
disabled and only `std`, `NSFileManager`, `NSString`, and `NSURL` enabled,
`hkdf =0.12.4`, `sha2 =0.10.9`, and `zeroize =1.9.0`. HKDF 0.12.4 is deliberately
selected instead of current 0.13.0 because 0.12.4 uses the already pinned
`hmac =0.12.1`, while 0.13.0 moves to HMAC 0.13. The activation pull request
direct declarations and resolved per-target reachability are enforced by xtask.
The high-level `security-framework` crate is deliberately not used: raw
`SecItemAdd` and `SecItemCopyMatching` preserve the add-only contract.
The direct dependency set is closed and exact: an unknown dependency, a
missing required dependency, or direct `hmac` is rejected. Resolved
HKDF-to-HMAC reachability remains allowed and separately checked.

The active direct `hmac =0.12.1` owner set is exactly `tersa-blob-spike` and
`tersa-keychain-macos`; the macOS-only CLI may reach it only through the active
Keychain composition chain. ChaCha20-Poly1305 remains
exclusive to `tersa-blob-spike`, including when a crate also reaches HMAC.
`tersa-keychain-macos` may not add direct application or domain edges. ADR 0019
accepts one macOS-gated PR 33a edge to `tersa-store-sqlcipher-macos` so the
private `SecretKey` owner can consume a derived key directly into the strict
`SqlCipherMailboxReader` opener. The classified constructor preserves only the
existing storage/corruption distinction and delegates to the same strict
read-only implementation. The adapter may reach SQLCipher only through that
store edge and may not declare `rusqlite` or `libsqlite3-sys` directly. Its
platform port accepts only the canonical domain `AccountId`; raw strings cannot
enter account hashing or derivation. `tersa-cli-macos` receives no direct
platform, SQLCipher, general Apple-framework, key export, database-path
override, or transport capability.

PR 32 keeps root retrieval and HKDF derivation private to the trusted adapter.
It exposes neither raw root/derived bytes nor a database opener. PR 33a owns the
trusted database-opening composition and must feed the privately derived key
directly into the strict SQLCipher reader without creating a callback or key
export API.

PR 33a.5 is a future authorized, inactive macOS-only edge from the existing
`tersa-apple-bridge` composition root to `tersa-keychain-macos`. The existing
`TersaMac` target is its sole production invoker through exactly one new
macOS-gated C ABI bootstrap call. That call accepts only an opaque account
identifier and returns a closed status. The bridge first validates the canonical
`AccountId`, then has only one-shot command authority to request fixed-profile
bootstrap. It receives no raw key, caller-selected path, profile or
configuration override, database handle, store object, or returned storage
capability and gains no direct edge to `tersa-store-sqlcipher-macos`.

The trusted `tersa-keychain-macos` composition is the sole filesystem-directory
establisher on behalf of the product application. It may create only the fixed
owner-only profile components through descriptor-relative no-follow operations,
with fail-closed validation, concurrent convergence, and deterministic safe
cleanup defined by ADR 0019. The existing validated SQLCipher write opener
remains the sole owner and migrator of the database leaf. Activating the future
bridge edge or its policy before the implementation pull request is forbidden.
PR 33b owns the same-team signed runtime evidence; PR 32 fake concurrency tests,
PR 33a deterministic tests, and PR 33a.5 credentialless tests are not that
evidence.

The active adapter opts every macOS Keychain operation into the Data
Protection Keychain, omits `kSecAttrSynchronizable` from add and copy queries,
and names the registered application group currently carried by the macOS app
target. That group also identifies the app's filesystem container. The active
adapter does not fall back to the legacy Keychain, the app's private sandbox
container, or ordinary Application Support when the entitlement, group, or
container is unavailable. PR 33b will add the separately signed bundled
`mailctl` target, give both targets the same registered group, and supply the
cross-target runtime evidence. Only then may the official CLI be described as
the signed executable from the notarized app distribution; a package-manager
entry may point to that executable but may not substitute a separately rebuilt
binary.

The signing guard treats the current direct XcodeGen declarations as an exact
allowlist. Project-wide or per-configuration sensitive overrides, includes,
target templates, setting groups, config files, conditional sensitive keys,
and reuse of the protected entitlement path fail closed. The current `options`
mapping is closed, including rejection of nested pre- and post-generation
hooks. The `TersaMac` target type, bundle identifier, sole Rust pre-build phase,
scheme, build rules, build-tool plugins, and additional signing controls are
also closed exact surfaces. Exact project-root and target top-level key sets
reject project/target attributes, dependencies, and legacy forms. The source
and XcodeGen entitlement dictionaries each contain exactly the five reviewed
keys with exact boolean capability values. The checked project-generation
wrapper always uses XcodeGen `--no-env`, preserving `${TeamIdentifierPrefix}`
for Xcode rather than environment expansion. A repository-wide tracked-file
inventory allows the generation command only in that byte-exact wrapper. Every
other source entitlement under `apple/` is parsed and rejected if it claims
either protected group entitlement. The ignored generated `apple/build/` tree
is excluded from filesystem inventory only when its root is a real directory;
Git-index checks reject any tracked entry below it and independently enumerate
tracked entitlement files and symlinks. Other source symlinks remain forbidden.

Provisioning must use a raw add-only operation. A duplicate discards and
zeroizes the losing candidate, then retrieves and validates the winner; it
never calls an add-or-update generic-password helper. All key states use a
private redacted `SecretKey` that zeroizes on drop. The no-copy Keychain add
constructs and consumes its Core Foundation objects inside one synchronous
scope so the candidate pointer cannot escape. The future shell-launched
CLI must have its own stable bundle identifier, embedded Info.plist, Hardened
Runtime, non-inherited App Sandbox entitlement, and the same application group.
PR 33b must satisfy its dedicated signed-package and direct-shell-launch
evidence condition without depending on or passing the later UI acceptance
gate.

The active PR 31 store boundary keeps WAL and shared-memory sidecars persistent
from the validated writer before authorizing a standalone read-only open. The
reader may coordinate through an existing `-shm`, but it exposes no create,
replace, delete, or repair operation for the main database or either sidecar.
Missing or ordinarily replaced sidecars that remain observable at the post-open
check fail closed until the owning writer establishes a valid state. The Unix
VFS does not descriptor-bind its internally opened `-shm` identity to the
caller's pathname preflight and opens sidecars with create-capable internal
flags. Same-user swap-in/open/swap-back and deletion/recreation races remain
explicit unlocked-device residuals, not prevented attacks or release claims.

The strict reader opens only existing regular main, WAL, and shared-memory
files with read-only/no-mutex/no-follow SQLite flags. It validates key, owner,
schema, SQLCipher and SQLite integrity, account binding, bounded metadata
decoding, connection-local persistent-WAL state, `journal_size_limit = -1`, and
pre/post pathname identities. It disables and verifies checkpoint-on-close. It
has no complete-body API, migration, checkpoint, repair, journal-mode,
creation, or mutation operation. A missing sidecar at preflight does not enter
SQLite; deletion after preflight can be recreated internally before the reader
fails its post-read identity check.

The reviewed delivery changes are policy, strict read-only SQLCipher open,
macOS Keychain/private-HKDF boundary, deterministic metadata-only JSON CLI
source, credentialless product-application bootstrap source, then real signed
CLI distribution evidence. PR 33a activates CLI source and dependency policy
but does not create the official CLI. PR 33a.5 must activate only the authorized
macOS-gated bridge edge and fixed bootstrap composition; this governance
amendment activates neither. Phase 1 roadmap item 7 remains open until PR 33b
passes. The CLI's trusted direct-store composition is an interim adapter
boundary replaceable by future `maild` IPC; it does not authorize `maild` in the
MVP. iPhone and iPad implementation remains in Phase 2, and no reservation or
macOS evidence changes a mobile gate.

Run the boundary check with:

```sh
cargo xtask architecture
```
