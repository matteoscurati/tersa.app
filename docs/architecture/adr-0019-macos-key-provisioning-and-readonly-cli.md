<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0019: macOS key provisioning and read-only CLI

- Status: Accepted
- Date: 2026-07-16

## Context

Phase 1 roadmap item 7 needs a read-only macOS CLI over the encrypted account
store. Giving that executable a database path or key on its command line would
create a second, unsafe provisioning channel. Reusing the existing read-write
store opening path could create, claim, migrate, configure, or otherwise mutate
a profile merely because a user asked to read it. A live WAL database also
cannot be opened with SQLite's `immutable=1` promise because the file is not
immutable and committed WAL content must remain visible.

The direct local reader is an interim composition boundary. The planned
`maild` owner remains outside the MVP, but a later IPC client must be able to
replace the direct reader without changing the CLI's public JSON contract.

## Decision

The CLI slice is divided into four independently reviewed pull requests:

1. **PR 30 — policy:** this ADR, dependency documentation, and fail-closed
   reservations only. It adds no crate, dependency, key access, store opening,
   command, or gate evidence.
2. **PR 31 — strict read-only SQLCipher open:** the existing macOS store adapter
   now owns persistent WAL coordination, the separately named
   `SqlCipherMailboxReader::open_read_only` constructor, and deterministic
   standalone/coexistence and fail-closed tests.
3. **PR 32 — macOS Keychain and private HKDF boundary:** add
   `tersa-keychain-macos`, the inward platform contract it implements, and the
   reviewed provisioning/retrieval internals and application-group locator.
   It exposes no raw root or derived key and no database opener. This pull
   request replaces and activates the Keychain reservation.
4. **PR 33 — metadata-only JSON CLI:** add `tersa-cli-macos` with exactly the
   `inbox` and `thread` commands and replace and activate the remaining CLI
   reservation.

Each later pull request requires exact-head independent review and must replace
its reservation with an explicitly activated policy. Merely adding either
reserved crate makes the architecture check fail.

### Root-key lifecycle and derivation

The product application, never the CLI, provisions exactly one installation
root key when the fixed Keychain item is absent. It generates 32 bytes with
Apple's CSPRNG and stores them as a generic-password item with service
`app.tersa.mac.storage-root.v1`, account `default`,
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, synchronization disabled,
and the shared application-group identifier as `kSecAttrAccessGroup`. Every
add and copy query omits `kSecAttrSynchronizable` and sets
`kSecUseDataProtectionKeychain` to true; an attribute-returning copy accepts
the synchronization attribute only when it is absent or false. Update and
delete operations are not implemented. There is no legacy-keychain fallback.
Missing entitlement, unexpected item attributes, or a query that cannot use
the Data Protection Keychain fails closed. Existing items are retrieved but
never replaced implicitly. The PR 33 CLI will have retrieval-only access: an
absent item is an error and cannot cause key generation, import, repair,
rotation, or a second Keychain write.

Provisioning uses an add-only `SecItemAdd` operation, never an add-or-update
password helper. On `errSecDuplicateItem`, the generated losing key is
zeroized, the process retrieves and validates the single winning item, and no
update occurs. Other add failures are terminal. PR 32 must test simultaneous
provisioners and prove they converge on the stored winner without exposing or
replacing either candidate.

PR 33 must make the macOS application and `mailctl` two targets of one
distribution. Both will be signed by the same Apple Developer team, carry the
registered `${TeamIdentifierPrefix}app.tersa.shared` application-group
entitlement, and use that group as their shared Keychain access group.
`mailctl` will have the stable bundle identifier `app.tersa.mailctl`, an
embedded Info.plist section, Hardened Runtime, and its own
`com.apple.security.app-sandbox = true` entitlement. It is
launched directly by the shell and therefore must not use
`com.apple.security.inherit`. After PR 33, the official CLI will be the signed
executable shipped inside the app bundle; a package manager may then install
only a symlink to that exact executable, not rebuild or re-sign it
independently. Community distributions must register and inject their own
group under their own signing team. Unsigned, differently signed,
missing-entitlement, or mismatched-group builds receive no production fallback
and cannot claim Keychain/profile interoperability.

The root key is never exported or accepted through arguments, environment,
stdin, files, IPC, logs, diagnostics, or JSON. PR 32 keeps retrieval and
HKDF-SHA256 derivation private to the trusted Keychain adapter; there is no
public callback, borrowed-key API, or other raw-key capability. The salt is
the literal byte string
`tersa.app/macos/root-key/v1`. The `info` input is unambiguous framing of the
literal prefix `tersa.app/macos/hkdf-sha256/v1`, followed by a two-byte
big-endian validated account-identifier length and its UTF-8 bytes, then a
two-byte big-endian purpose length and its ASCII bytes. Purposes are a closed,
versioned enum; the initial value is `sqlcipher/account-database/v1`. Unknown
versions or purposes fail closed. Root and derived key buffers use best-effort
zeroization through one private `SecretKey` newtype whose `Drop` implementation
clears its bytes and whose only `Debug` representation is redacted. Root,
candidate, retrieved, and derived keys never use a raw byte-array value across
adapter operations and never implement serialization.
This guarantee covers explicit buffers owned by the adapter; the internal
state and temporary storage of the `hkdf`, `hmac`, and digest implementations
are outside `zeroize`'s guarantee and may leave transient copies in process
memory.
PR 33 owns the trusted composition that will pass a privately derived key
directly into strict database opening without returning key bytes to the CLI.

The add-only Keychain boundary constructs its no-copy `CFData`, attribute
dictionary, and synchronous `SecItemAdd` call in one private scope. Neither the
dictionary nor any object containing the candidate pointer can escape that
scope.

PR 32 uses direct `security-framework-sys =2.17.0` with default features
disabled and only `OSX_10_15`,
`core-foundation =0.10.1`, `objc2-foundation =0.3.2` with default features
disabled and only `std`, `NSFileManager`, `NSString`, and `NSURL` enabled,
`hkdf =0.12.4`, `sha2 =0.10.9`, and `zeroize =1.9.0`. They are declared only
for the exact macOS target where applicable. The explicit Security/Core
Foundation surface exists so PR 32 can build add-only and attribute-returning
Keychain dictionaries; the high-level `security-framework` generic-password
setter is forbidden because its duplicate-item path can update existing data.
`OSX_10_15` is required for the
Data Protection Keychain API on macOS. The Foundation surface resolves and
validates the application-group container through the inward platform port.

The current HKDF release, 0.13.0, resolves HMAC 0.13; 0.12.4 is
deliberately selected because it uses the already reviewed `hmac =0.12.1`.
PR 32 narrowly expands the HMAC owner set to `tersa-blob-spike` and
`tersa-keychain-macos` after checking the exact resolved graph. ChaCha20-
Poly1305 remains exclusive to `tersa-blob-spike`.

`tersa-keychain-macos` may depend inward only on `tersa-platform`; the platform
port in turn uses the canonical domain `AccountId` so raw account strings
cannot reach hashing or derivation. Apple Security types do not cross the port.
Additional inward edges require a new ADR rather than an incidental manifest
edit.

PR 32 proves simultaneous-provisioner convergence only against its fake
backend. Real signed cross-target Data Protection Keychain interoperability is
a PR 33 acceptance condition; this is a Fable approval condition and is not
claimed by unsigned builds. PR 32 also does not claim a usable database opener:
the signed PR 33 composition is responsible for connecting private derivation
to the strict reader without adding a key-export surface.

### Fixed profile layout

Production resolution accepts no database path, profile-root, Keychain
service, access group, or derivation-purpose override from command-line flags,
environment, configuration, or test hooks. The only Phase 1 production profile
is `default` under the shared application-group container returned by
`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`:

```text
<shared-group-container>/profiles/default/
  accounts/<sha256-account-id>/mail.sqlite3
```

The expanded application-group identifier is a required signing-time setting
shared by the app and CLI entitlements. Resolution must verify access to the
returned container because macOS may return an expected-form URL even for an
invalid group. It never falls back to a normal Application Support path or
either target's private sandbox container.

The architecture check accepts the PR 32 signing configuration only at the
exact `TersaMac` target paths. It rejects project or per-configuration
overrides, includes, target templates, setting groups, configuration files,
conditional sensitive keys, protected entitlement-path reuse, and protected
groups in every other source entitlement file. The `options` mapping is closed
to the current three entries, which rejects XcodeGen's nested `preGenCommand`
and `postGenCommand` hooks. `TersaMac` is fixed to an application target, one
exact Rust build phase, no post-build or compile phases, no build rules or
build-tool plugins, and a scheme without executable actions. Signing controls,
conditional variants, identifier expansion roots, and the bundle identifier
are exact allowlists.

All repository project generation uses the checked
`apple/scripts/generate-project.sh` wrapper with XcodeGen `--no-env`. This keeps
`${TeamIdentifierPrefix}` literal in the generated project until Xcode resolves
it. The entitlement source inventory excludes only the ignored generated
`apple/build/` tree, including local DerivedData copies and symlinks. Every
other entitlement file under `apple/` is parsed and rejected if it claims
either protected group entitlement, and any source-tree symlink fails closed.
These surfaces require a reviewed policy change rather than attempted partial
XcodeGen resolution.

PR 33 has a CLI-specific acceptance condition independent of the later macOS
UI gate: a same-team Developer ID package must be notarized, contain the
embedded signed `mailctl`, expose only a symlink to that exact binary, and prove
a direct shell launch under its own non-inherited sandbox. Captured evidence
must verify the app and CLI code-signing identifiers and entitlements, App
Group container access, cross-target add/read of the non-synchronizable Data
Protection Keychain item, and denial after a group or signature mismatch. This
condition passes no UI, mobile, M0, or Phase 1 release gate.

`<sha256-account-id>` is the 64-character lowercase hexadecimal SHA-256 digest
of the validated opaque `AccountId` UTF-8 bytes. Tests may construct isolated
adapter paths directly, but the production CLI composition exposes no override.

### Strict read-only store contract

PR 31 opens an existing regular database only and fails when the file is
absent. The read path must preserve the current canonical parent, no-follow
leaf, path identity, account ownership, exact schema, SQLCipher version,
SQLite/SQLCipher integrity, bounded decode, and opaque error validation. It
must not create or claim a database, migrate schema, begin a write transaction,
fall back to read-write, or repair any state. Opening the CLI is never an
ownership or migration event.

Every validated read-write store connection sets and verifies
`SQLITE_FCNTL_PERSIST_WAL = 1` after ownership is established, so a clean final
checkpoint retains both `-wal` and `-shm` for a later reader. The read-only path
requires the main database and both sidecars to exist with the expected file
identities before it opens. It exposes no create, replace, delete, or repair
operation. If a legacy profile lacks the pair, a crash requires recovery, or a
sidecar replacement remains observable during the post-open identity check,
the reader fails closed until the owning read-write application opens and
establishes a valid persistent-WAL state.

The live connection uses SQLite read-only/no-mutex/no-follow mode without
`immutable=1` and without a private copy. It disables and verifies
checkpoint-on-close. SQLite may update lock and WAL-index coordination in the
existing `-shm` file; that is not mailbox persistence authority. In uncontended
operation, main and WAL content remain unchanged and no entry is created.
Deterministic tests prove both supported states: a standalone reader after a
clean writer close, and a reader while a writer holds WAL mode and commits data
that remains in the WAL. Missing sidecars at preflight and ordinary replacements
that remain observable at the post-open check fail without database/WAL
mutation. The bundled VFS opens WAL/SHM with create-capable internal flags, so
same-user deletion after preflight can recreate an entry before the post-read
identity check fails closed. Fixtures record that deletion/recreation residual
and the swap-in/open/swap-back non-detection instead of asserting prevention.
The reader verifies connection-local persistent-WAL state and requires
`journal_size_limit = -1`. Busy, moved-path, wrong-key, foreign-owner,
unknown-schema, and integrity failures remain fail closed and redacted.

The current bundled Unix VFS does not expose a supported handle that binds its
internally opened `-shm` inode to the caller's preflight identity. Pre-open and
post-open pathname identity checks detect ordinary replacement but cannot prove
defense against same-user regular-file swap-in/open/swap-back or
deletion/recreation races. PR 31 includes deterministic fixtures for both
limitations and does not claim that sidecar handles are descriptor-bound or
non-create-capable. A process able to race files inside the signed App Group
container is treated as the existing unlocked-device/local-malware residual
threat. If review expands that attacker into scope, direct SQLite access stops
and the design moves to an owning host or a reviewed VFS rather than overstating
the check.

### CLI and JSON contract

PR 33 exposes only these operations, both with a validated `StoreLimit`
(`1..=10_000`) and a default of 50:

```text
mailctl inbox --account <opaque-account-id> [--limit <count>]
mailctl thread --account <opaque-account-id> --thread <opaque-thread-id> [--limit <count>]
```

There is no `message`, body, raw, HTML, MIME, export, mutation, sync, key, path,
or human-rendering command. Version-1 JSON is one document on stdout with
`schema_version`, `command`, `account_id`, `limit`, and `messages`. Each message
contains only `message_id`, `thread_id`, `from`, `subject`,
`received_at_millis`, and `unread`; the body-derived preview and cached content
are excluded. Arrays preserve the store contract's deterministic order.

Before any string reaches stdout, PR 33 must encode every C0 control
(`U+0000..U+001F`), DEL (`U+007F`), and C1 control (`U+0080..U+009F`) as a
JSON `\uXXXX` escape, even if current domain validation would reject it. This
is a terminal-safety boundary, not a substitute for JSON serialization.
Successful stdout is an explicit user-directed declassification from encrypted
storage; redirected files, pipes, terminal history, and downstream consumers
are outside the encrypted cache boundary.

The CLI writes no user or provider data to stderr. Its complete stable exit and
stderr contract is:

| Exit | Fixed stderr line |
|---:|---|
| 0 | no stderr |
| 2 | `mailctl: invalid invocation` |
| 3 | `mailctl: key access failed` |
| 4 | `mailctl: local profile is unavailable` |
| 5 | `mailctl: mailbox item was not found` |
| 6 | `mailctl: local mailbox is corrupted` |
| 7 | `mailctl: operation failed` |

Serialization is completed before the first stdout write. A broken pipe or
partial stdout write returns 7 without retrying and emits the same fixed
`mailctl: operation failed` stderr line; it never emits mailbox content.

`tersa-cli-macos` may depend inward on `tersa-application`, `tersa-domain`,
`tersa-platform`, `tersa-store-sqlcipher-macos`, and
`tersa-keychain-macos`. It owns only composition and stable rendering. The
application use cases and JSON DTOs must remain independent of concrete Apple,
SQLCipher, and future IPC types. Replacing the direct adapters with `maild` IPC
must preserve commands, limits, ordering, JSON, exit codes, and declassification
semantics.

## Non-claims

PR 32 adds root provisioning, validated retrieval, private derivation, and
fixed profile discovery, but no CLI, public raw-key provider, database-opening
composition, IPC, or `maild`. It passes no signed runtime gate and leaves Phase
1 roadmap item 7 open. It does not add real Google
authorization, token persistence, sync, background work, mailbox mutation,
search, UI, or release evidence.

All iPhone and iPad product implementation, mobile Keychain and protected-data
behavior, mobile UI selection, device evidence, background behavior,
TestFlight, and App Store work remain deferred to Phase 2. No macOS source or
evidence closes a mobile or mobile-inclusive gate.

## Consequences

The first CLI is intentionally narrow and locally replaceable. Key generation
has one owner, the Data Protection Keychain and application-group boundaries
are shared only by same-team signed targets, direct database reads cannot
mutate or silently ignore live WAL, and JSON output has a defined privacy
boundary. Future commands, renderers, profiles, key rotation, path overrides,
and IPC require separately reviewed contracts rather than compatibility
assumptions.
