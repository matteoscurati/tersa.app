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
2. **PR 31 — strict read-only SQLCipher open:** extend the existing macOS store
   adapter with persistent WAL coordination, a separately named read-only
   constructor, and deterministic standalone/coexistence tests.
3. **PR 32 — macOS Keychain and HKDF provider:** add
   `tersa-keychain-macos`, the inward platform contract it implements, and the
   reviewed provisioning/retrieval split.
4. **PR 33 — metadata-only JSON CLI:** add `tersa-cli-macos` with exactly the
   `inbox` and `thread` commands and activate both reserved dependency entries.

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
add, copy, update, and delete query sets `kSecUseDataProtectionKeychain` to
true; there is no legacy-keychain fallback. Missing entitlement, unexpected
item attributes, or a query that cannot use the Data Protection Keychain fails
closed. Existing items are retrieved but never replaced implicitly. The CLI
has retrieval-only access: an absent item is an error and cannot cause key
generation, import, repair, rotation, or a second Keychain write.

The macOS application and `mailctl` are two targets of one distribution. Both
are signed by the same Apple Developer team, carry the same registered
application-group entitlement, and use that group as their shared Keychain
access group. The official CLI is the signed executable shipped inside the app
bundle; a package manager may install only a symlink to that exact executable,
not rebuild or re-sign it independently. Community distributions must register
and inject their own group under their own signing team. Unsigned, differently
signed, missing-entitlement, or mismatched-group builds receive no production
fallback and cannot claim Keychain/profile interoperability.

The root key is never exported or accepted through arguments, environment,
stdin, files, IPC, logs, diagnostics, or JSON. The provider derives a 32-byte
account key with HKDF-SHA256. The salt is the literal byte string
`tersa.app/macos/root-key/v1`. The `info` input is unambiguous framing of the
literal prefix `tersa.app/macos/hkdf-sha256/v1`, followed by a two-byte
big-endian validated account-identifier length and its UTF-8 bytes, then a
two-byte big-endian purpose length and its ASCII bytes. Purposes are a closed,
versioned enum; the initial value is `sqlcipher/account-database/v1`. Unknown
versions or purposes fail closed. Root and derived key buffers use best-effort
zeroization and never implement content-revealing `Debug` or serialization.

The reviewed future pins are `security-framework =3.7.0` with default features
disabled, `hkdf =0.12.4`, `sha2 =0.10.9`, and `zeroize =1.9.0`, all declared
only for the exact macOS target where applicable. crates.io metadata identifies
3.7.0 as the current `security-framework` release. The current HKDF release,
0.13.0, resolves HMAC 0.13; 0.12.4 is deliberately selected because it uses
the already reviewed `hmac =0.12.1`. This policy does not weaken the existing
exclusive HMAC ownership. PR 32 must explicitly and narrowly expand that owner
set after reviewing the exact resolved graph; PR 30 changes no manifest or
lockfile.

`tersa-keychain-macos` may depend inward only on `tersa-platform`. Any needed
portable key capability belongs in that inward port; Apple Security types do
not cross it. Additional inward edges require a new ADR rather than an
incidental manifest edit.

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

The application-group identifier is a required signing-time setting shared by
the app and CLI entitlements. Resolution must verify access to the returned
container because macOS may return an expected-form URL even for an invalid
group. It never falls back to a normal Application Support path or either
target's private sandbox container. Official distribution must be notarized
and satisfy the Phase 1 App Sandbox gate before PR 33 can land.

`<sha256-account-id>` is the 64-character lowercase hexadecimal SHA-256 digest
of the validated opaque `AccountId` UTF-8 bytes. Tests may construct isolated
adapter paths directly, but the production CLI composition exposes no override.

### Strict read-only store contract

PR 31 must open an existing regular database only and fail when the file is
absent. The read path must preserve the current canonical parent, no-follow
leaf, path identity, account ownership, exact schema, SQLCipher version,
SQLite/SQLCipher integrity, bounded decode, and opaque error validation. It
must not create or claim a database, migrate schema, begin a write transaction,
fall back to read-write, or repair any state. Opening the CLI is never an
ownership or migration event.

Every validated read-write store connection sets
`SQLITE_FCNTL_PERSIST_WAL = 1` after ownership is established, so a clean final
checkpoint retains both `-wal` and `-shm` for a later reader. The read-only path
requires the main database and both sidecars to exist with the expected file
identities before it opens. It never creates, replaces, deletes, or repairs a
sidecar. If a legacy profile lacks the pair, a crash requires recovery, or a
sidecar changes during open, the reader fails closed until the owning
read-write application opens and establishes a valid persistent-WAL state.

The live connection uses SQLite read-only mode without `immutable=1` and
without a private copy. SQLite may update lock and WAL-index coordination in
the existing `-shm` file; that is not mailbox persistence authority. The main
database and WAL content must remain unchanged, and no new filesystem entry may
be created. Deterministic tests must prove both supported states: a standalone
reader after a clean writer close, and a reader while a writer holds WAL mode
and commits data that remains in the WAL. They must also prove that missing or
replaced sidecars fail without creation or database/WAL mutation. Busy,
moved-path, wrong-key, foreign-owner, unknown-schema, and integrity failures
remain fail closed and redacted.

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

This ADR and PR 30 implement no CLI, Keychain provider, key derivation,
read-only SQLCipher constructor, profile discovery, IPC, or `maild`. They pass
no gate and leave Phase 1 roadmap item 7 open. They do not add real Google
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
