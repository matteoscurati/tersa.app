<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0031: Terminal-only product pivot

- Status: Accepted
- Date: 2026-10-04

## Context

tersa was planned as a macOS-first native client: a SwiftUI/AppKit
application over a shared Rust core, an Apple bridge with a closed C ABI, a
separately signed XPC token broker (ADR 0024), App Group and Data Protection
Keychain storage (ADR 0019), and Apple signed-distribution acceptance gates
(ADR 0013, ADR 0021). Most of the remaining Phase 1 work was Apple
distribution, signing, and UI acceptance rather than mail-client behavior.

The product owner decided on 2026-10-03 that tersa becomes **a terminal (TUI)
client only**. The Rust core already holds the portable value: domain
invariants, mailbox ports, PKCE and token lifecycle, the identity gate, bounded
sync, metadata search, the Gmail REST adapter, and the SQLCipher store.

The last commit of the Apple-era tree is tagged `pre-tui-pivot`.

## Decision

### Product

- tersa is one Rust binary, `tersa`, that runs a full-screen terminal UI.
  Non-interactive subcommands (`account add|list|remove`, `sync`, `doctor`)
  share the same core.
- Supported platforms are **macOS and Linux** (x86_64 and aarch64). Windows,
  iOS, iPadOS, and any GUI surface are out of scope.
- The MVP is a full client: multi-account with a unified inbox, reading,
  search, offline reopen, triage (archive, read state, labels, trash, undo),
  and composition (local-first drafts, reply, forward, attachments, and an
  idempotent outbox). Composition uses `$EDITOR`.
- Distribution is a Homebrew tap with prebuilt binaries. A notarized DMG and
  the Mac App Store are no longer planned.
- Gmail access remains the official Gmail API with OAuth 2.0 PKCE and a
  loopback redirect. Users configure their own Google Cloud "Desktop app"
  OAuth client until the project has a Google-verified client.

### Retained constraints

ADR 0006 A3 (no project-operated backend) and A4 (OSI-approved production
licensing) remain in force. Encrypted local persistence, bounded sync and
cache, the official Gmail API, and performance as a primary constraint
(ADR 0022) remain in force.

### Secrets and storage

- One random 32-byte installation root key. Purpose-separated keys (registry
  SQLCipher key, per-account SQLCipher keys, registry dedup HMAC key) are
  derived from it with HKDF, reusing the ADR 0019 and ADR 0026 framing.
- The root key is held by the operating-system keyring (macOS login
  Keychain, Linux Secret Service). An optional passphrase wraps the root key
  with Argon2id and an AEAD before it is stored. When no keyring is available,
  a passphrase-wrapped file is the fallback.
- OAuth refresh tokens are stored inside the owning account's SQLCipher
  database, not as separate keyring items.
- Paths follow XDG on both platforms (`$XDG_CONFIG_HOME/tersa`,
  `$XDG_DATA_HOME/tersa`).

Accepted residual: without separately signed processes there is no runtime
barrier between the refresh token and the root key inside one user account.
Same-user code that can read the keyring item, or capture the passphrase, can
decrypt local data. Linux Secret Service has no per-application access
control. These residuals replace the ADR 0024 process-isolation claim.

### Hostile content in a terminal

- Every provider-derived string is sanitized before it reaches the terminal:
  C0 controls except newline and tab, C1 controls, ESC, DEL, and bidirectional
  override and isolate characters are removed or replaced. The TUI renders
  only the sanitized type.
- HTML bodies are converted to text in Rust with size and depth limits. No
  remote resource is ever fetched. Links become a numbered list and open only
  on an explicit keypress after the URL is shown; tersa never emits OSC 8.
- Attachments are saved with sanitized names and never opened automatically.
- MIME parsing, HTML-to-text conversion, and the sanitizer get fuzz targets.

### Governance

- `cargo xtask verify` (format, Clippy with warnings denied, tests, doc tests,
  rustdoc, and a layering check) on Linux and macOS, plus `cargo deny`,
  `cargo audit`, feature powerset checks, and `typos`, are the merge checks.
- The layering check enforces only durable rules: core crates under
  `crates/` depend only on allowed core crates, forbid `unsafe`, and stay free
  of I/O and OS crates; nothing depends on `apps/` or `xtask`.
- ADRs are written only for decisions that change architecture, security
  boundaries, or the data model.

### Superseded and amended decisions

| ADR | Effect |
| --- | --- |
| 0013 macOS-first phasing | Superseded. |
| 0014 macOS production dependency boundaries | Superseded by the layering rules above and `cargo deny`. |
| 0019 macOS key provisioning and read-only CLI | Amended: HKDF framing retained; Keychain access groups, App Group layout, and CLI authority split superseded. |
| 0020 macOS production UI toolkit | Superseded. |
| 0021 macOS UI vertical slice | Superseded. |
| 0022 performance as a primary constraint | Amended: TUI budgets below replace the macOS acceptance-protocol budgets. |
| 0023 OAuth and bounded sync | Amended: loopback listener moves to Rust; BYO client configuration. |
| 0024 macOS token process isolation | Superseded by the accepted residual above. |
| 0026–0030 | Amended: their data-model, sync, outbox, and blob decisions carry over; Apple surfaces (App Group, Swift UI, WebKit/native rich rendering, Face ID app lock) are replaced by the terminal equivalents in this ADR. |

### Initial TUI performance budgets

Measured on the developer's reference machines with a warm cache of at least
10,000 messages: first frame under 100 ms, top-50 list query under 20 ms,
idle resident memory under 50 MiB, and a stripped release binary under
15 MB. A budget breach blocks the slice that introduced it unless an accepted
ADR changes the budget.

## Delivery

| Milestone | Scope |
| --- | --- |
| T0 | This ADR; removal of Apple sources, FFI crates, and Apple CI; minimal `xtask`. |
| T1 | Portable adapters, `crates/keys`, `adapters/secrets`, Rust loopback OAuth, in-process token service, `tersa account add`. |
| T2 | Read-only TUI: inbox, thread, search, offline reopen, background sync, sanitizer, HTML to text. |
| T3 | Multi-account registry and unified inbox. |
| T4 | Triage with history sync and pending actions. |
| T5 | Composition, drafts, and the idempotent outbox. |
| T6 | Encrypted cache budget, eviction, and lock. |
| T7 | Release workflow and Homebrew tap. |

## Consequences

- `apple/`, the Apple bridge, the mailbox-sync and token-broker FFI crates,
  Apple CI lanes, macOS acceptance and distribution protocols, and their
  evidence are removed. They remain available at the `pre-tui-pivot` tag.
- The `-macos` adapters stay in the workspace until T1 makes them portable
  and renames them.
- PR 33b, Apple signing campaigns, and the Phase 1 item 7 and item 8 gates are
  closed as not applicable.
- On macOS, keyring access control is tied to the binary's code signature.
  Unstably signed builds re-prompt for Keychain access; T7 decides the
  release-signing approach.

## Non-claims

This ADR implements no TUI, keyring, or passphrase code. It does not claim
that the residuals above are acceptable for every threat model, and it does
not claim Google restricted-scope verification.
