<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0021: macOS UI vertical slice

- Status: Accepted
- Date: 2026-07-18

## Context

Phase 1 is macOS-first. The
[macOS production UI toolkit ADR](adr-0020-macos-production-ui-toolkit.md)
selected native AppKit/SwiftUI and explicitly deferred the UI-slice bridge
surface and `xtask` policy extension to its own reviewed pull request; this
ADR is that plan. It decomposes Step 2, the macOS UI vertical-slice source,
into independently reviewable pull requests before any implementation. This
ADR plans and bounds Step 2; it implements nothing.

The target slice, per the roadmap, shows an encrypted cached inbox and
thread, supports the bounded mailbox state flow, reopens offline, and
exposes the same core through the read-only CLI. Real OAuth and Gmail
synchronization are Step 3.

The current state this ADR builds on: `tersa-presentation` holds only a
protocol-version constant, so the view-models must be authored;
`tersa-apple-bridge` exports an exact, exhaustive eight-symbol C ABI
allowlist enforced by `xtask`; the SQLCipher store is the sole writer and
migration owner and the CLI is retrieval-only per the
[key provisioning and read-only CLI ADR](adr-0019-macos-key-provisioning-and-readonly-cli.md);
and the [bounded sync and cache ADR](adr-0018-bounded-sync-and-cache.md)
excludes mutations from the bounded sync boundary.

## Decision

### Scope and the Step 2 / Step 3 boundary

This ADR decides the Step 2 pull-request decomposition and order; the
read-surface bridge contract principles and the `xtask` policy extension
plan; the screen inventory and data flows; the accessibility approach
binding; the no-new-entitlement position; the development-signed evidence
plan; and the ownership boundaries. It defers the exact C ABI
signatures to the implementation pull request's review and pins no
normative signature strings here. It also defers real OAuth, token,
network, and sync work to Step 3, the performance harness to Step 4, and
all distribution-signed gate evidence to Step 5, and it defers any mailbox
mutation contract and any production search engine indefinitely.

The Step 2 / Step 3 line: nothing that requires credentials, network,
tokens, or a live Gmail exchange enters Step 2. Step 2 renders the
read-only encrypted cache (inbox and thread), scaffolds the
account-connection UI states over the existing credentialless bootstrap C
ABI and the existing OAuth session state shapes only, and visualizes the
sync-flow states of the bounded sync and cache ADR without executing a real
sync. Step 2 must not invoke the existing macOS OAuth C ABI symbols
`tersa_oauth_macos_begin`, `tersa_oauth_macos_poll`, `tersa_oauth_cancel`,
or `tersa_oauth_macos_entitlement_probe`: begin stands up a live loopback
listener and authorization request, poll and cancel drive that
callback-transport session, and the entitlement probe performs a
loopback network check. Step 2 may only render the connection state
shapes those operations would drive; their invocation is deferred to
Step 3, and the authorization-code-to-token exchange itself remains
unimplemented until Step 3. Step 3 lights up OAuth and Gmail behind the
existing ports without changing the Step 2 bridge read surface; that
invariance is the test of a correct cut.

Because Step 2 runs no sync, the production cache is empty, so empty-state
UX is a first-class deliverable. No production demo-data or
fixture-injection channel is permitted: the key provisioning and read-only
CLI ADR forbids production overrides and test hooks, so deterministic cache
population happens only in Rust tests through the existing owning writer.

### Ownership invariants (from ADR-0019)

`SqlCipherMailboxStore` remains the sole writer, migration, and leaf owner;
`tersa-keychain-macos` remains the sole trusted composition executor;
`TersaMac` remains the sole logical profile owner.

The UI is a read/render and user-intent client only. It gains no store,
key, path, profile, or migration authority, and no raw key, handle, store
object, or storage capability crosses the bridge: the ADR-0019 rule,
extended verbatim to the read surface.

The read path uses the existing read-only reader open path through the
keychain composition's `open_default_read_only_mailbox`, never a second
opening path.

Step 2 ships zero write surface across the bridge. Mark-read/unread and
every other mailbox mutation require their own future reviewed contract
routed through the owning writer; Step 2 adds no mutation symbol.

### Bridge and FFI read-surface contract (principles only)

The exported C ABI allowlist stays exact and exhaustive: the current eight
symbols become eight plus N, each named. The implementation pull request
must update the expected-exports allowlist, the count check, the
reviewed-count message, and the fixtures atomically; a name-only allowance
is insufficient.

Data-only crossing: each Step 2 read call returns one bounded serialized
document (a caller-allocated buffer with a length-out parameter and a
closed `i32` status set). No pointer to Rust-owned state, no callback, and
no capability crosses. An opaque `u64` reader or session id identifies
Rust-held state and is therefore reserved for the later reviewed
session-held optimization, not Step 2.

No write symbol enters Step 2; the existing bootstrap call remains the only
symbol that can mutate mailbox, profile, or storage state.

Input validation stays inside the `tersa-keychain-macos` composition
entries; the bridge keeps only pointer and length checks. The bridge
tracked-source policy extends to a closed set of composition-entry calls,
still with no `AccountId` and no domain edge; this is a bound, not a
relaxation.

Layering runs `tersa-application` (mailbox-reader use cases and metadata
DTOs), then the newly authored `tersa-presentation` view-models, then the
bridge, which owns the wire encoding. Serde stays out of
`tersa-application`, per the ADR-0019 CLI precedent. No Apple or UI type
enters `tersa-domain`, `tersa-application`, `tersa-platform`, or
`tersa-presentation`.

The composition model is per-call open-read-query-close, at CLI parity,
trivially preserving the invariants. A session-held reader behind an opaque
id is a permitted later reviewed optimization only if the Step 4
performance harness shows the p95 budget demands it.

### Decomposition into bounded, independently reviewed PRs

| PR | Language | Content | Depends on |
|----|----------|---------|------------|
| 2a | Rust | `tersa-presentation` view-models (inbox list, thread) plus `tersa-application` read and query use cases, including the bounded cached-metadata search query; no bridge and no policy change | - |
| 2b | Rust + `xtask` | Bridge read C ABI for the inbox, thread, and search queries plus keychain composition read entries plus the exact allowlist, policy, and fixture extension | 2a |
| 2c | Swift | App scaffolding: window and navigation, account-connection flow states over the existing bootstrap symbol, empty-state inbox; parallel with 2a/2b since the existing eight symbols suffice | - |
| 2d | Swift | Inbox list and thread rendering over 2b; offline reopen is an acceptance check here, not a separate PR | 2b and 2c |
| 2e | Swift | Search screen as a bounded filter over cached envelope metadata via the 2b-exposed query (no FTS5, no Tantivy, no new dependency), plus a composer entry screen only (no send) | 2d |
| 2f | Evidence | Development-signed accessibility (VoiceOver, Full Keyboard Access) and sandbox denial development-evidence capture; explicitly non-gate. Any gap it surfaces is fixed in a freshly reviewed implementation PR, not in 2f | 2c through 2e |

View-model shape review (taste) and FFI/policy review (security-adjacent)
take separate reviewers. Only PR 2b extends the exported C ABI surface for
Step 2; any pull request that adds an exported symbol carries the same
atomic allowlist, count, message, and fixture obligation, and no other Step
2 PR adds an exported symbol. Accessibility is a per-screen acceptance
checklist in each Swift pull request per ADR-0020, not a trailing pull
request; 2f only audits and captures. Phase 1 search is a bounded filter
over cached envelope metadata: no production FTS5 or Tantivy (both
MVP-excluded) and no new dependency. The composer is an entry screen only;
send and outbox are MVP-completion work.

### Accessibility and App Sandbox

Each Swift pull request carries a per-screen accessibility acceptance
checklist per ADR-0020: native `NSAccessibility` roles, names, values,
states, logical order, and actions, with VoiceOver-only and
Full-Keyboard-Access-only core flows. This is the bar by reference to
`P1-MACOS-001`; it is not restated here.

The reviewed entitlement allowlist stays closed; Step 2 needs no new
entitlement. Any future entitlement enters only through a reviewed change
plus the acceptance-protocol denial tests.

### Dev-signed evidence

PR 2f captures development-signed accessibility and sandbox evidence for
iteration only. Such evidence can never count toward `P1-MACOS-001`,
`P1-MACOS-002`, or `P1-MACOS-003`, which remain Developer-ID and
notarization only.

## Non-claims

This ADR passes, reopens, closes, downgrades, or edits no gate;
`gate-register.json` is unchanged, `ui_baseline_approved` stays false, and
`M1-UI-001` stays blocked.

This ADR implies development or ad-hoc signing only; it and its Step 2
artifacts record no `P1-MACOS-001`, `P1-MACOS-002`, or `P1-MACOS-003`
evidence.

This ADR pre-approves no entitlement beyond the plan to keep the existing
reviewed set closed, and it adds no mailbox mutation, OAuth, token,
network, sync-execution, or search-engine claim.

This ADR approves no mobile or Phase 2 toolkit or evidence, and it adds no
new profile, store, or migration owner.

This ADR changes no manifest, policy, or code itself; every extension
activates only in its implementation pull request. It is consistent with
the [macOS-first phasing ADR](adr-0013-macos-first-phasing.md) and its
amendment, the
[bounded sync and cache ADR](adr-0018-bounded-sync-and-cache.md), the
[key provisioning and read-only CLI ADR](adr-0019-macos-key-provisioning-and-readonly-cli.md),
and the
[macOS production UI toolkit ADR](adr-0020-macos-production-ui-toolkit.md).

## Consequences

The UI slice is built in bounded, independently reviewed pull requests over
the shared Rust core, which stays UI-agnostic and the sole data owner. Real
OAuth and sync (Step 3), the performance harness (Step 4), and signed
evidence (Step 5) remain future gated work. Each bridge, policy, or
entitlement extension activates only in its own implementation pull request
with its own review.
