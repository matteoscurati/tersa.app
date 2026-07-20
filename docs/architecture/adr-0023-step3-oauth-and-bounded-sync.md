<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0023: Step 3 — production OAuth and bounded Gmail sync

- Status: Accepted
- Date: 2026-07-20

## Context

Phase 1 is macOS-first. Step 2 (the macOS UI vertical slice,
[ADR 0021](adr-0021-macos-ui-vertical-slice.md), PRs 2a–2f) shipped native
AppKit/SwiftUI account-connection, inbox, thread, search, and a composer-entry
screen. Those screens read an encrypted SQLCipher store that is **empty**: Step 2
explicitly shipped zero write surface and forbade invoking the OAuth symbols. Step
3 fills the store, so the existing read UI renders real mail, by connecting one
Google account per user and synchronizing a bounded recent mailbox read-only.

Much of the machinery exists and is reviewed:

- the PKCE authorization state machine and callback validation
  (`crates/application/src/oauth.rs`);
- the macOS loopback transport and the `tersa_oauth_macos_begin/poll/cancel`
  C ABI, already in the canonical (whitespace-normalized) pinned header and export
  fixtures;
- the Swift session driver `apple/macos/OAuthAuthorizationSession.swift`,
  instantiated and wrapped in a dormant `AppDelegate` method that is not reachable
  from any launch or UI path;
- the official Gmail read adapter ([ADR 0016](adr-0016-gmail-rest-adapter.md),
  `adapters/gmail-rest-macos`), `AccountId`-bound, `Zeroizing` tokens, GET-only
  under a fixed base;
- the bounded sync coordinator ([ADR 0018](adr-0018-bounded-sync-and-cache.md),
  `crates/application/src/sync.rs`) and the store reconcile path.

The one genuinely new and security-critical subsystem is the **token lifecycle**.
Today the bridge validates the authorization callback and then `drop(grant)`s it
(`apple/rust-bridge/src/oauth.rs`, `complete_callback`): no token exchange, no
refresh, no persistence, no revocation exists anywhere, and
`adapters/keychain-macos` has no token surface. This ADR plans Step 3; it
implements nothing. It follows the ADR 0021 precedent of a plan-only ADR whose
decisions are realized in later, independently reviewed pull requests.

The binding constraints (unchanged): each user connects **their own** Google
account through the official API; the product application is the sole profile
owner and migration authority; any CLI stays retrieval-only; there is no
write/send to Gmail in Phase 1; performance is the primary constraint
([ADR 0022](adr-0022-performance-primary-constraint.md)); signed distribution and
Developer-ID work stay last (the PR33b credential block).

## Decision

### Scope and the Step 3 / Step 4 boundary

Step 3 delivers: real per-user OAuth sign-in wired to the account-connection UI;
secure token lifecycle; a bounded read-only Gmail fetch that normalizes and writes
recent mail into the encrypted store through the reviewed write path; and the
existing inbox/thread/search rendering that real data. Per-slice size and the
runtime measurements enabled by a populated store are recorded on each PR's
ADR 0022 checklist, but the dedicated performance harness and its thresholds
remain **Step 4**; Step 3 does not build that harness or assert a threshold.

### Client-secret posture (amends an M0 invariant, empirically resolved)

The evidenced macOS transport binds an ephemeral `http://127.0.0.1:{port}/`
loopback; only Google's **Desktop app** client type accepts unregistered loopback
redirects. Whether the token endpoint requires the Desktop client's `client_secret`
under PKCE is contested — Google's native-app guidance has described it as optional,
while Desktop clients have historically been issued a secret and rejected exchanges
without it. This ADR does not settle it by reading docs: a one-off `curl` probe of
the token endpoint with the real Desktop client (a 3f prerequisite, run **before**
3a freezes its request shape) determines it empirically. Either result yields the
same posture: if a secret is required it is the Desktop client's, which is **not
confidential** for an installed app (RFC 8252 §8.5); if none is required, none is
sent. This ADR therefore amends the
[OAuth/PKCE feasibility](../m0/oauth-pkce-feasibility.md) deferred-work invariant
"exchange the validated code **without a client secret**" to "without a
**confidential** secret", so the plan holds under either outcome: any secret sent is
a build-injected non-confidential value carried alongside the client ID and used
only at the token endpoint. The alternative — an iOS-type client with no secret —
would force a reversed-client-ID custom-scheme redirect and discard the reviewed
loopback transport, and is rejected. No other feasibility invariant is weakened.

### Token lifecycle and ownership

- The **refresh token** is the only persisted credential: a single Keychain item
  per canonical `AccountId`, in the existing access group, with
  `WhenUnlockedThisDeviceOnly` accessibility (stricter than the root key and
  sufficient, since sync is user-triggered with no background work); never written
  to SQLCipher, never crossed over the C ABI, never logged. Owned by a new trusted
  composition entry in `tersa-keychain-macos`.
- **Rotation is an atomic replace.** Google may return a new refresh token on
  refresh or re-consent; replacing the stored item must be crash-safe
  (write-new-then-remove-old, never delete-then-add, so a crash never leaves the
  account with no persisted credential). ADR 0019's Keychain surface is add-only and
  forbids deletion, so 3c amends its guard with a **token-item-specific** atomic
  store-or-replace and delete while the installation root key stays add-only and
  deletion-forbidden.
- The **access token** stays in memory as a `Zeroizing` value (already
  adapter-side) and is never persisted. Refresh is **proactive**: the composition
  refreshes when the cached access token is within a clock-skew margin of its
  `expires_in` before driving a fetch. Reactive-refresh-on-401 is *not* used — the
  reviewed Gmail adapter (ADR 0016) fails a page on any non-404 error and cannot
  cleanly signal auth expiry — so expiry is tracked from `expires_in`, not inferred
  from a response.
- Refresh is **serialized per account**. Token exchange and refresh are modeled as
  a portable, I/O-free state machine (ports + fakes) with the network transport
  behind an adapter.
- **Refresh failure / revoked consent** (the common path: External + Testing
  expires the refresh token roughly weekly) is a first-class defined transition, not
  an error: an `invalid_grant` or a revoked token deletes the stored refresh token
  and surfaces a **re-connect** UI state; the encrypted store is **preserved** (no
  wipe — the read UI keeps working on cached mail) and the condition is never
  presented as store corruption.
- **Disconnect withdraws both consent and the harvested data.** Disconnecting an
  account calls the token `/revoke` endpoint, deletes the Keychain item, **and
  clears that `AccountId`'s cached mailbox from the store through the owning writer**
  — revoking consent while leaving the fetched mail readable would not be a complete
  consent story. Because Phase 1 uses a single fixed `default` `AccountId` (see
  Identity binding), connecting a different Google account is an account switch: the
  previous account's cached mailbox is cleared before the new sync writes, so two
  accounts' mail can never coexist under one slot. Step 3 ships the disconnect
  affordance.

### Read-only enforcement

Two server/build-enforced boundaries plus one source-convention layer, defense in
depth:

1. The genuinely enforced boundary is the Google-side scope
   `https://www.googleapis.com/auth/gmail.readonly` only (the metadata scope cannot
   fetch bodies; a modify/write scope is forbidden). 3a must **replace** the current
   `GMAIL_MODIFY_SCOPE` constant, not add a read-only one beside it, so no code path
   can still request `gmail.modify`; `access_type=offline` (already present,
   required for the refresh token) is retained.
2. No write/send symbol exists in the exported C ABI allowlist (xtask-enforced) —
   also structural.
3. The adapter is GET-only under the fixed Gmail base (ADR 0016) — a source
   convention reinforcing the two boundaries above, not itself a compile boundary.

The CLI reachability caveat extends to the token surface: the `xtask` source
allowlist must explicitly deny any CLI-reachable path to the token, exchange,
refresh, or revoke entries — defense in depth atop the compile boundary.

### Sync composition and write-path authority

Sync writes run **only** through a new trusted `tersa-keychain-macos` composition
entry that loads the refresh token, refreshes proactively, drives the existing
`GmailMailbox` fetch and `SyncCoordinator` bounded recent sync, and reconciles into
the store over the existing **validated read-write** SQLCipher path. The store
remains the sole writer and migration authority; the sync entry is an authorized
caller, not a second authority.

Concurrency: the store runs persistent WAL — one writer, many readers. Step 3 adds
a second read-write open (sync reconcile) alongside the bootstrap read-write open
and the ADR 0021 read-only UI readers. The sync write is serialized against the
bootstrap write path under the existing global bootstrap lock (a single owning
writer at a time); WAL leaves the read-only UI readers unaffected. Sync stays
bounded and single-flight per ADR 0018; sync status crossing the bridge is a closed
integer set with no addresses, subjects, or per-person mail counts beyond
ADR 0018's aggregate.

### Adapters, bridge, and FFI additions

- The token exchange/refresh/revoke transport is a **distinct component from the
  GET-only `GmailMailbox`**: 3b adds it in the `tersa-gmail-rest-macos` crate to
  reuse that crate's pinned HTTP client policy (HTTPS-only, no redirects/proxies,
  bounded), but as its own `POST`-to-the-token-endpoint transport, while
  `GmailMailbox` stays GET-only under the fixed Gmail base. ADR 0016 is amended to
  record that the crate hosts both bounded transports.
- The token transport applies ADR 0016's provider-data-free error discipline to
  **all** of its secrets: the authorization code, PKCE verifier, any client secret,
  and the access/refresh tokens are `Zeroizing` on the wire and never logged, and no
  token-endpoint request or response body is logged (Google error bodies can echo
  request parameters).
- `complete_callback` (and the iOS finish path) forward the validated grant into
  the token exchange instead of dropping it.
- New `tersa_mailbox_macos_sync_*` begin/poll symbols run the bounded sync on a
  **Rust-owned** dedicated worker (not the Swift `DispatchQueue` the synchronous
  read symbols hop onto), never the main thread.
- These bridge changes carry the same atomic obligation ADR 0021 set for 2b: the
  exact export allowlist, its count and message, the canonical (whitespace-
  normalized) pinned header, and the test fixtures are updated together in one
  reviewed PR.
- The trusted composition's new dependencies require boundary amendments, updated
  atomically with their `xtask` fixtures (direct and resolved graphs):
  `tersa-keychain-macos` gains an edge to `tersa-gmail-rest-macos` and to the pinned
  `tokio` (both currently rejected by the maximum and exact dependency sets), plus
  the token-item Keychain mutation-guard amendment from Token lifecycle.
- A new **OAuth/sync invocation seam** guard clones the Step-2 bootstrap
  launch-entry policy (`swift_bootstrap_intent_entries`): `OAuthAuthorizationSession`
  start/cancel and the sync trigger are each confined to a single reviewed
  view-model intent entry; `AppDelegate` declares but never calls them; no
  automatic or launch/init entry may reach them.

### Asynchronous runtime

The Gmail adapter's client and the token transport are asynchronous. Step 3
introduces an exact-pinned, current-thread `tokio` runtime, target-scoped to the
trusted composition, as an
[ADR 0014](adr-0014-macos-production-dependency-boundaries.md) dependency-boundary
amendment mirroring how `reqwest` entered — no workspace-wide async, no runtime in
the domain or the bridge surface. The runtime scope covers **both** network entry
points: the connect-time authorization-code→token exchange (driven from the
grant-forwarding path on the OAuth loopback worker) and the sync worker — the
grant-forwarding change must have a runtime to run on.

### Identity binding

Phase 1 keeps the single fixed `default` account. Step 3 does **not** add a
profile or `openid`/`email` scope to display an address; multi-account and
identity display are MVP-completion work.

### Client configuration and injection

The committed `apple/project.yml` OAuth placeholders stay `UNCONFIGURED`; the
client ID and the non-confidential secret are injected locally at build time
through a small reviewed override that leaves the pinned `project.yml` structure
unchanged, and are never committed. The Google Cloud requirements are: a project
with the Gmail API enabled; an OAuth consent screen (External, Testing, with the
developer's own address as a test user); the `gmail.readonly` scope; and a
**Desktop app** OAuth client (client ID + non-confidential secret; loopback needs
no redirect registration).

### Decomposition into bounded, independently reviewed PRs

Everything except the final live-run builds and is reviewed against the
`UNCONFIGURED` placeholder, which fails closed at every layer; only 3f needs the
live client.

- **ADR 0023** (this document): the plan.
- **3a** — portable token exchange/refresh state machine and port; **replace**
  `GMAIL_MODIFY_SCOPE` with `gmail.readonly` so no `gmail.modify` code path remains.
  No I/O; deterministic tests. Its request shape is frozen only after the
  client-secret `curl` probe above.
- **3b** — the token-endpoint transport (`/token`, `/revoke`) as a distinct `POST`
  component in `tersa-gmail-rest-macos` (reusing its pinned HTTP policy;
  `GmailMailbox` unchanged), implementing 3a's port; carries the ADR 0016 amendment.
- **3c** — the refresh-token Keychain surface in `tersa-keychain-macos` with atomic
  rotation and the token-item mutation-guard + fixture amendment (root key stays
  add-only, deletion-forbidden). Security-adjacent: senior review.
- **3d** — the composition and bridge: grant-forwarding exchange+persist, proactive
  refresh, the `connect` / `sync` / `disconnect` trusted entries (disconnect revokes
  and clears the cached mailbox), the new sync C ABI on a Rust-owned bounded worker,
  the atomic export allowlist/header/fixture update, and the `tokio` +
  `tersa-gmail-rest-macos` dependency-boundary amendments with their graph fixtures.
  Security-adjacent: senior review.
- **3e** — wire OAuth start/cancel, sync, and disconnect to the account-connection
  view-model as the single reviewed intent entries; real connection / sync /
  re-connect / disconnect states; the new Swift OAuth/sync invocation-seam guard
  (security-adjacent: senior review; taste per ADR 0020). No change to the 2b read
  surface — the ADR 0021 invariance test.
- **3f** — evidence: the live client on the developer's own account; the
  client-secret probe result; real consent, bounded sync populating the store,
  inbox/thread/search rendering real mail; disconnect and re-connect exercised; the
  ADR 0022 measurements a populated store enables. Run by the lead with the user's
  client.

3a and 3c may proceed in parallel; 3b after 3a; 3d after 3a–3c; 3e after 3d;
3f last.

## Non-claims

This ADR authorizes no write or send to Gmail, no distribution, notarization,
Developer-ID, TestFlight, or App Store evidence, no multi-account or non-Gmail
account, no identity/address display, and no performance threshold or harness
(Step 4). It does not weaken the App Sandbox, the entitlement allowlist (network
client/server already present; the only new endpoint pair is the Google token and
revoke endpoints under the existing pinned client policy), the read-only CLI
posture, or any OAuth/PKCE feasibility invariant other than the explicit
client-secret amendment above. The development operating condition that External +
Testing + a restricted scope expires refresh tokens roughly weekly is a
development inconvenience, not a product behavior; full restricted-scope
verification (CASA) is MVP-completion work.

## Consequences

Step 3 is mostly integration over reviewed parts, concentrated on one new
security-critical subsystem — the token lifecycle — which the senior/security lane
owns end to end (3c, 3d, the guard extensions, and the 3e wiring review). The read
UI is unchanged and its 2b surface stays invariant. The store gains real data, so
ADR 0022 runtime measurements become meaningful and are recorded per slice. The
account-connection screen gains a real Google sign-in and a disconnect affordance;
the developer configures a free Google Cloud Desktop client (about fifteen
minutes) for 3f, and re-consents about weekly while the app stays in Testing. When
the credential block clears, the deferred 2f runtime accessibility/sandbox walk and
signed distribution proceed independently of this step.
