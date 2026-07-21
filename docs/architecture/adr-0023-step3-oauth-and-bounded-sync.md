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
  to SQLCipher, never crossed over the C ABI, never logged. The store is the 3c
  `RefreshTokenStore` in `tersa-keychain-macos`; the trusted composition that loads
  and rotates it is the dedicated `tersa-oauth-sync-macos` crate (see Sync
  composition, amended 2026-07-21).
- **Rotation is an atomic in-place replace.** Google may return a new refresh token
  on refresh or re-consent. A refresh-token item has one fixed Keychain primary key
  (service + `AccountId` + access group), so a second `SecItemAdd` returns
  `errSecDuplicateItem` and there is no rename: the only atomic replace primitive is
  `SecItemUpdate`, which rotates the stored value in place with no window in which the
  account has no persisted credential (never delete-then-add). ADR 0019 made the
  Keychain surface add-only and deletion-forbidden specifically to keep the
  installation **root key** immutable and non-rotatable; the refresh token is a
  distinct item with a distinct lifecycle that is *designed* to rotate and to be
  withdrawn, so 3c amends the guard with a **token-item-specific** rule —
  `SecItemAdd` for the first store, `SecItemUpdate` for atomic rotation,
  `SecItemDelete` on disconnect and on `invalid_grant` — while the root key stays
  add-only, update- and deletion-forbidden.
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
  presented as store corruption. Preservation is **conditional on same-account
  re-consent** (see Account-identity gate): if the user re-consents with a different
  Google account, the preserved store would otherwise merge two accounts' mail under
  the one `default` slot, so the identity gate clears it before the first sync write.
- **Disconnect withdraws both consent and the harvested data.** Disconnecting an
  account calls the token `/revoke` endpoint, deletes the Keychain item, **and
  clears that `AccountId`'s cached mailbox from the store through the owning writer**
  in a single account-scoped transaction — revoking consent while leaving the fetched
  mail readable would not be a complete consent story. Step 3 ships the disconnect
  affordance.
- **Account-identity gate.** Because Phase 1 uses a single fixed `default`
  `AccountId` (see Identity binding), the store is guarded so two accounts' mail can
  never coexist under it — on **every** path that reaches a sync write, not only
  explicit disconnect. On the first successful connect the composition records a
  salted hash of the account's immutable OIDC `sub` (in hand from the `id_token` of
  each token response — no network fetch, no identity *displayed*, only a
  per-installation-salted hash stored in the encrypted store). Before any later sync
  write — a fresh connect or a re-connect after refresh failure — it hashes the
  connected account's `sub` and compares: a match preserves the store, a mismatch
  clears the previous account's cached mailbox before the new sync writes and
  records the new hash. The gate is **fail-closed** — if the hasher or the store
  read fails, the sync write is blocked rather than falling through to
  preserve-and-write — and the mailbox clear and the new-hash record commit in one
  account-scoped transaction. This makes the "never coexist" invariant hold for the
  account-switch, fresh-connect, and re-connect paths uniformly. Storing only a
  salted hash (not the subject) keeps this consistent with Identity binding, which
  forbids *displaying* an identity, not gating data lifecycle on a local hash.
  (3d-3a implemented the `sub` keying; see Identity source below for why the mutable
  `emailAddress` it originally used was replaced.)
- **Identity source — `sub` is a 3f-blocking requirement (amended 2026-07-21).**
  The gate as first built (3d-2a) hashes `getProfile.emailAddress`, but an email
  address is **not** an immutable Google-account identifier: Google documents it as
  mutable and reusable, and Workspace permits reassigning a removed address to a new
  account. Under `emailAddress`, that reassignment produces a silent false *match*
  that merges two principals' mail — precisely the outcome this gate exists to
  exclude. The gate is therefore **required to key on the OIDC `sub`** (unique, never
  reused) before the 3f live run; this is a **merge-blocking gate on 3f**, not a
  Phase-1 mechanism change. The gate mechanism is identifier-agnostic — it hashes an
  opaque string and stores only the salted hash — so the swap is confined to adding
  the `openid` scope, reading `sub` from **every** token response's `id_token`
  (exchange **and** refresh — a periodic refresh-driven sync after a restart holds no
  in-memory `sub`, so it must be re-derived from the refresh response), and having the
  connected session implement the profile port from its held `sub`; the salted-hash
  store, the decision logic, and the fail-closed/atomic-clear guarantees are
  unchanged. (Source: the 3d-2a independent review — a confirmed critical — and the
  Fable judgement verdict.)
  - **`id_token` decode is signature-unverified, by design (3d-2b).** The `id_token`
    is only ever read from the token-endpoint response body, received over the token
    transport's hardened TLS client directly from the token endpoint — never from a
    front channel. The TLS origin authenticates the issuer, so its signature is not
    verified (OIDC Core 3.1.3.7). This TLS-back-channel precondition is load-bearing:
    the decode helper is private to the token transport, and the `aud == client_id`
    check (with `iss` restricted to the Google issuers and a non-empty bounded `sub`)
    is what makes the decode-only posture sound. The day an `id_token` is accepted
    from any non-back-channel source, signature verification becomes mandatory.
  - **What 3d-2b landed:** the `openid` scope, the transport-confined `id_token`
    decode, semantic `aud`/`iss`/`sub` validation surfacing a validated subject on
    the token response, and the generic token-lifecycle composition (connect / refresh
    / proactive-refresh). A subject-less token response fails as a **non-destructive**
    `IdentityUnverified` (the stored refresh token is retained for retry), never the
    destructive consent-revoked terminal. 3d-2b makes the `sub` available; wiring it
    to the gate (the port rename, retiring the `emailAddress` GET, and the HKDF
    domain-label/version bump) lands with the concrete session in 3d-3.
  - **`exp`/`iat` validation — a 3d-3-blocking gate (amended 2026-07-21).** 3d-2b
    deliberately does NOT validate the `id_token`'s `exp`/`iat`: the token is always
    freshly minted over the confined TLS back channel (so `exp` is always in the
    future) AND the `sub` reaches no consumer in this slice, so the check would be
    inert twice over, and validating a Unix-time claim needs a wall clock the pure
    token layer deliberately excludes (it keeps `MonotonicClock` only). 3d-3 MUST,
    as a merge-blocking acceptance criterion, validate the claims **in the concrete
    session, before the subject feeds the identity gate, on EVERY token response
    (exchange and refresh)** using a **wall clock (Unix time) owned by the
    session/composition** — no wall-clock port is threaded into the pure token
    layer. Required checks: `exp` present and `now < exp + skew`; `iat` present and
    `iat <= now + skew` (reject a future-minted token); one fixed skew constant
    ≤ 5 minutes. Failure is the existing **non-destructive** `IdentityUnverified`
    (refresh token retained), never consent-revoked. TRIPWIRE (restated): the moment
    any non-back-channel `id_token` source is introduced, **signature verification
    AND `exp`/`iat`/`nonce` validation become mandatory at the acceptance point** —
    no deferral. (Source: the 3d-2b independent review — a Sol confirmed finding —
    and the Fable judgement verdict.)
    - **3d-3a landed** the freshness check at `GmailSession::new` (validated against
      a `WallClock`, 2-minute skew, non-destructive on failure). Because the session
      validates freshness ONCE at construction, the **3d-3c sync worker MUST build a
      fresh `GmailSession` per connect/refresh cycle** and never hold one long-term.
      (Source: the 3d-3a review.)

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

Sync writes run **only** through the new trusted `tersa-oauth-sync-macos`
composition crate — a dedicated crate, not an entry in `tersa-keychain-macos`
(amended 2026-07-21): giving `tersa-keychain-macos` the `tersa-gmail-rest-macos` /
`tokio` edges would make everything that depends on it — including the
**retrieval-only CLI** — transitively link `reqwest` (network), permanently deleting
the machine-checked reqwest-exclusivity that expresses the CLI's retrieval-only,
zero-network invariant. The composition crate keeps `tersa-keychain-macos` (the token
store) and the CLI off the network graph, realizing the dedicated-composition-crate
refactor the Consequences section anticipates. It loads the refresh token, refreshes
proactively, drives the existing `GmailMailbox` fetch and `SyncCoordinator` bounded
recent sync, and reconciles into the store over the existing **validated read-write**
SQLCipher path. The store remains the sole writer and migration authority; the sync
entry is an authorized
caller, not a second authority.

Concurrency: the store runs persistent WAL — one writer, many readers. Step 3 adds
a second read-write open (sync reconcile) alongside the bootstrap read-write open
and the ADR 0021 read-only UI readers. ADR 0019 scoped the global bootstrap lock to
"serialize cooperative bootstraps"; this ADR **amends** that contract to widen it to
serialize **every** read-write store open — bootstrap and sync alike — so a single
owning writer holds it at a time; WAL leaves the read-only UI readers unaffected.
The lock guards only the store-open-plus-reconcile-write critical section and is
**never held across network I/O**: bounded message bodies are fetched (per ADR 0018)
*before* the lock is taken and written under it in one short transaction, so a
network stall can never hold the writer. Sync stays bounded and single-flight per
ADR 0018 (only one sync runs at a time regardless of the lock); sync status crossing
the bridge is a closed integer set with no addresses, subjects, or per-person mail
counts beyond ADR 0018's aggregate.

The identity gate and the sync write it guards are distinct steps, so the
**whole gate-to-write cycle** must be serialized per account slot, not just each
transaction — otherwise two overlapping cycles could interleave a stale
identity record over a committed one and let two accounts' mail coexist. The 3d-2a
`gated_sync` building block documents this precondition but does not enforce it;
enforcement is a **3d-3 acceptance criterion (amended 2026-07-22, superseding the
2026-07-21 two-part framing)**. Part (2), an **in-transaction identity fence**, has
the sync carry the cycle's fresh identity hash so every mailbox-write transaction
commits only if the slot's recorded hash still equals it, aborting on mismatch
(landed in 3d-3b; see below). Part (1) is **whole-cycle serialization** of the
gate-to-write span, with two halves that are both hard, blocking 3d-3c criteria:
(1a) the Rust-owned sync worker is the **sole** production caller and holds one
whole-cycle permit per account slot — a concurrent begin returns busy rather than
queuing a second cycle; and (1b) a **compare-and-set identity record** —
`reconcile_identity` re-validates the observed prior state inside its own
`BEGIN IMMEDIATE` transaction (a `FirstRecord` inserts only if the row is still
absent; a `ClearAndRecord` only if the prior hash still matches what `decide`
observed), aborting to a fresh gate cycle on mismatch.

The fence guarantees no mailbox write commits under an identity other than its
cycle's fence, even cross-process — but it does **not** serialize the gate's own
read-decide-record step: a stale `RecordOnly` from a concurrent cycle can overwrite
a just-recorded different identity *without a clear*, letting the first cycle's
already-committed mail coexist with the second account's. The fence is therefore
**necessary but not sufficient**. The whole-cycle permit is required, not
convention, for in-process serialization; cross-process (and undisciplined-caller)
safety additionally requires the compare-and-set identity record — or a
cross-process whole-cycle exclusion proven held across the entire gate-to-write
span. Both are hard 3d-3c acceptance criteria, verified by a two-gate interleaving
regression test (empty store, concurrent double-`FirstRecord`, assert exactly one
account's mail survives). (Sources: the 3d-2a independent review — a confirmed
critical; and the 2026-07-22 Fable judgement verdict, which **reverses** the earlier
verdict that the fence alone was the guarantee.)

  - **3d-3c-1 landed part (1b), the compare-and-set (amended 2026-07-22).**
    `AccountIdentityStore::reconcile_identity` gained an `expected: Option<&Identity
    Hash>` (the identity `decide` observed); the SQLCipher store opens the record
    transaction `BEGIN IMMEDIATE` and, before any clear or upsert, re-reads
    `account_identity` and proceeds only if it still equals `expected` (a `None`
    requires the row still absent), else aborts the whole transaction with the new
    `MailboxStoreError::IdentityRaced`. `run_identity_gate` now loops read → decide →
    compare-and-set record, retrying on `IdentityRaced` (bounded, fail-closed on
    exhaustion): a lost first-connect race re-reads and re-decides to a
    clear-and-record rather than blindly re-recording, so the racing account's cached
    mail is wiped before its sync writes. The fence's and the CAS's in-transaction
    identity read are one shared fail-closed reader. Verified by the two-gate
    interleaving regression test above plus store-level CAS-abort tests. Part (1a) —
    the sole-caller worker's per-slot whole-cycle permit — remains a 3d-3c-2
    criterion (defense-in-depth in-process; the CAS is the cross-process guarantee).

  - **3d-3b landed part (2), the fence (amended 2026-07-21).** `run_identity_gate`
    now returns the identity hash it committed (on `Match`, the hash it just
    verified) as the cycle's fence; `gated_sync` threads it into `sync_recent`, and
    `MailboxStore::reconcile_recent_envelopes` / `cache_message_if_present` both take
    it. The SQLCipher store opens each writer transaction `BEGIN IMMEDIATE` (the
    write lock is taken up front, so the fence read cannot race a concurrent identity
    change *within that transaction*) and re-reads `account_identity` inside the
    transaction just before commit. A hash that no longer equals the fence, or a row
    that vanished, aborts the write with the new `MailboxStoreError::IdentityChanged`
    (surfaced by the coordinator as its own `SyncFailureSource::IdentityFenced`
    category rather than a generic store fault). A version-incompatible or otherwise
    unreadable identity row aborts as `MailboxStoreError::Corrupted` instead —
    matching the store's general rule that a present-but-unreadable identity never
    degrades to "no identity yet" — so it surfaces as `Store(Corrupted)`, not
    `IdentityFenced`; either way the write fails closed. Both the envelope write and
    the body cache are fenced (message IDs are not distinct across accounts, so a
    stale body-fetch could otherwise land on a colliding row). Part (1) —
    whole-cycle serialization (the sole-caller worker's permit **and** the
    compare-and-set identity record) — remains a 3d-3c criterion; the fence alone is
    necessary but not sufficient (see above).

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
  atomically with their `xtask` fixtures (direct and resolved graphs). The new
  `tersa-oauth-sync-macos` crate declares edges to `tersa-keychain-macos` (the token
  store), `tersa-gmail-rest-macos` (token transport + read adapter),
  `tersa-application`, `tersa-domain`, `tersa-store-sqlcipher-macos`, and the pinned
  current-thread `tokio`; it is added to the reqwest / SQLCipher / HMAC reachability
  owner-sets. `tersa-keychain-macos` gains **no** network edge, so the retrieval-only
  CLI stays off the `reqwest` / `tokio` graph (amended 2026-07-21). The token-item
  Keychain mutation-guard amendment from Token lifecycle (3c) stays in
  `tersa-keychain-macos`.
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
profile or `openid`/`email` scope to *display* an address; multi-account and
identity display are MVP-completion work. One narrow exception is required before
the 3f live run (see Account-identity gate → Identity source): the `openid` scope
is added solely to obtain the immutable OIDC `sub` for the account-identity gate —
never to display an address — because the gate cannot correctly key on the mutable,
reusable `emailAddress`. `sub` is used only as gate input (hashed, never shown).

### Client configuration and injection

The committed `apple/project.yml` OAuth placeholders stay `UNCONFIGURED`; the
client ID and — only if the client-secret probe shows the token endpoint requires
one — the non-confidential secret are injected locally at build time through a small
reviewed override that leaves the pinned `project.yml` structure unchanged, and are
never committed. The Google Cloud requirements are: a project with the Gmail API
enabled; an OAuth consent screen (External, Testing, with the developer's own
address as a test user); the `gmail.readonly` scope; and a **Desktop app** OAuth
client (client ID, plus the client's non-confidential secret if the probe requires
it; loopback needs no redirect registration).

### Decomposition into bounded, independently reviewed PRs

Everything except the final live run builds and is reviewed against the
`UNCONFIGURED` placeholder, which fails closed at every layer. Only 3f **builds or
runs** against the live client; the sole earlier touch of a live credential is the
one-off out-of-band `curl` client-secret probe before 3a (manual evidence, no build
artifact, the secret never committed or logged).

- **ADR 0023** (this document): the plan.
- **3a** — portable token exchange/refresh state machine and port; **replace**
  `GMAIL_MODIFY_SCOPE` with `gmail.readonly` so no `gmail.modify` code path remains.
  No I/O; deterministic tests. Its request shape is frozen only after the
  client-secret `curl` probe above.
- **3b** — the token-endpoint transport (`/token`, `/revoke`) as a distinct `POST`
  component in `tersa-gmail-rest-macos` (reusing its pinned HTTP policy;
  `GmailMailbox` unchanged), implementing 3a's port; carries the ADR 0016 amendment.
- **3c** — the refresh-token Keychain surface in `tersa-keychain-macos` with atomic
  in-place `SecItemUpdate` rotation and the token-item mutation-guard + fixture
  amendment (token item: `SecItemAdd` / `SecItemUpdate` / `SecItemDelete`; root key
  stays add-only, update- and deletion-forbidden). The token-item `SecItemUpdate` is
  the low-level primitive, not the high-level generic-password setter ADR 0019
  banned, and the fixture must prove the root key still rejects `Update` and
  `Delete`. Security-adjacent: senior review.
- **3d** — the composition and bridge: grant-forwarding exchange+persist, proactive
  refresh, the account-identity gate (salted `getProfile` hash; clear-before-sync on
  mismatch), the `connect` / `sync` / `disconnect` trusted entries (disconnect and
  the mismatch clear are account-scoped transactional deletes through the owning
  writer), the new sync C ABI on a Rust-owned bounded worker that fetches bodies
  before taking the write lock, the atomic export allowlist/header/fixture update,
  and the `tokio` + `tersa-gmail-rest-macos` dependency-boundary amendments with
  their graph fixtures. Security-adjacent: senior review.
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
owns end to end (3c, 3d, the guard extensions, and the 3e wiring review). This
concentrates token exchange, network entry, and the sync write path in the one
trusted `tersa-oauth-sync-macos` composition crate, which consumes the Keychain token
store and the SQLCipher store rather than absorbing them. 3d realizes the
dedicated-composition-crate refactor this section anticipated (Step 3 is the growth
that warrants it); keeping the composition out of `tersa-keychain-macos` keeps the
token store and, critically, the retrieval-only CLI off the `reqwest` / `tokio`
network graph — the machine-checked expression of the CLI's retrieval-only invariant. The read UI is
unchanged and its 2b surface stays invariant. The store gains real data, so
ADR 0022 runtime measurements become meaningful and are recorded per slice. The
account-connection screen gains a real Google sign-in and a disconnect affordance;
the developer configures a free Google Cloud Desktop client (about fifteen
minutes) for 3f, and re-consents about weekly while the app stays in Testing. When
the credential block clears, the deferred 2f runtime accessibility/sandbox walk and
signed distribution proceed independently of this step.
