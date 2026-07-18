# ADR 0013: macOS-first product phasing

- Status: Accepted
- Date: 2026-07-16
- Amended: 2026-07-18

## Context

tersa.app remains an open-source, privacy-first Gmail client with no required
or project-operated backend, encrypted local persistence, a shared Rust core,
and the official Gmail API. The M0 record contains useful diagnostic evidence,
but its authoritative gate set and `ui_baseline_approved` flag are
mobile-inclusive. In particular, `M1-UI-001` remains blocked and the current
M0 evidence does not approve a production UI baseline.

The product can reduce integration risk by first delivering a bounded macOS
path. That path must not reinterpret host diagnostics as iPhone or iPad
evidence, weaken the existing M0 gates, or let a desktop UI decision decide the
mobile toolkit. The existing [product constraints](adr-0006-product-constraints.md),
[dependency rules](dependency-rules.md), and [M0 gate register](../m0/gate-register.json)
remain authoritative until later governance work explicitly changes them.

## Decision

Product implementation is phased as macOS-first, followed by a separately
governed iPhone and iPad implementation. The binding pull-request sequence is:

1. ADR and roadmap (this pull request).
2. Governance gate split and macOS acceptance protocol, passing nothing.
3. Dependency-boundary amendment for production Gmail, macOS SQLCipher, and
   AEAD crates.
4. Shared mailbox contracts with no I/O.
5. Gmail REST adapter behind ports, with fake transport and no real network or
   credentials in tests.
6. Encrypted macOS store behind ports, with no mobile protected-data claim.
7. Sync and cache orchestration.
8. Read-only macOS CLI.
9. macOS UI baseline and signed/notarized vertical slice, only after its own
   gates pass.

The macOS UI work in pull request 9 is separately gated by
`P1-MACOS-001` (macOS UI acceptance), `P1-MACOS-002` (macOS release
acceptance), and `P1-MACOS-003` (macOS Phase 1 acceptance guard).
`P1-MACOS-003` can pass only after both preceding gates pass with the required
distribution-signed evidence. These are Phase 1-only claims: they do not
satisfy `M1-UI-001`, approve a mobile toolkit, change any M0/mobile/M1 status,
or change `ui_baseline_approved`. This ADR records no pass.

## Amendment 2026-07-18: Phase 1 delivery reordering

The binding pull-request sequence above is amended for delivery order only:
the credential-dependent signed and notarized distribution is deferred to
last, and credential-independent source work proceeds first. This amendment
passes, reopens, closes, or edits no gate and weakens no requirement.

The rationale is that a real Developer ID Application identity, the
registered application group, and notarization authority are preconditions
not yet available to the release operator (see
[ADR-0019](adr-0019-macos-key-provisioning-and-readonly-cli.md), "PR 33b does
not begin until ..."). This is a deferral of preconditions, not a failed
gate, and it is explicitly not the demonstrated-inability condition in the
"Fail-closed stop conditions" section below: that clause addresses proven
inability of signing or notarization to satisfy the macOS acceptance
protocol and would stop macOS UI work, whereas absent credentials only defer
the signed distribution.

The revised execution order is:

1. Select and validate the production macOS UI toolkit via a separately
   reviewed ADR (reserved ADR-0020). This amendment approves no toolkit;
   ADR-0006 A9 ("Neither Slint nor Dioxus is production-approved") still
   stands.
2. Implement the macOS UI vertical-slice source (item 9 above, roadmap
   item 8) against the existing Rust core, under ad-hoc/development
   signing, producing accessibility and App Sandbox development evidence
   only.
3. Implement the real OAuth and Gmail authorization source path behind the
   existing ports. This depends on Google credentials and Google
   verification, which the deferral of Apple credentials does not affect;
   `M0-OAUTH-001` stays open and no runtime or authorization gate is
   claimed.
4. Build the cache and performance measurement harness and take unsigned
   pre-measurements only; `M0-CACHE-001` stays open and the budgets remain
   constraints, not passes.
5. Last, once ADR-0019's PR 33b start conditions are satisfied -- a real
   Developer ID Application identity, the registered application group,
   notarization authority, and the ADR-0019 reviewed product-application
   provisioning path that provisions the fixed root and establishes the
   account profile -- the Apple-credential distribution block, comprising
   PR 33b (roadmap item 7, item 8 above, closure) and the
   distribution-signed `P1-MACOS-001`, `P1-MACOS-002`, and `P1-MACOS-003`
   evidence.

The load-bearing split is explicit: Steps 2 through 4 source and development
work may start before the credential block, but it produces only
ad-hoc/development evidence that can never count toward `P1-MACOS-001`,
`P1-MACOS-002`, or `P1-MACOS-003`, or toward any distribution-signed closure,
which remain Developer-ID/notarization-only per the macOS Phase 1 acceptance
protocol. Roadmap item 7 remains open until PR 33b, and ADR-0019's PR 33b
preconditions are unchanged.

The phrase "only after its own gates pass" in item 9 above (roadmap item 8)
governs gate-closure claims and signed release artifacts, not the start of
source and development work.

This amendment passes, reopens, closes, or edits no gate;
`ui_baseline_approved` stays false; no UI toolkit is approved; no signing,
App Sandbox, App Group, Keychain, or notarization requirement is weakened;
and Phase 1 evidence never closes a Phase 2 gate.

## Non-claims

- Phase 1 provides no iPhone or iPad evidence and passes no gate at any mobile
  evidence tier. It does not approve a mobile toolkit.
- No existing M0 gate is deleted, downgraded, or passed. `M1-UI-001` is not
  satisfied, and this ADR does not change `ui_baseline_approved`.
- The macOS store makes no claim about iOS Data Protection, Keychain behavior,
  or protected-data runtime.
- Real Google authorization, verification, token persistence, and revocation
  remain open. Deterministic Gmail-adapter tests use neither network access nor
  credentials.
- The current encrypted-cache budgets remain constraints, not passes; in
  particular, this ADR does not close `M0-CACHE-001`.

## Fail-closed stop conditions

- Stop macOS UI work if NSAccessibility, VoiceOver, Full Keyboard Access,
  App Sandbox, signing, or notarization cannot pass the separately defined
  macOS acceptance protocol.
- CI must fail on dependency-policy violations until a separately reviewed
  policy change is accepted.
- Phase 1 evidence must never close a Phase 2 device-signed gate.

## Consequences

- The Rust contracts, Gmail adapter, encrypted store, sync/cache orchestration,
  and CLI must remain behind ports so the macOS vertical slice does not pull
  Apple or UI types into the shared core.
- Gmail uses the official REST API. Production dependencies for the adapter,
  macOS SQLCipher store, and AEAD persistence are introduced only after the
  explicit dependency-boundary amendment in pull request 3.
- The Phase 1 cache remains bounded and encrypted. Its current budgets remain
  product constraints pending the existing cache measurement evidence.
- A signed and notarized macOS slice may establish only its own future macOS
  acceptance claims. It cannot unblock or satisfy the mobile-inclusive M1
  baseline by itself.

## Phase 2 entry and acceptance conditions

Phase 2 may begin only after separately accepted mobile governance defines a
reviewed acceptance protocol with pinned, mobile-specific gates. Toolkit
selection and all iPhone and iPad implementation then occur within Phase 2,
rather than being inferred from the macOS slice or performed during Phase 1.

Phase 2 cannot complete or release until its fail-closed acceptance gates have
all passed. Those gates include:

1. selection and approval of the mobile UI toolkit;
2. physical iPhone and iPad evidence at the required tiers, including
   accessibility, input, protected-data, lifecycle, and performance checks;
3. real Google authorization and Keychain behavior reviewed on the relevant
   devices;
4. TestFlight and App Store work, including signed-distribution evidence; and
5. independent review of any proposed closure of the current mobile gates.

Background refresh and every other mobile runtime capability also remain
inside Phase 2 and subject to its accepted protocol.

No Phase 2 gate is closed by source inspection, host evidence, or a macOS
release artifact.
