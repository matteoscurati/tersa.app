# ADR 0013: macOS-first product phasing

- Status: Accepted
- Date: 2026-07-16

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

The macOS UI work in pull request 9 is separately gated. A later governance
pull request defines and pins its macOS UI and release acceptance gates before
that work can claim a pass. Until then, this ADR authorizes sequencing only;
it passes no existing gate.

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
