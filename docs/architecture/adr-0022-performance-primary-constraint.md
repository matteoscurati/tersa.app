<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0022: performance as a primary constraint

- Status: Accepted
- Date: 2026-07-19

## Context

Performance and lightweightness are the product's primary priority for
Phase 1. Today they are governed only as a deferred final gate: the
[macOS Phase 1 acceptance protocol](../m0/macos-phase-1-acceptance-protocol.md)
(`P1-MACOS-001`, step 5) measures the release-equivalent signed candidate
at the end, the [product constraints](adr-0006-product-constraints.md)
(ADR-0006 A5) hold the cache budgets as constraints, and the
[macOS UI vertical-slice ADR](adr-0021-macos-ui-vertical-slice.md) defers
the measurement harness to its Step 4. This ADR elevates performance and
lightweightness to a primary, continuously and early measured constraint
without moving any gate or changing any threshold.

The Phase-1 macOS performance budgets form a single source-of-truth
chain: the acceptance protocol's Mac budgets are the Mac column of the
canonical performance table in the
[physical-device and distribution protocol](../m0/physical-device-and-distribution-protocol.md),
which carries dual iPhone and Mac columns. This ADR references both
documents by name and restates no threshold value; per the precedent of
the
[macOS production UI toolkit ADR](adr-0020-macos-production-ui-toolkit.md),
"the performance budgets are the acceptance bar by reference to
`P1-MACOS-001` and are not restated here". The cache budgets and their
"constraints, not a pass" status are ADR-0006 A5 and `M0-CACHE-001`; this
ADR neither restates nor bypasses them.

Distribution: the macOS release is distributed as a notarized DMG via
Developer ID direct download. The Mac App Store is an existing MVP
exclusion; Mac App Store distribution is post-MVP.

## Decision

### Performance and lightweightness as a primary constraint

Performance and lightweightness are a primary Phase-1 product constraint,
a peer in force to ADR-0006 A5 and A9, defined by reference to
`P1-MACOS-001` and the canonical table it derives from. This ADR restates
no threshold and changes none: the acceptance protocol states that a
threshold miss fails the gate unless a separately accepted ADR changes
that budget, and this ADR is not that change.

### Continuous early measurement regime (from PR 2c)

Every remaining Step-2 UI pull request (2c, 2d, 2e, and 2f) carries a
per-pull-request performance and size acceptance checklist recorded in
the pull request. This is the same mechanism ADR-0021 already uses for
accessibility: "a per-screen acceptance checklist in each Swift pull
request per ADR-0020, not a trailing pull request". Each slice's
checklist covers the metrics that are measurable at that slice: the
size metrics from PR 2c; cached-inbox cold start, inbox scroll, and
idle-inbox memory from PR 2d, where the inbox and thread render; and
query latency from PR 2e, where search lands. Sync and index peak
memory are not measurable until Step 3 introduces synchronization, so
they stay outside the Step-2 checklists. A metric not yet measurable at
a slice is outside that slice's checklist rather than a vacuous entry.

The checklist is a merge-acceptance review obligation: it is
reviewer-enforced, recorded in the pull request, and never written to
`gate-register.json`.

A development-signed measurement never passes or fails a budget:
`passed`, `failed`, and `diagnostic` are reserved gate-register statuses.
A budget breach in a development measurement blocks the slice's merge
until it is fixed, or explained with the measurement conditions
documented and the explanation accepted by the pull request's
independent reviewer -- never self-granted by the implementer. The
protocol numbers act as a merge-time tripwire, not a gate result, and a
breach is never relabelled as diagnostic success: the physical-device
and distribution protocol states that a threshold miss "is never
silently relabelled as diagnostic success".

### Size metrics (metric now, number later)

Every pull request from 2c through 2f records two tracked size metrics:
the installed `.app` bundle size and the compressed DMG download size.

This ADR pins no numeric size budget: no baseline exists, and PR 2c is
unmerged. A numeric size budget is set no later than the harness pull
request, and it lives in the macOS Phase 1 acceptance protocol, its
budget home, via that protocol's own reviewed edit; this ADR creates no
second budget home. Until then, a size growth against the prior slice
blocks the slice's merge until it is fixed, or explained with the
measurement conditions documented and the explanation accepted by the
pull request's independent reviewer -- never self-granted by the
implementer.

### Relationship to the ADR-0021 Step 4 harness (two regimes, no contradiction)

This ADR does not supersede or pull forward ADR-0021's Step 4 harness.
ADR-0021 defers the release-equivalent, protocol-grade measurement
harness to Step 4; this ADR adds an earlier, lighter, development-signed
checklist regime that the Step 4 harness later subsumes. The term
"pre-measurements" is reserved for Step 4, which the
[macOS-first phasing ADR](adr-0013-macos-first-phasing.md) owns; it is
not used for this regime.

Development-signed measurements can never count toward `P1-MACOS-001`,
`P1-MACOS-002`, or `P1-MACOS-003`, which remain Developer-ID and
notarization only. This ADR does not authorize the ADR-0021 session-held
reader optimization; that trigger stays bound to the Step 4 performance
harness.

Cache measurement remains owned by `M0-CACHE-001` and is not bypassed.
The macOS public MVP completion scope is unchanged: this ADR adds an
early development regime; it does not move any gate or rephase the
roadmap.

## Non-claims

This ADR passes, reopens, closes, downgrades, or edits no gate;
`gate-register.json` is unchanged, `ui_baseline_approved` stays false,
`M1-UI-001` stays blocked, and `P1-MACOS-003` stays blocked.

This ADR changes no acceptance-protocol threshold and restates no budget
number; it does not weaken the distribution-signed final bar or the
fail-closed threshold-miss rule.

This ADR makes no M0, mobile, or Phase 2 change; the "App Store last"
clarification is macOS-only and does not touch Phase 2's iOS App Store
work.

This ADR changes no entitlement, signing, code, manifest, or `xtask`
policy; the regime activates per implementation pull request (2c through
2f).

The Mac App Store stays MVP-excluded; distribution is a notarized DMG via
Developer ID direct download. This DMG note asserts no new gate evidence:
`P1-MACOS-002` still validates and staples `Tersa.app`, and any DMG
stapling or Gatekeeper evidence is a future reviewed protocol edit.

The regime starts at PR 2c; the merged PR 2a and the Rust-only PR 2b are
out of scope and are not retroactively reopened. This ADR is consistent
with ADR-0006, the
[macOS-first phasing ADR](adr-0013-macos-first-phasing.md) and its
amendment, the
[macOS production UI toolkit ADR](adr-0020-macos-production-ui-toolkit.md),
the
[macOS UI vertical-slice ADR](adr-0021-macos-ui-vertical-slice.md), and
the
[macOS Phase 1 acceptance protocol](../m0/macos-phase-1-acceptance-protocol.md).

## Consequences

Every macOS UI slice is measured for performance and size from its first
pull request, keeping the product fast and lightweight as a design lens
rather than a final surprise. The protocol-grade harness (Step 4) and the
numeric size budget follow in their own reviewed pull requests; the
distribution-signed gates remain unchanged.
