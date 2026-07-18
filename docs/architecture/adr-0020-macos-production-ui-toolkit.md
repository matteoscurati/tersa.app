<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0020: macOS production UI toolkit

- Status: Accepted
- Date: 2026-07-18

## Context

Phase 1 is macOS-first. The 2026-07-18 amendment to the
[macOS-first phasing ADR](adr-0013-macos-first-phasing.md) reorders the plan
so that selecting the production macOS UI toolkit is the first
credential-independent step, ahead of the UI vertical-slice source. No
production UI baseline has passed: `M0-SLINT-006` is failed because the locked
Winit iOS accessibility adapter is a no-op, and the Dioxus WebKit path
remains diagnostic-only with persistent WebKit state, navigation
interception, and runtime footprint unresolved. The existing `TersaMac`
target is already a minimal AppKit shell with a Rust static-library link.

The governing macOS accessibility and performance bar is the
[macOS Phase 1 acceptance protocol](../m0/macos-phase-1-acceptance-protocol.md)
(`P1-MACOS-001`), not the mobile-inclusive checklist in ADR-0006 A9. This ADR
references that protocol and does not restate A9's list or any thresholds.

## Decision

The Phase 1 production macOS UI toolkit is native AppKit/SwiftUI written in
Swift, hosted in the existing `TersaMac` target. Every approval sentence in
this ADR is scoped to macOS explicitly; this approves no mobile or Phase 2
toolkit, and Phase 2 selects its own.

The rationale is that standard native controls provide default
`NSAccessibility` exposure, with accessibility conformance remaining
subject to `P1-MACOS-001`; first-class App Sandbox integration; zero new
Rust crates or third-party UI packages; and sidestepping the recorded
Slint and Dioxus blockers above.

All mailbox state and logic stays in the Rust core, reached only through the
existing `tersa-apple-bridge` C ABI static-library link. UI-neutral
view-model shapes come from `tersa-presentation`; no Apple or UI type enters
`tersa-domain`, `tersa-application`, `tersa-platform`, or
`tersa-presentation`. The bridge's tracked-source policy today pins a
fixed, exhaustive C ABI allowlist with no mailbox or UI surface, so the UI
vertical slice will require its own separately reviewed bridge-surface and
`xtask` policy extension in the implementation pull request. This ADR
changes no policy, crate, dependency, or entitlement.

Standard native controls provide default accessibility exposure (roles,
names, values, states, logical order, and actions, per `P1-MACOS-001` item
1). Custom AppKit elements must implement the `NSAccessibility` protocols
or subclass `NSAccessibilityElement`, while custom SwiftUI views use
SwiftUI accessibility modifiers. The VoiceOver-only and
Full-Keyboard-Access-only core-flow requirements and the performance
budgets are the acceptance bar by reference to `P1-MACOS-001` and are not
restated here.

The application is sandboxed from the first slice. The current reviewed
entitlement allowlist enforced by the `xtask` signing guard is the baseline.
This ADR pre-approves no entitlement; any entitlement outside the existing
reviewed allowlist enters only through a reviewed change, and
`P1-MACOS-001` still requires the final entitlement set to be minimal and
denial-tested.

## Scope

This ADR selects the toolkit and defines the accessibility and sandbox
approach. "Validate" in the reordered Step 1 means this ADR's independent
review, not runtime evidence. This is not the UI vertical-slice
implementation and not a signed or notarized release; only ad-hoc or
development signing is implied, and such evidence can never count toward
`P1-MACOS-001`, `P1-MACOS-002`, or `P1-MACOS-003`.

Slint and Dioxus remain diagnostic-only under ADR-0004, ADR-0005, and
ADR-0007 through ADR-0010; their spikes, schemes, gates, and the ADR-0004
attribution badge are unchanged. ADR-0006 A9's sentence "Neither Slint nor
Dioxus is production-approved" remains true and is not edited by this ADR.

## Non-claims

This ADR passes, reopens, closes, downgrades, or edits no gate;
`gate-register.json` is unchanged, `ui_baseline_approved` stays false, and
`M1-UI-001` stays blocked. No `M0-SLINT-*` or `M0-DIOXUS-*` gate is closed,
reopened, or downgraded.

This ADR makes no signing, notarization, or distribution claim and records no
`P1-MACOS-001`, `P1-MACOS-002`, or `P1-MACOS-003` evidence. This is
consistent with the reorder: source work precedes signed evidence, and the
PR 33b preconditions are untouched.

This ADR approves no mobile or Phase 2 toolkit; it adds no Rust crate,
dependency, `xtask` policy, or entitlement; and it edits no other ADR.

## Consequences

The macOS product UI is built in AppKit/SwiftUI over the shared Rust core,
which stays UI-agnostic behind the bridge. The UI vertical slice, the next
step, will add its own reviewed bridge surface and any entitlement or policy
changes. Accessibility, sandbox, performance, and signed-distribution closure
remain future gated work under `P1-MACOS-001`, `P1-MACOS-002`, and
`P1-MACOS-003`.
