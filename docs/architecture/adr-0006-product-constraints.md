# ADR 0006: Product constraints and M0 evidence gates

## Status

Accepted. Durable product constraints A3, A4, A5, and A9 remain in force.
The M0/Slint/Dioxus diagnostic gate program and toolkit-isolation machinery
described historically below are retired by
[ADR-0025](adr-0025-retire-m0-diagnostic-program.md). The former live gate
register and validator were removed with PR5 documentation consolidation; see
the [M0 historical summary](../history/m0-summary.md). Active acceptance work
uses the [macOS acceptance protocol](../quality/macos-acceptance.md) and the
[Apple physical-device and distribution protocol](../release/apple-distribution.md).

## Decisions

- **A3 — service boundary.** MVP has no required or project-operated backend.
  A user-operated, open-source relay may be considered in vNext, but can never
  be an MVP dependency.
- **A4 — production licensing.** Production dependencies must be
  OSI-approved unless a separate accepted legal ADR authorizes a narrow
  exception. Historical note: Slint's royalty-free license was diagnostic-only
  under [ADR 0004](adr-0004-slint-binary-license.md); those diagnostic binaries
  and the README badge attribution path are retired and no longer apply.
- **A5 — cache boundary.** The default encrypted-cache budgets are 2 GiB on
  iOS and 10 GiB on macOS, configurable per account. These are product
  constraints, not evidence or a pass. Full-mailbox offline is excluded from
  MVP; cache measurement remains required before any future expansion.
- **A9 — UI boundary.** Apple-quality custom UI is accepted; actual UIKit or
  AppKit widgets are not required. A custom UI must expose native
  UIAccessibility/NSAccessibility and pass VoiceOver, Dynamic Type, Full
  Keyboard Access, Switch Control, physical input, lifecycle, performance, and
  signed-distribution acceptance. Historical note: neither the retired Slint nor
  Dioxus M0 diagnostics was production-approved; production UI selection is
  governed by later ADRs (including ADR-0020).

## Gate governance (historical)

While the M0 program was active, a tracked gate register was the HEAD-checkable
gate record. Its strict status order was `open`, `diagnostic`, `blocked`,
`failed`, `passed`; only `passed` closed a gate. Evidence tiers were ordered
`none`, `source`, `host`, `simulator`, `device-unsigned`, `device-signed`, and
`distribution-signed`. Historical phrases such as “PASS locally” and “PASS by
code” were represented as `diagnostic`, never `passed`.

That register and its validator are no longer live. Removed M0 gate IDs and
statuses are historical only. The durable product requirements above, and the
active quality and release protocols, govern current work.

macOS Phase 1 acceptance (UI, release, and aggregate) remains a separately
governed macOS carve-out. Passes do not count as M1 or UI-dependent
mobile-inclusive passes and leave the mobile-inclusive production UI baseline
unapproved. They neither approve a mobile toolkit nor alter mobile acceptance
policy.

Evidence claiming a physical-device or signed-distribution pass must be
commit-bound, redacted, and independently reviewed. A qualifying reviewer is
a named contributor other than the implementer, with relevant Apple platform,
accessibility, security, or release-review competence, who records an explicit
attestation. Review metadata has an expiry; missing, unknown, or unparsable
fields fail closed. Current procedure is in the
[Apple physical-device and distribution protocol](../release/apple-distribution.md).

## Consequences

M1 remains blocked until a production UI baseline has passed. `cargo xtask
verify` deliberately remains Rust-only because changing its Rust crate is out
of scope for this decision. Product CI no longer runs a gate-register validator.

Historical note: diagnostic-only Slint/Dioxus isolation was previously enforced
by `xtask` dependency-boundary checks against the retired spike packages. Those
packages and guards are removed; durable product dependency boundaries for the
active workspace remain enforced by `xtask` and `cargo deny`.
