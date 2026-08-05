# ADR 0006: Product constraints and M0 evidence gates

## Status

Accepted. Durable product constraints A3, A4, A5, and A9 remain in force.
The M0/Slint/Dioxus diagnostic gate program and toolkit-isolation machinery
described historically below are retired by
[ADR-0025](adr-0025-retire-m0-diagnostic-program.md) housekeeping (PR2). The
gate-register validator remains transitional only while
`docs/m0/gate-register.json` is still tracked (PR5 owns register removal).

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
  MVP; `M0-CACHE-001` owns measurement before any future expansion.
- **A9 — UI boundary.** Apple-quality custom UI is accepted; actual UIKit or
  AppKit widgets are not required. A custom UI must expose native
  UIAccessibility/NSAccessibility and pass VoiceOver, Dynamic Type, Full
  Keyboard Access, Switch Control, physical input, lifecycle, performance, and
  signed-distribution gates. Historical note: neither the retired Slint nor
  Dioxus M0 diagnostics was production-approved; production UI selection is
  governed by later ADRs (including ADR-0020).

## Gate governance

`docs/m0/gate-register.json` is the authoritative HEAD-checkable gate record.
Its strict status order is `open`, `diagnostic`, `blocked`, `failed`, `passed`;
only `passed` closes a gate. Evidence tiers are ordered `none`, `source`,
`host`, `simulator`, `device-unsigned`, `device-signed`, and
`distribution-signed`. Historical phrases such as “PASS locally” and “PASS by
code” are represented as `diagnostic`, never `passed`.

The register is authoritative for current state and evidence. The validator
separately pins the reviewed gate-ID set and minimum required tier so a register
edit cannot silently add a gate or lower its acceptance bar. A passed gate must
also have every declared dependency in `passed` state. Changing the canonical
ID or tier policy is an architecture change and requires exact-head review.

`P1-MACOS-001`, `P1-MACOS-002`, and `P1-MACOS-003` are a separately governed
macOS Phase 1 carve-out. Their passes do not count as M1 or UI-dependent
mobile-inclusive passes, do not satisfy `M1-UI-001`, and leave
`ui_baseline_approved` false. They neither approve a mobile toolkit nor alter
the existing mobile gate policy.

Evidence claiming a physical-device or signed-distribution pass must be
commit-bound, redacted, and independently reviewed. A qualifying reviewer is
a named contributor other than the implementer, with relevant Apple platform,
accessibility, security, or release-review competence, who records an explicit
attestation. Review metadata has an expiry; missing, unknown, or unparsable
fields fail validation. The validator also enforces the UI-table ID/status
parity and prevents a UI-dependent or M1 pass while
`ui_baseline_approved` is false.

## Consequences

M1 remains blocked until a production UI baseline has passed. `cargo xtask
verify` deliberately remains Rust-only because changing its Rust crate is out
of scope for this decision. The lightweight change-scope job runs
`python3 scripts/verify-m0-gates.py --self-test`, which performs full register
validation plus negative mutation self-tests, until the gate register is
removed in PR5. The policy job does not own the gate validator. Contributors
must run the same command locally before `cargo xtask verify`.

Historical note: diagnostic-only Slint/Dioxus isolation was previously enforced
by `xtask` dependency-boundary checks against the retired spike packages. Those
packages and guards are removed; durable product dependency boundaries for the
active workspace remain enforced by `xtask` and `cargo deny`.
