# ADR 0006: Product constraints and M0 evidence gates

## Status

Accepted.

## Decisions

- **A3 — service boundary.** MVP has no required or project-operated backend.
  A user-operated, open-source relay may be considered in vNext, but can never
  be an MVP dependency.
- **A4 — production licensing.** Production dependencies must be
  OSI-approved unless a separate accepted legal ADR authorizes a narrow
  exception. Slint's royalty-free license is diagnostic-only. The
  [ADR 0004](adr-0004-slint-binary-license.md) badge and attribution remain
  while distributable Slint diagnostic binaries exist.
- **A5 — cache boundary.** The default encrypted-cache budgets are 2 GiB on
  iOS and 10 GiB on macOS, configurable per account. These are product
  constraints, not evidence or a pass. Full-mailbox offline is excluded from
  MVP; `M0-CACHE-001` owns measurement before any future expansion.
- **A9 — UI boundary.** Apple-quality custom UI is accepted; actual UIKit or
  AppKit widgets are not required. A custom UI must expose native
  UIAccessibility/NSAccessibility and pass VoiceOver, Dynamic Type, Full
  Keyboard Access, Switch Control, physical input, lifecycle, performance, and
  signed-distribution gates. Neither Slint nor Dioxus is production-approved.

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
of scope for this decision. CI's policy job runs the Python gate validator;
contributors must run it explicitly before `cargo xtask verify`.

Diagnostic-only UI isolation is enforced by `xtask` dependency-boundary checks:
Slint and Dioxus may occur only in their respective spike packages, not in the
production crates or Apple bridge. `cargo deny` is complementary license and
supply-chain policy; it is not sufficient to enforce that runtime isolation.
