# ADR 0004: Slint royalty-free binary license election

## Status

Accepted for the M0 diagnostic feasibility spike; legal review remains open.

## Decision

`tersa-slint-spike` pins Slint to `=1.16.1` and elects
`LicenseRef-Slint-Royalty-free-2.0` only for the Slint and `i-slint-*` packages
listed as narrow `cargo-deny` exceptions. The election permits distribution of
the diagnostic executable in binary form. It does not globally allow that
license and does not allow GPL licenses.

The executable is a standalone application binary. It does not re-expose the
Slint API, embed Slint in a library for third-party use, or expose a user-facing
plugin surface. Any design that changes those conditions requires legal review
and a new decision.

## Consequences

Distribution must retain the required Slint attribution and license notices.
The repository elects the public-webpage attribution option by displaying a
vendored copy of Slint's official attribution badge in the root README, which
is the public project and future download page. The vendored source is
`slint-ui/slint/logo/MadeWithSlint-logo-light-whitebg.svg`. If binary
distribution moves elsewhere, that page must carry the same attribution or the
application must expose Slint's `AboutSlint` widget in an About dialog reachable
from the top-level menu. The M0 team must obtain legal
confirmation before any production distribution. The `cargo-deny` exceptions
are intentionally package-specific and must be reduced if the locked graph no
longer requires an entry.

Skia is bundled through `rust-skia` and `skia-bindings`. Their native archive
and source-notice obligations remain applicable. `skia-bindings` downloads a
prebuilt archive when its build cannot use a local build; its observed archive
source URL and SHA-256 must be recorded in the feasibility evidence whenever
an Apple build exposes them. This repository does not treat an unavailable
download as evidence of provenance.

Slint 1.16.1 also locks non-Apple Winit/Wayland packages that are absent from
the macOS and iOS dependency graphs. `cargo-deny` therefore evaluates the three
supported Apple triples. `cargo-audit` cannot infer that reachability from the
lockfile, so CI narrowly ignores `RUSTSEC-2026-0194` and
`RUSTSEC-2026-0195`; both affect `quick-xml` through the non-shipping Wayland
scanner. The target-aware `cargo-deny` policy records reasons for the three
Apple-reachable unmaintained notices. The full-lockfile `cargo-audit` gate
rejects all other warnings and vulnerabilities while listing the six temporary
Slint-transitive exceptions explicitly. CI expires the complete exception set
on 15 August 2026. Removing or renewing these exceptions requires explicit
review and remains a production UI gate, not an accepted product risk.

## Alternatives considered

Deferring Slint avoided the license decision but would not test native Winit and
Skia packaging. Allowing the license globally would weaken the supply-chain
policy and was rejected.
