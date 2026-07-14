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
and source-notice obligations remain applicable. Before Cargo runs,
`prepare-verified-skia.sh` downloads the target's pinned rust-skia 0.90.0
archive, verifies its SHA-256, and exposes only that verified file to
`skia-bindings` through its supported local `file://` source. Both Xcode and
the workspace-wide macOS CI job use this helper, so unverified archive bytes
never reach the extraction step. The source URL and all three Apple archive
digests are recorded in the feasibility evidence.

The macOS and iOS diagnostic bundles carry separate, target-specific
`THIRD_PARTY_NOTICES-*.txt` resources. `cargo-about` 0.9.1 generates their
complete linked Rust package inventory and available full license texts from
the locked Slint spike graph. A deterministic renderer removes cargo cache
state from the result and adds the pinned rust-skia, Skia, Expat, HarfBuzz,
ICU, libjpeg-turbo, libpng, Wuffs, and zlib notices explicitly. The native
component revisions come from the pinned Skia `DEPS` snapshot, and each copied
license text records its source path and SHA-256. Checksum-bound clarifications
also include the exact elected Slint license text. CI regenerates both
inventories offline and requires a byte-for-byte match before distribution
evidence can pass.

Slint 1.16.1 also locks non-Apple packages that are absent from the macOS and
iOS dependency graphs. `cargo-deny` therefore evaluates the three supported
Apple triples. The target-aware policy records reasons for three
Apple-reachable unmaintained notices: `RUSTSEC-2024-0436`,
`RUSTSEC-2026-0192`, and `RUSTSEC-2026-0206`. The full-lockfile `cargo-audit`
gate duplicates those three exceptions. It also records
`RUSTSEC-2025-0141` for build-time-only `bincode` through
`i-slint-compiler`, plus `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195` for
`quick-xml` through the non-shipping Wayland scanner. These last three packages
are absent from the supported Apple runtime graphs, but `cargo-audit` cannot
apply target reachability to a lockfile. The gate rejects every other warning
or vulnerability. CI expires all six exceptions on 15 August 2026. Removing or
renewing an exception requires explicit review and remains a production UI
gate, not an accepted product risk.

## Alternatives considered

Deferring Slint avoided the license decision but would not test native Winit and
Skia packaging. Allowing the license globally would weaken the supply-chain
policy and was rejected.
