<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0025: Retire the M0 diagnostic program

- Status: Accepted
- Date: 2026-08-05
- Amended: 2026-08-05 (PR5 consolidation completed)

## Context

The M0 program used diagnostic spikes and gated evidence capture to learn about
candidate UI toolkits, storage, search, MIME, and blob paths before the product
architecture was settled. Those spikes produced useful constraints and rejected
production candidates, but they are no longer the path forward.

The functioning product is the SwiftUI/AppKit macOS client with the reviewed
Rust core, Apple bridge, mailbox-sync and token-broker FFI surfaces, production
SQLCipher store, OAuth and Keychain boundaries, and product third-party notices.
Keeping diagnostic CI jobs, evidence artifacts, and manual capture gates in the
single GitHub Actions workflow dilutes the product-only merge signal and delays
removal of the spike sources.

## Decision

Retire the M0 diagnostic program from continuous integration and record that
retirement as an accepted architectural decision.

Product-only CI remains: draft-PR guards, DCO, scoped product Apple
test/build/symbol checks, Rust Linux and macOS verification, policy and supply
chain checks, active third-party notices, and the required `CI gate`. Manual
`workflow_dispatch` evidence suites, diagnostic evidence jobs, GitHub Actions
evidence-manifest creation, artifact uploads, and the manual evidence gate are
removed.

Housekeeping pull requests removed spike crates, Apple diagnostic targets, the
frozen gate register, the register validator, the obsolete combined OAuth
verifier, and the dedicated entitlement-probe example/export. The fifth and
final consolidation PR records that completion: one short
[historical summary](../history/m0-summary.md) replaces the detailed M0 study
corpus, and still-valid product protocols live under
[docs/quality/](../quality/macos-acceptance.md) and
[docs/release/](../release/apple-distribution.md).

The following remain preserved:

- architectural decision records that capture the learning;
- security and governance controls that still apply to the product;
- production SQLCipher and store decisions and code;
- product third-party notice generation;
- acceptance, performance, and distribution protocols;
- a short historical summary of the diagnostic program.

This consolidation does not claim that release, accessibility, or
distribution-signed acceptance gates have passed.

## Consequences

- Pull requests and the merge queue exercise only active product validation
  lanes.
- GitHub Actions no longer creates or uploads diagnostic evidence manifests,
  and no M0 gate validator remains in the tree.
- Spike crates and Apple diagnostic targets are gone; product behavior, Rust
  FFI contracts, database behavior, OAuth product flows, Keychain, and UI code
  are unchanged by this retirement decision.
- Temporary audit ignores and review deadlines that still cover reachable or
  transitional spike dependencies remain only if those sources still exist.
- This decision does not change product behavior, Rust FFI, database behavior,
  OAuth, Keychain, or user interface code.
