<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0025: Retire the M0 diagnostic program

- Status: Accepted
- Date: 2026-08-05

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
`workflow_dispatch` evidence suites, diagnostic evidence jobs, evidence
manifests, artifact uploads, and the manual evidence gate are removed.

Detailed spike sources, schemes, and packaging will be removed in follow-up
pull requests. The following remain preserved:

- architectural decision records that capture the learning;
- security and governance controls that still apply to the product;
- production SQLCipher and store decisions and code;
- product third-party notice generation;
- acceptance, performance, and distribution protocols;
- a short historical summary of the diagnostic program where still useful.

## Consequences

- Pull requests and the merge queue exercise only active product validation
  lanes.
- Later housekeeping pull requests can delete spike crates and Apple diagnostic
  targets without first reworking CI classification.
- Temporary audit ignores and review deadlines that still cover reachable or
  transitional spike dependencies remain until those sources are removed.
- This decision does not change product behavior, Rust FFI, database behavior,
  OAuth, Keychain, or user interface code.
