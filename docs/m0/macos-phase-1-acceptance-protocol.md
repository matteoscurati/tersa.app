# macOS Phase 1 acceptance protocol

## Purpose and non-claims

This protocol defines the evidence required to close `P1-MACOS-001`,
`P1-MACOS-002`, and their aggregate guard `P1-MACOS-003`. This PR records no
pass, execution, evidence artifact, Developer ID signature, notarization, or
stapling result. It passes no M0, mobile, or M1 gate; it does not approve a
mobile toolkit; and `ui_baseline_approved` remains false.

Every candidate is the immutable, exact 40-character Git commit named by the
evidence record. It uses one redacted, independently reviewed Developer ID
artifact, with an immutable commit-bound manifest and SHA-256 digest. The
artifact and its manifest must be retained and reviewed under the same
commit-binding, expiry, and retention rules as the physical-device and
distribution protocol. The artifact is not reusable for a different commit.

At least two qualifying people participate in each gate: an implementer or
evidence producer and an independent reviewer. The reviewer cannot be the
implementer, including under case or whitespace variation, and must have the
reviewed competence required by the gate register.

## Common evidence and fail-closed requirements

The evidence record must meet the register validator's distribution-signed
requirements: exact lowercase commit SHA, immutable commit-bound locator,
manifest SHA-256, `redacted: true`, named independent reviewer, canonical
attestation, timezone-qualified review and expiry timestamps, and expiry no
later than artifact retention. Repository and GitHub Actions manifest locator
forms, the 90-day Actions retention bound, and the 89-day safety margin are
identical to the physical-device and distribution protocol.

Before review, scan every evidence file and command summary for device
identifiers, certificate or provisioning material, Apple IDs, team identifiers,
account data, filesystem paths, credentials, tokens, message content, keys,
and private notarization or submission identifiers. Record only redacted,
fixed-vocabulary outcomes, command results, hashes, versions, and aggregate
measurements. A failed redaction scan, an unredacted artifact, a mutable or
commit-mismatched locator, an expired review, incomplete metadata, or
self-review fails closed.

## `P1-MACOS-001`: macOS UI acceptance

Use the release-equivalent Developer ID candidate on an Apple Silicon Mac.
Record the operating-system version, application version, build number, UI
candidate, commit, manifest digest, and non-unique machine class.

1. Inspect every core screen in the account connection, inbox, thread, search,
   and composer flow. Record native NSAccessibility roles, names, values,
   states, logical order, and available actions. Missing, misleading, or
   unreachable semantics fail the gate.
2. Complete the core flow using VoiceOver only, with no pointer or visual
   fallback. A blocked core action, misleading announcement, focus loss, or
   crash fails the gate.
3. Enable Full Keyboard Access and complete the same core flow using only the
   keyboard. Focus must be visible at every step, follow logical order, and
   remain trap-free. A pointer fallback, invisible focus, or focus trap fails
   the gate.
4. Enable App Sandbox with minimal reviewed entitlements. Record the reviewed
   entitlement set and run denial tests for every capability not granted. An
   unnecessary entitlement, an unreviewed entitlement, or a failed denial test
   fails the gate.
5. Measure the release-equivalent signed candidate after one warm-up run and at
   least five recorded runs. Report median and p95 using the existing Mac
   thresholds: cached inbox interactive cold start p95 below 1.0 s, local
   top-50 query p95 below 100 ms, inbox scroll p95 at 60 frames/s with no
   unbounded row materialization, idle inbox memory below 140 MiB, and
   sync/index peak memory below 350 MiB. A threshold miss fails the gate unless
   a separately accepted ADR changes that budget.

## `P1-MACOS-002`: macOS release acceptance

Build the exact candidate with Hardened Runtime and the reviewed minimal
entitlements, sign it with Developer ID, submit it for notarization, and staple
the accepted ticket. The redacted command summary must show successful results
for:

```sh
codesign --verify --deep --strict --verbose=2 Tersa.app
xcrun stapler validate Tersa.app
spctl --assess --type execute --verbose=4 Tersa.app
```

Install the stapled artifact in a clean user account and complete a bounded
core smoke: launch, account-connection entry, inbox navigation, thread open,
search, composer entry, quit, and relaunch. The artifact manifest must include
the application SHA-256 and redacted outputs for signing, notarization,
stapling, installation, and smoke results. Signing, notarization, stapling,
installation, smoke, hash, or redaction failure fails the gate.

## `P1-MACOS-003`: Phase 1 aggregate attestation

`P1-MACOS-003` is evidence-bearing when it passes. It may pass only when
`P1-MACOS-001` and `P1-MACOS-002` are both passed with independently reviewed,
current distribution-signed evidence for their exact commits. Its own
commit-bound, immutable, redacted, independently reviewed distribution-signed
artifact must attest that both prerequisite records, manifests, hashes,
redaction scans, reviewer independence, expiry windows, and exact commit
bindings were checked together for the claimed Phase 1 candidate.

An unresolved prerequisite, failing prerequisite, mismatched commit, expired
review, incomplete attestation, self-review, unredacted evidence, or failed
review of the aggregate record fails closed. Passing this guard does not alter
M0, mobile, M1, or `ui_baseline_approved` status, and cannot satisfy
`M1-UI-001`.
