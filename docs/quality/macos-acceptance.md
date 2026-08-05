# macOS acceptance protocol

## Purpose and non-claims

This protocol defines the evidence required to close macOS UI acceptance, macOS
release acceptance, and their aggregate Phase 1 guard. This document records no
pass, execution, evidence artifact, Developer ID signature, notarization, or
stapling result. It does not approve a mobile toolkit, and a macOS pass never
satisfies the mobile-inclusive production UI baseline.

Every candidate is the immutable, exact 40-character Git commit named by the
evidence record. It uses one redacted, independently reviewed Developer ID
artifact, with an immutable commit-bound manifest and SHA-256 digest. The
artifact and its manifest must be retained and reviewed under the same
commit-binding, expiry, and retention rules as the
[Apple physical-device and distribution protocol](../release/apple-distribution.md).
The artifact is not reusable for a different commit.

At least two qualifying people participate in each acceptance claim: an
implementer or evidence producer and an independent reviewer. The reviewer
cannot be the implementer, including under case or whitespace variation, and
must have relevant Apple platform, accessibility, security, or
release-engineering competence.

## Common evidence and fail-closed requirements

A distribution-signed acceptance claim requires all of the following:

- an exact lowercase 40-character Git commit SHA;
- an immutable commit-bound artifact locator for that same SHA;
- a SHA-256 for a redacted evidence manifest;
- `redacted: true` after an explicit scan for device identifiers, certificate or
  provisioning material, Apple IDs, team identifiers, account data, filesystem
  paths, credentials, tokens, message content, keys, and private notarization
  or submission identifiers;
- a named implementer/evidence producer;
- a different named independent reviewer with reviewed competence;
- an explicit independent-review attestation;
- timezone-qualified review and expiry timestamps, with review expiry no later
  than artifact retention.

Repository and GitHub Actions manifest locator forms, the 90-day Actions
retention bound, and the 89-day safety margin match the
[distribution protocol](../release/apple-distribution.md).

Record only redacted, fixed-vocabulary outcomes, command results, hashes,
versions, and aggregate measurements. A failed redaction scan, an unredacted
artifact, a mutable or commit-mismatched locator, an expired review, incomplete
metadata, or self-review fails closed.

## macOS UI acceptance

Use the release-equivalent Developer ID candidate on an Apple Silicon Mac.
Record the operating-system version, application version, build number, UI
candidate, commit, manifest digest, and non-unique machine class.

1. Inspect every core screen in the account connection, inbox, thread, search,
   and composer flow. Record native NSAccessibility roles, names, values,
   states, logical order, and available actions. Missing, misleading, or
   unreachable semantics fails acceptance.
2. Complete the core flow using VoiceOver only, with no pointer or visual
   fallback. A blocked core action, misleading announcement, focus loss, or
   crash fails acceptance.
3. Enable Full Keyboard Access and complete the same core flow using only the
   keyboard. Focus must be visible at every step, follow logical order, and
   remain trap-free. A pointer fallback, invisible focus, or focus trap fails
   acceptance.
4. Enable App Sandbox with minimal reviewed entitlements. Record the reviewed
   entitlement set and run denial tests for every capability not granted. An
   unnecessary entitlement, an unreviewed entitlement, or a failed denial test
   fails acceptance.
5. Measure the release-equivalent signed candidate after one warm-up run and at
   least five recorded runs. Report median and p95 using the Mac thresholds in
   the [performance harness](macos-performance.md) and the Mac column of the
   [distribution protocol](../release/apple-distribution.md): cached inbox
   interactive cold start p95 below 1.0 s, local top-50 query p95 below 100 ms,
   inbox scroll p95 at 60 frames/s with no unbounded row materialization, idle
   inbox memory below 140 MiB, and sync/index peak memory below 350 MiB. A
   threshold miss fails acceptance unless a separately accepted ADR changes that
   budget.

The installed application bundle must not exceed 16 MiB and the compressed DMG
download must not exceed 8 MiB. Measure regular-file bytes inside `Tersa.app`
and the final compressed DMG file bytes. A size-budget miss follows the same
fail-closed rule as the performance thresholds. The collection mechanism and
unsigned pre-measurement limits are documented in the
[macOS performance harness](macos-performance.md).

## macOS release acceptance

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
installation, smoke, hash, or redaction failure fails acceptance.

## Phase 1 aggregate attestation

The Phase 1 aggregate is evidence-bearing when it passes. It may pass only when
macOS UI acceptance and macOS release acceptance are both passed with
independently reviewed, current distribution-signed evidence for their exact
commits. Its own commit-bound, immutable, redacted, independently reviewed
distribution-signed artifact must attest that both prerequisite records,
manifests, hashes, redaction scans, reviewer independence, expiry windows, and
exact commit bindings were checked together for the claimed Phase 1 candidate.

An unresolved prerequisite, failing prerequisite, mismatched commit, expired
review, incomplete attestation, self-review, unredacted evidence, or failed
review of the aggregate record fails closed. Passing this guard does not alter
mobile or M1 status and cannot satisfy the mobile-inclusive production UI
baseline.
