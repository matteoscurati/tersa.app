# Apple physical-device and distribution protocol

## Purpose and non-claim

This protocol defines the evidence required to close physical-device and
signed-distribution acceptance. It records no execution, device result,
signature, notarization, TestFlight installation, or App Review result. Host,
simulator, unsigned archive, and source-inspection results cannot substitute
for the procedures below.

Related active protocols:

- [macOS acceptance protocol](../quality/macos-acceptance.md)
- [macOS performance harness](../quality/macos-performance.md)

## Candidate and device matrix

Every run must identify the exact 40-character Git commit, application version,
build number, UI candidate, operating-system version, and evidence-manifest
SHA-256. Device identifiers are recorded only as non-unique classes.

| Class | Minimum evidence target | Required coverage |
|---|---|---|
| iPhone | Physical supported iPhone with 4 GiB RAM and a notched or Dynamic Island display | Touch and keyboard input, safe areas, VoiceOver, lifecycle, protected data, memory, network changes, performance, energy, TestFlight installation |
| iPad | Physical supported iPad with external hardware keyboard | Split layout, rotation, pointer and keyboard navigation, Full Keyboard Access, VoiceOver, lifecycle, memory, performance, TestFlight installation |
| Mac | Apple Silicon Mac with 8 GiB RAM | Keyboard-only operation, VoiceOver, window lifecycle, lock/unlock, memory, performance, energy, Developer ID distribution |

At least two qualifying people participate: an implementer or evidence producer
and an independent reviewer. A person cannot fill both roles for the same
acceptance claim.

## Test procedures

### Accessibility and input

1. Navigate account connection, inbox, thread, search, and composer using
   VoiceOver without touch or pointer fallbacks. Record the accessible role,
   name, value, state, order, and actionable controls for each screen.
2. Exercise the largest supported Dynamic Type size without clipped required
   actions, hidden content, or loss of logical reading order.
3. Complete the same core flow with Full Keyboard Access and, on iOS/iPadOS,
   Switch Control. Focus must remain visible and must not become trapped.
4. In the multiline composer, test a marked-text IME sequence, autocorrect,
   dictation, selection handles, copy/paste, undo/redo, and hardware-keyboard
   shortcuts. The final text and cursor position must match the scripted
   synthetic fixture.

Acceptance fails on an unreachable core action, missing or misleading accessible
state, focus loss, destructive text corruption, or a crash. A source-generated
semantic tree without physical assistive-technology execution is diagnostic
evidence only.

### Lifecycle, protected data, and hostile content

1. Repeat foreground/background, active/inactive, rotation, memory-pressure,
   lock/unlock, and protected-data-unavailable transitions while the inbox,
   composer, and OAuth callback are active. Include the hostile-content
   renderer only after an approved `SafeHtml` boundary exists.
2. Confirm cancellation and recovery are bounded, no sensitive state appears in
   logs or the app switcher, and no protected store is opened while unavailable.
3. Load the current synthetic hostile MIME corpus. While the temporary
   plain-text-only policy is active, verify that only plain text/preview is
   displayed, no HTML mode exists, the product has no WebKit UI surface, and a
   positive transport control first proves that the harness can observe a
   request; the protected product run must then report zero requests. After a
   separately approved renderer exists, additionally prove that JavaScript,
   navigation, pop-ups, downloads, forms, remote requests, and persistent
   WebKit residue remain denied.
4. Toggle airplane mode and change networks during OAuth and synchronization.
   The app must fail closed, preserve local intent, and avoid duplicate actions.

### Performance and energy

Measure a release-equivalent signed build after one warm-up run and at least
five recorded runs per device class. Report median and p95 without device
identifiers or content. The product thresholds are:

| Metric | iPhone/iPad threshold | Mac threshold |
|---|---:|---:|
| Cached inbox interactive cold start | p95 below 1.5 s | p95 below 1.0 s |
| Local top-50 query | p95 below 150 ms | p95 below 100 ms |
| Inbox scroll | p95 60 frames/s, no unbounded row materialization | p95 60 frames/s, no unbounded row materialization |
| Idle inbox memory | below 110 MiB | below 140 MiB |
| Sync/index peak memory | below 220 MiB | below 350 MiB |

Record Energy Log or equivalent aggregate results for a fixed 30-minute
foreground script and an idle interval. No periodic iOS background execution is
assumed or claimed. A threshold miss is a failed acceptance claim or an accepted
ADR with a new budget; it is never silently relabelled as diagnostic success.

## Signed distribution procedures

### iOS and iPadOS

Archive with distribution signing, upload through App Store Connect, install
the same build from TestFlight on both physical device classes, and repeat the
smoke, accessibility, lifecycle, protected-data, and hostile-content checks.
Record only redacted Organizer/TestFlight result summaries, build number,
commit, and manifest digest. Provisioning profiles, certificate serials,
submission identifiers, Apple IDs, and device identifiers are excluded.

### macOS

Build with Hardened Runtime and the reviewed minimal entitlements, sign with
Developer ID, submit for notarization, staple the accepted ticket, and run the
installed artifact on a clean user account. The redacted command summary must
show successful equivalents of:

```sh
codesign --verify --deep --strict --verbose=2 Tersa.app
xcrun stapler validate Tersa.app
spctl --assess --type execute --verbose=4 Tersa.app
```

The evidence manifest records the application artifact SHA-256 without
publishing certificate material, local paths, team identifiers, or notarization
credentials. An App Review smoke result remains a separate claim from
notarization. macOS UI and release acceptance details are in the
[macOS acceptance protocol](../quality/macos-acceptance.md).

## Evidence, redaction, and attestation

At every evidence tier, commit and artifact are a presence-bound pair: both are
absent, or both are present. A present commit is an exact lowercase 40-character
Git SHA. Any present artifact is validated as an immutable commit-bound
manifest, including its digest, redaction flag, generation timestamp, and
retention semantics. Simulator-tier evidence must include that commit-bound
artifact even when it is only diagnostic. Device-unsigned diagnostics may retain
null commit and artifact fields; they do not claim a device pass or substitute
for signed physical-device evidence.

Each passed physical-device or signed-distribution claim requires:

- an exact commit SHA and an immutable artifact locator bound to that same SHA;
- a SHA-256 for a redacted evidence manifest;
- `redacted: true` after an explicit scan for UDIDs, certificate or provisioning
  material, account data, filesystem paths, credentials, tokens, message
  content, keys, and private submission identifiers;
- the named implementer/evidence producer;
- a different named reviewer, compared case-insensitively, with one or more
  reviewed competence identifiers: `apple-platform`, `accessibility`,
  `security`, or `release-engineering`;
- an explicit independent-review attestation;
- timezone-qualified review and expiry timestamps.

Repository evidence uses
`repository://evidence/<exact-commit>/<path>`. GitHub Actions evidence uses
`github-actions://runs/<run>/artifacts/<id>/manifest.json#evidence-commit=<exact-commit>`.
The repository path is relative to the commit-specific evidence namespace and
must not contain empty, current-directory, or parent-directory segments.
The uploaded `manifest.json` records the exact `GITHUB_SHA`, generation and
retention timestamps, and the relative path, size, and SHA-256 of every evidence
file. The acceptance record contains the manifest SHA-256 and matching
timestamps. Reviewers compare the locator SHA with the claimed commit, bound
retention to 90 days, and require review expiry no later than artifact expiry;
they do not rely on a mutable run name, branch, or artifact label. The
independent reviewer verifies the downloaded manifest and its file hashes before
attesting.

Whenever complete review metadata and an artifact coexist at any tier, the
review timestamp must be on or after manifest generation. For GitHub Actions
artifacts, review expiry must also be no later than the artifact retention
timestamp. Signed-tier and passed physical/distribution claims additionally
require the named independent reviewer and attestation described above.

GitHub Actions evidence is retained for 90 days, while the manifest uses an
89-day safety margin. A claim backed by that form must be reviewed and expire no
later than the recorded retention timestamp; repository evidence is preferred
when the review period needs to outlive artifact retention. Missing fields, tier
downgrades, unresolved prerequisites, self-review, expired review, abbreviated
commit identifiers, mutable or mismatched locators, unredacted artifacts, or
insufficient evidence tiers fail closed. No UI or M1 pass is valid while no
production UI baseline is approved.
