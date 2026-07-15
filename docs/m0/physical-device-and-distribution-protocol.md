# M0 physical-device and distribution protocol

## Purpose and non-claim

This protocol defines the evidence required to close physical-device and
signed-distribution gates. It records no execution, device result, signature,
notarization, TestFlight installation, or App Review result in this PR. Host,
simulator, unsigned archive, and source-inspection results cannot substitute
for the procedures below.

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
and an independent reviewer. A person cannot fill both roles for the same gate.

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

A gate fails on an unreachable core action, missing or misleading accessible
state, focus loss, destructive text corruption, or a crash. A source-generated
semantic tree without physical assistive-technology execution is diagnostic
evidence only.

### Lifecycle, protected data, and hostile content

1. Repeat foreground/background, active/inactive, rotation, memory-pressure,
   lock/unlock, and protected-data-unavailable transitions while the inbox,
   composer, OAuth callback, and hostile-content renderer are active.
2. Confirm cancellation and recovery are bounded, no sensitive state appears in
   logs or the app switcher, and no protected store is opened while unavailable.
3. Load the current synthetic hostile MIME corpus. JavaScript, navigation,
   pop-ups, downloads, forms, remote requests, and persistent WebKit residue
   must remain denied. The positive transport control must prove the harness
   could observe a request before the protected run reports zero requests.
4. Toggle airplane mode and change networks during OAuth and synchronization.
   The app must fail closed, preserve local intent, and avoid duplicate actions.

### Performance and energy

Measure a release-equivalent signed build after one warm-up run and at least
five recorded runs per device class. Report median and p95 without device
identifiers or content. The M0 targets are:

| Metric | iPhone/iPad threshold | Mac threshold |
|---|---:|---:|
| Cached inbox interactive cold start | p95 below 1.5 s | p95 below 1.0 s |
| Local top-50 query | p95 below 150 ms | p95 below 100 ms |
| Inbox scroll | p95 60 frames/s, no unbounded row materialization | p95 60 frames/s, no unbounded row materialization |
| Idle inbox memory | below 110 MiB | below 140 MiB |
| Sync/index peak memory | below 220 MiB | below 350 MiB |

Record Energy Log or equivalent aggregate results for a fixed 30-minute
foreground script and an idle interval. No periodic iOS background execution is
assumed or claimed. A threshold miss is a failed gate or an accepted ADR with a
new budget; it is never silently relabelled as diagnostic success.

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
credentials. An App Review smoke result remains a separate gate from
notarization.

## Evidence, redaction, and attestation

Each passed physical-device or signed-distribution gate requires:

- an exact commit SHA and an immutable artifact locator bound to that same SHA;
- a SHA-256 for a redacted evidence manifest;
- `redacted: true` after an explicit scan for UDIDs, certificate or provisioning
  material, account data, filesystem paths, credentials, tokens, message
  content, keys, and private submission identifiers;
- the named implementer/evidence producer;
- a different named reviewer, compared case-insensitively, with one or more
  reviewed competence identifiers: `apple-platform`, `accessibility`,
  `security`, or `release-engineering`;
- the canonical explicit independent-review attestation required by the gate
  schema;
- timezone-qualified review and expiry timestamps.

Repository evidence uses
`repository://evidence/<exact-evidence.commit>/<path>`. GitHub Actions evidence
uses `github-actions://runs/<run>/artifacts/<id>/manifest.json#evidence-commit=<exact-evidence.commit>`.
The uploaded `manifest.json` records the exact `GITHUB_SHA`, generation and
retention timestamps, and the relative path, size, and SHA-256 of every evidence
file. The gate record contains the manifest SHA-256 and matching timestamps. The
validator compares the locator SHA with `evidence.commit`, bounds retention to
90 days, and requires review expiry before artifact expiry; it does not rely on
a mutable run name, branch, or artifact label. The independent reviewer verifies
the downloaded manifest and its file hashes before attesting.

GitHub Actions evidence is retained for 90 days, while the manifest uses an
89-day safety margin. A gate backed by that form must be reviewed and expire no
later than the recorded retention timestamp; repository evidence is
preferred when the review period needs to outlive artifact retention. The gate
validator rejects missing fields, unknown gate IDs, tier downgrades, unresolved
dependencies, self-review, expired review, abbreviated commit identifiers,
mutable or mismatched locators, unredacted artifacts, insufficient evidence
tiers, and any UI or M1 pass while no production UI baseline is approved.
