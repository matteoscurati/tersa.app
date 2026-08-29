# macOS UI development-signed accessibility, App Sandbox, and Keychain isolation evidence

## Purpose and non-claim

This document is the active record for **ADR-0021 slice 2f**: development-signed
accessibility (VoiceOver, Full Keyboard Access), App Sandbox denial, and
fixed-purpose Keychain wrong-group denial capture for the macOS UI vertical
slice (connection, inbox, thread, search, composer).

It is **explicitly non-gate**. It does not change a gate, approve the UI,
satisfy independent review, prove normal token operations, close issue #51, or
produce Developer ID, notarized, TestFlight, or App Store evidence. It does not
satisfy `P1-MACOS-001`, `P1-MACOS-002`, or `P1-MACOS-003`. Those require the
[macOS acceptance protocol](macos-acceptance.md) on a release-equivalent
Developer ID candidate.

The capture runs no own-group positive control. It deliberately invokes only
the fixed wrong-group, query-only probes; normal token exchange, refresh,
persistence, revoke, and delete operations remain required follow-up evidence
under ADR-0024.

Any product gap this capture surfaces is fixed in a separate, freshly reviewed
implementation pull request — never by editing this evidence or weakening an
entitlement. Open implementation work that improves keyboard and VoiceOver
traversal remains queued independently of this record.

## Redaction

Record only: reviewed entitlement keys, aggregate observations, the sandbox
container path relative to the home directory, sizes, fixed-vocabulary outcomes,
and the signing tier as **Apple Development** (authority and team redacted).
Never record an Apple ID, team identifier, certificate name, machine name or
UUID, absolute local path, account identifier, credential, token, or mail
content.

## Capture procedure

Prerequisites on an Apple Silicon Mac:

- clean worktree at the exact commit under review
- exactly one valid **Apple Development** identity
- exactly one current matching Mac Development provisioning profile for that team
- native arm64 process (not Rosetta)

```sh
sh apple/scripts/capture-macos-ui-dev-evidence.sh
```

The script:

1. Exports only tracked source for `HEAD` via `git archive`
2. Builds Release/arm64 `TersaMac` with team-prefixed App Group and token
   Keychain group compile-time values
3. Inventories and nested-signs the embedded `TersaMacTokenBroker.xpc` before
   signing the outer application (inside-out)
4. Verifies Hardened Runtime, the exact five reviewed outer entitlements, launch,
   and App Sandbox container materialization
5. Runs the exact signed main-app and embedded token-broker probe entrypoints
   after the normal launch/container check and before the sandbox canary, each
   only with `--tersa-keychain-isolation-probe-v1`; it requires exit `0`, empty
   stderr, and the corresponding one-line byte-exact redacted JSON result
6. Proves outside-container create denial with a same-signature canary and an
   unsandboxed positive control
7. Prints the interactive VoiceOver / Full Keyboard Access checklist for the
   owner walk

Automated output is redacted by design: the probe captures stay in private
scratch files and only fixed summary outcomes are printed. Interactive walk
results are recorded in the table below by the evidence producer.

## Historical, superseded capture status

The `6dac4efd74b4a08db1ce95162894d05698ee50ee` capture from 2026-08-05
(Xcode 26.6, arm64-native, Apple Development identity and team redacted) is
superseded by the current procedure because it predates the live wrong-group
probes. Every row below is historical and non-gate; it establishes neither
probe result, normal token operations, nor signed release closure.

| Historical observation | Historical result |
|---|---|
| Nested XPC inventory and inside-out signing | HISTORICAL PASS — exact reviewed `TersaMacTokenBroker.xpc`; three-key broker entitlements; token group redacted |
| Native build and Apple Development signature | HISTORICAL PASS — arm64, strict signature verification, Hardened Runtime |
| Provisioning and entitlement binding | HISTORICAL PASS — current embedded profile; outer five-key set; team values redacted |
| Main-app and token-broker wrong-group probes | HISTORICAL NOT RUN — this superseded capture predates the live signed probes required by the current procedure |
| Product launch and App Sandbox container | HISTORICAL PASS — app remained running; `~/Library/Containers/app.tersa.mac` present |
| Sandbox denial and observation-path control | HISTORICAL PASS — sandboxed canary denied outside-container create; unsandboxed control succeeded |
| Installed application regular-file bytes | HISTORICAL PASS — 15,086,960 (~14.4 MiB), under the 16 MiB product budget |
| VoiceOver-only five-screen walk | HISTORICAL PENDING — owner physical walk; no spoken-output claim |
| Full Keyboard Access-only five-screen walk | HISTORICAL PENDING — owner physical walk; no keyboard-navigation claim |

VoiceOver-only and Full Keyboard Access-only walks remain owner-executed. Source
semantics and screenshots are not substituted for assistive-technology speech or
physical keyboard evidence. Implementation improvements for those walks stay on
the queued accessibility pull request and do not belong in this evidence record.

Future exact-head Apple Development captures include both signed wrong-group
negative probes. Passing those probes proves only their fixed negative controls;
they do not prove normal exchange, refresh, persistence, revoke, or delete
operations, and they do not close the signed Developer ID/notarized release gate.

### Prior Apple Development capture (historical reference)

At commit `beda68b512e32f9cf7be1e4dfacccc81e1acce70` (2026-08-02), an earlier
form of the capture script recorded PASS for signature, profile binding, launch,
sandbox container, sandbox denial, and live Gmail connect/disconnect teardown.
That capture predated nested token-broker signing inventory.

## Interactive checklist (owner)

Record with no pointer or visual fallback:

1. **VoiceOver:** connection, inbox, thread, search, and composer roles, names,
   values, actions, logical order, focus continuity, and announcements.
2. **VoiceOver edges:** composer unavailable-send announcement; body editor
   Tab/Escape behavior; edited-mid-search result suppression stays silent.
3. **Full Keyboard Access:** the same five-screen traversal with visible focus
   and no trap, using keyboard controls only.
4. **App Sandbox:** the automated bundled canary above must remain denied while
   its unsandboxed positive control succeeds.

This Apple Development result is non-gate. Developer ID, notarization, retained
artifact binding, and independent distribution review remain mandatory for
acceptance claims.
