# macOS UI development-signed accessibility and App Sandbox evidence

## Purpose and non-claim

This document is the active record for **ADR-0021 slice 2f**: development-signed
accessibility (VoiceOver, Full Keyboard Access) and App Sandbox denial capture
for the macOS UI vertical slice (connection, inbox, thread, search, composer).

It is **explicitly non-gate**. It does not change a gate, approve the UI,
satisfy independent review, or produce Developer ID, notarized, TestFlight, or
App Store evidence. It does not satisfy `P1-MACOS-001`, `P1-MACOS-002`, or
`P1-MACOS-003`. Those require the
[macOS acceptance protocol](macos-acceptance.md) on a release-equivalent
Developer ID candidate.

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
5. Proves outside-container create denial with a same-signature canary and an
   unsandboxed positive control
6. Prints the interactive VoiceOver / Full Keyboard Access checklist for the
   owner walk

Automated output is redacted by design. Interactive walk results are recorded
in the table below by the evidence producer.

## Current capture status

| Observation | Result |
|---|---|
| Nested XPC inventory and inside-out signing tooling | READY — enforced by `xtask architecture` and unit tests |
| Native build and Apple Development signature | PENDING re-run at this branch head |
| Provisioning and entitlement binding (five-key outer set) | PENDING re-run at this branch head |
| Product launch and App Sandbox container | PENDING re-run at this branch head |
| Sandbox denial and observation-path control | PENDING re-run at this branch head |
| VoiceOver-only five-screen walk | PENDING — owner physical walk; no spoken-output claim |
| Full Keyboard Access-only five-screen walk | PENDING — owner physical walk; no keyboard-navigation claim |

### Prior Apple Development capture (historical reference)

At commit `beda68b512e32f9cf7be1e4dfacccc81e1acce70` (2026-08-02), an earlier
form of the capture script recorded PASS for signature, profile binding, launch,
sandbox container, sandbox denial, and live Gmail connect/disconnect teardown.
VoiceOver-only and Full Keyboard Access-only walks were not executed on that
run. That capture predated nested token-broker signing inventory and is not a
substitute for a re-run at the current product head.

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
