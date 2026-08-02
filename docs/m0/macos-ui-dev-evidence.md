# macOS UI development-signed accessibility and App Sandbox evidence

## Current Apple Development capture — 2026-08-02

The capture script built tracked Release/arm64 source at commit
`f89a427cdd6f1ad6a957bdbb98e5fd29d6b1aaac`. It selected the one available
Apple Development identity and the one current matching Mac Development
profile without printing either identifier. The resulting app used Hardened
Runtime and the exact five committed production entitlements; no entitlement
was weakened or rewritten in the repository.

| Observation | Result |
|---|---|
| Native build and Apple Development signature | PASS — arm64, strict signature verification, Hardened Runtime |
| Provisioning and entitlement binding | PASS — current embedded profile and the exact five-key set; team values redacted |
| Product launch and App Sandbox container | PASS — the app remained running and `~/Library/Containers/app.tersa.mac` existed |
| Sandbox denial and observation-path control | PASS — the same-signature bundled canary was denied an outside-container create; its unsandboxed control succeeded |
| Live Gmail connect and bounded sync | PASS — owner completed consent; the mailbox reader observed 50 rows and the UI rendered the inbox |
| Live disconnect and local teardown | PASS — clean disconnect confirmation; signed probes observed 0 mailbox rows, no refresh token, and no account identity |
| VoiceOver-only five-screen walk | PENDING — not executed; no spoken-output claim |
| Full Keyboard Access-only five-screen walk | PENDING — not executed; no keyboard-navigation claim |

The two accessibility walks remain pending because the local automation runtime
was unavailable and the console session was locked during capture. Source-level
semantics and a screenshot are not substituted for VoiceOver speech or physical
keyboard evidence. The script leaves the exact interactive checklist visible
after every successful automated capture.

The live run used the same full production entitlement set. Google first returned
an explicit `openid`-only scope after Gmail access was not selected; the owner
then repeated consent and allowed Gmail read access. The resulting product fix
rejects any explicit callback or token-response scope set missing
`gmail.readonly`, stores no credential for that attempt, and presents a specific
permission-required recovery message. Scope values, credentials, account data,
and mail metadata were not retained in this evidence.

This is development-only, explicitly non-gate evidence. It is not Developer ID,
notarization, retained distribution evidence, or independent accessibility
approval. The ADR-0023 Step-3f live OAuth, sync, and disconnect outcome is also
recorded in the project resume memory; the current branch contains the source
fixes found by the run.

## Historical ad-hoc capture

The remainder of this document preserves the earlier ad-hoc capture at its
original source state. Its credential statements are historical and do not
describe current Apple Development availability.

## Purpose and non-claim

This document records **local ad-hoc** accessibility and App
Sandbox observations for the macOS UI vertical slice (ADR-0021 slices 2c–2e:
account connection, inbox, thread, search, composer entry), captured at an exact
commit by `apple/scripts/capture-macos-ui-dev-evidence.sh`.

It is **explicitly non-gate**. It does not change a gate, approve the UI, satisfy
independent review, or produce Developer-ID, notarized, TestFlight, or App Store
evidence, and it does not satisfy P1-MACOS-001, P1-MACOS-002, or P1-MACOS-003 —
those require Developer-ID signing and remain part of the credential-blocked
distribution work. Every observation here stays review-required. Any gap it
surfaces is fixed in a separate, freshly reviewed implementation PR, never by
editing this evidence or weakening an entitlement.

Signing tier is **ad-hoc** (`codesign -s -`, a local non-Apple identity): no
Apple-issued identity or provisioning profile is available, and ADR-0021 (the
slice-2f row and its development-signed-evidence section) authorizes development
or ad-hoc signing for this slice. With no team,
`${TeamIdentifierPrefix}` expands empty, so the application-group and
keychain-access-group are the unprefixed `app.tersa.shared`. The empirical
finding of this run (section 2) is that the app with these reviewed entitlements
**does not launch** under ad-hoc signing without an Apple team — the same
credential constraint as the PR33b block — so the runtime accessibility and
sandbox walk is deferred (sections 3–6). This is a recorded condition, not a
defect to fix by changing entitlements.

## Redaction

This document contains only: the reviewed entitlement keys, aggregate
observations, the sandbox container path relative to the home directory, sizes,
and the signing tier as "ad-hoc / local non-Apple identity". It never contains an
Apple ID, team identifier, certificate name, machine name or UUID, an absolute
local path, an account identifier, or any mail content.

## Capture

Run, at the exact commit under review:

```
sh apple/scripts/capture-macos-ui-dev-evidence.sh
```

The declaration evidence (section 1) needs no launch and is captured in any
session. The script also attempts to launch the ad-hoc app and records the
outcome; on a team-less machine that launch is expected to fail (section 2), so
the runtime walk (sections 3–6) is deferred, not run here.

The script builds unsigned, ad-hoc-signs with the reviewed entitlements, records
the signature/entitlement/size evidence below automatically, then prints the
interactive checklist for the remaining runtime sections, which a human records
here.

---

## 1. Signature and embedded entitlements (automated)

Evidence anchor: the app is built from the base `af975b5` sources — slice 2f adds
only `capture-macos-ui-dev-evidence.sh` (in this PR) and this document, no
app-source change, so the signature, entitlements, and size below are properties
of the merged `af975b5` 2c–2e UI code, captured by that script on this branch.

Signature: **ad-hoc** (`Signature=adhoc`, `TeamIdentifier=not set`, bundle
identifier `app.tersa.mac`). Embedded entitlements — the exact five reviewed
keys, unchanged from `apple/macos/TersaMac.entitlements`:

| entitlement | value |
|---|---|
| `com.apple.security.app-sandbox` | `true` |
| `com.apple.security.network.client` | `true` |
| `com.apple.security.network.server` | `true` |
| `com.apple.security.application-groups` | `[ app.tersa.shared ]` (unprefixed — empty team) |
| `keychain-access-groups` | `[ app.tersa.shared ]` (unprefixed — empty team) |

App bundle size (ad-hoc Release, arm64): **5,460,052 bytes (~5.2 MB)**.

## 2. Empirical launch finding (recorded condition)

The ad-hoc-signed app **does not launch** on a machine with no Apple team.
`open` returns, verbatim (absolute paths redacted):

```
The application cannot be opened for an unexpected reason,
error=Error Domain=RBSRequestErrorDomain Code=5 "Launch failed."
… NSPOSIXErrorDomain Code=163 … "Launchd job spawn failed"
```

Root cause (inferred from the reproduction below, not from the error text, which
names no daemon): `com.apple.security.application-groups` and
`keychain-access-groups` carry the unprefixed value `app.tersa.shared` because
`${TeamIdentifierPrefix}` expands empty under an identity with no team. macOS
rejects an app-group / keychain-access-group value that is not prefixed by a valid
Team Identifier at spawn — consistent with team-prefix entitlement validation
(`amfid`) — so `launchd` fails the spawn. Reproduced identically in a logged-in
GUI session (not a headless artifact). A direct `exec` of the binary
initializes the App Sandbox container (`~/Library/Containers/app.tersa.mac` is
created) before the process is killed, confirming the rejection is the
team-prefix entitlement validation, not the sandbox itself.

This is the **same credential constraint as the PR33b block**: the reviewed
entitlements require a real Apple Team Identifier, which is unavailable in this
phase. It is a recorded condition — the entitlements are **not** weakened, and no
group value is changed, to make the app launch.

## 3–6. Runtime accessibility and sandbox walk — DEFERRED (credential-blocked)

Because the app with its reviewed entitlements cannot launch under ad-hoc
signing without an Apple team (section 2), the runtime evidence — App Sandbox
container/denial observation, the Keychain-under-signing condition, the
VoiceOver-only and Full-Keyboard-Access-only walks (including the three items
flagged in 2c–2e review), and the ADR-0022 runtime perf numbers — **cannot be
captured in this phase** and is deferred to the credential unblock alongside
PR33b (a Developer-ID / real-team-signed run).

Items carried to that run:
- App Sandbox container materialization and `sender == "Sandbox"` denial observation.
- Keychain bootstrap outcome under a team-prefixed signature.
- VoiceOver-only walk of the five screens (connection, inbox empty-state, thread, search, composer): roles / names / values / focus order / announcements.
- The three flagged accessibility items: (a) ComposerView on-appear announcement actually spoken; (b) Body `TextEditor` Tab/Esc behavior and any keyboard trap; (c) SearchView edit-field-mid-search dropped-result silence.
- Full-Keyboard-Access-only walk of the five screens.
- ADR-0022 runtime numbers (window-interactive cold start; connect → inbox render; idle inbox RSS), documented conditions; omit any not meaningfully measurable at zero rows.

This document's checklist above is ready for that run. The
`apple/scripts/capture-macos-ui-dev-evidence.sh` tool signs ad-hoc only (it strips
the empty team prefix), so it captures the declaration evidence and records the
launch condition but cannot itself perform the deferred runtime walk — that
requires a build signed with a real Apple team identity, not merely supplying an
identity to this script. Source-level accessibility was reviewed per screen in the
2c–2e PRs; this deferral concerns the runtime, assistive-technology-executed
evidence only.
