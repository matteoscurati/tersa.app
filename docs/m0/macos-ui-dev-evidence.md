# macOS UI development-signed accessibility and App Sandbox evidence

## Purpose and non-claim

This document records **development-signed (ad-hoc)** accessibility and App
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
Apple-issued identity or provisioning profile is available, and ADR-0021 line 177
authorizes development or ad-hoc signing for this slice. With no team,
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

Run, at the exact commit under review, in an **interactive logged-in GUI
session** (a headless or automation shell cannot launch a GUI app — launchd
returns error 163):

```
sh apple/scripts/capture-macos-ui-dev-evidence.sh
```

The script builds unsigned, ad-hoc-signs with the reviewed entitlements, records
the signature/entitlement/size evidence below automatically, then prints the
interactive checklist for the remaining runtime sections, which a human records
here.

---

## 1. Signature and embedded entitlements (automated)

Captured by `capture-macos-ui-dev-evidence.sh` from this branch (capture tool
committed at `d716504`); the evidenced app is built from the base `af975b5`
sources — slice 2f adds only the capture tool and this document, no app-source
change, so the signature, entitlements, and size below are properties of the
shipped 2c–2e UI build.

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

Root cause: `com.apple.security.application-groups` and `keychain-access-groups`
carry the unprefixed value `app.tersa.shared` because `${TeamIdentifierPrefix}`
expands empty under an identity with no team. macOS rejects an app-group /
keychain-access-group value that is not prefixed by a valid Team Identifier at
spawn time (`amfid`), so `launchd` fails the spawn. Reproduced identically in a
logged-in GUI session (not a headless artifact). A direct `exec` of the binary
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

The `apple/scripts/capture-macos-ui-dev-evidence.sh` capture tool and this
document are ready for that run; only the signing identity is missing. Source-
level accessibility was reviewed per screen in the 2c–2e PRs; this deferral
concerns the runtime, assistive-technology-executed evidence only.
