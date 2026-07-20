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
keychain-access-group are the unprefixed `app.tersa.shared`. Whether the Keychain
bootstrap works under that unprefixed group is a recorded empirical condition
(section 3), not a defect to fix by changing entitlements.

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

Exact commit: `<fill: git rev-parse HEAD>`

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

## 2. Launch and App Sandbox container (interactive)

- Launch via `open` — result: `<fill: launches and stays running | verbatim launchd/signature error, paths redacted>`
- Sandbox container `~/Library/Containers/app.tersa.mac` present after launch: `<fill: yes | no>`
- Aggregate `sender == "Sandbox"` denial observations during the session (redacted): `<fill>`

> Note: full per-capability sandbox-denial testing (P1-MACOS-001 item 4) is the
> Developer-ID interactive procedure; only development-tier observations are
> recorded here, scope documented.

## 3. Keychain-under-ad-hoc empirical condition (interactive)

On the connection screen, enter an opaque identifier and activate Connect.

- `ConnectionState` reached: `<fill: connected | invalidExecutionContext | busyOrUnavailable | rootMissingWithExistingProfile | unavailable>`
- Interpretation: either outcome is a legitimate 2c screen state. The Step-2
  cache is empty by design, so inbox / thread / search render their empty states
  regardless of whether bootstrap reaches `connected`.

## 4. VoiceOver-only walk (interactive; diagnostic evidence, review-required)

For each screen: roles, names, values, focus order, announcements.

| screen | observations |
|---|---|
| Connection (2c) | `<fill>` |
| Inbox empty-state (2d) | `<fill>` |
| Thread (2d) | `<fill: reachable only with data; empty store — record if unreachable>` |
| Search (2e) | `<fill>` |
| Composer entry (2e) | `<fill>` |

Three items flagged in 2c–2e review, to resolve here (a gap is fixed in a fresh
PR, not in 2f):

- (a) ComposerView on-appear announcement actually spoken by VoiceOver: `<fill>`
- (b) Body `TextEditor`: Tab inserts a tab; Esc exits; any keyboard trap: `<fill>`
- (c) SearchView edit-field-mid-search: the dropped result is silent (no completion announcement): `<fill>`

## 5. Full-Keyboard-Access-only walk (interactive)

Every control reachable and operable by keyboard, no trap, logical order.

| screen | observations |
|---|---|
| Connection | `<fill>` |
| Inbox | `<fill>` |
| Search | `<fill>` |
| Composer | `<fill>` |

## 6. Performance observations (interactive; ADR-0022 checklist regime, non-gate)

Documented conditions: ad-hoc-signed, local non-Apple identity, empty cache, one
machine class. Record only meaningfully measurable values; omit any metric that
is not (for example scroll and query p95 at zero rows).

- window-interactive cold start: `<fill or omit with reason>`
- connect → inbox render: `<fill or omit with reason>`
- idle inbox resident memory (RSS): `<fill or omit with reason>`

> Empty-cache cold start under-exercises the thresholds; populated-cache
> measurement is deferred to a later slice. No threshold is asserted here.
