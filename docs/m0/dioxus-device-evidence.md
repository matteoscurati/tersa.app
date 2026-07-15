# Dioxus physical-device input and accessibility harness

## Purpose and non-claim

This opt-in harness prepares device-signed, exact-head observations for
`M0-DIOXUS-006` and `M0-DIOXUS-014`, plus the VoiceOver and Dynamic Type parts
of `M0-DIOXUS-013`. It does not measure contrast and cannot complete
`M0-DIOXUS-013`. It does not change a gate, approve Dioxus, satisfy independent
review, or produce TestFlight or App Store evidence. Every observation remains
review-required even when all applicable fixed scripts are marked `pass`.

The harness uses only synthetic text. Evidence contains aggregate fixed
outcomes, timestamps, SHA-256 values, a random observer record ID, a non-unique
device and viewport class, the iOS version, and a fixed observer-competence
value. It never retains a device identifier or name, Apple ID, team,
certificate, profile,
signing output, `devicectl` output, free-form notes, or an unredacted screenshot.

## Local preparation

1. Copy `apple/local.xcconfig.example` to the ignored
   `apple/local.xcconfig` and populate it locally. Do not pass signing values on
   the command line or store them in another repository file.
2. Connect and unlock one physical iPhone or iPad. Enable Developer Mode.
3. Generate an opaque record ID with `openssl rand -hex 16`. It identifies the
   observation record, not a person; keep any reviewer assignment only in the
   independent review system.
4. Prepare a PNG screenshot file. Before the harness consumes it,
   dismiss the software keyboard and any notification or personalized
   prediction surface; capture only the synthetic diagnostic screen. Then
   replace the complete top 8 percent and bottom 4 percent with solid black and
   export a non-interlaced 8-bit RGB or RGBA PNG without ancillary metadata.
   The verifier rejects missing bands, all-black images, and metadata.
5. Keep the worktree clean at an exact 40-character commit.

The script is a dry run by default. A real run requires both `--execute` and
`TERSA_DEVICE_EVIDENCE_OPT_IN=YES`; the physical device selector is read only
from `TERSA_DEVICE_SELECTOR` and is deleted with temporary command output.

```sh
TERSA_DEVICE_EVIDENCE_OPT_IN=YES \
TERSA_DEVICE_SELECTOR='<local selector>' \
sh apple/scripts/capture-dioxus-device-evidence.sh \
  --execute \
  --device-class iphone \
  --viewport compact \
  --os-version 'iOS 18.5' \
  --observer-competence accessibility \
  --observer-record-id '<32 lowercase hexadecimal characters>' \
  --redacted-screenshot-source '<ignored local png>'
```

The script generates the project, creates a signed Release archive from the
ignored configuration, verifies the effective signing settings, signature,
minimal entitlement allowlist, provisioning profile, and embedded exact commit;
installs the app; verifies its bundle identity; and launches only
`--tersa-device-evidence`. It then checks that the returned process is still
running. Before any fixed result is accepted, the observer must confirm that the
harness card is visible and its displayed commit exactly matches the source
commit. Installation and termination of an existing diagnostic instance occur
only after both opt-ins. No uninstall, account change, network request, or gate
edit is performed. The diagnostic remains installed after capture; remove it
manually from the device when the review record no longer needs it.

## Fixed synthetic scripts

Use a fresh composer value for each input script. A `pass` requires the exact
final text and an intact caret/selection; a crash, corruption, focus loss, or
substitution mismatch is `fail`.

| ID | Physical-device script and exact expected state |
|---|---|
| `marked-text-ime` | With a Japanese keyboard, enter marked text `てるさ`, choose `テルサ`, then prefix `IME: `. Final text: `IME: テルサ`; caret after `サ`. |
| `autocorrect` | With English autocorrect enabled, type `Autocorrect: t`, followed immediately by `eh message`. Final text: `Autocorrect: the message`; caret at end. |
| `dictation` | Dictate “Dictation colon Tersa synthetic input period”. Final text: `Dictation: Tersa synthetic input.`; caret at end. |
| `selection` | Type `Selection: alpha beta gamma`, select `beta` with handles, and replace it with `delta`. Final text: `Selection: alpha delta gamma`; selection collapsed after `delta`. |
| `copy-paste` | Type `Copy: amber`, select and copy `amber`, add a newline, and paste. Final text is two lines: `Copy: amber` then `amber`; caret at end. |
| `undo-redo` | Type `Undo: one two`, replace `two` with `three`, undo once, then redo once. Final text: `Undo: one three`; caret at end. |
| `hardware-keyboard` | On iPad with a physical keyboard, type `Keyboard: first`, press Return, type `second`, use Command-A, then Right Arrow. Final text is two lines: `Keyboard: first` then `second`; selection collapsed at end. |
| `voiceover-order-state` | With VoiceOver and touch exploration, use the exact visible-viewport order below. Activate the review toggle twice; its pressed state and live status must announce both changes. |
| `dynamic-type` | When prompted, set the largest Accessibility Dynamic Type size and enter `READY`. The harness relaunches the exact evidence mode with `devicectl`; never relaunch from SpringBoard or the app switcher. Confirm the same exact commit, then use the visible-viewport order below. Required text and actions must remain visible or scroll-reachable with logical order and no overlap that blocks activation. |
| `full-keyboard-access` | Enable Full Keyboard Access and use only Tab, Shift-Tab, arrows, Space, and Return. Search, jump control, at least one list row, review toggle, and composer must be reachable in logical order with visible focus and no trap. |
| `switch-control` | Enable Switch Control with auto scanning. Reach search, jump control, one focusable list row, review toggle, and composer without touch; activate the jump control and review toggle. Focus order and announced state must remain correct. |

Run `hardware-keyboard` on iPad. The harness records `not-applicable`
automatically on iPhone; that outcome is rejected for iPad and every other test.
The required M0 matrix still needs both device classes and an independent
qualifying reviewer.

Pass the selected variant through `--viewport`. For `voiceover-order-state` and
`dynamic-type`, use exactly that fixed viewport variant:

- iPhone and compact iPad viewport (860 CSS pixels or narrower): brand,
  safe-area status, inbox heading, search, all seven diagnostic statuses, jump
  control, synthetic list, harness heading, explanatory text, commit, candidate,
  review toggle and live status, composer heading, message editor, character
  status, disabled actions, and four runtime facts. The transport badge and
  sidebar are intentionally hidden and must not be announced.
- Regular iPad viewport (wider than 860 CSS pixels): brand, safe-area status,
  transport badge, sidebar Inbox heading, all four sidebar navigation items,
  focus-probe heading and three statuses, then every compact-viewport item from the inbox heading
  onward. Record `fail` if an element hidden by the active viewport is announced
  or a visible required element is skipped.

## Evidence and review boundary

`apple/build/dioxus-device-evidence` uses the existing `manifest.json` schema
and binds file hashes to the exact source commit. `observations.json` stores
only fixed-vocabulary results, application version/build, a canonical app-bundle
SHA-256, the launch argument, the observer-confirmed evidence screen, and its
displayed commit. Developer signing embeds a local provisioning profile, so the
bundle SHA-256 is an integrity fingerprint for that installed capture only; it
is not a reproducible-build claim. The screenshot verifier checks solid-black
status/home bands and rejects ancillary metadata.

Raw build, signing, provisioning, device-discovery, install, application-list,
and launch output exists only in a temporary directory removed on success,
failure, interruption, and termination. The signed archive and provisioning
profile are deleted with that directory after installation. The artifact label is
`DEVICE-SIGNED OBSERVATIONS - INDEPENDENT REVIEW REQUIRED`; it is not a pass.
Only a later PR may attach reviewed evidence to the gate register, and any such
PR must follow the independent-review and expiry rules in
[`physical-device-and-distribution-protocol.md`](physical-device-and-distribution-protocol.md).
The generated manifest retains local evidence for 89 days. Complete independent
review and any gate-record PR before `retained_until`, or treat the observation
as expired and capture it again.

Contrast remains a separate, unresolved requirement. Do not use this artifact
as contrast evidence or as complete evidence for `M0-DIOXUS-013`.
