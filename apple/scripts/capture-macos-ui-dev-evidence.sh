#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Development-signed (ad-hoc) accessibility and App Sandbox evidence capture for
# the macOS UI vertical slice (ADR-0021 slice 2f). This produces DEVELOPMENT
# evidence only: it does not satisfy P1-MACOS-001/002/003, does not change a
# gate, does not approve the UI, and does not produce Developer-ID, notarized,
# TestFlight, or App Store evidence. Every observation stays review-required.
#
# It signs ad-hoc (`codesign -s -`, no Apple identity) because no Apple-issued
# identity or provisioning profile is present; ADR-0021 authorizes development or
# ad-hoc signing for this slice. With no team, `${TeamIdentifierPrefix}` expands
# empty, so the application-group and keychain-access-group become the
# unprefixed `app.tersa.shared`; whether the Keychain bootstrap works under that
# is the documented empirical unknown recorded by this run, not a bug to fix by
# weakening entitlements.
#
# Redaction: this script prints only the reviewed entitlement keys, aggregate
# outcomes, the sandbox container path relative to $HOME, and the ad-hoc tier. It
# never prints an Apple ID, team, certificate name, machine name/UUID, or an
# absolute local path. The interactive VoiceOver / Full-Keyboard-Access walk is
# NOT automated here — it must be run by a human in an interactive GUI session
# (a headless/automation session cannot spawn a GUI app: launchd returns 163).

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/build/dev-evidence"
DERIVED="$BUILD_DIR/DerivedData"
APP="$DERIVED/Build/Products/Release/Tersa.app"
ENTITLEMENTS_SRC="$ROOT/macos/TersaMac.entitlements"
RESOLVED_ENTITLEMENTS="$BUILD_DIR/resolved.entitlements.plist"
CONTAINER="$HOME/Library/Containers/app.tersa.mac"

mkdir -p "$BUILD_DIR"

section() { printf '\n== %s ==\n' "$1"; }

section "Toolchain"
xcodebuild -version | head -1
printf 'signing tier: ad-hoc (local non-Apple identity)\n'

section "Generate project (never invokes xcodegen directly)"
sh "$ROOT/scripts/generate-project.sh" >/dev/null
printf 'project generated\n'

section "Build (unsigned) then ad-hoc sign with the reviewed entitlements"
xcodebuild -project "$ROOT/Tersa.xcodeproj" -scheme TersaMac -configuration Release \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO >/dev/null
# Resolve the empty team prefix locally; the entitlement KEYS are unchanged.
sed 's/\${TeamIdentifierPrefix}//g' "$ENTITLEMENTS_SRC" >"$RESOLVED_ENTITLEMENTS"
plutil -lint "$RESOLVED_ENTITLEMENTS" >/dev/null
codesign -s - --entitlements "$RESOLVED_ENTITLEMENTS" --force --timestamp=none "$APP" >/dev/null 2>&1
printf 'ad-hoc signature applied\n'

section "App Sandbox evidence: signature + embedded entitlements"
codesign -dv --verbose=2 "$APP" 2>&1 | grep -E '^(Identifier|Signature|TeamIdentifier|CodeDirectory)' | sed 's/=.*flags=/ flags=/'
printf -- '-- embedded entitlements (reviewed keys only) --\n'
codesign -d --entitlements :- --xml "$APP" 2>/dev/null | plutil -p - 2>/dev/null \
  | grep -E 'app-sandbox|network\.(client|server)|application-groups|keychain-access-groups|app\.tersa\.shared|=> (true|false)'

section "Size (ad-hoc Release, arm64)"
APP_BYTES="$(find "$APP" -type f -exec stat -f%z {} + | awk '{s+=$1} END {print s}')"
printf 'app_bytes=%s\n' "$APP_BYTES"

section "MANUAL / INTERACTIVE STEPS (run in a logged-in GUI session — not automatable here)"
cat <<'MANUAL'
A headless/automation shell cannot launch a GUI app (launchd 163). Run the rest
in an interactive session, and record outcomes into docs/m0/macos-ui-dev-evidence.md:

  1. Launch:   open "<APP>"    (the printed app path)
     - Record whether it launches and stays running, or the launchd/signature
       error verbatim (redact absolute paths). If it does not launch, the runtime
       walk cannot proceed on this machine — record the condition; do not weaken
       entitlements to make it launch.
  2. Sandbox container: confirm ~/Library/Containers/app.tersa.mac exists.
  3. Keychain-under-ad-hoc probe (the empirical unknown): on the connection
     screen, enter any opaque identifier and activate Connect. Record which
     ConnectionState is reached (connected / a specific failure). Either is a
     legitimate 2c screen state; the empty cache means inbox/thread/search render
     empty regardless.
  4. VoiceOver-only walk of the five screens (connection, inbox empty-state,
     thread if reachable, search, composer): roles / names / values / focus
     order / announcements. Note the three flagged items:
       (a) ComposerView on-appear announcement — is it actually spoken?
       (b) Body TextEditor — does Tab insert a tab; does Esc exit; any FKA trap?
       (c) SearchView — edit the field mid-search: is the dropped result silent?
  5. Full-Keyboard-Access-only walk: every control reachable and operable by
     keyboard; no trap; logical order.
  6. Sandbox-denial observation: `log show --last 3m --predicate 'sender == "Sandbox"'`
     during the session; record aggregate denial observations only (redacted).
  7. Perf (documented conditions: ad-hoc, empty cache, one machine class): note
     window-interactive cold start; connect->inbox render; idle inbox RSS. Omit
     any metric that is not meaningfully measurable (e.g. scroll / query p95 at
     zero rows) rather than record a vacuous value.
MANUAL
printf '\n<APP> = %s\n' "$APP"
printf '\nDONE (automatable evidence captured; interactive steps above pending a GUI session)\n'
