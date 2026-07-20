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
# unprefixed `app.tersa.shared`. macOS rejects an app-group / keychain-access-group
# value not prefixed by a valid Team Identifier at spawn, so the ad-hoc app DOES
# NOT LAUNCH without an Apple team (launchd 163, reproduced in a GUI session) — the
# same credential constraint as the PR33b block. Recorded condition, not a bug to
# fix by weakening entitlements.
#
# This script therefore captures only the DECLARATION evidence (signature, embedded
# entitlements, size), which needs no launch. The runtime VoiceOver /
# Full-Keyboard-Access + App Sandbox walk is DEFERRED to a real-team-signed build at
# the credential unblock; it cannot be produced from this ad-hoc capture.
#
# Redaction: into evidence this script prints only the reviewed entitlement keys,
# aggregate outcomes, the sandbox container path relative to $HOME, sizes, and the
# ad-hoc tier — never an Apple ID, team, certificate name, machine name/UUID, or an
# absolute local path. It prints the build path once, repo-relative (never
# absolute), so an operator can inspect the artifact.

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
# Capture into variables so a failed codesign/plutil is detected (a pipeline
# hides upstream failure from set -e).
SIGNATURE="$(codesign -dv --verbose=2 "$APP" 2>&1)" \
  || { printf 'error: codesign display failed\n' >&2; exit 1; }
printf '%s\n' "$SIGNATURE" \
  | grep -E '^(Identifier|Signature|TeamIdentifier|CodeDirectory)' | sed 's/=.*flags=/ flags=/'
ENTITLEMENTS_OUT="$(codesign -d --entitlements :- --xml "$APP" 2>/dev/null | plutil -p - 2>/dev/null)"
[ -n "$ENTITLEMENTS_OUT" ] \
  || { printf 'error: entitlement extraction produced no output\n' >&2; exit 1; }
# Require each reviewed key present AND that there are exactly five top-level
# entitlement keys (no unreviewed entitlement is embedded or printed).
for key in \
  'com.apple.security.app-sandbox' 'com.apple.security.network.client' \
  'com.apple.security.network.server' 'com.apple.security.application-groups' \
  'keychain-access-groups'; do
  printf '%s\n' "$ENTITLEMENTS_OUT" | grep -q "\"$key\"" \
    || { printf 'error: reviewed entitlement missing: %s\n' "$key" >&2; exit 1; }
done
TOP_LEVEL_KEYS="$(printf '%s\n' "$ENTITLEMENTS_OUT" | grep -cE '^  "[^"]+" =>')"
[ "$TOP_LEVEL_KEYS" -eq 5 ] \
  || { printf 'error: expected exactly 5 entitlement keys, found %s\n' "$TOP_LEVEL_KEYS" >&2; exit 1; }
printf -- '-- embedded entitlements (the five reviewed keys) --\n'
# Print only the reviewed key lines (booleans are inline) and the reviewed group
# value; no bare `=> true|false` match, so an unreviewed Boolean cannot print.
printf '%s\n' "$ENTITLEMENTS_OUT" \
  | grep -E '"(com\.apple\.security\.(app-sandbox|network\.(client|server)|application-groups)|keychain-access-groups)" =>|"app\.tersa\.shared"'

section "Size (ad-hoc Release, arm64)"
APP_BYTES="$(find "$APP" -type f -exec stat -f%z {} + | awk '{s+=$1} END {print s}')"
[ -n "$APP_BYTES" ] || { printf 'error: size discovery produced no bytes\n' >&2; exit 1; }
printf 'app_bytes=%s\n' "$APP_BYTES"

section "Launch condition (recorded, not forced)"
# The ad-hoc app with the reviewed entitlements is expected NOT to launch without
# an Apple team: application-groups/keychain-access-groups require a Team
# Identifier prefix. Attempt it, record the outcome, and never weaken entitlements
# to force a launch. Only safe error tokens are printed (no paths/identifiers).
if open "$APP" >/dev/null 2>"$BUILD_DIR/launch.err"; then
  printf 'launched: yes — the runtime walk can proceed on this machine\n'
else
  printf 'launched: no — tokens: '
  grep -oE 'Code=[0-9]+|Launchd job spawn failed' "$BUILD_DIR/launch.err" | tr '\n' ' '
  printf '\n(expected on a team-less machine; see docs/m0/macos-ui-dev-evidence.md section 2)\n'
fi

section "DEFERRED runtime walk (requires a real-team-signed build — not this ad-hoc capture)"
cat <<'MANUAL'
Because the ad-hoc build does not launch without an Apple team, the runtime
evidence below is DEFERRED to a real-team-signed build at the credential unblock
and is carried as the checklist in docs/m0/macos-ui-dev-evidence.md sections 3-6.
This script signs ad-hoc only; performing the walk needs a real Apple identity
(supplying one to this script is not enough — it always strips the team prefix):

  - App Sandbox container + sender=="Sandbox" denial observation.
  - Keychain bootstrap outcome under a team-prefixed signature.
  - VoiceOver-only walk of the five screens; the three flagged accessibility items.
  - Full-Keyboard-Access-only walk.
  - ADR-0022 runtime numbers (cold start; connect->inbox render; idle inbox RSS),
    documented conditions; omit any not meaningfully measurable at zero rows.
MANUAL
printf '\nbuild artifact (repo-relative): apple/%s\n' "${APP#"$ROOT/"}"
printf 'DONE (declaration evidence and launch condition captured; runtime walk deferred)\n'
