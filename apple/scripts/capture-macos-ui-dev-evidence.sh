#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Apple-Development-signed accessibility and App Sandbox evidence capture for
# ADR-0021 slice 2f. This is local development evidence only: it cannot satisfy
# P1-MACOS-001/002/003 or substitute for Developer ID and notarization.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="$ROOT/apple/build/dev-evidence"
DERIVED="$BUILD_DIR/DerivedData"
APP="$DERIVED/Build/Products/Release/Tersa.app"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/tersa-ui-evidence.XXXXXX")"
SOURCE="$SCRATCH/source"
RESOLVED_ENTITLEMENTS="$SCRATCH/resolved.entitlements.plist"
EMBEDDED_ENTITLEMENTS="$SCRATCH/embedded.entitlements.plist"
trap 'rm -rf "$SCRATCH"' EXIT HUP INT TERM

section() { printf '\n== %s ==\n' "$1"; }
fail() { printf 'error: %s\n' "$1" >&2; exit 1; }

cd "$ROOT"

[ "$(uname -m)" = arm64 ] || fail 'capture requires native arm64 macOS'
TRANSLATED="$(/usr/sbin/sysctl -in sysctl.proc_translated 2>/dev/null || true)"
[ "$TRANSLATED" = 0 ] || fail 'capture requires a non-Rosetta process'
[ -z "$(git status --porcelain --untracked-files=all)" ] \
  || fail 'commit-bound capture requires a clean worktree'
COMMIT="$(git rev-parse HEAD)"

IDENTITIES="$(security find-identity -v -p codesigning 2>/dev/null \
  | sed -nE 's/^[[:space:]]*[0-9]+\) ([0-9A-Fa-f]{40}) "Apple Development: .+"$/\1/p')"
IDENTITY_COUNT="$(printf '%s\n' "$IDENTITIES" | awk 'NF { count += 1 } END { print count + 0 }')"
[ "$IDENTITY_COUNT" -eq 1 ] \
  || fail 'capture requires exactly one valid Apple Development identity'
IDENTITY_HASH="$(printf '%s\n' "$IDENTITIES" | awk 'NF { print $1 }')"
[ -n "$IDENTITY_HASH" ] || fail 'the Apple Development identity is incomplete'

mkdir -p "$SOURCE" "$BUILD_DIR"
git archive --format=tar --output="$SCRATCH/source.tar" "$COMMIT"
tar -xf "$SCRATCH/source.tar" -C "$SOURCE"
cd "$SOURCE"

section 'Toolchain and source binding'
xcodebuild -version | head -1
printf 'source_commit=%s\n' "$COMMIT"
printf 'architecture=arm64-native\n'
printf 'signing_tier=Apple Development (identity and team redacted)\n'

section 'Build tracked Release source'
sh apple/scripts/generate-project.sh >/dev/null
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac -configuration Release \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO \
  TERSA_OAUTH_CLIENT_ID="${TERSA_OAUTH_CLIENT_ID:-public-development-evidence.apps.googleusercontent.com}" \
  TERSA_OAUTH_REDIRECT_SCHEME="${TERSA_OAUTH_REDIRECT_SCHEME:-app.tersa.oauth.development-evidence}" \
  build >/dev/null
printf 'unsigned_build=ok\n'

# Derive the effective Team Identifier from a first, entitlement-free signature.
# The human-readable certificate label is not authoritative and may contain a
# different parenthesized account identifier on development certificates.
codesign -s "$IDENTITY_HASH" --force --options runtime --timestamp=none \
  "$APP" >/dev/null 2>&1
TEAM_ID="$(codesign -dv --verbose=4 "$APP" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
printf '%s\n' "$TEAM_ID" | grep -qE '^[A-Z0-9]{10}$' \
  || fail 'the effective Apple Development team identifier is unavailable'

sed "s/\${TeamIdentifierPrefix}/${TEAM_ID}./g" \
  "$SOURCE/apple/macos/TersaMac.entitlements" >"$RESOLVED_ENTITLEMENTS"
plutil -lint "$RESOLVED_ENTITLEMENTS" >/dev/null
codesign -s "$IDENTITY_HASH" --entitlements "$RESOLVED_ENTITLEMENTS" \
  --force --options runtime --timestamp=none "$APP" >/dev/null 2>&1
codesign --verify --deep --strict "$APP" >/dev/null 2>&1 \
  || fail 'strict code-signature verification failed'

SIGNATURE="$(codesign -dv --verbose=4 "$APP" 2>&1)" \
  || fail 'code-signature inspection failed'
printf '%s\n' "$SIGNATURE" | grep -q '^Authority=Apple Development:' \
  || fail 'the application is not signed by Apple Development'
printf '%s\n' "$SIGNATURE" | grep -q "^TeamIdentifier=$TEAM_ID$" \
  || fail 'the signature has the wrong team identifier'
printf '%s\n' "$SIGNATURE" | grep -qE '^CodeDirectory .*flags=.*runtime' \
  || fail 'the signed application is missing Hardened Runtime'
printf 'signature=valid Apple Development (authority and team redacted)\n'
printf 'hardened_runtime=present\n'

codesign -d --entitlements :- --xml "$APP" >"$EMBEDDED_ENTITLEMENTS" 2>/dev/null
plutil -lint "$EMBEDDED_ENTITLEMENTS" >/dev/null
ENTITLEMENTS_OUT="$(plutil -p "$EMBEDDED_ENTITLEMENTS")"
TOP_LEVEL_KEYS="$(printf '%s\n' "$ENTITLEMENTS_OUT" | grep -cE '^  "[^"]+" =>')"
[ "$TOP_LEVEL_KEYS" -eq 5 ] \
  || fail 'the embedded entitlement count differs from the reviewed five-key set'
for key in \
  'com.apple.security.app-sandbox' 'com.apple.security.network.client' \
  'com.apple.security.network.server' 'com.apple.security.application-groups' \
  'keychain-access-groups'; do
  printf '%s\n' "$ENTITLEMENTS_OUT" | grep -qE "^  \"$key\" =>" \
    || fail "reviewed entitlement missing: $key"
done
APP_GROUP="$(plutil -extract com.apple.security.application-groups.0 raw "$EMBEDDED_ENTITLEMENTS")"
KEYCHAIN_GROUP="$(plutil -extract keychain-access-groups.0 raw "$EMBEDDED_ENTITLEMENTS")"
[ "$APP_GROUP" = "$TEAM_ID.app.tersa.shared" ] \
  || fail 'the embedded application group is not team-prefixed app.tersa.shared'
[ "$KEYCHAIN_GROUP" = "$TEAM_ID.app.tersa.shared" ] \
  || fail 'the embedded Keychain group is not team-prefixed app.tersa.shared'
printf 'entitlements=exact reviewed five-key set\n'
printf 'application_group=[TEAM_REDACTED].app.tersa.shared\n'
printf 'keychain_group=[TEAM_REDACTED].app.tersa.shared\n'

APP_BYTES="$(find "$APP" -type f -exec stat -f%z {} + | awk '{ total += $1 } END { print total }')"
[ -n "$APP_BYTES" ] || fail 'application size discovery failed'
printf 'installed_app_bytes=%s\n' "$APP_BYTES"

section 'Launch'
open -n "$APP" >/dev/null 2>&1 || fail 'LaunchServices rejected the signed application'
APP_PID=''
attempt=0
while [ "$attempt" -lt 20 ]; do
  APP_PID="$(pgrep -f "$APP/Contents/MacOS/Tersa" | head -1 || true)"
  [ -n "$APP_PID" ] && break
  attempt=$((attempt + 1))
  sleep 0.25
done
[ -n "$APP_PID" ] || fail 'the signed application did not remain running'
kill -0 "$APP_PID" 2>/dev/null || fail 'the signed application exited during launch'
printf 'launch=ok\n'
[ -d "$HOME/Library/Containers/app.tersa.mac" ] \
  || fail 'the App Sandbox container was not materialized'
printf 'sandbox_container=~/Library/Containers/app.tersa.mac present\n'

section 'Interactive development-only walk'
cat <<'CHECKLIST'
Record with no pointer fallback:
  1. VoiceOver: connection, inbox, thread, search, and composer roles/names/
     values/actions, logical order, focus continuity, and announcements.
  2. VoiceOver checks: composer unavailable-send announcement; Body editor
     Tab/Escape behavior; edited-mid-search result suppression stays silent.
  3. Full Keyboard Access: complete the same five-screen traversal with visible
     focus and no trap, using keyboard controls only.
  4. App Sandbox: record a sender=="Sandbox" denial for an ungranted capability
     and a positive control proving the observation path was active.

This Apple Development result is non-gate. Developer ID, notarization, retained
artifact binding, and independent distribution review remain mandatory.
CHECKLIST
printf 'artifact=apple/build/dev-evidence/DerivedData/Build/Products/Release/Tersa.app\n'
