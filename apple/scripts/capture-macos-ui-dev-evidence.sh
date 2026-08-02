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
TEAM_PROBE_SOURCE="$SCRATCH/tersa-team-probe.c"
TEAM_PROBE="$SCRATCH/tersa-team-probe"
SANDBOX_CANARY_APP="$SCRATCH/Tersa Sandbox Canary.app"
SANDBOX_CANARY="$SANDBOX_CANARY_APP/Contents/MacOS/tersa-sandbox-write-canary"
UNSANDBOXED_CANARY="$SCRATCH/tersa-sandbox-write-canary-unsandboxed"
CANARY_DESTINATION="$BUILD_DIR/outside-sandbox-write-canary"
APP_PID=''

cleanup() {
  if [ -n "$APP_PID" ] && kill -0 "$APP_PID" 2>/dev/null; then
    kill -TERM "$APP_PID" 2>/dev/null || true
    cleanup_attempt=0
    while kill -0 "$APP_PID" 2>/dev/null && [ "$cleanup_attempt" -lt 20 ]; do
      cleanup_attempt=$((cleanup_attempt + 1))
      sleep 0.1
    done
    kill -KILL "$APP_PID" 2>/dev/null || true
  fi
  rm -rf "$SCRATCH"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

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

# Resolve the effective Team Identifier BEFORE the unsigned Xcode build. The
# Rust adapters compile TERSA_MACOS_APP_GROUP into the binary, so deriving the
# team only after the build would sign one group while the adapters address the
# unprefixed app.tersa.shared group at runtime.
cat >"$TEAM_PROBE_SOURCE" <<'TEAM_PROBE_C'
int main(void) { return 0; }
TEAM_PROBE_C
cc "$TEAM_PROBE_SOURCE" -o "$TEAM_PROBE"
codesign -s "$IDENTITY_HASH" --force --options runtime --timestamp=none \
  "$TEAM_PROBE" >/dev/null 2>&1
TEAM_ID="$(codesign -dv --verbose=4 "$TEAM_PROBE" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
printf '%s\n' "$TEAM_ID" | grep -qE '^[A-Z0-9]{10}$' \
  || fail 'the effective Apple Development team identifier is unavailable'

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
set -- -project apple/Tersa.xcodeproj -scheme TersaMac -configuration Release \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath "$DERIVED"
if [ -f "$ROOT/apple/local.xcconfig" ]; then
  set -- "$@" -xcconfig "$ROOT/apple/local.xcconfig"
else
  set -- "$@" \
    TERSA_OAUTH_CLIENT_ID="${TERSA_OAUTH_CLIENT_ID:-public-development-evidence.apps.googleusercontent.com}" \
    TERSA_OAUTH_REDIRECT_SCHEME="${TERSA_OAUTH_REDIRECT_SCHEME:-app.tersa.oauth.development-evidence}"
fi
set -- "$@" CODE_SIGNING_ALLOWED=NO \
  TERSA_MACOS_APP_GROUP="$TEAM_ID.app.tersa.shared"
xcodebuild "$@" build >/dev/null
printf 'unsigned_build=ok\n'
LC_ALL=C grep -aFq "$TEAM_ID.app.tersa.shared" "$APP/Contents/MacOS/Tersa" \
  || fail 'the Rust binary did not compile the team-prefixed App Group'
printf 'compiled_application_group=matches signing team (identifier redacted)\n'

PROFILE_MATCH=''
PROFILE_COUNT=0
for profile_dir in \
  "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles" \
  "$HOME/Library/MobileDevice/Provisioning Profiles"; do
  [ -d "$profile_dir" ] || continue
  for profile in "$profile_dir"/*; do
    [ -f "$profile" ] || continue
    security cms -D -i "$profile" >"$SCRATCH/profile.plist" 2>/dev/null || continue
    profile_team="$(plutil -extract TeamIdentifier.0 raw "$SCRATCH/profile.plist" 2>/dev/null || true)"
    profile_app_id="$(plutil -extract 'Entitlements.com\.apple\.application-identifier' raw "$SCRATCH/profile.plist" 2>/dev/null || true)"
    profile_expiry="$(plutil -extract ExpirationDate raw "$SCRATCH/profile.plist" 2>/dev/null || true)"
    [ "$profile_team" = "$TEAM_ID" ] || continue
    case "$profile_app_id" in
      "$TEAM_ID.*"|"$TEAM_ID.app.tersa.mac") ;;
      *) continue ;;
    esac
    python3 -c 'from datetime import datetime, timezone; import sys; assert datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00")) > datetime.now(timezone.utc)' \
      "$profile_expiry" 2>/dev/null || continue
    PROFILE_MATCH="$profile"
    PROFILE_COUNT=$((PROFILE_COUNT + 1))
  done
done
[ "$PROFILE_COUNT" -eq 1 ] \
  || fail 'capture requires exactly one current matching Mac Development profile'
cp "$PROFILE_MATCH" "$APP/Contents/embedded.provisionprofile"
chmod 600 "$APP/Contents/embedded.provisionprofile"

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
printf 'embedded_profile=present current Mac Development (identifier redacted)\n'

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
APP_GROUP="$(plutil -extract 'com\.apple\.security\.application-groups.0' raw "$EMBEDDED_ENTITLEMENTS")"
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
PRE_LAUNCH_PIDS="$SCRATCH/pre-launch-pids"
pgrep -f "$APP/Contents/MacOS/Tersa" 2>/dev/null | sort -n >"$PRE_LAUNCH_PIDS" || :
open -n "$APP" >/dev/null 2>&1 || fail 'LaunchServices rejected the signed application'
attempt=0
while [ "$attempt" -lt 20 ]; do
  CANDIDATE_PIDS="$(pgrep -f "$APP/Contents/MacOS/Tersa" 2>/dev/null || true)"
  for candidate in $CANDIDATE_PIDS; do
    if ! grep -qx "$candidate" "$PRE_LAUNCH_PIDS"; then
      APP_PID="$candidate"
      break
    fi
  done
  [ -n "$APP_PID" ] && break
  attempt=$((attempt + 1))
  sleep 0.25
done
[ -n "$APP_PID" ] || fail 'the signed application did not remain running'
kill -0 "$APP_PID" 2>/dev/null || fail 'the signed application exited during launch'
printf 'launch=ok\n'
[ -d "$HOME/Library/Containers/app.tersa.mac" ] \
  || fail 'the App Sandbox container is unavailable'
printf 'sandbox_container=~/Library/Containers/app.tersa.mac present\n'

section 'App Sandbox denial'
cat >"$SCRATCH/sandbox-write-canary.c" <<'CANARY'
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    int descriptor = open(argv[1], O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (descriptor < 0) {
        return errno == EACCES || errno == EPERM ? 73 : 74;
    }
    if (write(descriptor, "sandbox-canary\n", 15) != 15) return 75;
    return close(descriptor) == 0 ? 0 : 76;
}
CANARY
cc "$SCRATCH/sandbox-write-canary.c" -o "$UNSANDBOXED_CANARY"
mkdir -p "$SANDBOX_CANARY_APP/Contents/MacOS"
cp "$UNSANDBOXED_CANARY" "$SANDBOX_CANARY"
cp "$APP/Contents/Info.plist" "$SANDBOX_CANARY_APP/Contents/Info.plist"
plutil -replace CFBundleExecutable -string tersa-sandbox-write-canary \
  "$SANDBOX_CANARY_APP/Contents/Info.plist"
plutil -replace CFBundleName -string 'Tersa Sandbox Canary' \
  "$SANDBOX_CANARY_APP/Contents/Info.plist"
cp "$PROFILE_MATCH" "$SANDBOX_CANARY_APP/Contents/embedded.provisionprofile"
chmod 600 "$SANDBOX_CANARY_APP/Contents/embedded.provisionprofile"
codesign -s "$IDENTITY_HASH" --entitlements "$RESOLVED_ENTITLEMENTS" \
  --force --options runtime --timestamp=none "$SANDBOX_CANARY_APP" >/dev/null 2>&1
codesign --verify --deep --strict "$SANDBOX_CANARY_APP" >/dev/null 2>&1 \
  || fail 'sandbox write canary signature verification failed'

rm -f -- "$CANARY_DESTINATION"
set +e
"$SANDBOX_CANARY" "$CANARY_DESTINATION"
SANDBOX_STATUS=$?
set -e
[ "$SANDBOX_STATUS" -eq 73 ] \
  || fail 'the sandboxed canary did not receive an outside-container write denial'
[ ! -e "$CANARY_DESTINATION" ] \
  || fail 'the sandboxed canary created its outside-container destination'
"$UNSANDBOXED_CANARY" "$CANARY_DESTINATION" \
  || fail 'the unsandboxed positive control could not create its destination'
[ -f "$CANARY_DESTINATION" ] \
  || fail 'the unsandboxed positive control did not create its destination'
rm -f -- "$CANARY_DESTINATION"
printf 'sandbox_denial=outside-container create denied\n'
printf 'sandbox_positive_control=outside-container create succeeded\n'

section 'Interactive development-only walk'
cat <<'CHECKLIST'
Record with no pointer fallback:
  1. VoiceOver: connection, inbox, thread, search, and composer roles/names/
     values/actions, logical order, focus continuity, and announcements.
  2. VoiceOver checks: composer unavailable-send announcement; Body editor
     Tab/Escape behavior; edited-mid-search result suppression stays silent.
  3. Full Keyboard Access: complete the same five-screen traversal with visible
     focus and no trap, using keyboard controls only.
  4. App Sandbox: the automated bundled canary above must be denied while its
     unsandboxed positive control succeeds.

This Apple Development result is non-gate. Developer ID, notarization, retained
artifact binding, and independent distribution review remain mandatory.
CHECKLIST
printf 'artifact=apple/build/dev-evidence/DerivedData/Build/Products/Release/Tersa.app\n'
