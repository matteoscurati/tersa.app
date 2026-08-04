#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Apple-Development-signed macOS token/root Keychain isolation evidence
# capture for ADR-0024 "Required implementation and evidence" Item 5.
#
# This is DEVELOPMENT EVIDENCE ONLY. On an exact Apple Development signed build
# it proves that normal broker token operations can succeed (owner-driven
# positive control) and that both fixed-purpose negative probes return
# errSecMissingEntitlement: the broker querying the installation root/store
# group and the main app querying the token group. It does NOT claim Developer
# ID, notarization, distribution, or closure of ADR-0024 Item 6. It is opt-in,
# never runs in CI, and fails closed without recording a live claim on any
# unresolved precondition.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="$ROOT/apple/build/dev-evidence"
RECORD="$BUILD_DIR/token-isolation-evidence.txt"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/tersa-token-isolation-evidence.XXXXXX")"
DERIVED="$SCRATCH/DerivedData"
SOURCE="$SCRATCH/source"
APP="$DERIVED/Build/Products/Release/Tersa.app"
BROKER_XPC="$APP/Contents/XPCServices/TersaMacTokenBroker.xpc"
RESOLVED_APP_ENT="$SCRATCH/app.resolved.entitlements.plist"
RESOLVED_BROKER_ENT="$SCRATCH/broker.resolved.entitlements.plist"
APP_ENT="$SCRATCH/app.embedded.entitlements.plist"
BROKER_ENT="$SCRATCH/broker.embedded.entitlements.plist"
TEAM_PROBE_SOURCE="$SCRATCH/tersa-team-probe.c"
TEAM_PROBE="$SCRATCH/tersa-team-probe"
PROFILE_PLIST="$SCRATCH/profile.plist"
PROBE_ARG='--tersa-keychain-isolation-probe-v2'
POSITIVE_CONTROL='not-confirmed'
APP_PID=''
PROBE_PID=''

cleanup() {
  # A timed-out or interrupted probe must never be left running. PROBE_PID is the
  # real probe process (launched directly, not under a subshell), so killing it
  # reaps the probe itself rather than orphaning it under launchd.
  if [ -n "$PROBE_PID" ] && kill -0 "$PROBE_PID" 2>/dev/null; then
    kill -KILL "$PROBE_PID" 2>/dev/null || true
    wait "$PROBE_PID" 2>/dev/null || true
  fi
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

# --- Preconditions: native arm64, clean worktree, exact commit ---------------
[ "$(uname -m)" = arm64 ] || fail 'capture requires native arm64 macOS'
TRANSLATED="$(/usr/sbin/sysctl -in sysctl.proc_translated 2>/dev/null || true)"
[ "$TRANSLATED" = 0 ] || fail 'capture requires a non-Rosetta process'
[ -z "$(git status --porcelain --untracked-files=all)" ] \
  || fail 'commit-bound capture requires a clean worktree'
COMMIT="$(git rev-parse HEAD)"

# --- Apple Development identity and effective team (never printed) ------------
IDENTITIES="$(security find-identity -v -p codesigning 2>/dev/null \
  | sed -nE 's/^[[:space:]]*[0-9]+\) ([0-9A-Fa-f]{40}) "Apple Development: .+"$/\1/p')"
IDENTITY_COUNT="$(printf '%s\n' "$IDENTITIES" | awk 'NF { count += 1 } END { print count + 0 }')"
[ "$IDENTITY_COUNT" -eq 1 ] \
  || fail 'capture requires exactly one valid Apple Development identity'
IDENTITY_HASH="$(printf '%s\n' "$IDENTITIES" | awk 'NF { print $1 }')"
[ -n "$IDENTITY_HASH" ] || fail 'the Apple Development identity is incomplete'

# Resolve the effective Team Identifier before the unsigned build. The Rust
# adapters compile TERSA_MACOS_APP_GROUP and TERSA_MACOS_TOKEN_GROUP into their
# binaries, and $(TeamIdentifierPrefix) expands empty under CODE_SIGNING_ALLOWED
# NO, so both group settings must be supplied with the resolved team prefix.
cat >"$TEAM_PROBE_SOURCE" <<'TEAM_PROBE_C'
int main(void) { return 0; }
TEAM_PROBE_C
cc "$TEAM_PROBE_SOURCE" -o "$TEAM_PROBE"
codesign -s "$IDENTITY_HASH" --force --options runtime --timestamp=none \
  "$TEAM_PROBE" >/dev/null 2>&1
TEAM_ID="$(codesign -dv --verbose=4 "$TEAM_PROBE" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
printf '%s\n' "$TEAM_ID" | grep -qE '^[A-Z0-9]{10}$' \
  || fail 'the effective Apple Development team identifier is unavailable'

# --- Build tracked Release source from a git-archive of HEAD -----------------
mkdir -p "$SOURCE" "$BUILD_DIR"
git archive --format=tar --output="$SCRATCH/source.tar" "$COMMIT"
tar -xf "$SCRATCH/source.tar" -C "$SOURCE"
cd "$SOURCE"

section 'Toolchain and source binding'
xcodebuild -version | head -1
printf 'source_commit=%s\n' "$COMMIT"
printf 'architecture=arm64-native\n'
printf 'signing_tier=Apple Development (identity, team, and profile redacted)\n'
printf 'build_source=git-archive of HEAD from a clean worktree\n'

section 'Build tracked Release source (unsigned, team-prefixed groups in Rust)'
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
  TERSA_MACOS_APP_GROUP="$TEAM_ID.app.tersa.shared" \
  TERSA_MACOS_TOKEN_GROUP="$TEAM_ID.app.tersa.token"
xcodebuild "$@" build >/dev/null
printf 'unsigned_build=ok\n'
APP_BIN="$APP/Contents/MacOS/$(plutil -extract CFBundleExecutable raw "$APP/Contents/Info.plist")"
BROKER_BIN="$BROKER_XPC/Contents/MacOS/$(plutil -extract CFBundleExecutable raw "$BROKER_XPC/Contents/Info.plist")"
[ -f "$APP_BIN" ] || fail 'the main app executable was not produced'
[ -f "$BROKER_BIN" ] || fail 'the embedded broker executable was not produced'
LC_ALL=C grep -aFq "$TEAM_ID.app.tersa.shared" "$APP_BIN" \
  || fail 'the app Rust binary did not compile the team-prefixed App Group'
LC_ALL=C grep -aFq "$TEAM_ID.app.tersa.token" "$BROKER_BIN" \
  || fail 'the broker Rust binary did not compile the team-prefixed token group'
printf 'compiled_groups=app.tersa.shared (app) and app.tersa.token (broker); team redacted\n'

# --- Provisioning: one current app profile and one current broker profile -----
section 'Provisioning material (redacted)'
APP_PROFILE=''
BROKER_PROFILE=''
APP_PROFILE_COUNT=0
BROKER_PROFILE_COUNT=0

# A profile authorizes a requested Keychain group when its keychain-access-groups
# entitlement array holds the exact TEAMID.<group> entry or the TEAMID.* team
# wildcard. A single wildcard profile may therefore legitimately authorize both
# principals; the exactly-one-current-profile-per-principal count below keeps the
# binding deterministic. Never prints the team ID, group, UUID, profile path, or
# any entitlement value.
kc_group_authorized() {
  kga_xml="$1"; kga_group="$2"
  if printf '%s' "$kga_xml" | grep -Fq "<string>$TEAM_ID.$kga_group</string>"; then
    return 0
  fi
  if printf '%s' "$kga_xml" | grep -Fq "<string>$TEAM_ID.*</string>"; then
    return 0
  fi
  return 1
}
for profile_dir in \
  "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles" \
  "$HOME/Library/MobileDevice/Provisioning Profiles"; do
  [ -d "$profile_dir" ] || continue
  for profile in "$profile_dir"/*; do
    [ -f "$profile" ] || continue
    security cms -D -i "$profile" >"$PROFILE_PLIST" 2>/dev/null || continue
    p_team="$(plutil -extract TeamIdentifier.0 raw "$PROFILE_PLIST" 2>/dev/null || true)"
    [ "$p_team" = "$TEAM_ID" ] || continue
    p_expiry="$(plutil -extract ExpirationDate raw "$PROFILE_PLIST" 2>/dev/null || true)"
    python3 -c 'from datetime import datetime, timezone; import sys; assert datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00")) > datetime.now(timezone.utc)' \
      "$p_expiry" 2>/dev/null || continue
    p_appid="$(plutil -extract 'Entitlements.com\.apple\.application-identifier' raw "$PROFILE_PLIST" 2>/dev/null || true)"
    p_kc_xml="$(plutil -extract Entitlements.keychain-access-groups xml1 -o - "$PROFILE_PLIST" 2>/dev/null || true)"
    case "$p_appid" in
      "$TEAM_ID.*"|"$TEAM_ID.app.tersa.mac")
        # The app Keychain group is authorized by an exact TEAMID.app.tersa.shared
        # entry or the TEAMID.* team wildcard. The macOS application group is
        # verified on the final signed app entitlement below, not required to
        # appear in this development profile.
        if kc_group_authorized "$p_kc_xml" app.tersa.shared; then
          APP_PROFILE="$profile"; APP_PROFILE_COUNT=$((APP_PROFILE_COUNT + 1))
        fi ;;
    esac
    case "$p_appid" in
      "$TEAM_ID.*"|"$TEAM_ID.app.tersa.mac.token-broker")
        if kc_group_authorized "$p_kc_xml" app.tersa.token; then
          BROKER_PROFILE="$profile"; BROKER_PROFILE_COUNT=$((BROKER_PROFILE_COUNT + 1))
        fi ;;
    esac
  done
done
[ "$APP_PROFILE_COUNT" -eq 1 ] \
  || fail 'capture requires exactly one current Apple Development profile authorizing app.tersa.mac and the app.tersa.shared Keychain group (exact entry or team wildcard)'
[ "$BROKER_PROFILE_COUNT" -eq 1 ] \
  || fail 'capture requires exactly one current Apple Development profile authorizing the app.tersa.token Keychain group (exact entry or team wildcard); resolve to exactly one before capture'
printf 'app_profile=present current Apple Development (identifier redacted)\n'
printf 'broker_profile=present current Apple Development; token group authorized by exact entry or team wildcard (identifier redacted)\n'

# --- Inside-out Apple Development signing ------------------------------------
section 'Inside-out Apple Development signing'
sed "s/\${TeamIdentifierPrefix}/${TEAM_ID}./g" \
  "$SOURCE/apple/macos-token-broker/TersaMacTokenBroker.entitlements" >"$RESOLVED_BROKER_ENT"
sed "s/\${TeamIdentifierPrefix}/${TEAM_ID}./g" \
  "$SOURCE/apple/macos/TersaMac.entitlements" >"$RESOLVED_APP_ENT"
plutil -lint "$RESOLVED_BROKER_ENT" >/dev/null
plutil -lint "$RESOLVED_APP_ENT" >/dev/null

cp "$BROKER_PROFILE" "$BROKER_XPC/Contents/embedded.provisionprofile"
chmod 600 "$BROKER_XPC/Contents/embedded.provisionprofile"
codesign -s "$IDENTITY_HASH" --entitlements "$RESOLVED_BROKER_ENT" \
  --force --options runtime --timestamp=none "$BROKER_XPC" >/dev/null 2>&1 \
  || fail 'the embedded broker XPC signing failed'
codesign --verify --strict "$BROKER_XPC" >/dev/null 2>&1 \
  || fail 'the broker XPC strict signature verification failed'
printf 'broker_signed=Apple Development (signed inside first)\n'

cp "$APP_PROFILE" "$APP/Contents/embedded.provisionprofile"
chmod 600 "$APP/Contents/embedded.provisionprofile"
codesign -s "$IDENTITY_HASH" --entitlements "$RESOLVED_APP_ENT" \
  --force --options runtime --timestamp=none "$APP" >/dev/null 2>&1 \
  || fail 'the containing application signing failed'
codesign --verify --deep --strict "$APP" >/dev/null 2>&1 \
  || fail 'strict deep code-signature verification failed'
printf 'app_signed=Apple Development (signed outside; deep strict verified)\n'

# --- Strict posture and exact entitlement verification ----------------------
section 'Signature and entitlement posture (redacted)'
verify_posture() {
  vp_bin="$1"; vp_label="$2"
  vp_sig="$(codesign -dv --verbose=4 "$vp_bin" 2>&1)" \
    || fail "$vp_label code-signature inspection failed"
  printf '%s\n' "$vp_sig" | grep -q '^Authority=Apple Development:' \
    || fail "$vp_label is not signed by Apple Development"
  printf '%s\n' "$vp_sig" | grep -q "^TeamIdentifier=$TEAM_ID$" \
    || fail "$vp_label has the wrong team identifier"
  printf '%s\n' "$vp_sig" | grep -qE '^CodeDirectory .*flags=.*runtime' \
    || fail "$vp_label is missing Hardened Runtime"
}
verify_posture "$BROKER_XPC" 'broker'
verify_posture "$APP" 'app'
printf 'signature=valid Apple Development, same team, Hardened Runtime on both (authority/team redacted)\n'

codesign -d --entitlements :- --xml "$BROKER_XPC" >"$BROKER_ENT" 2>/dev/null
codesign -d --entitlements :- --xml "$APP" >"$APP_ENT" 2>/dev/null
plutil -lint "$BROKER_ENT" >/dev/null
plutil -lint "$APP_ENT" >/dev/null

ent_value() { plutil -extract "$1" raw "$2" 2>/dev/null || true; }
# `ent_has` takes a literal plist key (dots included) and escapes every dot for
# the plutil key path, so a reviewed key such as com.apple.security.app-sandbox
# is matched as one top-level key instead of a nested com.apple.security path.
# It never prints the key, value, or plist path. Callers pass literal keys only;
# array-index reads (e.g. keychain-access-groups.0) stay with `ent_value`.
ent_has() {
  eh_key="$(printf '%s' "$1" | sed 's/\./\\./g')"
  plutil -extract "$eh_key" raw "$2" >/dev/null 2>&1
}

# Broker: exactly the three reviewed keys; token group only; no App Group or
# network.server.
BROKER_KEYS="$(plutil -p "$BROKER_ENT" | grep -cE '^  "[^"]+" =>')"
[ "$BROKER_KEYS" -eq 3 ] \
  || fail 'the broker embedded entitlement count differs from the reviewed three-key set'
for key in 'com.apple.security.app-sandbox' 'com.apple.security.network.client' 'keychain-access-groups'; do
  ent_has "$key" "$BROKER_ENT" || fail "broker reviewed entitlement missing: $key"
done
[ "$(ent_value 'keychain-access-groups.0' "$BROKER_ENT")" = "$TEAM_ID.app.tersa.token" ] \
  || fail 'the broker Keychain group is not team-prefixed app.tersa.token'
ent_has 'com.apple.security.application-groups' "$BROKER_ENT" \
  && fail 'the broker must not carry an App Group entitlement'
ent_has 'com.apple.security.network.server' "$BROKER_ENT" \
  && fail 'the broker must not carry the network.server entitlement'
printf 'broker_entitlements=exact three-key set; token group only; no App Group; network.client only\n'

# App: exactly the five reviewed keys; shared Keychain/App Group; network.server.
APP_KEYS="$(plutil -p "$APP_ENT" | grep -cE '^  "[^"]+" =>')"
[ "$APP_KEYS" -eq 5 ] \
  || fail 'the app embedded entitlement count differs from the reviewed five-key set'
for key in 'com.apple.security.app-sandbox' 'com.apple.security.network.client' \
  'com.apple.security.network.server' 'com.apple.security.application-groups' 'keychain-access-groups'; do
  ent_has "$key" "$APP_ENT" || fail "app reviewed entitlement missing: $key"
done
[ "$(ent_value 'com\.apple\.security\.application-groups.0' "$APP_ENT")" = "$TEAM_ID.app.tersa.shared" ] \
  || fail 'the app App Group is not team-prefixed app.tersa.shared'
[ "$(ent_value 'keychain-access-groups.0' "$APP_ENT")" = "$TEAM_ID.app.tersa.shared" ] \
  || fail 'the app Keychain group is not team-prefixed app.tersa.shared'
printf 'app_entitlements=exact five-key set; shared group; App Group and network.server present\n'

# Disjoint Keychain groups by construction.
[ "$(ent_value 'keychain-access-groups.0' "$APP_ENT")" != "$(ent_value 'keychain-access-groups.0' "$BROKER_ENT")" ] \
  || fail 'the app and broker Keychain groups are not disjoint'

# Forbidden debug/injection exceptions must be absent on both executables.
for plist in "$APP_ENT" "$BROKER_ENT"; do
  for forbidden in 'get-task-allow' \
    'com.apple.security.cs.debugger' \
    'com.apple.security.cs.disable-library-validation' \
    'com.apple.security.cs.allow-dyld-environment-variables'; do
    if ent_has "$forbidden" "$plist"; then
      fail 'a forbidden debug/injection entitlement is present on a signed executable'
    fi
  done
done
printf 'library_validation=enabled (Hardened Runtime; disable-library-validation absent)\n'
printf 'forbidden_exceptions=absent on both executables\n'

# --- Negative controls: both fixed-purpose probes ---------------------------
section 'Negative controls - fixed-purpose Keychain isolation probes'
run_probe() {
  # Runs the probe binary directly in the background with the single opt-in
  # argument, bounded to 40s, and exposes the completion status file and stdout
  # file. The probe is launched (not wrapped in a subshell) so PROBE_PID is the
  # real probe process: a timeout or interrupt kills exactly that PID and cannot
  # leave an orphaned probe reparented to launchd. Completion is detected with
  # kill -0, and the probe's own exit code is captured via wait without disabling
  # errexit (a nonzero probe exit flows to assert_probe, which fails closed).
  rp_bin="$1"; rp_label="$2"
  rp_out="$SCRATCH/probe-$rp_label.out"
  rp_err="$SCRATCH/probe-$rp_label.err"
  rp_status="$SCRATCH/probe-$rp_label.status"
  rm -f "$rp_out" "$rp_err" "$rp_status"
  "$rp_bin" "$PROBE_ARG" >"$rp_out" 2>"$rp_err" &
  PROBE_PID=$!
  rp_wait=0
  while [ "$rp_wait" -lt 40 ]; do
    kill -0 "$PROBE_PID" 2>/dev/null || break
    sleep 1
    rp_wait=$((rp_wait + 1))
  done
  if kill -0 "$PROBE_PID" 2>/dev/null; then
    kill -KILL "$PROBE_PID" 2>/dev/null || true
    wait "$PROBE_PID" 2>/dev/null || true
    PROBE_PID=''
    fail "the $rp_label probe did not finish within 40s; stopping without a live claim"
  fi
  rp_exit=0
  wait "$PROBE_PID" || rp_exit=$?
  PROBE_PID=''
  printf '%s\n' "$rp_exit" >"$rp_status"
  PROBE_EXIT_FILE="$rp_status"
  PROBE_OUT_FILE="$rp_out"
}
assert_probe() {
  ap_bin="$1"; ap_principal="$2"
  run_probe "$ap_bin" "$ap_principal"
  ap_exit="$(cat "$PROBE_EXIT_FILE" 2>/dev/null || echo absent)"
  [ "$ap_exit" = 0 ] \
    || fail "the $ap_principal isolation probe exited '$ap_exit' (expected 0 / missing-entitlement)"
  ap_lines="$(wc -l < "$PROBE_OUT_FILE" | tr -d ' ')"
  [ "$ap_lines" -eq 1 ] \
    || fail "the $ap_principal probe emitted $ap_lines line(s); expected exactly one evidence line"
  ap_expected='{"schema_version":2,"principal":"'"$ap_principal"'","result":"missing-entitlement"}'
  grep -Fxq "$ap_expected" "$PROBE_OUT_FILE" \
    || fail "the $ap_principal probe output is not the exact missing-entitlement evidence line"
  # The exact missing-entitlement line is already enforced above, so any of the
  # closed v2 non-pass labels here means the probe was not the expected refusal;
  # fail closed. item-not-found is a read-only v1 outcome and cannot occur.
  case "$(cat "$PROBE_OUT_FILE")" in
    *'"result":"unexpectedly-authorized"'* | *'"result":"cleanup-failed"'* \
      | *'"result":"unexpected-status"'* | *'"result":"configuration-invalid"'*)
      fail "the $ap_principal probe returned a non-pass result label" ;;
  esac
  printf 'isolation_probe[%s]=missing-entitlement (exit 0)\n' "$ap_principal"
}
assert_probe "$BROKER_BIN" 'token-broker'
assert_probe "$APP_BIN" 'main-app'
printf 'negative_controls=both real-process probes were denied the forbidden group\n'

# --- Positive control: owner-driven normal token operations (interactive) ----
section 'Positive control - owner-driven normal token operations (interactive)'
PRE_LAUNCH_PIDS="$SCRATCH/pre-launch-pids"
pgrep -f "$APP_BIN" 2>/dev/null | sort -n >"$PRE_LAUNCH_PIDS" || :
open -n "$APP" >/dev/null 2>&1 || fail 'LaunchServices rejected the signed application'
launch_attempt=0
while [ "$launch_attempt" -lt 40 ]; do
  CANDIDATE_PIDS="$(pgrep -f "$APP_BIN" 2>/dev/null || true)"
  for candidate in $CANDIDATE_PIDS; do
    if ! grep -qx "$candidate" "$PRE_LAUNCH_PIDS"; then
      APP_PID="$candidate"
      break
    fi
  done
  [ -n "$APP_PID" ] && break
  launch_attempt=$((launch_attempt + 1))
  sleep 0.25
done
[ -n "$APP_PID" ] || fail 'the signed application did not remain running for the positive control'
printf 'app_launched=ok (pid redacted)\n'
cat <<'CHECKLIST'
Owner-driven positive control. This script never touches Google credentials,
authorization codes, tokens, account data, or mail content. Complete each step
in the running app, then confirm ONLY the bounded, non-secret outcome:

  1. CONNECT: sign in to Google through the token broker. Browser consent and
     any credentials stay owner-only. Observe the broker complete the code
     exchange (or a stored-token refresh) and hand the short-lived access token
     to the main process.
  2. SYNC/RENDER: observe Gmail synchronization succeed and the inbox render.
  3. DISCONNECT: disconnect the account and observe the decided teardown
     ordering succeed - broker revoke, broker token delete, local purge, marker
     clear - ending in a clean disconnect, not an unconfirmed failure.

Confirm ONLY by typing the exact source commit shown below. Any other input
aborts the capture without recording a live positive-control claim. No
credential, token, account, or mail datum is recorded by this harness.
CHECKLIST
printf 'Type the exact source commit (%s) to confirm the bounded outcome: ' "$COMMIT"
if ! read -r confirmation; then
  fail 'the positive-control confirmation could not be read (no interactive terminal); stopping without a live claim'
fi
[ "$confirmation" = "$COMMIT" ] \
  || fail 'the positive control was not confirmed; stopping without a live claim'
POSITIVE_CONTROL='confirmed-by-operator (commit-bound attestation)'
printf 'positive_control=confirmed; broker exchange/refresh + Gmail sync/render + disconnect teardown observed by owner\n'

# --- Final redacted, commit-bound evidence record (gitignored path) ----------
section 'Evidence record (redacted, commit-bound)'
{
  printf 'tersa-macos-token-isolation-dev-evidence\n'
  printf 'schema_version=2\n'
  printf 'source_commit=%s\n' "$COMMIT"
  printf 'captured_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'architecture=arm64-native\n'
  printf 'build_source=git-archive of HEAD from a clean worktree\n'
  printf 'signing_tier=Apple Development (identity, team, and profile redacted)\n'
  printf 'signing_order=broker XPC signed inside first, then containing app; deep strict verified\n'
  printf 'app_profile=present current Apple Development (identifier redacted)\n'
  printf 'broker_profile=present current Apple Development; token group authorized by exact entry or team wildcard (identifier redacted)\n'
  printf 'app_entitlements=exact five-key set; keychain group app.tersa.shared; App Group and network.server present\n'
  printf 'broker_entitlements=exact three-key set; keychain group app.tersa.token; no App Group; network.client only\n'
  printf 'hardened_runtime=present on both executables\n'
  printf 'library_validation=enabled (Hardened Runtime; disable-library-validation absent)\n'
  printf 'forbidden_exceptions=absent on both executables\n'
  printf 'deep_signature=valid strict\n'
  printf 'isolation_probe[token-broker]=%s\n' "$(cat "$SCRATCH/probe-token-broker.out")"
  printf 'isolation_probe[main-app]=%s\n' "$(cat "$SCRATCH/probe-main-app.out")"
  printf 'positive_control=%s\n' "$POSITIVE_CONTROL"
  printf 'claim=development evidence only; NOT Developer ID, notarization, distribution, or ADR-0024 Item 6 closure\n'
} >"$RECORD"
printf 'evidence_record=%s (gitignored; inspect and selectively record)\n' "$RECORD"
printf '\nThis run is development evidence only. It is not Developer ID, notarization,\ndistribution, or closure of ADR-0024 Item 6.\n'
