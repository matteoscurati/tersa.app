#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Builds, verifies, installs, launches, and records aggregate physical-device
# observations. External device actions require both an argument and local opt-in.
set -eu
umask 077

apple_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
workspace_dir=$(CDPATH='' cd -- "${apple_dir}/.." && pwd)
config="${apple_dir}/local.xcconfig"
output="${apple_dir}/build/dioxus-device-evidence"
bundle_id='app.tersa.dioxus-spike.ios'
execute=0
contract_self_test=0
device_class=''
viewport=''
os_version=''
observer_competence=''
observer_record_id=''
screenshot=''
test_ids='marked-text-ime autocorrect dictation selection copy-paste undo-redo hardware-keyboard voiceover-order-state dynamic-type full-keyboard-access switch-control'

append_machine_result() {
  destination=$1
  result_device_class=$2
  result_test_id=$3
  result_outcome=$4
  case " ${test_ids} " in
    *" ${result_test_id} "*) ;;
    *) return 1 ;;
  esac
  if [ "$result_test_id" = hardware-keyboard ] && [ "$result_device_class" = iphone ]; then
    test "$result_outcome" = not-applicable || return 1
  else
    case "$result_outcome" in pass|fail) ;; *) return 1 ;; esac
  fi
  printf '%s=%s\n' "$result_test_id" "$result_outcome" >> "$destination"
}

usage() {
  cat <<'EOF'
usage: capture-dioxus-device-evidence.sh [--execute --device-class iphone|ipad
  --viewport compact|regular
  --os-version 'iOS 18.x' --observer-competence apple-platform|accessibility
  --observer-record-id <32-hex> --redacted-screenshot-source <png>]

The default is a no-build, no-install, no-launch dry run. Execution also requires
TERSA_DEVICE_EVIDENCE_OPT_IN=YES and a populated ignored apple/local.xcconfig.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) execute=1; shift ;;
    --self-test-contract) contract_self_test=1; shift ;;
    --device-class) device_class=${2:-}; shift 2 ;;
    --viewport) viewport=${2:-}; shift 2 ;;
    --os-version) os_version=${2:-}; shift 2 ;;
    --observer-competence) observer_competence=${2:-}; shift 2 ;;
    --observer-record-id) observer_record_id=${2:-}; shift 2 ;;
    --redacted-screenshot-source) screenshot=${2:-}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$contract_self_test" -eq 1 ]; then
  contract_temporary=$(mktemp -d "${TMPDIR:-/tmp}/tersa-device-contract.XXXXXX")
  trap 'rm -rf -- "$contract_temporary"' EXIT HUP INT TERM
  for contract_device_class in iphone ipad; do
    contract_results="${contract_temporary}/${contract_device_class}.txt"
    : > "$contract_results"
    for contract_test_id in $test_ids; do
      contract_outcome=pass
      if [ "$contract_device_class" = iphone ] && [ "$contract_test_id" = hardware-keyboard ]; then
        contract_outcome=not-applicable
      fi
      append_machine_result "$contract_results" "$contract_device_class" \
        "$contract_test_id" "$contract_outcome"
    done
    python3 "${apple_dir}/scripts/verify-dioxus-device-evidence.py" \
      --verify-machine-results "$contract_results" "$contract_device_class" >/dev/null
  done
  grep -Fx 'hardware-keyboard=not-applicable' "${contract_temporary}/iphone.txt" >/dev/null
  if append_machine_result /dev/null ipad hardware-keyboard not-applicable; then
    echo 'The machine-result helper accepted an invalid iPad outcome.' >&2
    exit 1
  fi
  printf '%s\n' 'Dioxus device machine-result contract self-test passed.'
  exit 0
fi

if [ "$execute" -ne 1 ]; then
  printf '%s\n' \
    'DIOXUS DEVICE EVIDENCE DRY RUN' \
    'No build, signing, installation, launch, or device command was executed.' \
    'NOT A DEVICE-GATE RESULT'
  exit 0
fi

if [ "${TERSA_DEVICE_EVIDENCE_OPT_IN:-}" != YES ]; then
  echo 'Execution requires TERSA_DEVICE_EVIDENCE_OPT_IN=YES.' >&2
  exit 2
fi
if [ -z "${TERSA_DEVICE_SELECTOR:-}" ]; then
  echo 'Execution requires a local TERSA_DEVICE_SELECTOR; it is never retained.' >&2
  exit 2
fi
test -t 0 && test -t 1 || { echo 'Execution requires an interactive terminal.' >&2; exit 2; }
test -n "$screenshot" || { echo 'A redacted screenshot source is required.' >&2; exit 2; }
case "$device_class" in iphone|ipad) ;; *) echo 'Invalid device class.' >&2; exit 2 ;; esac
case "$viewport" in compact|regular) ;; *) echo 'Invalid viewport class.' >&2; exit 2 ;; esac
if [ "$device_class" = iphone ] && [ "$viewport" != compact ]; then
  echo 'iPhone observations must use the compact viewport script.' >&2
  exit 2
fi
case "$observer_competence" in apple-platform|accessibility) ;; *) echo 'Invalid observer competence.' >&2; exit 2 ;; esac
printf '%s' "$observer_record_id" | grep -Eq '^[0-9a-f]{32}$' || { echo 'Observer record ID must be 32 lowercase hexadecimal characters.' >&2; exit 2; }
printf '%s' "$os_version" | grep -Eq '^iOS [0-9]+[.][0-9]+([.][0-9]+)?$' || { echo 'Invalid iOS version.' >&2; exit 2; }

cd "$workspace_dir"
head=$(git rev-parse HEAD)
printf '%s' "$head" | grep -Eq '^[0-9a-f]{40}$' || { echo 'HEAD is not an exact commit.' >&2; exit 1; }
test -z "$(git status --porcelain)" || { echo 'Device evidence requires a clean exact-head worktree.' >&2; exit 1; }
test -f "$config" || { echo 'Copy apple/local.xcconfig.example to the ignored local config.' >&2; exit 2; }
git check-ignore -q "$config" || { echo 'The signing configuration must be ignored by Git.' >&2; exit 1; }
grep -Eq '^TERSA_DIOXUS_DEVICE_EVIDENCE_OPT_IN[[:space:]]*=[[:space:]]*YES[[:space:]]*$' "$config" || { echo 'Local signing opt-in is absent.' >&2; exit 2; }
if grep -Eq '^TERSA_EVIDENCE_COMMIT[[:space:]]*=' "$config"; then
  echo 'The local signing configuration must not override the evidence commit.' >&2
  exit 2
fi
temporary=$(mktemp -d "${TMPDIR:-/tmp}/tersa-device-evidence.XXXXXX")
archive="${temporary}/TersaDioxusDevice.xcarchive"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM

sh apple/scripts/generate-project.sh >"${temporary}/xcodegen.log" 2>&1 || { echo 'Project generation failed; no log was retained.' >&2; exit 1; }
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaDioxusIOS \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -xcconfig "$config" -showBuildSettings >"${temporary}/build-settings.txt" 2>&1 || { echo 'Effective signing settings could not be inspected.' >&2; exit 1; }
grep -Eq '^[[:space:]]*CODE_SIGNING_ALLOWED = YES$' "${temporary}/build-settings.txt" || { echo 'Effective signing permission is not enabled.' >&2; exit 2; }
grep -Eq '^[[:space:]]*CODE_SIGNING_REQUIRED = YES$' "${temporary}/build-settings.txt" || { echo 'Effective signing requirement is not enabled.' >&2; exit 2; }
team_count=$(sed -n 's/^[[:space:]]*DEVELOPMENT_TEAM = //p' "${temporary}/build-settings.txt" | sort -u | wc -l | tr -d ' ')
team=$(sed -n 's/^[[:space:]]*DEVELOPMENT_TEAM = //p' "${temporary}/build-settings.txt" | sort -u)
if [ "$team_count" -ne 1 ] || ! printf '%s' "$team" | grep -Eq '^[A-Z0-9]{10}$'; then
  echo 'Effective development team must be one 10-character uppercase identifier.' >&2
  exit 2
fi
grep -Eq '^[[:space:]]*CODE_SIGN_STYLE = (Automatic|Manual)$' "${temporary}/build-settings.txt" || { echo 'Effective signing style is invalid.' >&2; exit 2; }
grep -Eq '^[[:space:]]*CODE_SIGN_IDENTITY = [^[:space:]].*$' "${temporary}/build-settings.txt" || { echo 'Effective signing identity is absent.' >&2; exit 2; }
grep -Fq "PRODUCT_BUNDLE_IDENTIFIER = ${bundle_id}" "${temporary}/build-settings.txt" || { echo 'Effective bundle identity is invalid.' >&2; exit 1; }
test ! -e "$output" || { echo 'Evidence output already exists; preserve or remove it explicitly.' >&2; exit 2; }
rm -rf -- "$archive"
staged_output="${temporary}/evidence"
mkdir -p "$staged_output"

if ! xcodebuild -project apple/Tersa.xcodeproj -scheme TersaDioxusIOS \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath "${temporary}/DerivedData" \
  -archivePath "$archive" -xcconfig "$config" \
  TERSA_EVIDENCE_COMMIT="$head" archive >"${temporary}/xcodebuild.log" 2>&1; then
  echo 'Signed Release archive failed; signing output was deleted.' >&2
  exit 1
fi

app="${archive}/Products/Applications/Tersa Dioxus Spike.app"
binary="${app}/tersa-dioxus-spike"
info="${app}/Info.plist"
test -x "$binary" && test -f "$info" || { echo 'Release archive is incomplete.' >&2; exit 1; }
test "$(plutil -extract CFBundleIdentifier raw "$info")" = "$bundle_id" || { echo 'Archived bundle identity is invalid.' >&2; exit 1; }
app_version=$(plutil -extract CFBundleShortVersionString raw "$info")
app_build=$(plutil -extract CFBundleVersion raw "$info")
strings -a "$binary" | grep -Fxq "TERSA-DIOXUS-BUILD-COMMIT:${head}" || { echo 'Executable commit binding is absent.' >&2; exit 1; }
codesign --verify --deep --strict "$app" >"${temporary}/codesign-verify.log" 2>&1 || { echo 'Application signature verification failed.' >&2; exit 1; }
codesign -d --entitlements :- "$app" >"${temporary}/entitlements.plist" 2>"${temporary}/codesign-display.log" || { echo 'Entitlement inspection failed.' >&2; exit 1; }
python3 - "$temporary/entitlements.plist" "$bundle_id" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as source:
    value = plistlib.load(source)
allowed = {
    "application-identifier",
    "com.apple.developer.team-identifier",
    "get-task-allow",
    "keychain-access-groups",
}
if set(value) - allowed:
    raise SystemExit("Signed application has entitlements outside the minimal allowlist.")
application = value.get("application-identifier", "")
team = value.get("com.apple.developer.team-identifier", "")
groups = value.get("keychain-access-groups", [])
debuggable = value.get("get-task-allow", False)
if application != team + "." + sys.argv[2] or groups != [application] or not isinstance(debuggable, bool):
    raise SystemExit("Signed application identity entitlements are inconsistent.")
PY
test -f "${app}/embedded.mobileprovision" || { echo 'A device provisioning profile is absent.' >&2; exit 1; }
security cms -D -i "${app}/embedded.mobileprovision" >"${temporary}/profile.plist" 2>"${temporary}/profile.log" || { echo 'Provisioning profile verification failed.' >&2; exit 1; }
python3 - "$temporary/profile.plist" "$bundle_id" "$team" <<'PY'
import datetime as dt
import plistlib
import sys

with open(sys.argv[1], "rb") as source:
    profile = plistlib.load(source)
expires = profile.get("ExpirationDate")
entitlements = profile.get("Entitlements", {})
teams = profile.get("TeamIdentifier", [])
devices = profile.get("ProvisionedDevices", [])
if not isinstance(expires, dt.datetime) or expires <= dt.datetime.now(dt.UTC).replace(tzinfo=None):
    raise SystemExit("Provisioning profile is expired or malformed.")
if not isinstance(teams, list) or teams != [sys.argv[3]]:
    raise SystemExit("Provisioning profile team is malformed.")
if entitlements.get("application-identifier") != teams[0] + "." + sys.argv[2]:
    raise SystemExit("Provisioning profile application identity is inconsistent.")
if not isinstance(devices, list) or not devices or not all(isinstance(item, str) for item in devices):
    raise SystemExit("Provisioning profile is not bound to physical devices.")
PY

device_json="${temporary}/device.json"
xcrun devicectl device info details --device "$TERSA_DEVICE_SELECTOR" --json-output "$device_json" --quiet >"${temporary}/device.log" 2>&1 || { echo 'Physical device preflight failed; device output was deleted.' >&2; exit 1; }
python3 apple/scripts/verify-dioxus-device-evidence.py \
  --verify-device-details "$device_json" "$os_version" "$device_class"

xcrun devicectl device install app --device "$TERSA_DEVICE_SELECTOR" "$app" --json-output "${temporary}/install.json" --quiet >"${temporary}/install.log" 2>&1 || { echo 'Device installation failed; raw output was deleted.' >&2; exit 1; }
xcrun devicectl device info apps --device "$TERSA_DEVICE_SELECTOR" --bundle-id "$bundle_id" --json-output "${temporary}/apps.json" --quiet >"${temporary}/apps.log" 2>&1 || { echo 'Installed application identity check failed.' >&2; exit 1; }
python3 apple/scripts/verify-dioxus-device-evidence.py \
  --verify-installed-app "$temporary/apps.json" "$bundle_id"

launch_evidence() {
  launch_label=$1
  launch_json="${temporary}/launch-${launch_label}.json"
  processes_json="${temporary}/processes-${launch_label}.json"
  xcrun devicectl device process launch --device "$TERSA_DEVICE_SELECTOR" \
    --terminate-existing --json-output "$launch_json" --quiet \
    "$bundle_id" --tersa-device-evidence >"${temporary}/launch-${launch_label}.log" 2>&1 || { echo 'Evidence-mode launch failed; raw output was deleted.' >&2; exit 1; }
  xcrun devicectl device info processes --device "$TERSA_DEVICE_SELECTOR" \
    --json-output "$processes_json" --quiet >"${temporary}/processes-${launch_label}.log" 2>&1 || { echo 'Launched-process liveness check failed; raw output was deleted.' >&2; exit 1; }
  python3 apple/scripts/verify-dioxus-device-evidence.py \
    --verify-launch-process "$launch_json" "$processes_json" \
    "$bundle_id" 'tersa-dioxus-spike'
}

launch_evidence initial

started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf '%s\n' \
  'The signed exact-head diagnostic is installed and running.' \
  'Before observations, confirm that the physical-device harness card is visible' \
  "and its displayed Commit value is exactly ${head}."
printf '%s' 'Evidence screen and exact displayed commit [PASS/FAIL]: '
IFS= read -r evidence_precondition
test "$evidence_precondition" = PASS || { echo 'The evidence-mode exact-commit precondition did not pass.' >&2; exit 2; }
cat <<'EOF'
Perform every fixed script in docs/m0/dioxus-device-evidence.md. Enter PASS or
FAIL only. Save one already-redacted screenshot at the path supplied to
--redacted-screenshot-source.
EOF
results="${temporary}/results.txt"
: > "$results"
for test_id in $test_ids; do
  if [ "$test_id" = hardware-keyboard ] && [ "$device_class" = iphone ]; then
    printf '%s\n' 'Hardware-keyboard observation is not applicable to the iPhone run.'
    append_machine_result "$results" "$device_class" "$test_id" not-applicable
    printf '%s\n' 'hardware-keyboard=not-applicable'
    continue
  fi
  if [ "$test_id" = dynamic-type ]; then
    printf '%s\n' \
      'Set the largest Accessibility Dynamic Type size now.' \
      'Enter READY; the harness will relaunch the exact evidence mode itself.'
    printf '%s' 'Dynamic Type relaunch [READY]: '
    IFS= read -r ready
    test "$ready" = READY || { echo 'Dynamic Type relaunch requires READY.' >&2; exit 2; }
    launch_evidence dynamic-type
    printf '%s\n' "Confirm the relaunched harness still displays commit ${head}."
  fi
  printf '%s outcome [PASS/FAIL]: ' "$test_id"
  IFS= read -r outcome
  case "$outcome" in PASS) normalized=pass ;; FAIL) normalized=fail ;; *) echo 'Only PASS or FAIL is accepted.' >&2; exit 2 ;; esac
  append_machine_result "$results" "$device_class" "$test_id" "$normalized" || {
    echo 'Machine-result generation violated the fixed contract.' >&2
    exit 1
  }
done
test -f "$screenshot" || { echo 'The redacted screenshot is absent.' >&2; exit 2; }
cp "$screenshot" "${staged_output}/device-redacted.png"
completed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
bundle_hash=$(python3 - "$app" <<'PY'
import hashlib
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.rglob("*")):
    if path.is_symlink():
        raise SystemExit("Application bundle contains an unsupported entry.")
    if path.is_dir():
        continue
    if not path.is_file():
        raise SystemExit("Application bundle contains an unsupported entry.")
    relative = path.relative_to(root).as_posix().encode()
    digest.update(struct.pack(">I", len(relative)))
    digest.update(relative)
    digest.update(struct.pack(">Q", path.stat().st_size))
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
print(digest.hexdigest())
PY
)
screenshot_hash=$(shasum -a 256 "${staged_output}/device-redacted.png" | awk '{print $1}')

python3 - "$staged_output/observations.json" "$results" "$head" "$device_class" "$viewport" "$os_version" "$observer_record_id" "$observer_competence" "$started_at" "$completed_at" "$bundle_hash" "$screenshot_hash" "$app_version" "$app_build" <<'PY'
import json
import sys

destination, results, commit, device_class, viewport, os_version, observer, competence, started, completed, bundle, screenshot, version, build = sys.argv[1:]
tests = []
for line in open(results, encoding="utf-8"):
    test_id, outcome = line.rstrip("\n").split("=", 1)
    tests.append({"id": test_id, "outcome": outcome})
value = {
    "schema_version": 1,
    "label": "DEVICE-SIGNED OBSERVATIONS - INDEPENDENT REVIEW REQUIRED",
    "commit": commit,
    "candidate": "dioxus-diagnostic",
    "device": {"class": device_class, "viewport": viewport, "os": os_version},
    "application": {"bundle_id": "app.tersa.dioxus-spike.ios", "version": version, "build": build, "app_bundle_sha256": bundle, "signature": "verified", "entitlements": "verified", "installation": "verified", "launch": "verified-running", "launch_arguments": ["--tersa-device-evidence"], "evidence_screen": "observer-confirmed", "displayed_commit": commit},
    "capture": {"started_at": started, "completed_at": completed, "observer_record_id": observer, "observer_competence": competence, "screenshot": "device-redacted.png", "screenshot_sha256": screenshot, "redaction": "solid-black-status-and-home-bands"},
    "tests": tests,
}
open(destination, "w", encoding="utf-8").write(json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n")
PY

python3 apple/scripts/verify-dioxus-device-evidence.py "$staged_output" "$head"
printf '%s\n' 'DEVICE-SIGNED OBSERVATIONS - INDEPENDENT REVIEW REQUIRED' 'NO GATE STATUS WAS CHANGED' >"${staged_output}/result.txt"
python3 scripts/write-evidence-manifest.py "$staged_output" "$head" >/dev/null
mkdir -p "${apple_dir}/build"
mkdir "$output" || { echo 'Evidence output appeared concurrently; nothing was overwritten.' >&2; exit 1; }
cp "$staged_output"/* "$output"/ || { echo 'Evidence publication was incomplete; remove it explicitly before retrying.' >&2; exit 1; }
printf '%s\n' 'Evidence written to apple/build/dioxus-device-evidence. Independent review is required before any gate update.'
