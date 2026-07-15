#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Verifies the bounded portable MIME policy and macOS-host WKWebView controls.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
apple_dir=$(CDPATH='' cd -- "${script_dir}/.." && pwd)
workspace_dir=$(CDPATH='' cd -- "${apple_dir}/.." && pwd)
evidence_dir="${apple_dir}/build/mime-evidence"
staging_dir="${apple_dir}/build/mime-staging"
archive="${apple_dir}/build/TersaMimeMac.xcarchive"
application="${archive}/Products/Applications/Tersa MIME Spike.app"
executable="${application}/Contents/MacOS/tersa-mime-native-spike"
resource="${application}/Contents/Resources/sanitized.html"
rust_binary="${workspace_dir}/target/aarch64-apple-darwin/release/tersa-mime-spike"
port_file="${staging_dir}/canary-port"
native_output="${evidence_dir}/native.json"
native_stderr="${staging_dir}/native.stderr"
rust_output="${evidence_dir}/portable.txt"
listener_output="${staging_dir}/listeners.txt"

rm -rf "$evidence_dir" "$staging_dir"
mkdir -p "$evidence_dir" "$staging_dir"

canary_pid=''
app_pid=''
cleanup() {
  if [ -n "$app_pid" ] && kill -0 "$app_pid" 2>/dev/null; then
    kill "$app_pid" 2>/dev/null || true
  fi
  if [ -n "$canary_pid" ] && kill -0 "$canary_pid" 2>/dev/null; then
    kill "$canary_pid" 2>/dev/null || true
  fi
  rm -f "$native_stderr" "$listener_output" "$port_file"
}
trap cleanup EXIT HUP INT TERM

test -x "$rust_binary"
test -x "$executable"

"$rust_binary" > "$rust_output"
grep -Fx 'mime_spike.accepted=4' "$rust_output"
grep -Fx 'mime_spike.rejected=6' "$rust_output"
grep -Eq '^mime_spike.output_hash=[0-9a-f]{16}$' "$rust_output"
grep -Fx 'NOT A DEVICE-GATE RESULT' "$rust_output"

"$rust_binary" --export-sanitized-html "${staging_dir}/sanitized.html"
test -s "${staging_dir}/sanitized.html"
if rg -i 'script|https?:|javascript:|data:|file:|src=|href=' "${staging_dir}/sanitized.html"; then
  echo 'The exported sanitized fixture contains active or remote content.' >&2
  exit 1
fi
mkdir -p "$(dirname "$resource")"
cp "${staging_dir}/sanitized.html" "$resource"

codesign --force --deep --sign - \
  --entitlements "${apple_dir}/mime-macos/TersaMimeMac.entitlements" \
  "$application"
codesign --verify --deep --strict "$application"
codesign -d --entitlements :- "$application" \
  > "${staging_dir}/entitlements.plist" 2>/dev/null
python3 - "${staging_dir}/entitlements.plist" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as source:
    entitlements = plistlib.load(source)
expected = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.network.client": True,
}
if entitlements != expected:
    raise SystemExit("the MIME diagnostic has unexpected entitlements")
PY

python3 "${script_dir}/mime-canary.py" --port-file "$port_file" &
canary_pid=$!
attempt=0
while [ ! -s "$port_file" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    echo 'The MIME canary did not start.' >&2
    exit 1
  fi
  sleep 0.05
done
port=$(cat "$port_file")

curl --fail --silent --show-error "http://127.0.0.1:${port}/positive-control" >/dev/null
positive_count=$(curl --fail --silent --show-error \
  "http://127.0.0.1:${port}/control/count" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
test "$positive_count" -eq 1
curl --fail --silent --show-error "http://127.0.0.1:${port}/control/reset" >/dev/null

TERSA_MIME_CANARY_PORT="$port" "$executable" > "$native_output" 2> "$native_stderr" &
app_pid=$!
sleep 0.5
if kill -0 "$app_pid" 2>/dev/null; then
  lsof -nP -a -p "$app_pid" -iTCP -sTCP:LISTEN > "$listener_output" || true
  if [ -s "$listener_output" ]; then
    echo 'The MIME diagnostic opened a TCP listener.' >&2
    exit 1
  fi
fi

attempt=0
while kill -0 "$app_pid" 2>/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ]; then
    echo 'The native MIME diagnostic did not terminate.' >&2
    exit 1
  fi
  sleep 0.05
done
if ! wait "$app_pid"; then
  echo 'The native MIME diagnostic exited unsuccessfully.' >&2
  exit 1
fi
app_pid=''

canary_count=$(curl --fail --silent --show-error \
  "http://127.0.0.1:${port}/control/count" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
test "$canary_count" -eq 0

expected_safe_hash=$(shasum -a 256 "${staging_dir}/sanitized.html" | awk '{print $1}')
python3 - "$native_output" "$expected_safe_hash" <<'PY'
import json
import re
import sys

path, expected_safe_hash = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    evidence = json.load(source)

expected_true = [
    "contentRuleListAttached",
    "dataStoreIsNonPersistent",
    "initialNavigationAllowed",
    "javaScriptDisabled",
    "pageJavaScriptDidNotExecute",
    "probeCompleted",
    "rawControlLoaded",
    "sanitizedDocumentLoaded",
    "sanitizedResourceFound",
]
for key in expected_true:
    if evidence.get(key) is not True:
        raise SystemExit(f"native MIME evidence did not prove {key}")
if evidence.get("failureCount") != 0:
    raise SystemExit("native MIME evidence reported a failure")
if evidence.get("navigationActionsDenied", 0) < 1:
    raise SystemExit("native MIME evidence did not exercise navigation denial")
if evidence.get("websiteDataRecordCount") != 0:
    raise SystemExit("the nonpersistent WKWebsiteDataStore retained website records")
if evidence.get("label") != "NOT A DEVICE-GATE RESULT":
    raise SystemExit("native MIME evidence is missing the host-only label")
if evidence.get("sanitizedDocumentHash") != expected_safe_hash:
    raise SystemExit("WKWebView did not load the Rust-sanitized fixture")
if not re.fullmatch(r"[0-9a-f]{64}", evidence.get("rawControlHash", "")):
    raise SystemExit("native MIME evidence has an invalid raw-control hash")
PY

if rg -i 'inline-js|image\.png|script\.js|style\.css|127\.0\.0\.1|http://' \
  "$native_output" "$rust_output"; then
  echo 'MIME evidence contains hostile input or a canary address.' >&2
  exit 1
fi

{
  printf '%s\n' 'MIME and HTML M0 feasibility PASS'
  printf '%s\n' 'portable_corpus_accepted=4'
  printf '%s\n' 'portable_corpus_rejected=6'
  printf '%s\n' 'native_canary_hits=0'
  printf '%s\n' 'native_tcp_listeners=0'
  printf '%s\n' 'native_website_data_records=0'
  printf '%s\n' 'NOT A DEVICE-GATE RESULT'
} > "${evidence_dir}/result.txt"

rm -f "${staging_dir}/sanitized.html" "${staging_dir}/entitlements.plist"
printf '%s\n' 'MIME and HTML feasibility evidence passed.'
