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
transport_output="${evidence_dir}/transport-control.json"
native_stderr="${staging_dir}/native.stderr"
canary_stderr="${staging_dir}/canary.stderr"
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
  rm -f "$native_stderr" "$canary_stderr" "$listener_output" "$port_file"
}
trap cleanup EXIT HUP INT TERM

test -x "$rust_binary"
test -x "$executable"

"$rust_binary" > "$rust_output"
grep -Fx 'mime_spike.accepted=4' "$rust_output"
grep -Fx 'mime_spike.rejected=13' "$rust_output"
grep -Fx 'mime_spike.output_hash=4a831df98f8213a0' "$rust_output"
grep -Fx 'NOT A DEVICE-GATE RESULT' "$rust_output"

"$rust_binary" --export-sanitized-html "${staging_dir}/sanitized.html"
test -s "${staging_dir}/sanitized.html"
if grep -Eiq 'script|https?:|javascript:|data:|file:|src=|href=' \
  "${staging_dir}/sanitized.html"; then
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

python3 - "${application}/Contents/Info.plist" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as source:
    information = plistlib.load(source)
expected = {"NSAllowsArbitraryLoadsInWebContent": True}
if information.get("NSAppTransportSecurity") != expected:
    raise SystemExit("the MIME diagnostic is missing its exact WebKit transport-control exception")
PY

python3 -u "${script_dir}/mime-canary.py" --port-file "$port_file" \
  2> "$canary_stderr" &
canary_pid=$!
attempt=0
while [ ! -s "$port_file" ]; do
  if ! kill -0 "$canary_pid" 2>/dev/null; then
    cat "$canary_stderr" >&2
    echo 'The MIME canary terminated before becoming ready.' >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    echo 'The MIME canary did not start.' >&2
    exit 1
  fi
  sleep 0.05
done
port=$(cat "$port_file")

TERSA_MIME_CANARY_PORT="$port" \
  TERSA_MIME_RUN_MODE='transport-control' \
  "$executable" > "$transport_output" 2> "$native_stderr" &
app_pid=$!
sleep 0.5
if kill -0 "$app_pid" 2>/dev/null; then
  lsof -nP -a -p "$app_pid" -iTCP -sTCP:LISTEN > "$listener_output" || true
  if [ -s "$listener_output" ]; then
    echo 'The MIME transport control opened a TCP listener.' >&2
    exit 1
  fi
fi
attempt=0
while kill -0 "$app_pid" 2>/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ]; then
    echo 'The native MIME transport control did not terminate.' >&2
    exit 1
  fi
  sleep 0.05
done
if ! wait "$app_pid"; then
  echo 'The native MIME transport control exited unsuccessfully.' >&2
  exit 1
fi
app_pid=''

transport_count=$(curl --fail --silent --show-error \
  "http://127.0.0.1:${port}/control/count" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
test "$transport_count" -eq 1
python3 - "$transport_output" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    evidence = json.load(source)
expected_true = [
    "dataStoreIsNonPersistent",
    "initialNavigationAllowed",
    "javaScriptDisabled",
    "probeCompleted",
    "transportControlLoaded",
]
for key in expected_true:
    if evidence.get(key) is not True:
        raise SystemExit(f"native MIME transport evidence did not prove {key}")
if evidence.get("contentRuleListAttached") is not False:
    raise SystemExit("the transport control unexpectedly attached the content blocker")
if evidence.get("failureCount") != 0:
    raise SystemExit("native MIME transport evidence reported a failure")
if evidence.get("navigationResponsesDenied", 0) < 1:
    raise SystemExit("native MIME evidence did not exercise response denial")
if evidence.get("runMode") != "transport-control":
    raise SystemExit("native MIME transport evidence has the wrong run mode")
if evidence.get("label") != "NOT A DEVICE-GATE RESULT":
    raise SystemExit("native MIME transport evidence is missing the host-only label")
PY
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
expected_raw_hash=$(python3 - "$port" <<'PY'
import hashlib
import sys

base = f"http://127.0.0.1:{sys.argv[1]}"
document = f'''<!doctype html><html><head><meta charset="utf-8"><title>RAW_CONTROL</title><meta http-equiv="refresh" content="0;url={base}/navigation"><link rel="stylesheet" href="{base}/style.css"><script src="{base}/script.js"></script></head><body onload="document.title='JAVASCRIPT_EXECUTED';fetch('{base}/inline-js');window.open('{base}/new-window');location='{base}/inline-navigation'"><img src="{base}/image.png"><form action="{base}/form" method="post" target="_blank"><button type="submit">Submit</button></form><script>document.forms[0].submit();</script></body></html>'''
print(hashlib.sha256(document.encode("utf-8")).hexdigest())
PY
)
python3 - "$native_output" "$expected_safe_hash" "$expected_raw_hash" <<'PY'
import json
import sys

path, expected_safe_hash, expected_raw_hash = sys.argv[1:]
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
if evidence.get("newWindowsDenied", 0) < 1:
    raise SystemExit("native MIME evidence did not exercise new-window denial")
if evidence.get("websiteDataRecordCount") != 0:
    raise SystemExit("the nonpersistent WKWebsiteDataStore retained website records")
if evidence.get("label") != "NOT A DEVICE-GATE RESULT":
    raise SystemExit("native MIME evidence is missing the host-only label")
if evidence.get("sanitizedDocumentHash") != expected_safe_hash:
    raise SystemExit("WKWebView did not load the Rust-sanitized fixture")
if evidence.get("rawControlHash") != expected_raw_hash:
    raise SystemExit("native MIME evidence has the wrong raw-control hash")
if evidence.get("runMode") != "protected":
    raise SystemExit("native MIME evidence has the wrong protected run mode")
if evidence.get("transportControlLoaded") is not False:
    raise SystemExit("protected MIME evidence was contaminated by the transport control")
PY

if grep -Eiq 'inline-js|image\.png|script\.js|style\.css|127\.0\.0\.1|http://' \
  "$native_output" "$transport_output" "$rust_output"; then
  echo 'MIME evidence contains hostile input or a canary address.' >&2
  exit 1
fi

{
  printf '%s\n' 'MIME and HTML M0 feasibility PASS'
  printf '%s\n' 'portable_corpus_accepted=4'
  printf '%s\n' 'portable_corpus_rejected=13'
  printf '%s\n' 'native_transport_control_hits=1'
  printf '%s\n' 'native_canary_hits=0'
  printf '%s\n' 'native_tcp_listeners=0'
  printf '%s\n' 'native_website_data_records=0'
  printf '%s\n' 'NOT A DEVICE-GATE RESULT'
} > "${evidence_dir}/result.txt"

rm -f "${staging_dir}/sanitized.html" "${staging_dir}/entitlements.plist"
printf '%s\n' 'MIME and HTML feasibility evidence passed.'
