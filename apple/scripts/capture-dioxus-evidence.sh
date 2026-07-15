#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Captures reproducible launch, transport, sandbox, and screenshot evidence for
# the Dioxus diagnostic packages.
set -eu

apple_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
build_dir="${apple_dir}/build/dioxus-evidence"
mac_home="${build_dir}/macos-home"
window_finder="${apple_dir}/build/find-process-window"
mac_app="${apple_dir}/build/TersaDioxusMac.xcarchive/Products/Applications/Tersa Dioxus Spike.app"
mac_sandbox_app="${build_dir}/Tersa Dioxus Spike Sandbox.app"
ios_app="${apple_dir}/build/DerivedDataDioxus/Build/Products/Release-iphonesimulator/Tersa Dioxus Spike.app"
rm -rf "$build_dir"
mkdir -p "$build_dir" "$mac_home"

mac_pid=''
device=''
sandbox_container=''
readonly sandbox_probe_bundle_identifier='app.tersa.dioxus-spike.mac'

cleanup() {
  if [ -n "$mac_pid" ] && kill -0 "$mac_pid" 2>/dev/null; then
    kill "$mac_pid" 2>/dev/null || true
    wait "$mac_pid" 2>/dev/null || true
  fi
  if [ -n "$device" ]; then
    xcrun simctl terminate "$device" app.tersa.dioxus-spike.ios 2>/dev/null || true
  fi
}

trap cleanup EXIT HUP INT TERM

mac_unsigned_binary="${mac_app}/Contents/MacOS/tersa-dioxus-spike"
mac_entitlements="${apple_dir}/dioxus-macos/TersaDioxusMac.entitlements"
ios_archive_app="${apple_dir}/build/TersaDioxusIOS.xcarchive/Products/Applications/Tersa Dioxus Spike.app"
ios_archive_binary="${ios_archive_app}/tersa-dioxus-spike"

require_no_devtools_strings() {
  binary="$1"
  strings_output=$(mktemp "${build_dir}/release-strings.XXXXXX")
  if ! strings -a "$binary" > "$strings_output"; then
    rm -f "$strings_output"
    echo "Could not inspect Release Dioxus binary strings: $binary" >&2
    return 1
  fi
  for forbidden_devtools_string in \
    'dioxus-toggle-dev-tools' \
    'Toggle Developer Tools' \
    'developerExtrasEnabled' \
    '_inspector'; do
    if grep -F -- "$forbidden_devtools_string" "$strings_output" >/dev/null 2>&1; then
      rm -f "$strings_output"
      echo "Release Dioxus binary contains forbidden devtools string '$forbidden_devtools_string': $binary" >&2
      return 1
    fi
  done
  rm -f "$strings_output"
}

test -x "$mac_unsigned_binary"
test -x "${ios_app}/tersa-dioxus-spike"
test -x "$ios_archive_binary"
file "$mac_unsigned_binary" | grep -F 'arm64'
file "${ios_app}/tersa-dioxus-spike" | grep -F 'arm64'
file "$ios_archive_binary" | grep -F 'arm64'
otool -L "$mac_unsigned_binary" | grep -F 'WebKit.framework'
otool -L "${ios_app}/tersa-dioxus-spike" | grep -F 'WebKit.framework'
otool -L "$ios_archive_binary" | grep -F 'WebKit.framework'
strings -a "$mac_unsigned_binary" | grep -F 'TERSA-DIOXUS-M0-THREAD'
strings -a "${ios_app}/tersa-dioxus-spike" | grep -F 'TERSA-DIOXUS-M0-THREAD'
strings -a "$ios_archive_binary" | grep -F 'TERSA-DIOXUS-M0-THREAD'
require_no_devtools_strings "$mac_unsigned_binary"
require_no_devtools_strings "${ios_app}/tersa-dioxus-spike"
require_no_devtools_strings "$ios_archive_binary"

python3 "${apple_dir}/scripts/verify-dioxus-runtime.py"

ditto "$mac_app" "$mac_sandbox_app"
codesign --force --sign - --entitlements "$mac_entitlements" "$mac_sandbox_app"
mac_binary="${mac_sandbox_app}/Contents/MacOS/tersa-dioxus-spike"
codesign -d --entitlements :- "$mac_binary" > "${build_dir}/sandbox-entitlements.plist" 2>/dev/null
python3 - "${build_dir}/sandbox-entitlements.plist" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as entitlement_file:
    actual = plistlib.load(entitlement_file)
expected = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.network.client": True,
    "com.apple.security.network.server": True,
}
if actual != expected:
    raise SystemExit(f"Sandbox entitlements differ from the exact allowlist: {actual!r}")
PY

cat > "${build_dir}/sandbox-write-probe.c" <<'C'
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    int descriptor = open(argv[1], O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (descriptor < 0) return 73;
    if (write(descriptor, "sandbox-probe\n", 14) != 14) return 74;
    return close(descriptor) == 0 ? 0 : 74;
}
C
cc "${build_dir}/sandbox-write-probe.c" -o "${build_dir}/sandbox-write-probe-unsandboxed"
probe_app="${build_dir}/Sandbox Write Probe.app"
probe_binary="${probe_app}/Contents/MacOS/sandbox-write-probe"
mkdir -p "${probe_app}/Contents/MacOS"
cp "${build_dir}/sandbox-write-probe-unsandboxed" "$probe_binary"
cp "${mac_sandbox_app}/Contents/Info.plist" "${probe_app}/Contents/Info.plist"
plutil -replace CFBundleIdentifier -string app.tersa.sandbox-write-probe \
  "${probe_app}/Contents/Info.plist"
plutil -replace CFBundleExecutable -string sandbox-write-probe \
  "${probe_app}/Contents/Info.plist"
codesign --force --sign - --entitlements "$mac_entitlements" \
  "$probe_app"

mac_notice_source="${apple_dir}/licenses/THIRD_PARTY_NOTICES-dioxus-macos.txt"
ios_notice_source="${apple_dir}/licenses/THIRD_PARTY_NOTICES-dioxus-ios.txt"
cmp "$mac_notice_source" "${mac_app}/Contents/Resources/THIRD_PARTY_NOTICES-dioxus-macos.txt"
cmp "$ios_notice_source" "${ios_app}/THIRD_PARTY_NOTICES-dioxus-ios.txt"
cmp "$ios_notice_source" "${ios_archive_app}/THIRD_PARTY_NOTICES-dioxus-ios.txt"
grep -F -- '- dioxus 0.7.9:' "$mac_notice_source"
grep -F -- '- dioxus-desktop 0.7.9:' "$mac_notice_source"
grep -F -- '- dioxus 0.7.9:' "$ios_notice_source"
grep -F -- '- dioxus-desktop 0.7.9:' "$ios_notice_source"

now_ns() {
  python3 -c 'import time; print(time.monotonic_ns())'
}

recognize_text() {
  image_path="$1"
  xcrun swift - "$image_path" <<'SWIFT'
import AppKit
import Vision

let path = CommandLine.arguments[1]
guard let image = NSImage(contentsOfFile: path) else {
    fatalError("Cannot load screenshot at \(path)")
}
var proposedRect = NSRect(origin: .zero, size: image.size)
guard let cgImage = image.cgImage(forProposedRect: &proposedRect, context: nil, hints: nil) else {
    fatalError("Cannot create a CGImage for \(path)")
}
let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesLanguageCorrection = false
try VNImageRequestHandler(cgImage: cgImage).perform([request])
for observation in request.results ?? [] {
    if let candidate = observation.topCandidates(1).first {
        print(candidate.string)
    }
}
SWIFT
}

capture_mac_until_text() {
  image_path="$1"
  ocr_path="$2"
  expected_pattern="$3"
  maximum_attempts="$4"
  attempts=0
  while :; do
    attempts=$((attempts + 1))
    if screencapture -x -l "$mac_window" "$image_path" \
      && recognize_text "$image_path" > "$ocr_path"; then
      if grep -E "$expected_pattern" "$ocr_path" >/dev/null 2>&1; then
        return 0
      fi
    fi
    if [ "$attempts" -ge "$maximum_attempts" ]; then
      echo "Timed out waiting for macOS Dioxus evidence: $expected_pattern" >&2
      return 1
    fi
    sleep 0.5
  done
}

xcrun swiftc "${apple_dir}/scripts/find-process-window.swift" -o "$window_finder"

verify_virtualization_ocr() {
  ocr_file="$1"
  dom_rows=$(sed -nE '/ACTUAL/!s/.*DOM ROWS[^0-9]*([0-9]+).*/\1/p' "$ocr_file" | head -n 1)
  actual_rows=$(sed -nE 's/.*ACTUAL DOM ROWS[^0-9]*([0-9]+).*/\1/p' "$ocr_file" | head -n 1)
  first_row=$(sed -nE 's/.*FIRST ROW[^0-9]*([0-9]+).*/\1/p' "$ocr_file" | head -n 1)
  test -n "$dom_rows"
  test -n "$actual_rows"
  test -n "$first_row"
  test "$dom_rows" -gt 0
  test "$actual_rows" -gt 0
  test "$dom_rows" -eq "$actual_rows"
  test "$dom_rows" -le 100
  test "$actual_rows" -le 100
  printf '%s %s\n' "$dom_rows" "$first_row"
}

find_mac_window() {
  process_id="$1"
  "$window_finder" "$process_id"
}

wait_for_mac_window() {
  attempts=0
  mac_window=''
  while [ -z "$mac_window" ]; do
    attempts=$((attempts + 1))
    test "$attempts" -lt 150
    mac_window=$(find_mac_window "$mac_pid")
    if ! kill -0 "$mac_pid" 2>/dev/null; then
      echo "macOS Dioxus process exited before presenting a window" >&2
      return 1
    fi
    sleep 0.1
  done
}

verify_loopback_listener() {
  process_id="$1"
  output_file="$2"
  attempts=0
  : > "$output_file"
  while ! grep -F '127.0.0.1:' "$output_file" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    test "$attempts" -lt 100
    lsof -nP -a -p "$process_id" -iTCP -sTCP:LISTEN > "$output_file" 2>/dev/null || true
    sleep 0.1
  done
  grep -F '127.0.0.1:' "$output_file"
  if ! awk 'NR > 1 && $9 !~ /^127[.]0[.]0[.]1:[0-9]+$/ { exit 1 }' "$output_file"; then
    echo "Dioxus opened a non-loopback TCP listener" >&2
    return 1
  fi
}

wait_for_exact_log_line() {
  expected_line="$1"
  log_file="$2"
  attempts=0
  while ! grep -Fx "$expected_line" "$log_file" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 250 ]; then
      echo "Timed out waiting for process evidence: $expected_line" >&2
      return 1
    fi
    sleep 0.1
  done
}

start_mac() {
  evidence_mode="$1"
  relaunch_mode="${2:-0}"
  process_log="${3:-macos-process.log}"
  listener_log="${4:-macos-listeners.txt}"
  launch_binary="$mac_binary"
  if [ "$evidence_mode" -eq 1 ]; then
    launch_binary="$mac_unsigned_binary"
    if [ "$relaunch_mode" -eq 1 ]; then
      HOME="$mac_home" TERSA_DIOXUS_EVIDENCE=1 TERSA_DIOXUS_RELAUNCH=1 \
        "$launch_binary" -ApplePersistenceIgnoreState YES >"${build_dir}/${process_log}" 2>&1 &
    else
      HOME="$mac_home" TERSA_DIOXUS_EVIDENCE=1 \
        "$launch_binary" -ApplePersistenceIgnoreState YES \
        >"${build_dir}/${process_log}" 2>&1 &
    fi
  else
    "$launch_binary" -ApplePersistenceIgnoreState YES >"${build_dir}/${process_log}" 2>&1 &
  fi
  mac_pid=$!
  wait_for_mac_window
  verify_loopback_listener "$mac_pid" "${build_dir}/${listener_log}"
}

prepare_sandbox_probe_container() {
  bundle_identifier=$(plutil -extract CFBundleIdentifier raw \
    "${mac_sandbox_app}/Contents/Info.plist")
  if [ "$bundle_identifier" != "$sandbox_probe_bundle_identifier" ]; then
    echo "Unexpected Dioxus sandbox probe bundle identifier: $bundle_identifier" >&2
    return 1
  fi
  sandbox_container="${HOME}/Library/Containers/${bundle_identifier}"
  rm -rf -- "$sandbox_container"
}

record_sandbox_webkit_directories() {
  output_file="$1"
  : > "$output_file"
  if [ -d "${sandbox_container}/Data" ]; then
    (
      cd "${sandbox_container}/Data"
      find . -type d \( -name WebKit -o -name WebsiteData \) -print
    ) > "$output_file"
  fi
}

start_sandbox_probe() {
  probe="$1"
  process_log="$2"
  listener_log="$3"
  prepare_sandbox_probe_container
  HOME="$HOME" TERSA_DIOXUS_EVIDENCE=1 TERSA_DIOXUS_SANDBOX_PROBE="$probe" \
    "$mac_binary" -ApplePersistenceIgnoreState YES \
    >"${build_dir}/${process_log}" 2>&1 &
  mac_pid=$!
  wait_for_mac_window
  verify_loopback_listener "$mac_pid" "${build_dir}/${listener_log}"
}

capture_sandbox_probe() {
  probe="$1"
  upper_probe=$(printf '%s' "$probe" | tr '[:lower:]' '[:upper:]')
  denial_url="$2"
  probe_dir="${build_dir}/sandbox-probe-${probe}"
  mkdir -p "$probe_dir"
  start_sandbox_probe "$probe" "sandbox-probe-${probe}.log" \
    "sandbox-probe-${probe}-listeners.txt"
  process_log="${build_dir}/sandbox-probe-${probe}.log"
  listener_log="${build_dir}/sandbox-probe-${probe}-listeners.txt"

  capture_mac_until_text "$probe_dir/armed.png" "$probe_dir/armed-ocr.txt" \
    "SANDBOX PROBE ${upper_probe} ARMED" 60
  test "$(stat -f '%z' "$probe_dir/armed.png")" -gt 10000
  if ! kill -0 "$mac_pid" 2>/dev/null; then
    echo "Sandbox probe ${probe} exited before its action" >&2
    return 1
  fi
  sleep 12
  wait_for_exact_log_line "TERSA-DIOXUS-NAV-DENIED ${denial_url}" "$process_log"
  if ! kill -0 "$mac_pid" 2>/dev/null; then
    echo "Sandbox probe ${probe} exited before final classification" >&2
    return 1
  fi
  screencapture -x -l "$mac_window" "$probe_dir/final.png"
  test "$(stat -f '%z' "$probe_dir/final.png")" -gt 10000
  recognize_text "$probe_dir/final.png" > "$probe_dir/final-ocr.txt"
  verify_loopback_listener "$mac_pid" "$listener_log"
  record_sandbox_webkit_directories "$probe_dir/container-webkit-directories.txt"

  has_thread_marker=0
  if grep -E 'TERSA-DIOXUS-M[0O]-THREAD' "$probe_dir/final-ocr.txt" >/dev/null 2>&1; then
    has_thread_marker=1
  fi
  has_inbox_marker=0
  if grep -E '10.?000' "$probe_dir/final-ocr.txt" >/dev/null 2>&1; then
    has_inbox_marker=1
  fi
  fired=0
  if grep -F "SANDBOX PROBE ${upper_probe} FIRED" "$probe_dir/final-ocr.txt" >/dev/null 2>&1; then
    fired=1
  fi

  if [ "$has_thread_marker" -eq 1 ] && [ "$has_inbox_marker" -eq 1 ] \
    && [ "$fired" -eq 1 ]; then
    printf '%s\n' RENDERED_PRESERVED > "$probe_dir/outcome.txt"
  elif [ "$has_thread_marker" -eq 0 ] && [ "$has_inbox_marker" -eq 0 ]; then
    printf '%s\n' BLANK_AFTER_DENIAL > "$probe_dir/outcome.txt"
  else
    echo "Sandbox probe ${probe} has ambiguous final OCR" >&2
    return 1
  fi
  stop_mac
}

verify_sandbox_enforcement() {
  probe_path="${build_dir}/outside-sandbox-write-probe"
  rm -f "$probe_path"
  python3 - "$probe_binary" \
    "${build_dir}/sandbox-write-probe-unsandboxed" "$probe_path" <<'PY'
import pathlib
import subprocess
import sys

sandboxed, unsandboxed, destination = sys.argv[1:]
sandboxed_result = subprocess.run(
    [sandboxed, destination], capture_output=True, check=False
)
if sandboxed_result.returncode != 73:
    raise SystemExit(
        "The sandboxed write canary did not reach the expected denied open: "
        f"returncode={sandboxed_result.returncode}, "
        f"stdout={sandboxed_result.stdout!r}, stderr={sandboxed_result.stderr!r}"
    )
path = pathlib.Path(destination)
if path.exists():
    raise SystemExit("The sandboxed write canary left an outside-container file")
subprocess.run([unsandboxed, destination], check=True)
if not path.is_file():
    raise SystemExit("The unsandboxed write control did not create its output")
PY
  printf '%s\n' \
    'Sandboxed bundled write canary: denied outside-container create with exit 73.' \
    'Unsandboxed write control: outside-container create succeeded.' \
    > "${build_dir}/sandbox-enforcement.txt"
  rm -f "$probe_path"
}

stop_mac() {
  kill "$mac_pid"
  attempts=0
  while kill -0 "$mac_pid" 2>/dev/null; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 100 ]; then
      kill -KILL "$mac_pid" 2>/dev/null || true
      break
    fi
    sleep 0.1
  done
  wait "$mac_pid" 2>/dev/null || true
  mac_pid=''
}

mac_cold_start=$(now_ns)
start_mac 0 0 macos-process.log macos-sandbox-listeners.txt
mac_cold_end=$(now_ns)
verify_sandbox_enforcement
capture_mac_until_text \
  "${build_dir}/macos-initial.png" \
  "${build_dir}/macos-initial-ocr.txt" \
  'ACTUAL DOM ROWS [0-9]+' \
  30
test "$(stat -f '%z' "${build_dir}/macos-initial.png")" -gt 10000
grep -E 'TERSA-DIOXUS-M[0O]-THREAD' "${build_dir}/macos-initial-ocr.txt"
grep -E '10.?000' "${build_dir}/macos-initial-ocr.txt"
virtualization=$(verify_virtualization_ocr "${build_dir}/macos-initial-ocr.txt")
first_row=${virtualization#* }
test "$first_row" -eq 0
stop_mac
sleep 1

mac_warm_start=$(now_ns)
start_mac 0 0 macos-warm-process.log macos-sandbox-warm-listeners.txt
mac_warm_end=$(now_ns)
sleep 2
stop_mac
sleep 1

start_mac 1 0 macos-navigation-process.log macos-navigation-listeners.txt
capture_mac_until_text \
  "${build_dir}/macos.png" \
  "${build_dir}/macos-ocr.txt" \
  'LOCAL STORAGE (WRITTEN|WRITE FAILED)' \
  40
test "$(stat -f '%z' "${build_dir}/macos.png")" -gt 10000
grep -E 'TERSA-DIOXUS-M[0O]-THREAD' "${build_dir}/macos-ocr.txt"
grep -E '10.?000' "${build_dir}/macos-ocr.txt"
grep -F 'TERSA DIOXUS INPUT ONE' "${build_dir}/macos-ocr.txt"
grep -F 'TERSA DIOXUS INPUT TWO' "${build_dir}/macos-ocr.txt"
grep -E '45 characters' "${build_dir}/macos-ocr.txt"
grep -F 'NAVIGATION PROBE PAGE UNCHANGED' "${build_dir}/macos-ocr.txt"
grep -F 'LOCAL STORAGE WRITTEN' "${build_dir}/macos-ocr.txt"
grep -F 'COOKIE API UNAVAILABLE ON DIOXUS SCHEME' "${build_dir}/macos-ocr.txt"
grep -F 'WINDOW OPEN REJECTED' "${build_dir}/macos-ocr.txt"
wait_for_exact_log_line \
  'TERSA-DIOXUS-NAV-DENIED https://example.invalid/anchor' \
  "${build_dir}/macos-navigation-process.log"
wait_for_exact_log_line \
  'TERSA-DIOXUS-NAV-DENIED https://example.invalid/ipc-browser-open' \
  "${build_dir}/macos-navigation-process.log"
wait_for_exact_log_line \
  'TERSA-DIOXUS-NAV-DENIED https://example.invalid/location' \
  "${build_dir}/macos-navigation-process.log"
virtualization=$(verify_virtualization_ocr "${build_dir}/macos-ocr.txt")
first_row=${virtualization#* }
test "$first_row" -gt 0
verify_loopback_listener "$mac_pid" "${build_dir}/macos-navigation-listeners.txt"
stop_mac

capture_sandbox_probe anchor 'https://example.invalid/anchor'
capture_sandbox_probe ipc 'https://example.invalid/ipc-browser-open'
capture_sandbox_probe location 'https://example.invalid/location'

start_mac 1 1 macos-relaunch-process.log macos-relaunch-listeners.txt
capture_mac_until_text \
  "${build_dir}/macos-relaunch.png" \
  "${build_dir}/macos-relaunch-ocr.txt" \
  'LOCAL STORAGE (ABSENT|PRESENT) AFTER RELAUNCH' \
  30
grep -F 'LOCAL STORAGE ABSENT AFTER RELAUNCH' "${build_dir}/macos-relaunch-ocr.txt"
grep -F 'COOKIE API UNAVAILABLE ON DIOXUS SCHEME' "${build_dir}/macos-relaunch-ocr.txt"
stop_mac

if find "$mac_home" -type d \( -name WebKit -o -name WebsiteData \) -print -quit | grep -q .; then
  echo "Incognito Dioxus diagnostic created a WebKit data directory below its isolated HOME" >&2
  exit 1
fi

device=$(xcrun simctl list devices available \
  | awk -F '[()]' '/iPhone (1[5-9].*Pro|Air)/ { print $2; exit }')
if [ -z "$device" ]; then
  device=$(xcrun simctl list devices available \
    | awk -F '[()]' '/iPhone (1[5-9]|Air)/ { print $2; exit }')
fi
test -n "$device"
xcrun simctl boot "$device" 2>/dev/null || true
xcrun simctl bootstatus "$device" -b
xcrun simctl install "$device" "$ios_app"
ios_cold_start=$(now_ns)
ios_launch=$(SIMCTL_CHILD_TERSA_DIOXUS_EVIDENCE=1 xcrun simctl launch \
  --stdout="${build_dir}/ios-process-stdout.log" \
  --stderr="${build_dir}/ios-process-stderr.log" \
  "$device" app.tersa.dioxus-spike.ios)
ios_cold_end=$(now_ns)
ios_pid=$(printf '%s\n' "$ios_launch" | awk -F ': ' 'NF == 2 { print $2 }')
test -n "$ios_pid"
verify_loopback_listener "$ios_pid" "${build_dir}/ios-simulator-listeners.txt"
sleep 7
xcrun simctl launch "$device" com.apple.Preferences
sleep 2
grep -F 'TERSA-DIOXUS-LIFECYCLE suspended' "${build_dir}/ios-process-stderr.log"
xcrun simctl launch "$device" app.tersa.dioxus-spike.ios
sleep 2
xcrun simctl io "$device" screenshot "${build_dir}/ios-simulator.png"
test "$(grep -c 'TERSA-DIOXUS-LIFECYCLE resumed' "${build_dir}/ios-process-stderr.log")" -ge 2
test "$(stat -f '%z' "${build_dir}/ios-simulator.png")" -gt 10000
recognize_text "${build_dir}/ios-simulator.png" > "${build_dir}/ios-simulator-ocr.txt"
grep -F 'TERSA' "${build_dir}/ios-simulator-ocr.txt"
grep -E '10.?000' "${build_dir}/ios-simulator-ocr.txt"
grep -E 'SAFE TOP[^0-9]*([4-9][0-9]|[1-9][0-9]{2,})' \
  "${build_dir}/ios-simulator-ocr.txt"
virtualization=$(verify_virtualization_ocr "${build_dir}/ios-simulator-ocr.txt")
first_row=${virtualization#* }
test "$first_row" -gt 0
verify_loopback_listener "$ios_pid" "${build_dir}/ios-simulator-listeners.txt"
xcrun simctl terminate "$device" app.tersa.dioxus-spike.ios

unsigned_release_size=$(stat -f '%z' "$mac_unsigned_binary")
printf '{"mac_sandboxed_cold_harness_ready_ns":%s,"mac_sandboxed_warm_harness_ready_ns":%s,"ios_cold_launch_command_ns":%s,"mac_unsigned_release_binary_bytes":%s,"synthetic_rows":10000}\n' \
  "$((mac_cold_end - mac_cold_start))" "$((mac_warm_end - mac_warm_start))" \
  "$((ios_cold_end - ios_cold_start))" "$unsigned_release_size" \
  > "${build_dir}/metrics.json"

printf '%s\n' \
  'Physical-device gates remain open: IME composition, autocorrect, dictation,' \
  'selection, copy and paste, hardware keyboard, VoiceOver traversal, Dynamic Type,' \
  'Full Keyboard Access, safe-area rotations, lifecycle edge cases, memory warning,' \
  'protected data, energy, memory, and signed TestFlight/App Review behavior.' \
  > "${build_dir}/physical-device-gaps.txt"

printf '%s\n' \
  'The sandboxed macOS host copy verifies stable UI markers, a loopback-only' \
  'listener, an exact entitlement allowlist, and a denied bundled write canary' \
  'with a successful unsandboxed control.' \
  'The separate unsigned macOS host probe verifies a localStorage write,' \
  'location stability,' \
  'anchor navigation and injected browser_open IPC denial markers while the' \
  'page remains rendered, plus a later direct-location denial marker and a' \
  'rejected window.open,' \
  'localStorage absence after relaunch, and' \
  'the absence of WebKit or WebsiteData directories below an isolated HOME.' \
  'The dioxus:// custom scheme exposes no usable document.cookie API, so this' \
  'probe cannot make or verify a cookie-persistence claim.' \
  'The direct-location marker does not claim that WebKit preserves the rendered' \
  'page after cancellation; that behavior remains a device-signed gate.' \
  'Navigation and WebKit storage are not exercised as sandboxed claims.' \
  'It cannot enumerate every operating-system WebKit cache surface, prove zero' \
  'in-memory state, or establish physical-device or signed-distribution behavior.' \
  > "${build_dir}/ephemeral-navigation-limitations.txt"
