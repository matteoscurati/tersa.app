#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Captures reproducible launch, transport, and screenshot evidence for the
# unsigned Dioxus diagnostic packages.
set -eu

apple_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
build_dir="${apple_dir}/build/dioxus-evidence"
mac_app="${apple_dir}/build/TersaDioxusMac.xcarchive/Products/Applications/Tersa Dioxus Spike.app"
ios_app="${apple_dir}/build/DerivedDataDioxus/Build/Products/Debug-iphonesimulator/Tersa Dioxus Spike.app"
mkdir -p "$build_dir"

mac_pid=''
device=''

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

mac_binary="${mac_app}/Contents/MacOS/tersa-dioxus-spike"
ios_archive_app="${apple_dir}/build/TersaDioxusIOS.xcarchive/Products/Applications/Tersa Dioxus Spike.app"
ios_archive_binary="${ios_archive_app}/tersa-dioxus-spike"
test -x "$mac_binary"
test -x "$ios_archive_binary"
file "$mac_binary" | grep -F 'arm64'
file "$ios_archive_binary" | grep -F 'arm64'
otool -L "$mac_binary" | grep -F 'WebKit.framework'
otool -L "$ios_archive_binary" | grep -F 'WebKit.framework'
strings -a "$mac_binary" | grep -F 'TERSA-DIOXUS-M0-THREAD'
strings -a "$ios_archive_binary" | grep -F 'TERSA-DIOXUS-M0-THREAD'

python3 "${apple_dir}/scripts/verify-dioxus-runtime.py"

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

verify_virtualization_ocr() {
  ocr_file="$1"
  dom_rows=$(sed -nE 's/.*DOM ROWS[^0-9]*([0-9]+).*/\1/p' "$ocr_file" | head -n 1)
  first_row=$(sed -nE 's/.*FIRST ROW[^0-9]*([0-9]+).*/\1/p' "$ocr_file" | head -n 1)
  test -n "$dom_rows"
  test -n "$first_row"
  test "$dom_rows" -le 100
  printf '%s %s\n' "$dom_rows" "$first_row"
}

find_mac_window() {
  process_id="$1"
  xcrun swift - "$process_id" <<'SWIFT'
import CoreGraphics
import Foundation

let processIdentifier = Int32(CommandLine.arguments[1])!
let options: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
let windows = CGWindowListCopyWindowInfo(options, kCGNullWindowID) as? [[CFString: Any]] ?? []
for window in windows {
    let owner = (window[kCGWindowOwnerPID] as? NSNumber)?.int32Value
    let layer = (window[kCGWindowLayer] as? NSNumber)?.intValue
    let number = (window[kCGWindowNumber] as? NSNumber)?.intValue
    if owner == processIdentifier && layer == 0, let number {
        print(number)
        break
    }
}
SWIFT
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

start_mac() {
  TERSA_DIOXUS_EVIDENCE=1 "$mac_binary" >"${build_dir}/macos-process.log" 2>&1 &
  mac_pid=$!
  wait_for_mac_window
  verify_loopback_listener "$mac_pid" "${build_dir}/macos-listeners.txt"
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
start_mac
mac_cold_end=$(now_ns)
sleep 2
stop_mac
mac_warm_start=$(now_ns)
start_mac
mac_warm_end=$(now_ns)
sleep 2
screencapture -x -l "$mac_window" "${build_dir}/macos-initial.png"
test "$(stat -f '%z' "${build_dir}/macos-initial.png")" -gt 10000
recognize_text "${build_dir}/macos-initial.png" > "${build_dir}/macos-initial-ocr.txt"
grep -E 'TERSA-DIOXUS-M[0O]-THREAD' "${build_dir}/macos-initial-ocr.txt"
grep -E '10.?000' "${build_dir}/macos-initial-ocr.txt"
virtualization=$(verify_virtualization_ocr "${build_dir}/macos-initial-ocr.txt")
first_row=${virtualization#* }
test "$first_row" -eq 0

sleep 5
screencapture -x -l "$mac_window" "${build_dir}/macos.png"
stop_mac
test "$(stat -f '%z' "${build_dir}/macos.png")" -gt 10000
recognize_text "${build_dir}/macos.png" > "${build_dir}/macos-ocr.txt"
grep -E 'TERSA-DIOXUS-M[0O]-THREAD' "${build_dir}/macos-ocr.txt"
grep -E '10.?000' "${build_dir}/macos-ocr.txt"
grep -F 'TERSA DIOXUS INPUT ONE' "${build_dir}/macos-ocr.txt"
grep -F 'TERSA DIOXUS INPUT TWO' "${build_dir}/macos-ocr.txt"
virtualization=$(verify_virtualization_ocr "${build_dir}/macos-ocr.txt")
first_row=${virtualization#* }
test "$first_row" -gt 0

device=$(xcrun simctl list devices available \
  | awk -F '[()]' '/iPhone (1[5-9]|Air).*Pro/ { print $2; exit }')
if [ -z "$device" ]; then
  device=$(xcrun simctl list devices available | awk -F '[()]' '/iPhone/ { print $2; exit }')
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
xcrun simctl terminate "$device" app.tersa.dioxus-spike.ios
test "$(stat -f '%z' "${build_dir}/ios-simulator.png")" -gt 10000
recognize_text "${build_dir}/ios-simulator.png" > "${build_dir}/ios-simulator-ocr.txt"
grep -F 'TERSA' "${build_dir}/ios-simulator-ocr.txt"
grep -E '10.?000' "${build_dir}/ios-simulator-ocr.txt"
grep -E 'SAFE TOP[^0-9]*([4-9][0-9]|[1-9][0-9]{2,})' \
  "${build_dir}/ios-simulator-ocr.txt"
virtualization=$(verify_virtualization_ocr "${build_dir}/ios-simulator-ocr.txt")
first_row=${virtualization#* }
test "$first_row" -gt 0

debug_size=$(stat -f '%z' "$mac_binary")
printf '{"mac_cold_window_observed_ns":%s,"mac_warm_window_observed_ns":%s,"ios_cold_launch_command_ns":%s,"mac_debug_binary_bytes":%s,"synthetic_rows":10000}\n' \
  "$((mac_cold_end - mac_cold_start))" "$((mac_warm_end - mac_warm_start))" \
  "$((ios_cold_end - ios_cold_start))" "$debug_size" \
  > "${build_dir}/metrics.json"

printf '%s\n' \
  'Physical-device gates remain open: IME composition, autocorrect, dictation,' \
  'selection, copy and paste, hardware keyboard, VoiceOver traversal, Dynamic Type,' \
  'Full Keyboard Access, safe-area rotations, lifecycle edge cases, memory warning,' \
  'protected data, energy, memory, and signed TestFlight/App Review behavior.' \
  > "${build_dir}/physical-device-gaps.txt"
