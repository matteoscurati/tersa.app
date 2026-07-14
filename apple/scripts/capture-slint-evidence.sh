#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Captures reproducible launch evidence for the unsigned diagnostic packages.
set -eu

apple_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
build_dir="${apple_dir}/build/slint-evidence"
mac_app="${apple_dir}/build/TersaSlintMac.xcarchive/Products/Applications/Tersa Slint Spike.app"
ios_app="${apple_dir}/build/DerivedData/Build/Products/Debug-iphonesimulator/Tersa Slint Spike.app"
mkdir -p "$build_dir"

mac_pid=''
device=''

cleanup() {
  if [ -n "$mac_pid" ] && kill -0 "$mac_pid" 2>/dev/null; then
    kill "$mac_pid" 2>/dev/null || true
    wait "$mac_pid" 2>/dev/null || true
  fi
  if [ -n "$device" ]; then
    xcrun simctl terminate "$device" app.tersa.slint-spike.ios 2>/dev/null || true
  fi
}

trap cleanup EXIT HUP INT TERM

mac_binary="${mac_app}/Contents/MacOS/tersa-slint-spike"
test -x "$mac_binary"
file "$mac_binary" | grep -F 'arm64'
otool -L "$mac_binary" | grep -F 'AppKit.framework'
strings -a "$mac_binary" | grep -F 'TERSA-SLINT-M0-THREAD'
strings -a "$mac_binary" | grep -F 'INBOX / 10,000 ROWS'

ios_archive_binary="${apple_dir}/build/TersaSlintIOS.xcarchive/Products/Applications/Tersa Slint Spike.app/tersa-slint-spike"
test -x "$ios_archive_binary"
file "$ios_archive_binary" | grep -F 'arm64'
strings -a "$ios_archive_binary" | grep -F 'TERSA-SLINT-M0-THREAD'
strings -a "$ios_archive_binary" | grep -F 'INBOX / 10,000 ROWS'

ios_simulator_binary="${ios_app}/tersa-slint-spike"
test -x "$ios_simulator_binary"
strings -a "$ios_simulator_binary" | grep -F 'TERSA-SLINT-M0-THREAD'
strings -a "$ios_simulator_binary" | grep -F 'INBOX / 10,000 ROWS'

mac_notice_source="${apple_dir}/licenses/THIRD_PARTY_NOTICES-macos.txt"
ios_notice_source="${apple_dir}/licenses/THIRD_PARTY_NOTICES-ios.txt"
cmp "$mac_notice_source" "${mac_app}/Contents/Resources/THIRD_PARTY_NOTICES-macos.txt"
cmp "$ios_notice_source" "${ios_app}/THIRD_PARTY_NOTICES-ios.txt"
cmp "$ios_notice_source" "${apple_dir}/build/TersaSlintIOS.xcarchive/Products/Applications/Tersa Slint Spike.app/THIRD_PARTY_NOTICES-ios.txt"
for component in Expat HarfBuzz ICU libjpeg-turbo libpng Wuffs zlib; do
  grep -Fx "$component" "$mac_notice_source"
  grep -Fx "$component" "$ios_notice_source"
done

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
    test "$attempts" -lt 100
    mac_window=$(find_mac_window "$mac_pid")
    if ! kill -0 "$mac_pid" 2>/dev/null; then
      echo "macOS diagnostic process exited before presenting a window" >&2
      return 1
    fi
    sleep 0.1
  done
}

start_mac() {
  "$mac_binary" >"${build_dir}/macos-process.log" 2>&1 &
  mac_pid=$!
  wait_for_mac_window
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
screencapture -x -l "$mac_window" "${build_dir}/macos.png"
stop_mac
test "$(stat -f '%z' "${build_dir}/macos.png")" -gt 10000
recognize_text "${build_dir}/macos.png" > "${build_dir}/macos-ocr.txt"
grep -E 'TERSA-SLINT-M[0O]-THREAD' "${build_dir}/macos-ocr.txt"
grep -E '10.?000' "${build_dir}/macos-ocr.txt"

device=$(xcrun simctl list devices available | awk -F '[()]' '/iPhone/ { print $2; exit }')
test -n "$device"
xcrun simctl boot "$device" 2>/dev/null || true
xcrun simctl bootstatus "$device" -b
xcrun simctl install "$device" "$ios_app"
ios_cold_start=$(now_ns)
xcrun simctl launch "$device" app.tersa.slint-spike.ios
ios_cold_end=$(now_ns)
sleep 2
xcrun simctl terminate "$device" app.tersa.slint-spike.ios
ios_warm_start=$(now_ns)
xcrun simctl launch "$device" app.tersa.slint-spike.ios
ios_warm_end=$(now_ns)
sleep 2
xcrun simctl io "$device" screenshot "${build_dir}/ios-simulator.png"
xcrun simctl terminate "$device" app.tersa.slint-spike.ios
test "$(stat -f '%z' "${build_dir}/ios-simulator.png")" -gt 10000
recognize_text "${build_dir}/ios-simulator.png" > "${build_dir}/ios-simulator-ocr.txt"
grep -E 'TERSA-SLINT-M[0O]-THREAD' "${build_dir}/ios-simulator-ocr.txt"
grep -Ei 'diagnostic thread [0O]*[0O][1-9]' "${build_dir}/ios-simulator-ocr.txt"

release_size=$(stat -f '%z' "$mac_binary")
printf '{"mac_cold_window_observed_ns":%s,"mac_warm_window_observed_ns":%s,"ios_cold_launch_command_ns":%s,"ios_warm_launch_command_ns":%s,"mac_release_binary_bytes":%s}\n' \
  "$((mac_cold_end - mac_cold_start))" "$((mac_warm_end - mac_warm_start))" \
  "$((ios_cold_end - ios_cold_start))" "$((ios_warm_end - ios_warm_start))" "$release_size" \
  > "${build_dir}/metrics.json"
