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

mac_binary="${mac_app}/Contents/MacOS/tersa-slint-spike"
test -x "$mac_binary"
file "$mac_binary" | grep -F 'arm64'
otool -L "$mac_binary" | grep -F 'AppKit.framework'
strings -a "$mac_binary" | grep -F 'TERSA-SLINT-M0-THREAD'

ios_archive_binary="${apple_dir}/build/TersaSlintIOS.xcarchive/Products/Applications/Tersa Slint Spike.app/tersa-slint-spike"
test -x "$ios_archive_binary"
file "$ios_archive_binary" | grep -F 'arm64'
strings -a "$ios_archive_binary" | grep -F 'TERSA-SLINT-M0-THREAD'

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

wait_for_mac_process() {
  attempts=0
  while ! pgrep -f "$mac_binary" >/dev/null; do
    attempts=$((attempts + 1))
    test "$attempts" -lt 100
    sleep 0.1
  done
}

wait_for_mac_exit() {
  attempts=0
  while pgrep -f "$mac_binary" >/dev/null; do
    attempts=$((attempts + 1))
    test "$attempts" -lt 100
    sleep 0.1
  done
}

pkill -f "$mac_binary" 2>/dev/null || true
wait_for_mac_exit
mac_cold_start=$(now_ns)
open -n "$mac_app"
wait_for_mac_process
mac_cold_end=$(now_ns)
sleep 2
pkill -f "$mac_binary"
wait_for_mac_exit
mac_warm_start=$(now_ns)
open -n "$mac_app"
wait_for_mac_process
mac_warm_end=$(now_ns)
sleep 2
screencapture -x "${build_dir}/macos.png"
pkill -f "$mac_binary"
test "$(stat -f '%z' "${build_dir}/macos.png")" -gt 10000
recognize_text "${build_dir}/macos.png" > "${build_dir}/macos-ocr.txt"
grep -F 'TERSA' "${build_dir}/macos-ocr.txt"
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
grep -F 'TERSA' "${build_dir}/ios-simulator-ocr.txt"
grep -E '10.?000' "${build_dir}/ios-simulator-ocr.txt"

release_size=$(stat -f '%z' "$mac_binary")
printf '{"mac_cold_process_observed_ns":%s,"mac_warm_process_observed_ns":%s,"ios_cold_launch_command_ns":%s,"ios_warm_launch_command_ns":%s,"mac_release_binary_bytes":%s}\n' \
  "$((mac_cold_end - mac_cold_start))" "$((mac_warm_end - mac_warm_start))" \
  "$((ios_cold_end - ios_cold_start))" "$((ios_warm_end - ios_warm_start))" "$release_size" \
  > "${build_dir}/metrics.json"
