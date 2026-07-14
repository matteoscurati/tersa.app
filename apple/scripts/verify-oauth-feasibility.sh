#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
apple_dir=$(CDPATH='' cd -- "${script_dir}/.." && pwd)
workspace_dir=$(CDPATH='' cd -- "${apple_dir}/.." && pwd)
mac_archive=${1:-"${apple_dir}/build/TersaMac.xcarchive"}
ios_archive=${2:-"${apple_dir}/build/TersaIOS.xcarchive"}
evidence_dir="${apple_dir}/build/oauth-evidence"
mac_app="${mac_archive}/Products/Applications/Tersa.app"
ios_app="${ios_archive}/Products/Applications/Tersa.app"
probe_pid=''

cleanup() {
  if [ -n "$probe_pid" ] && kill -0 "$probe_pid" 2>/dev/null; then
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

rm -rf "$evidence_dir"
mkdir -p "$evidence_dir"

python3 - "$apple_dir" "$mac_app" "$ios_app" <<'PY'
import plistlib
import sys
from pathlib import Path

apple_dir = Path(sys.argv[1])
mac_app = Path(sys.argv[2])
ios_app = Path(sys.argv[3])

with (apple_dir / "macos/TersaMac.entitlements").open("rb") as stream:
    entitlements = plistlib.load(stream)
for key in (
    "com.apple.security.app-sandbox",
    "com.apple.security.network.client",
    "com.apple.security.network.server",
):
    if entitlements.get(key) is not True:
        raise SystemExit(f"missing required macOS entitlement: {key}")

with (mac_app / "Contents/Info.plist").open("rb") as stream:
    mac_info = plistlib.load(stream)
with (ios_app / "Info.plist").open("rb") as stream:
    ios_info = plistlib.load(stream)
if mac_info.get("TersaOAuthClientID") != "public-ci-client.apps.googleusercontent.com":
    raise SystemExit("macOS public test client ID was not injected")
if ios_info.get("TersaOAuthClientID") != "public-ci-client.apps.googleusercontent.com":
    raise SystemExit("iOS public test client ID was not injected")
if ios_info.get("TersaOAuthRedirectScheme") != "app.tersa.oauth.ci":
    raise SystemExit("iOS public test redirect scheme was not injected")
schemes = [
    scheme
    for item in ios_info.get("CFBundleURLTypes", [])
    for scheme in item.get("CFBundleURLSchemes", [])
]
if schemes != ["app.tersa.oauth.ci"]:
    raise SystemExit("iOS callback URL scheme is not exact")
PY

nm -gU "${mac_app}/Contents/MacOS/Tersa" | grep -Fq '_tersa_oauth_macos_begin'
nm -gU "${ios_app}/Tersa" | grep -Fq '_tersa_oauth_ios_begin'
nm -gU "${ios_app}/Tersa" | grep -Fq '_tersa_oauth_ios_finish'
cmp "${apple_dir}/licenses/THIRD_PARTY_NOTICES-bridge-macos.txt" \
  "${mac_app}/Contents/Resources/THIRD_PARTY_NOTICES-bridge-macos.txt"
cmp "${apple_dir}/licenses/THIRD_PARTY_NOTICES-bridge-ios.txt" \
  "${ios_app}/THIRD_PARTY_NOTICES-bridge-ios.txt"

cp -R "$mac_app" "${evidence_dir}/Tersa.app"
codesign --force --deep --sign - \
  --entitlements "${apple_dir}/macos/TersaMac.entitlements" \
  "${evidence_dir}/Tersa.app"
codesign --display --entitlements :- "${evidence_dir}/Tersa.app" \
  >"${evidence_dir}/signed-entitlements.plist" 2>/dev/null
python3 - "${evidence_dir}/signed-entitlements.plist" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as stream:
    entitlements = plistlib.load(stream)
for key in (
    "com.apple.security.app-sandbox",
    "com.apple.security.network.client",
    "com.apple.security.network.server",
):
    if entitlements.get(key) is not True:
        raise SystemExit(f"signed app is missing entitlement: {key}")
PY

CARGO_TARGET_DIR="${apple_dir}/build/oauth-probe-target" cargo build --locked \
  --manifest-path "${apple_dir}/rust-bridge/Cargo.toml" \
  --target aarch64-apple-darwin --example oauth_entitlement_probe
probe_app="${evidence_dir}/TersaOAuthProbe.app"
mkdir -p "${probe_app}/Contents/MacOS"
cp "${apple_dir}/build/oauth-probe-target/aarch64-apple-darwin/debug/examples/oauth_entitlement_probe" \
  "${probe_app}/Contents/MacOS/oauth-entitlement-probe"
python3 - "${probe_app}/Contents/Info.plist" <<'PY'
import plistlib
import sys

info = {
    "CFBundleExecutable": "oauth-entitlement-probe",
    "CFBundleIdentifier": "app.tersa.oauth-probe",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "Tersa OAuth Probe",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": "1.0",
    "CFBundleVersion": "1",
}
with open(sys.argv[1], "wb") as stream:
    plistlib.dump(info, stream)
PY
codesign --force --deep --sign - \
  --entitlements "${apple_dir}/macos/TersaMac.entitlements" \
  "$probe_app"
codesign --display --entitlements :- "$probe_app" \
  >"${evidence_dir}/probe-entitlements.plist" 2>/dev/null
cmp "${evidence_dir}/signed-entitlements.plist" \
  "${evidence_dir}/probe-entitlements.plist"

"${probe_app}/Contents/MacOS/oauth-entitlement-probe" \
  >"${evidence_dir}/sandbox-network-probe.txt" \
  2>"${evidence_dir}/sandbox-network-probe-error.txt" &
probe_pid=$!
probe_checks=0
while kill -0 "$probe_pid" 2>/dev/null && [ "$probe_checks" -lt 100 ]; do
  sleep 0.1
  probe_checks=$((probe_checks + 1))
done
if kill -0 "$probe_pid" 2>/dev/null; then
  kill "$probe_pid" 2>/dev/null || true
  wait "$probe_pid" 2>/dev/null || true
  echo "OAuth sandbox network entitlement probe timed out" >&2
  exit 1
fi
wait "$probe_pid"
probe_pid=''
grep -Fxq 'OAuth sandbox network entitlement probe passed.' \
  "${evidence_dir}/sandbox-network-probe.txt"

cargo test --locked --manifest-path "${workspace_dir}/Cargo.toml" \
  --package tersa-application oauth::tests
cargo test --locked --manifest-path "${workspace_dir}/Cargo.toml" \
  --package tersa-apple-bridge oauth::

printf '%s\n' 'OAuth PKCE fake-callback and sandbox entitlement evidence passed.' \
  >"${evidence_dir}/result.txt"
