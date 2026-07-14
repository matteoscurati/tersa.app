#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Builds the locked Dioxus executable with Cargo only and installs it in the
# Xcode application bundle. No Dioxus CLI or asset bundler is involved.
set -eu

platform="$1"
configuration="$2"

case "$platform" in
  macos)
    target="aarch64-apple-darwin"
    ;;
  ios)
    case "${PLATFORM_NAME:-iphoneos}" in
      iphonesimulator)
        target="aarch64-apple-ios-sim"
        ;;
      iphoneos)
        target="aarch64-apple-ios"
        ;;
      *)
        echo "Unsupported Apple platform: ${PLATFORM_NAME}" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Unsupported Dioxus executable platform: $platform" >&2
    exit 1
    ;;
esac

case "$configuration" in
  Debug)
    profile="debug"
    ;;
  Release)
    echo "Dioxus 0.7.9 minimal Release builds are blocked by unguarded devtools calls." >&2
    echo "Do not enable private WebKit devtools APIs to bypass this product gate." >&2
    exit 1
    ;;
  *)
    echo "Unsupported Xcode configuration: $configuration" >&2
    exit 1
    ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
apple_dir=$(CDPATH='' cd -- "${script_dir}/.." && pwd)
workspace_dir=$(CDPATH='' cd -- "${apple_dir}/.." && pwd)
bundle_binary="${TARGET_BUILD_DIR}/${EXECUTABLE_PATH}"

export CARGO_TARGET_DIR="${apple_dir}/build/dioxus-rust"
cd "$workspace_dir"

cargo build --locked --package tersa-dioxus-spike --target "$target"

binary="${CARGO_TARGET_DIR}/${target}/${profile}/tersa-dioxus-spike"
test -f "$binary"
mkdir -p "$(dirname -- "$bundle_binary")"
cp "$binary" "$bundle_binary"
chmod 755 "$bundle_binary"
