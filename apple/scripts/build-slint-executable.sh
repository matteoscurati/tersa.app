#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Builds the locked Apple-only Slint executable and installs it in Xcode's app
# bundle. Cargo intermediates stay below the ignored apple/build directory.
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
    echo "Unsupported Slint executable platform: $platform" >&2
    exit 1
    ;;
esac

bundle_binary="${TARGET_BUILD_DIR}/${EXECUTABLE_PATH}"

case "$configuration" in
  Debug)
    profile="debug"
    profile_flag=""
    ;;
  Release)
    profile="release"
    profile_flag="--release"
    ;;
  *)
    echo "Unsupported Xcode configuration: $configuration" >&2
    exit 1
    ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
apple_dir=$(CDPATH='' cd -- "${script_dir}/.." && pwd)
workspace_dir=$(CDPATH='' cd -- "${apple_dir}/.." && pwd)

export CARGO_TARGET_DIR="${apple_dir}/build/slint-rust"
cd "$workspace_dir"

# skia-bindings supports file URLs but does not verify downloaded archives
# itself. Point it only at the checksum-verified local file so unverified bytes
# never reach its extraction step.
SKIA_BINARIES_URL=$(sh "${script_dir}/prepare-verified-skia.sh" "$target")
export SKIA_BINARIES_URL

if [ -n "$profile_flag" ]; then
  cargo build --locked --package tersa-slint-spike --target "$target" --release
else
  cargo build --locked --package tersa-slint-spike --target "$target"
fi

binary="${CARGO_TARGET_DIR}/${target}/${profile}/tersa-slint-spike"
test -f "$binary"
mkdir -p "$(dirname -- "$bundle_binary")"
cp "$binary" "$bundle_binary"
chmod 755 "$bundle_binary"
