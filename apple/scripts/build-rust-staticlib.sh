#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
    echo "Unsupported Rust bridge platform: $platform" >&2
    exit 1
    ;;
esac

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

export CARGO_TARGET_DIR="${apple_dir}/build/rust"

if [ -n "$profile_flag" ]; then
  cargo build --locked --manifest-path "${apple_dir}/rust-bridge/Cargo.toml" --target "$target" --release
else
  cargo build --locked --manifest-path "${apple_dir}/rust-bridge/Cargo.toml" --target "$target"
fi

library="${CARGO_TARGET_DIR}/${target}/${profile}/libtersa_apple_bridge.a"
test -f "$library"

platform_name="${PLATFORM_NAME:-$platform}"
output_directory="${CARGO_TARGET_DIR}/${platform_name}/${configuration}"
mkdir -p "$output_directory"
cp "$library" "${output_directory}/libtersa_apple_bridge.a"
