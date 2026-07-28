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
    # The macOS app links ONLY this archive; it re-exports the bridge's C
    # symbols. The bridge archive must not also be on the link line: placed
    # before this one the link fails with duplicate symbols, placed after it the
    # linker silently ignores it — so the single-archive rule is enforced by the
    # pinned OTHER_LDFLAGS (xtask `tersa_mac_target_surface_violations`), not by
    # the linker alone. This script builds only the FFI archive for macOS.
    manifest="../adapters/mailbox-sync-ffi-macos/Cargo.toml"
    archive="libtersa_mailbox_sync_ffi_macos.a"
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
    manifest="rust-bridge/Cargo.toml"
    archive="libtersa_apple_bridge.a"
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
  cargo build --locked --manifest-path "${apple_dir}/${manifest}" --target "$target" --release
else
  cargo build --locked --manifest-path "${apple_dir}/${manifest}" --target "$target"
fi

library="${CARGO_TARGET_DIR}/${target}/${profile}/${archive}"
test -f "$library"

platform_name="${PLATFORM_NAME:-$platform}"
output_directory="${CARGO_TARGET_DIR}/${platform_name}/${configuration}"
mkdir -p "$output_directory"
# Remove any stale Rust archive from a previous build (e.g. a pre-swap
# libtersa_apple_bridge.a in a warm checkout) so exactly one archive sits at the
# destination the link line points at — never two next to each other.
rm -f "${output_directory}"/libtersa_*.a
cp "$library" "${output_directory}/${archive}"
