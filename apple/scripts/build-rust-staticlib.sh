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
  macos-token-broker)
    target="aarch64-apple-darwin"
    # The token-broker XPC service links ONLY this dedicated archive. It must
    # never share the main app's mailbox-sync FFI archive (ADR-0024).
    manifest="../adapters/token-broker-ffi-macos/Cargo.toml"
    archive="libtersa_token_broker_ffi_macos.a"
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

# Map script platform names onto the Xcode PLATFORM_NAME directory so both the
# main app and the token-broker XPC service can share apple/build/rust/macosx
# without clobbering each other's dedicated archive.
case "$platform" in
  macos|macos-token-broker)
    platform_name="${PLATFORM_NAME:-macosx}"
    ;;
  *)
    platform_name="${PLATFORM_NAME:-$platform}"
    ;;
esac
output_directory="${CARGO_TARGET_DIR}/${platform_name}/${configuration}"
mkdir -p "$output_directory"
# Replace only this target's archive. The main app and token broker each link
# exactly one dedicated Rust archive; wiping every libtersa_*.a would delete the
# sibling process's library when both targets build into the same directory.
cp "$library" "${output_directory}/${archive}"
