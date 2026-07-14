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

skia_tag="0.90.0"
skia_key_prefix="da4579b39b75fa2187c5"
case "$target" in
  aarch64-apple-darwin)
    skia_sha256="ffce3a615d922cb6358ec98cc3796541c350fbe0a67e1d46aaaa34d3483eee59"
    ;;
  aarch64-apple-ios)
    skia_sha256="dd62d2aeb55dffbdeedee9a2d095b7ac28e11ce0e86ec57e7c05e895bef267e2"
    ;;
  aarch64-apple-ios-sim)
    skia_sha256="9142067da699773e0cc042e27b8c90d8356db90203955be42a9bb27b4955e2d4"
    ;;
esac

skia_filename="skia-binaries-${skia_key_prefix}-${target}-gl-metal-pdf-textlayout.tar.gz"
skia_cache_root="${apple_dir}/build/verified-skia"
skia_release_dir="${skia_cache_root}/${skia_tag}"
skia_archive="${skia_release_dir}/${skia_filename}"
skia_download="${skia_archive}.download.$$"

cleanup() {
  rm -f "$skia_download"
}

trap cleanup EXIT HUP INT TERM
mkdir -p "$skia_release_dir"

if ! test -f "$skia_archive" || \
  ! printf '%s  %s\n' "$skia_sha256" "$skia_archive" | shasum -a 256 --check --status; then
  rm -f "$skia_archive"
  curl --fail --location --retry 3 \
    --output "$skia_download" \
    "https://github.com/rust-skia/skia-binaries/releases/download/${skia_tag}/${skia_filename}"
  printf '%s  %s\n' "$skia_sha256" "$skia_download" | shasum -a 256 --check
  mv "$skia_download" "$skia_archive"
fi

# skia-bindings supports file URLs but does not verify downloaded archives
# itself. Point it only at the checksum-verified local file so unverified bytes
# never reach its extraction step.
export SKIA_BINARIES_URL="file://${skia_cache_root}/{tag}/skia-binaries-{key}.tar.gz"

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
