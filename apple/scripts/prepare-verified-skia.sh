#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Downloads the pinned rust-skia archive for one Apple target, verifies it,
# and prints the local SKIA_BINARIES_URL template. All diagnostics go to stderr
# so callers can safely capture stdout and export the result.
set -eu

target="${1:?usage: prepare-verified-skia.sh <Apple Rust target>}"

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
  *)
    echo "Unsupported rust-skia Apple target: $target" >&2
    exit 1
    ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
apple_dir=$(CDPATH='' cd -- "${script_dir}/.." && pwd)
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
  curl --fail --location --retry 3 --silent --show-error \
    --output "$skia_download" \
    "https://github.com/rust-skia/skia-binaries/releases/download/${skia_tag}/${skia_filename}"
  if ! printf '%s  %s\n' "$skia_sha256" "$skia_download" | \
    shasum -a 256 --check --status; then
    echo "rust-skia archive checksum verification failed for $target" >&2
    exit 1
  fi
  mv "$skia_download" "$skia_archive"
fi

# skia-bindings supports file URLs but does not verify downloaded archives.
# Expose only the directory containing the checksum-verified local archive.
printf 'file://%s/{tag}/skia-binaries-{key}.tar.gz\n' "$skia_cache_root"
