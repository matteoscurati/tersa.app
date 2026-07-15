#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Builds and verifies the host-only crash-safe chunked-AEAD blob diagnostic.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
apple_dir=$(CDPATH='' cd -- "${script_dir}/.." && pwd)
workspace_dir=$(CDPATH='' cd -- "${apple_dir}/.." && pwd)
evidence_dir="${apple_dir}/build/blob-evidence"
target_dir="${apple_dir}/build/blob-target"
binary="${target_dir}/aarch64-apple-darwin/release/tersa-blob-spike"
actual="${evidence_dir}/result.txt"
expected="${evidence_dir}/expected.txt"

rm -rf "$evidence_dir" "$target_dir"
mkdir -p "$evidence_dir"

CARGO_TARGET_DIR="$target_dir" cargo build --locked --release \
  --manifest-path "${workspace_dir}/Cargo.toml" \
  --package tersa-blob-spike --target aarch64-apple-darwin

"$binary" > "$actual"
{
  printf '%s\n' 'Blob AEAD M0 feasibility PASS'
  printf '%s\n' 'Blob format version 1'
  printf '%s\n' 'NOT A DEVICE-GATE RESULT'
} > "$expected"
cmp "$expected" "$actual"
rm -f "$expected"

printf '%s\n' 'Blob AEAD feasibility evidence passed.'
