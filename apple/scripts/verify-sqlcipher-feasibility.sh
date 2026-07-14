#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Captures deterministic, redacted SQLCipher M0 feasibility evidence.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
apple_dir=$(CDPATH='' cd -- "${script_dir}/.." && pwd)
workspace_dir=$(CDPATH='' cd -- "${apple_dir}/.." && pwd)
evidence_dir="${apple_dir}/build/sqlcipher-evidence"
: "${MACOSX_DEPLOYMENT_TARGET:=15.0}"
export MACOSX_DEPLOYMENT_TARGET

rm -rf "$evidence_dir"
mkdir -p "$evidence_dir"

target_dir="${apple_dir}/build/sqlcipher-target"
CARGO_TARGET_DIR="$target_dir" cargo build --locked \
  --package tersa-sqlcipher-spike \
  --manifest-path "${workspace_dir}/Cargo.toml" \
  --target aarch64-apple-darwin
"${target_dir}/aarch64-apple-darwin/debug/tersa-sqlcipher-spike" \
  >"${evidence_dir}/result.txt"

test "$(wc -l <"${evidence_dir}/result.txt" | tr -d ' ')" -eq 4
grep -Fxq 'SQLCipher M0 feasibility PASS' "${evidence_dir}/result.txt"
grep -Fxq 'SQLCipher provider commoncrypto' "${evidence_dir}/result.txt"
grep -Fxq 'SQLCipher version 4.10.0 community' "${evidence_dir}/result.txt"
grep -Fxq 'SQLCipher journal mode wal' "${evidence_dir}/result.txt"
