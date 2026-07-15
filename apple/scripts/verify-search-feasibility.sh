#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Runs the redacted macOS CI profile of the encrypted-search diagnostic.
set -eu
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
workspace_dir=$(CDPATH='' cd -- "${script_dir}/../.." && pwd)
evidence_dir="${workspace_dir}/apple/build/search-evidence"
rm -rf "$evidence_dir"
mkdir -p "$evidence_dir"
CARGO_TARGET_DIR="${workspace_dir}/apple/build/search-target" cargo run --locked \
  --release \
  --package tersa-search-spike --manifest-path "${workspace_dir}/Cargo.toml" \
  --target aarch64-apple-darwin -- --profile ci >"${evidence_dir}/result.txt"
test "$(wc -l <"${evidence_dir}/result.txt" | tr -d ' ')" -eq 5
grep -Fxq 'Encrypted search M0 feasibility PASS' "${evidence_dir}/result.txt"
grep -Eq '^Profile ci messages=10000 normalized_text_bytes=[0-9]+$' \
  "${evidence_dir}/result.txt"
awk -F= '/^Profile ci / { if ($3 + 0 < 134217728) exit 1 }' \
  "${evidence_dir}/result.txt"
grep -Fxq \
  'Search engine SQLCipher 4.10.0 community SQLite 3.50.4 FTS5 and Tantivy 0.26.1' \
  "${evidence_dir}/result.txt"
grep -Eq \
  '^Host metrics fts_p95_ms=[0-9]+ tantivy_p95_ms=[0-9]+ current_index_bytes=[0-9]+$' \
  "${evidence_dir}/result.txt"
grep -Fxq 'NOT A DEVICE-GATE RESULT' "${evidence_dir}/result.txt"
