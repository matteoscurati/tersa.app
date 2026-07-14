#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Generates or verifies complete target-specific license inventories for the
# Apple diagnostic applications.
set -eu

mode=${1:---check}
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
apple_dir=$(CDPATH='' cd -- "${script_dir}/.." && pwd)
workspace_dir=$(CDPATH='' cd -- "${apple_dir}/.." && pwd)
slint_config="${workspace_dir}/about.toml"
dioxus_config="${workspace_dir}/about-dioxus.toml"
bridge_config="${workspace_dir}/about-bridge.toml"
sqlcipher_config="${workspace_dir}/about-sqlcipher.toml"
renderer="${script_dir}/render-third-party-notices.py"
supplemental="${apple_dir}/licenses/rust-skia-notices.txt"
sqlcipher_supplemental="${apple_dir}/licenses/sqlcipher-notices.txt"

python3 "${script_dir}/verify-rust-skia-notices.py" "$supplemental"
python3 "${script_dir}/verify-sqlcipher-notices.py" \
  "$sqlcipher_supplemental" "${workspace_dir}/Cargo.lock"

case "$mode" in
  --check)
    output_dir=$(mktemp -d "${TMPDIR:-/tmp}/tersa-notices.XXXXXX")
    cleanup() {
      rm -rf "$output_dir"
    }
    trap cleanup EXIT HUP INT TERM
    ;;
  --write)
    output_dir="${apple_dir}/licenses"
    ;;
  *)
    echo "Usage: $0 [--check|--write]" >&2
    exit 1
    ;;
esac

generate_notice() {
  output_file="$1"
  target_name="$2"
  manifest="$3"
  notice_supplement="$4"
  about_config="$5"
  json_file="${output_dir}/${output_file}.json"
  shift 5
  cargo about generate \
    --config "$about_config" \
    --manifest-path "${workspace_dir}/${manifest}" \
    --locked \
    --offline \
    --fail \
    "$@" \
    --format json \
    --output-file "$json_file"
  python3 "$renderer" "$json_file" "$notice_supplement" "$target_name" \
    "${output_dir}/${output_file}"
  rm -f "$json_file"
}

generate_notice THIRD_PARTY_NOTICES-macos.txt "macOS arm64" \
  apps/slint-spike/Cargo.toml "$supplemental" "$slint_config" \
  --target aarch64-apple-darwin
generate_notice THIRD_PARTY_NOTICES-ios.txt "iOS arm64 device and simulator targets" \
  apps/slint-spike/Cargo.toml "$supplemental" "$slint_config" \
  --target aarch64-apple-ios --target aarch64-apple-ios-sim
generate_notice THIRD_PARTY_NOTICES-dioxus-macos.txt "macOS arm64" \
  apps/dioxus-spike/Cargo.toml - "$dioxus_config" \
  --target aarch64-apple-darwin
generate_notice THIRD_PARTY_NOTICES-dioxus-ios.txt \
  "iOS arm64 device and simulator targets" \
  apps/dioxus-spike/Cargo.toml - "$dioxus_config" \
  --target aarch64-apple-ios --target aarch64-apple-ios-sim
generate_notice THIRD_PARTY_NOTICES-bridge-macos.txt "tersa.app macOS arm64" \
  apple/rust-bridge/Cargo.toml - "$bridge_config" \
  --target aarch64-apple-darwin
generate_notice THIRD_PARTY_NOTICES-bridge-ios.txt \
  "tersa.app iOS arm64 device and simulator targets" \
  apple/rust-bridge/Cargo.toml - "$bridge_config" \
  --target aarch64-apple-ios --target aarch64-apple-ios-sim

generate_notice THIRD_PARTY_NOTICES-sqlcipher-macos.txt "macOS arm64" \
  apps/sqlcipher-spike/Cargo.toml "$sqlcipher_supplemental" "$sqlcipher_config" \
  --target aarch64-apple-darwin
generate_notice THIRD_PARTY_NOTICES-sqlcipher-ios.txt "iOS arm64 device and simulator targets" \
  apps/sqlcipher-spike/Cargo.toml "$sqlcipher_supplemental" "$sqlcipher_config" \
  --target aarch64-apple-ios --target aarch64-apple-ios-sim

if [ "$mode" = "--check" ]; then
  cmp "${output_dir}/THIRD_PARTY_NOTICES-macos.txt" \
    "${apple_dir}/licenses/THIRD_PARTY_NOTICES-macos.txt"
  cmp "${output_dir}/THIRD_PARTY_NOTICES-ios.txt" \
    "${apple_dir}/licenses/THIRD_PARTY_NOTICES-ios.txt"
  cmp "${output_dir}/THIRD_PARTY_NOTICES-dioxus-macos.txt" \
    "${apple_dir}/licenses/THIRD_PARTY_NOTICES-dioxus-macos.txt"
  cmp "${output_dir}/THIRD_PARTY_NOTICES-dioxus-ios.txt" \
    "${apple_dir}/licenses/THIRD_PARTY_NOTICES-dioxus-ios.txt"
  cmp "${output_dir}/THIRD_PARTY_NOTICES-bridge-macos.txt" \
    "${apple_dir}/licenses/THIRD_PARTY_NOTICES-bridge-macos.txt"
  cmp "${output_dir}/THIRD_PARTY_NOTICES-bridge-ios.txt" \
    "${apple_dir}/licenses/THIRD_PARTY_NOTICES-bridge-ios.txt"
  cmp "${output_dir}/THIRD_PARTY_NOTICES-sqlcipher-macos.txt" \
    "${apple_dir}/licenses/THIRD_PARTY_NOTICES-sqlcipher-macos.txt"
  cmp "${output_dir}/THIRD_PARTY_NOTICES-sqlcipher-ios.txt" \
    "${apple_dir}/licenses/THIRD_PARTY_NOTICES-sqlcipher-ios.txt"
fi
