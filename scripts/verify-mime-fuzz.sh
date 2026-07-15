#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -eu
export LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FUZZ_DIR="$ROOT/fuzz"
EVIDENCE_DIR="$FUZZ_DIR/target/mime-fuzz-evidence"
ARTIFACT_DIR="$FUZZ_DIR/target/mime-fuzz-artifacts"
WORKING_CORPUS="$FUZZ_DIR/target/mime-fuzz-corpus"
NIGHTLY="nightly-2026-07-14"
CARGO_FUZZ_VERSION="0.13.2"
RUNS="10000"
SEED="240715"
MAX_LEN="524288"
TIMEOUT_SECONDS="5"
RSS_LIMIT_MB="1024"
EXPECTED_SEEDS="12"

fail() {
    printf 'MIME fuzz verification failed at %s.\n' "$1" >&2
    exit 1
}

run_quietly() {
    stage=$1
    shift
    "$@" >/dev/null 2>&1 || fail "$stage"
}

fuzz_build() {
    if [ -n "${TERSA_FUZZ_TARGET:-}" ]; then
        cargo +"$NIGHTLY" fuzz build --target "$TERSA_FUZZ_TARGET" mime_display
    else
        cargo +"$NIGHTLY" fuzz build mime_display
    fi
}

fuzz_run_quietly() {
    stage=$1
    corpus_path=$2
    shift 2

    if [ -n "${TERSA_FUZZ_TARGET:-}" ]; then
        run_quietly "$stage" cargo +"$NIGHTLY" fuzz run \
            --target "$TERSA_FUZZ_TARGET" mime_display "$corpus_path" -- "$@"
    else
        run_quietly "$stage" cargo +"$NIGHTLY" fuzz run \
            mime_display "$corpus_path" -- "$@"
    fi
}

corpus_checksum() {
    LC_ALL=C find corpus/mime_display -type f -print \
        | LC_ALL=C sort \
        | while IFS= read -r corpus_path; do cksum "$corpus_path"; done \
        | cksum
}

cd "$FUZZ_DIR"

rustup run "$NIGHTLY" rustc --version >/dev/null 2>&1 || fail "F1_TOOLCHAIN"
actual_fuzz_version=$(cargo +"$NIGHTLY" fuzz --version 2>/dev/null) \
    || fail "F2_DRIVER"
[ "$actual_fuzz_version" = "cargo-fuzz $CARGO_FUZZ_VERSION" ] \
    || fail "F3_DRIVER_VERSION"

seed_count=$(find corpus/mime_display -type f | wc -l | tr -d ' ')
[ "$seed_count" = "$EXPECTED_SEEDS" ] || fail "F4_SEED_COUNT"
seed_checksum=$(corpus_checksum) || fail "F5_SEED_CHECKSUM"
lock_checksum=$(cksum Cargo.lock) || fail "F6_LOCK_CHECKSUM"

rm -rf "$EVIDENCE_DIR" "$ARTIFACT_DIR" "$WORKING_CORPUS"
mkdir -p "$EVIDENCE_DIR" "$ARTIFACT_DIR" "$WORKING_CORPUS" \
    || fail "F7_WORKSPACE"
run_quietly "F8_SEED_COPY" cp -R corpus/mime_display/. "$WORKING_CORPUS/"

# Compiler diagnostics cannot contain fuzz input bytes and are safe to expose in CI.
fuzz_build || fail "F9_BUILD"
for seed_path in corpus/mime_display/*; do
    [ -f "$seed_path" ] || fail "F10_SEED_ENTRY"
    fuzz_run_quietly "F11_SEED_REPLAY" "$seed_path" \
        -runs=1 \
        -max_len="$MAX_LEN" \
        -timeout="$TIMEOUT_SECONDS" \
        -rss_limit_mb="$RSS_LIMIT_MB" \
        -artifact_prefix="$ARTIFACT_DIR/"
done

fuzz_run_quietly "F12_GENERATED_RUN" "$WORKING_CORPUS" \
    -seed="$SEED" \
    -runs="$RUNS" \
    -max_len="$MAX_LEN" \
    -timeout="$TIMEOUT_SECONDS" \
    -rss_limit_mb="$RSS_LIMIT_MB" \
    -artifact_prefix="$ARTIFACT_DIR/"
[ "$(cksum Cargo.lock)" = "$lock_checksum" ] || fail "F13_LOCK_MUTATION"
[ "$(find corpus/mime_display -type f | wc -l | tr -d ' ')" = "$EXPECTED_SEEDS" ] \
    || fail "F14_SEED_COUNT_MUTATION"
[ "$(corpus_checksum)" = "$seed_checksum" ] || fail "F15_SEED_MUTATION"

result=$(printf '%s\n' \
    "MIME parser fuzz regression PASS" \
    "Seed corpus cases $EXPECTED_SEEDS" \
    "Deterministic fuzz runs $RUNS" \
    "Maximum input bytes $MAX_LEN" \
    "NOT A DEVICE-GATE RESULT")
printf '%s\n' "$result" | tee "$EVIDENCE_DIR/result.txt"
