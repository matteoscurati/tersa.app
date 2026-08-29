#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Produce or validate redacted, non-gate Apple Development evidence for one
# manual Gmail OAuth lifecycle observation. This script never starts OAuth,
# opens a browser, reads mail, reads credentials, or prints tool transcripts.

set -eu
umask 077

ROOT="$(CDPATH='' cd "$(dirname "$0")/../.." && pwd -P)"
APPLICATION_SCOPE_SOURCE="$ROOT/crates/application/src/oauth.rs"
EXPECTED_MAIN_PROBE='{"schema_version":1,"principal":"main-app","result":"missing-entitlement"}'
EXPECTED_BROKER_PROBE='{"schema_version":1,"principal":"token-broker","result":"missing-entitlement"}'

usage() {
  cat <<'USAGE'
usage:
  capture-macos-live-oauth-dev-evidence.sh --validate <manifest-or-manual-observation.json>
  capture-macos-live-oauth-dev-evidence.sh --canonicalize <manifest.json>
  capture-macos-live-oauth-dev-evidence.sh --digest <Tersa.app>
  capture-macos-live-oauth-dev-evidence.sh --scope
  capture-macos-live-oauth-dev-evidence.sh --capture <manual-observation.json> <Tersa.app> <output.json>
USAGE
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

# The complete data contract is intentionally dependency-free and embedded
# here. It emits no exception detail, so malformed input and local tool output
# cannot become evidence output.
run_contract_python() {
  python3 - "$APPLICATION_SCOPE_SOURCE" "$@" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys


class ContractError(Exception):
    pass


MAX_PAYLOAD_BYTES = 65_536
PLACEHOLDER_CAPTURE_SHA256 = (
    "25ec8ba33e11e11ac9572188dcf14ab908a66bd9de6c9142a6733cc72268e092"
)
NONCLAIMS = [
    "Testing refresh tokens may expire after 7 days.",
    "No durability or post-expiry claim.",
    "No cold stored refresh after process death.",
    "No legacy pre-split app.tersa.mac.oauth-refresh-token.v1 absence claim.",
    "No Developer ID, notarization, distribution, or accessibility claim.",
    "This local manifest is non-gate and does not close issue #51.",
]


def require(condition: bool) -> None:
    if not condition:
        raise ContractError()


def exact_keys(value: object, keys: set[str]) -> dict[str, object]:
    require(type(value) is dict)
    mapping = value
    require(set(mapping) == keys)
    return mapping


def exact_list(value: object, expected: list[object]) -> None:
    require(type(value) is list)
    require(value == expected)


def fixed(value: object, expected: object) -> None:
    require(value == expected)


def integer(value: object) -> int:
    require(type(value) is int)
    return value


def sha256(value: object) -> None:
    require(type(value) is str)
    require(re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def git_oid(value: object) -> None:
    require(type(value) is str)
    require(re.fullmatch(r"[0-9a-f]{40}", value) is not None)


def version(value: object) -> None:
    require(type(value) is str)
    require(re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", value) is not None)


def build_identifier(value: object) -> None:
    require(type(value) is str)
    require(re.fullmatch(r"[0-9][0-9A-Z._-]*", value) is not None)


def safe_text(value: object) -> None:
    """Reject every redaction class before schema-specific interpretation."""
    if type(value) is str:
        require("\x00" not in value)
        require(re.search(r"(^|[\t\r\n ])/(?!/)[^\t\r\n ]*", value) is None)
        require(re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value) is None)
        require(re.search(r"\b[A-Z0-9]{10}\b", value) is None)
        require(re.search(r"(?i)apple development\s*:", value) is None)
        require(re.search(r"(?i)\b(?:team|certificate|cert|account)[ _-]?(?:id|identifier)\b", value) is None)
    elif type(value) is list:
        for item in value:
            safe_text(item)
    elif type(value) is dict:
        for item in value.values():
            safe_text(item)
    elif value is None or type(value) in (bool, int):
        return
    else:
        raise ContractError()


def object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError()
        result[key] = value
    return result


def read_limited_bytes(path: str, limit: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode))
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65_536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= limit)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_exclusive(path: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def canonical_bytes(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def read_payload(path: str) -> tuple[bytes, object]:
    data = read_limited_bytes(path, MAX_PAYLOAD_BYTES)
    payload = json.loads(data.decode("utf-8"), object_pairs_hook=object_without_duplicates)
    safe_text(payload)
    return data, payload


def requested_scope(application_source: str) -> str:
    source = read_limited_bytes(application_source, 262_144).decode("utf-8")
    match = re.search(
        r'^pub const REQUESTED_SCOPE: &str = "([^"\\]+)";$',
        source,
        flags=re.MULTILINE,
    )
    require(match is not None)
    scope = match.group(1)
    tokens = scope.split(" ")
    require(len(tokens) == 2 and all(tokens) and len(set(tokens)) == 2)
    return scope


def validate_build_input_provenance(value: object) -> None:
    data = exact_keys(
        value,
        {"source", "client_secret_used", "scheme", "configuration"},
    )
    fixed(data["source"], "apple/local.xcconfig-values-redacted")
    fixed(data["client_secret_used"], True)
    fixed(data["scheme"], "TersaMac")
    fixed(data["configuration"], "Release")


def validate_toolchain(value: object) -> None:
    data = exact_keys(
        value,
        {
            "macos_product_version",
            "macos_build_version",
            "xcode_version",
            "xcode_build_version",
        },
    )
    version(data["macos_product_version"])
    build_identifier(data["macos_build_version"])
    version(data["xcode_version"])
    build_identifier(data["xcode_build_version"])


def validate_oauth_lifecycle(value: object, scope: str) -> None:
    data = exact_keys(
        value,
        {
            "authorization_request_scope",
            "callback_scopes",
            "consent",
            "exchange",
            "refresh_token_persistence",
            "initial_sync",
            "stored_credential_refresh",
            "stored_credential_refresh_after_relaunch",
            "disconnect",
            "linked_app_after_disconnect",
            "local_database_after_disconnect",
            "relaunch_state",
        },
    )
    fixed(data["authorization_request_scope"], scope)
    exact_list(data["callback_scopes"], scope.split(" "))

    consent = exact_keys(
        data["consent"],
        {
            "publishing_status",
            "user_type",
            "test_user",
            "gmail_readonly_granular_scope_selected",
        },
    )
    fixed(consent["publishing_status"], "testing")
    fixed(consent["user_type"], "external")
    fixed(consent["test_user"], True)
    fixed(consent["gmail_readonly_granular_scope_selected"], True)

    fixed(data["exchange"], "pass")
    persistence = exact_keys(data["refresh_token_persistence"], {"temperature", "outcome"})
    fixed(persistence["temperature"], "warm")
    fixed(persistence["outcome"], "pass")

    initial_sync = exact_keys(data["initial_sync"], {"outcome", "message_count"})
    fixed(initial_sync["outcome"], "pass")
    count = integer(initial_sync["message_count"])
    require(0 <= count <= 10_000)

    stored_refresh = exact_keys(data["stored_credential_refresh"], {"temperature", "outcome"})
    fixed(stored_refresh["temperature"], "warm")
    fixed(stored_refresh["outcome"], "pass")
    after_relaunch = exact_keys(
        data["stored_credential_refresh_after_relaunch"],
        {"observed", "outcome"},
    )
    fixed(after_relaunch["observed"], False)
    fixed(after_relaunch["outcome"], "not-run")

    disconnect = exact_keys(data["disconnect"], {"revoke", "token_delete", "local_purge"})
    fixed(disconnect["revoke"], "pass")
    fixed(disconnect["token_delete"], "pass")
    fixed(disconnect["local_purge"], "pass")
    fixed(data["linked_app_after_disconnect"], False)
    fixed(data["local_database_after_disconnect"], False)
    fixed(data["relaunch_state"], "not-connected")


def validate_operator_observations(value: object, scope: str) -> None:
    data = exact_keys(
        value,
        {
            "attestation",
            "build_input_provenance",
            "token_path",
            "production_archive_surface",
            "oauth_lifecycle",
        },
    )
    fixed(data["attestation"], "operator-attested-not-locally-recomputable")
    validate_build_input_provenance(data["build_input_provenance"])
    token_path = exact_keys(data["token_path"], {"value", "attested_not_proven"})
    fixed(token_path["value"], "embedded-xpc-broker")
    fixed(token_path["attested_not_proven"], True)
    archive_surface = exact_keys(
        data["production_archive_surface"],
        {"value", "attested_not_proven"},
    )
    fixed(archive_surface["value"], True)
    fixed(archive_surface["attested_not_proven"], True)
    validate_oauth_lifecycle(data["oauth_lifecycle"], scope)


def validate_manual(value: object, scope: str) -> None:
    data = exact_keys(value, {"record_type", "operator_observations"})
    fixed(data["record_type"], "macos-live-oauth-development-manual-observation-v2")
    validate_operator_observations(data["operator_observations"], scope)


def validate_recomputed(value: object) -> None:
    data = exact_keys(value, {"candidate", "artifact", "wrong_group_probes"})
    candidate = exact_keys(data["candidate"], {"commit", "tree"})
    git_oid(candidate["commit"])
    git_oid(candidate["tree"])

    artifact = exact_keys(
        data["artifact"],
        {
            "attribution",
            "verification",
            "bundle_digest_algorithm",
            "bundle_regular_file_manifest_sha256",
            "main_binary_sha256",
            "token_broker_binary_sha256",
            "signing_tier",
            "reproducible_from_commit_alone",
            "toolchain",
        },
    )
    fixed(artifact["attribution"], "live-artifact")
    fixed(artifact["verification"], "locally-recomputed-from-live-artifact")
    fixed(artifact["bundle_digest_algorithm"], "sha256-lc-all-c-regular-file-manifest-v1")
    sha256(artifact["bundle_regular_file_manifest_sha256"])
    sha256(artifact["main_binary_sha256"])
    sha256(artifact["token_broker_binary_sha256"])
    fixed(artifact["signing_tier"], "Apple Development")
    fixed(artifact["reproducible_from_commit_alone"], False)
    validate_toolchain(artifact["toolchain"])

    probes = exact_keys(
        data["wrong_group_probes"],
        {"rerun_on_live_artifact", "observed_on", "main_app", "token_broker"},
    )
    fixed(probes["rerun_on_live_artifact"], True)
    fixed(probes["observed_on"], "live-artifact")
    for key in ("main_app", "token_broker"):
        probe = exact_keys(probes[key], {"outcome", "result"})
        fixed(probe["outcome"], "pass")
        fixed(probe["result"], "missing-entitlement")


def validate_record_provenance(value: object) -> None:
    data = exact_keys(value, {"producer_validator", "emitted_by_capture_at_candidate"})
    require(type(data["emitted_by_capture_at_candidate"]) is bool)
    accepted = {
        ("capture-producer-at-current-candidate", True),
        ("later-tooling-canonicalization", False),
    }
    require((data["producer_validator"], data["emitted_by_capture_at_candidate"]) in accepted)


def validate_manifest(value: object, scope: str) -> None:
    data = exact_keys(
        value,
        {
            "schema_version",
            "evidence_kind",
            "redacted",
            "gate_status",
            "candidate",
            "artifact",
            "wrong_group_probes",
            "operator_observations",
            "record_provenance",
            "related_fixed_placeholder_development_capture",
            "nonclaims",
        },
    )
    fixed(data["schema_version"], 2)
    fixed(data["evidence_kind"], "macos-live-oauth-development")
    fixed(data["redacted"], True)
    fixed(data["gate_status"], "unchanged")
    validate_recomputed(
        {
            "candidate": data["candidate"],
            "artifact": data["artifact"],
            "wrong_group_probes": data["wrong_group_probes"],
        }
    )
    validate_operator_observations(data["operator_observations"], scope)
    validate_record_provenance(data["record_provenance"])

    related = exact_keys(
        data["related_fixed_placeholder_development_capture"],
        {
            "artifact_attribution",
            "capture_sha256",
            "same_artifact_as_live_artifact",
            "used_for_item5_colocation",
            "attestation",
        },
    )
    fixed(related["artifact_attribution"], "fixed-placeholder-development-artifact")
    fixed(related["capture_sha256"], PLACEHOLDER_CAPTURE_SHA256)
    fixed(related["same_artifact_as_live_artifact"], False)
    fixed(related["used_for_item5_colocation"], False)
    fixed(related["attestation"], "historical-reference-not-live-artifact")
    exact_list(data["nonclaims"], NONCLAIMS)


def file_sha256(path: str) -> str:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode))
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def bundle_digests(bundle: str) -> tuple[str, str, str]:
    require(stat.S_ISDIR(os.lstat(bundle).st_mode))
    main_binary = os.path.join(bundle, "Contents", "MacOS", "Tersa")
    broker_binary = os.path.join(
        bundle,
        "Contents",
        "XPCServices",
        "TersaMacTokenBroker.xpc",
        "Contents",
        "MacOS",
        "TersaMacTokenBroker",
    )
    for path in (main_binary, broker_binary):
        require(stat.S_ISREG(os.lstat(path).st_mode))
        require(not os.path.islink(path))

    entries: list[tuple[bytes, str, str]] = []
    for directory, names, files in os.walk(bundle, followlinks=False):
        names[:] = [name for name in names if not os.path.islink(os.path.join(directory, name))]
        for name in files:
            path = os.path.join(directory, name)
            if not stat.S_ISREG(os.lstat(path).st_mode):
                continue
            relative = os.path.relpath(path, bundle).replace(os.sep, "/")
            require(not relative.startswith("../"))
            require("\n" not in relative and "\r" not in relative)
            entries.append((relative.encode("utf-8"), relative, file_sha256(path)))

    require(entries)
    entries.sort(key=lambda entry: entry[0])
    digest = hashlib.sha256()
    for _, relative, file_digest in entries:
        digest.update(f"{file_digest}  {relative}\n".encode("utf-8"))
    return digest.hexdigest(), file_sha256(main_binary), file_sha256(broker_binary)


def digest_json(bundle: str) -> bytes:
    bundle_digest, main_digest, broker_digest = bundle_digests(bundle)
    payload = {
        "bundle_digest_algorithm": "sha256-lc-all-c-regular-file-manifest-v1",
        "bundle_regular_file_manifest_sha256": bundle_digest,
        "main_binary_sha256": main_digest,
        "token_broker_binary_sha256": broker_digest,
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def snapshot(source: str, destination: str) -> None:
    write_exclusive(destination, read_limited_bytes(source, MAX_PAYLOAD_BYTES))


def recompute(output: str, values: list[str]) -> None:
    require(len(values) == 18)
    (
        commit,
        tree,
        bundle_digest,
        main_digest,
        broker_digest,
        signing_tier,
        attribution,
        verification,
        macos_product_version,
        macos_build_version,
        xcode_version,
        xcode_build_version,
        rerun,
        observed_on,
        main_outcome,
        main_result,
        broker_outcome,
        broker_result,
    ) = values
    payload = {
        "candidate": {"commit": commit, "tree": tree},
        "artifact": {
            "attribution": attribution,
            "verification": verification,
            "bundle_digest_algorithm": "sha256-lc-all-c-regular-file-manifest-v1",
            "bundle_regular_file_manifest_sha256": bundle_digest,
            "main_binary_sha256": main_digest,
            "token_broker_binary_sha256": broker_digest,
            "signing_tier": signing_tier,
            "reproducible_from_commit_alone": False,
            "toolchain": {
                "macos_product_version": macos_product_version,
                "macos_build_version": macos_build_version,
                "xcode_version": xcode_version,
                "xcode_build_version": xcode_build_version,
            },
        },
        "wrong_group_probes": {
            "rerun_on_live_artifact": rerun == "true",
            "observed_on": observed_on,
            "main_app": {"outcome": main_outcome, "result": main_result},
            "token_broker": {"outcome": broker_outcome, "result": broker_result},
        },
    }
    validate_recomputed(payload)
    write_exclusive(output, canonical_bytes(payload))


def render(manual_path: str, recomputed_path: str, output_path: str, scope: str) -> None:
    _, manual = read_payload(manual_path)
    validate_manual(manual, scope)
    _, recomputed = read_payload(recomputed_path)
    validate_recomputed(recomputed)
    manifest = {
        "schema_version": 2,
        "evidence_kind": "macos-live-oauth-development",
        "redacted": True,
        "gate_status": "unchanged",
        "candidate": recomputed["candidate"],
        "artifact": recomputed["artifact"],
        "wrong_group_probes": recomputed["wrong_group_probes"],
        "operator_observations": manual["operator_observations"],
        "record_provenance": {
            "producer_validator": "capture-producer-at-current-candidate",
            "emitted_by_capture_at_candidate": True,
        },
        "related_fixed_placeholder_development_capture": {
            "artifact_attribution": "fixed-placeholder-development-artifact",
            "capture_sha256": PLACEHOLDER_CAPTURE_SHA256,
            "same_artifact_as_live_artifact": False,
            "used_for_item5_colocation": False,
            "attestation": "historical-reference-not-live-artifact",
        },
        "nonclaims": NONCLAIMS,
    }
    validate_manifest(manifest, scope)
    write_exclusive(output_path, canonical_bytes(manifest))


def absolute_path(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


def main() -> None:
    require(len(sys.argv) >= 3)
    application_source = sys.argv[1]
    mode = sys.argv[2]
    if mode == "validate":
        require(len(sys.argv) == 4)
        data, payload = read_payload(sys.argv[3])
        scope = requested_scope(application_source)
        if type(payload) is dict and payload.get("record_type") == "macos-live-oauth-development-manual-observation-v2":
            validate_manual(payload, scope)
        else:
            validate_manifest(payload, scope)
            require(data == canonical_bytes(payload))
    elif mode == "canonicalize":
        require(len(sys.argv) == 4)
        _, payload = read_payload(sys.argv[3])
        validate_manifest(payload, requested_scope(application_source))
        sys.stdout.buffer.write(canonical_bytes(payload))
    elif mode == "digest-lines":
        require(len(sys.argv) == 4)
        for value in bundle_digests(sys.argv[3]):
            print(value)
    elif mode == "digest-json":
        require(len(sys.argv) == 4)
        sys.stdout.buffer.write(digest_json(sys.argv[3]))
    elif mode == "scope":
        require(len(sys.argv) == 3)
        print(requested_scope(application_source))
    elif mode == "snapshot":
        require(len(sys.argv) == 5)
        snapshot(sys.argv[3], sys.argv[4])
    elif mode == "recompute":
        require(len(sys.argv) == 22)
        recompute(sys.argv[3], sys.argv[4:])
    elif mode == "render":
        require(len(sys.argv) == 6)
        render(sys.argv[3], sys.argv[4], sys.argv[5], requested_scope(application_source))
    elif mode == "absolute":
        require(len(sys.argv) == 4)
        print(absolute_path(sys.argv[3]))
    else:
        raise ContractError()


try:
    main()
except Exception:
    sys.exit(1)
PY
}

validate_payload() {
  run_contract_python validate "$1" >/dev/null 2>&1 \
    || fail 'schema or redaction validation failed'
}

cleanup() {
  if [ -n "${SCRATCH:-}" ] && [ -d "$SCRATCH" ]; then
    rm -rf "$SCRATCH" >/dev/null 2>&1 || true
  fi
}

absolute_path() {
  run_contract_python absolute "$1" 2>/dev/null
}

capture_toolchain() {
  sw_vers -productVersion >"$SCRATCH/macos-product-version" 2>/dev/null \
    || fail 'macOS product version discovery failed'
  sw_vers -buildVersion >"$SCRATCH/macos-build-version" 2>/dev/null \
    || fail 'macOS build version discovery failed'
  xcodebuild -version >"$SCRATCH/xcode-version.stdout" 2>"$SCRATCH/xcode-version.stderr" \
    || fail 'Xcode version inspection failed'
  [ ! -s "$SCRATCH/xcode-version.stderr" ] \
    || fail 'Xcode version inspection wrote stderr'
  sed -n '1s/^Xcode //p' "$SCRATCH/xcode-version.stdout" >"$SCRATCH/xcode-version" 2>/dev/null \
    || fail 'Xcode version parsing failed'
  sed -n '2s/^Build version //p' "$SCRATCH/xcode-version.stdout" >"$SCRATCH/xcode-build-version" 2>/dev/null \
    || fail 'Xcode build version parsing failed'
  MACOS_PRODUCT_VERSION="$(sed -n '1p' "$SCRATCH/macos-product-version" 2>/dev/null)" \
    || fail 'macOS product version parsing failed'
  MACOS_BUILD_VERSION="$(sed -n '1p' "$SCRATCH/macos-build-version" 2>/dev/null)" \
    || fail 'macOS build version parsing failed'
  XCODE_VERSION="$(sed -n '1p' "$SCRATCH/xcode-version" 2>/dev/null)" \
    || fail 'Xcode version parsing failed'
  XCODE_BUILD_VERSION="$(sed -n '1p' "$SCRATCH/xcode-build-version" 2>/dev/null)" \
    || fail 'Xcode build version parsing failed'
}

capture() {
  [ "$#" -eq 3 ] || {
    usage >&2
    exit 2
  }

  case "$1" in
    /*) ;;
    *) fail 'manual observation must be an absolute path' ;;
  esac
  case "$3" in
    /*) ;;
    *) fail 'capture output must be an absolute path' ;;
  esac
  MANUAL_OBSERVATION_ABSOLUTE="$(absolute_path "$1")" \
    || fail 'manual observation path is invalid'
  OUTPUT_ABSOLUTE="$(absolute_path "$3")" \
    || fail 'capture output path is invalid'
  APP_INPUT="$2"
  case "$MANUAL_OBSERVATION_ABSOLUTE" in
    "$ROOT"|"$ROOT"/*) fail 'manual observation must be outside the repository' ;;
  esac
  case "$OUTPUT_ABSOLUTE" in
    "$ROOT"|"$ROOT"/*) fail 'capture output must be outside the repository' ;;
  esac

  [ ! -L "$APP_INPUT" ] || fail 'capture refuses a symlinked application bundle'
  APP="$(absolute_path "$APP_INPUT")" \
    || fail 'application bundle path is invalid'
  [ "$(basename "$APP")" = 'Tersa.app' ] \
    || fail 'capture requires a Tersa.app bundle'
  [ -d "$APP" ] && [ ! -L "$APP" ] \
    || fail 'capture requires a regular application bundle directory'

  cd "$ROOT"
  WORKTREE_STATUS="$(git status --porcelain --untracked-files=all 2>/dev/null)" \
    || fail 'clean worktree inspection failed'
  [ -z "$WORKTREE_STATUS" ] \
    || fail 'commit-bound capture requires a clean worktree'
  COMMIT="$(git rev-parse HEAD 2>/dev/null)" \
    || fail 'current commit discovery failed'
  TREE="$(git rev-parse 'HEAD^{tree}' 2>/dev/null)" \
    || fail 'current tree discovery failed'

  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/tersa-live-oauth-evidence.XXXXXX" 2>/dev/null)" \
    || fail 'private capture directory creation failed'
  chmod 700 "$SCRATCH" >/dev/null 2>&1 || fail 'private capture directory protection failed'
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM
  MANUAL_SNAPSHOT="$SCRATCH/manual-observation.json"
  run_contract_python snapshot "$MANUAL_OBSERVATION_ABSOLUTE" "$MANUAL_SNAPSHOT" \
    >"$SCRATCH/manual-snapshot.stdout" 2>"$SCRATCH/manual-snapshot.stderr" \
    || fail 'manual observation snapshot failed'
  capture_toolchain

  MAIN_BINARY="$APP/Contents/MacOS/Tersa"
  XPC="$APP/Contents/XPCServices/TersaMacTokenBroker.xpc"
  BROKER_BINARY="$XPC/Contents/MacOS/TersaMacTokenBroker"
  [ -d "$XPC" ] && [ ! -L "$XPC" ] \
    || fail 'capture requires the embedded token broker XPC bundle'
  [ -f "$MAIN_BINARY" ] && [ ! -L "$MAIN_BINARY" ] \
    || fail 'capture requires the main application binary'
  [ -f "$BROKER_BINARY" ] && [ ! -L "$BROKER_BINARY" ] \
    || fail 'capture requires the token broker binary'

  codesign --verify --deep --strict "$APP" \
    >"$SCRATCH/app-signature.stdout" 2>"$SCRATCH/app-signature.stderr" \
    || fail 'application signature verification failed'
  codesign --verify --deep --strict "$XPC" \
    >"$SCRATCH/xpc-signature.stdout" 2>"$SCRATCH/xpc-signature.stderr" \
    || fail 'token broker signature verification failed'
  codesign -dv --verbose=4 "$APP" \
    >"$SCRATCH/app-signature-details.stdout" 2>"$SCRATCH/app-signature-details.stderr" \
    || fail 'application signing-tier inspection failed'
  grep -q '^Authority=Apple Development:' "$SCRATCH/app-signature-details.stderr" 2>/dev/null \
    || fail 'application is not Apple Development signed'
  codesign -dv --verbose=4 "$XPC" \
    >"$SCRATCH/xpc-signature-details.stdout" 2>"$SCRATCH/xpc-signature-details.stderr" \
    || fail 'token broker signing-tier inspection failed'
  grep -q '^Authority=Apple Development:' "$SCRATCH/xpc-signature-details.stderr" 2>/dev/null \
    || fail 'token broker is not Apple Development signed'
  SIGNING_TIER='Apple Development'

  run_contract_python digest-lines "$APP" \
    >"$SCRATCH/pre-probe-digests.stdout" 2>"$SCRATCH/pre-probe-digests.stderr" \
    || fail 'artifact digest calculation failed'
  [ "$(wc -l <"$SCRATCH/pre-probe-digests.stdout" 2>/dev/null | tr -d ' ')" -eq 3 ] \
    || fail 'artifact digest calculation was incomplete'

  printf '%s\n' "$EXPECTED_MAIN_PROBE" >"$SCRATCH/main-probe.expected"
  set +e
  "$MAIN_BINARY" --tersa-keychain-isolation-probe-v1 \
    >"$SCRATCH/main-probe.stdout" 2>"$SCRATCH/main-probe.stderr"
  MAIN_PROBE_STATUS=$?
  set -e
  [ "$MAIN_PROBE_STATUS" -eq 0 ] \
    || fail 'main-app wrong-group probe did not exit 0'
  [ ! -s "$SCRATCH/main-probe.stderr" ] \
    || fail 'main-app wrong-group probe wrote stderr'
  cmp -s "$SCRATCH/main-probe.expected" "$SCRATCH/main-probe.stdout" \
    || fail 'main-app wrong-group probe output did not match the reviewed JSON'
  MAIN_APP_PROBE_OUTCOME='pass'
  MAIN_APP_PROBE_RESULT='missing-entitlement'

  printf '%s\n' "$EXPECTED_BROKER_PROBE" >"$SCRATCH/broker-probe.expected"
  set +e
  "$BROKER_BINARY" --tersa-keychain-isolation-probe-v1 \
    >"$SCRATCH/broker-probe.stdout" 2>"$SCRATCH/broker-probe.stderr"
  BROKER_PROBE_STATUS=$?
  set -e
  [ "$BROKER_PROBE_STATUS" -eq 0 ] \
    || fail 'token broker wrong-group probe did not exit 0'
  [ ! -s "$SCRATCH/broker-probe.stderr" ] \
    || fail 'token broker wrong-group probe wrote stderr'
  cmp -s "$SCRATCH/broker-probe.expected" "$SCRATCH/broker-probe.stdout" \
    || fail 'token broker wrong-group probe output did not match the reviewed JSON'
  TOKEN_BROKER_PROBE_OUTCOME='pass'
  TOKEN_BROKER_PROBE_RESULT='missing-entitlement'

  run_contract_python digest-lines "$APP" \
    >"$SCRATCH/post-probe-digests.stdout" 2>"$SCRATCH/post-probe-digests.stderr" \
    || fail 'post-probe artifact digest calculation failed'
  cmp -s "$SCRATCH/pre-probe-digests.stdout" "$SCRATCH/post-probe-digests.stdout" \
    || fail 'live artifact changed during wrong-group probes'
  BUNDLE_DIGEST="$(sed -n '1p' "$SCRATCH/post-probe-digests.stdout" 2>/dev/null)" \
    || fail 'artifact digest calculation was incomplete'
  MAIN_DIGEST="$(sed -n '2p' "$SCRATCH/post-probe-digests.stdout" 2>/dev/null)" \
    || fail 'artifact digest calculation was incomplete'
  BROKER_DIGEST="$(sed -n '3p' "$SCRATCH/post-probe-digests.stdout" 2>/dev/null)" \
    || fail 'artifact digest calculation was incomplete'
  ARTIFACT_ATTRIBUTION='live-artifact'
  ARTIFACT_VERIFICATION='locally-recomputed-from-live-artifact'
  PROBES_RERUN_ON_LIVE_ARTIFACT=true
  PROBES_OBSERVED_ON='live-artifact'

  RECOMPUTED="$SCRATCH/recomputed.json"
  run_contract_python recompute "$RECOMPUTED" \
    "$COMMIT" "$TREE" "$BUNDLE_DIGEST" "$MAIN_DIGEST" "$BROKER_DIGEST" \
    "$SIGNING_TIER" "$ARTIFACT_ATTRIBUTION" "$ARTIFACT_VERIFICATION" \
    "$MACOS_PRODUCT_VERSION" "$MACOS_BUILD_VERSION" "$XCODE_VERSION" "$XCODE_BUILD_VERSION" \
    "$PROBES_RERUN_ON_LIVE_ARTIFACT" "$PROBES_OBSERVED_ON" \
    "$MAIN_APP_PROBE_OUTCOME" "$MAIN_APP_PROBE_RESULT" \
    "$TOKEN_BROKER_PROBE_OUTCOME" "$TOKEN_BROKER_PROBE_RESULT" \
    >"$SCRATCH/recompute.stdout" 2>"$SCRATCH/recompute.stderr" \
    || fail 'recomputed artifact observation emission failed'
  run_contract_python render "$MANUAL_SNAPSHOT" "$RECOMPUTED" "$OUTPUT_ABSOLUTE" \
    >"$SCRATCH/render.stdout" 2>"$SCRATCH/render.stderr" \
    || fail 'redacted manifest emission failed'
  printf '%s\n' 'capture=pass'
}

case "${1:-}" in
  --validate)
    [ "$#" -eq 2 ] || {
      usage >&2
      exit 2
    }
    validate_payload "$2"
    printf '%s\n' 'validation=pass'
    ;;
  --canonicalize)
    [ "$#" -eq 2 ] || {
      usage >&2
      exit 2
    }
    run_contract_python canonicalize "$2" || fail 'schema or redaction validation failed'
    ;;
  --digest)
    [ "$#" -eq 2 ] || {
      usage >&2
      exit 2
    }
    BUNDLE_ABSOLUTE="$(absolute_path "$2")" || fail 'application bundle path is invalid'
    run_contract_python digest-json "$BUNDLE_ABSOLUTE" || fail 'artifact digest calculation failed'
    ;;
  --scope)
    [ "$#" -eq 1 ] || {
      usage >&2
      exit 2
    }
    run_contract_python scope || fail 'requested scope discovery failed'
    ;;
  --capture)
    shift
    capture "$@"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
