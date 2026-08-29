#!/usr/bin/env python3
"""Contract tests for the redacted macOS live OAuth development evidence tool."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "apple/scripts/capture-macos-live-oauth-dev-evidence.sh"
MANIFEST_PATH = (
    ROOT
    / "docs/quality/evidence/98fdfa455d02c8278b024dead93f34df1df04895"
    / "macos-live-oauth-development.json"
)
APPLICATION_SCOPE_SOURCE = ROOT / "crates/application/src/oauth.rs"
DOCUMENTATION = ROOT / "docs/quality/macos-live-oauth-dev-evidence.md"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"


def current_requested_scope() -> str:
    source = APPLICATION_SCOPE_SOURCE.read_text(encoding="utf-8")
    match = re.search(r'^pub const REQUESTED_SCOPE: &str = "([^"\\]+)";$', source, re.MULTILINE)
    assert match is not None
    return match.group(1)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def known_bundle_digest(bundle: Path) -> tuple[str, str, str]:
    main = bundle / "Contents/MacOS/Tersa"
    broker = bundle / "Contents/XPCServices/TersaMacTokenBroker.xpc/Contents/MacOS/TersaMacTokenBroker"
    entries: list[tuple[bytes, str, str]] = []
    for directory, names, files in os.walk(bundle, followlinks=False):
        names[:] = [name for name in names if not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                continue
            relative = path.relative_to(bundle).as_posix()
            if "\n" in relative or "\r" in relative:
                raise AssertionError("known digest rejects line-breaking paths")
            entries.append((relative.encode("utf-8"), relative, sha256_file(path)))
    digest = hashlib.sha256()
    for _, relative, file_digest in sorted(entries):
        digest.update(f"{file_digest}  {relative}\n".encode("utf-8"))
    return digest.hexdigest(), sha256_file(main), sha256_file(broker)


def delete_path(value: object, path: tuple[object, ...]) -> None:
    cursor = value
    for part in path[:-1]:
        cursor = cursor[part]  # type: ignore[index]
    del cursor[path[-1]]  # type: ignore[index]


def required_paths(value: object, prefix: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    paths: list[tuple[object, ...]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            path = prefix + (key,)
            paths.append(path)
            paths.extend(required_paths(nested, path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            path = prefix + (index,)
            paths.append(path)
            paths.extend(required_paths(nested, path))
    return paths


class LiveOAuthDevelopmentEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest_bytes = MANIFEST_PATH.read_bytes()
        cls.manifest = json.loads(cls.manifest_bytes.decode("utf-8"))
        cls.scope = current_requested_scope()

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["sh", str(SCRIPT), *arguments],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )

    def validate_bytes(self, data: bytes) -> subprocess.CompletedProcess[bytes]:
        with tempfile.TemporaryDirectory() as directory:
            payload_path = Path(directory) / "payload.json"
            payload_path.write_bytes(data)
            return self.invoke("--validate", str(payload_path))

    def validate_object(self, payload: object) -> subprocess.CompletedProcess[bytes]:
        return self.validate_bytes(
            (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        )

    def assert_invalid(self, payload: object) -> None:
        result = self.validate_object(payload)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"error: schema or redaction validation failed\n")

    def manual_observation(self) -> dict[str, object]:
        return {
            "record_type": "macos-live-oauth-development-manual-observation-v2",
            "operator_observations": copy.deepcopy(self.manifest["operator_observations"]),
        }

    def test_committed_bytes_are_canonical_and_validate_without_roundtrip(self) -> None:
        self.assertLessEqual(len(self.manifest_bytes), 65_536)
        self.assertTrue(self.manifest_bytes.endswith(b"\n"))
        direct = self.invoke("--validate", str(MANIFEST_PATH))
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assertEqual(direct.stdout, b"validation=pass\n")
        canonical = self.invoke("--canonicalize", str(MANIFEST_PATH))
        self.assertEqual(canonical.returncode, 0, canonical.stderr)
        self.assertEqual(canonical.stdout, self.manifest_bytes)

    def test_duplicate_keys_and_noncanonical_bytes_fail_before_any_json_roundtrip(self) -> None:
        duplicate = b'{"schema_version":2,"schema_version":2}\n'
        result = self.validate_bytes(duplicate)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"error: schema or redaction validation failed\n")
        noncanonical = self.manifest_bytes.replace(b'\n  "artifact"', b'\n\t"artifact"', 1)
        direct_noncanonical = self.validate_bytes(noncanonical)
        self.assertNotEqual(direct_noncanonical.returncode, 0)
        self.assertEqual(direct_noncanonical.stderr, b"error: schema or redaction validation failed\n")

    def test_scope_is_read_from_the_current_application_constant(self) -> None:
        scope = self.invoke("--scope")
        self.assertEqual(scope.returncode, 0, scope.stderr)
        self.assertEqual(scope.stdout, f"{self.scope}\n".encode("utf-8"))
        lifecycle = self.manifest["operator_observations"]["oauth_lifecycle"]
        self.assertEqual(lifecycle["authorization_request_scope"], self.scope)
        self.assertEqual(lifecycle["callback_scopes"], self.scope.split(" "))
        self.assertNotIn(self.scope, SCRIPT.read_text(encoding="utf-8"))

    def test_manual_observation_validates_without_bundle_or_provider(self) -> None:
        result = self.validate_object(self.manual_observation())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"validation=pass\n")

    def test_digest_mode_uses_the_actual_bundle_algorithm_and_ignores_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Tersa.app"
            main = bundle / "Contents/MacOS/Tersa"
            broker = bundle / "Contents/XPCServices/TersaMacTokenBroker.xpc/Contents/MacOS/TersaMacTokenBroker"
            resource = bundle / "Contents/Resources/A.txt"
            for path, data in ((main, b"main"), (broker, b"broker"), (resource, b"resource")):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            (bundle / "Contents/Resources/ignored-link").symlink_to(resource)
            bundle_digest, main_digest, broker_digest = known_bundle_digest(bundle)
            expected = {
                "bundle_digest_algorithm": "sha256-lc-all-c-regular-file-manifest-v1",
                "bundle_regular_file_manifest_sha256": bundle_digest,
                "main_binary_sha256": main_digest,
                "token_broker_binary_sha256": broker_digest,
            }
            result = self.invoke("--digest", str(bundle))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout,
                (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
            )
            (bundle / "Contents/Resources/bad\nname").write_bytes(b"bad")
            invalid = self.invoke("--digest", str(bundle))
            self.assertNotEqual(invalid.returncode, 0)
            self.assertEqual(invalid.stdout, b"")
            self.assertEqual(invalid.stderr, b"error: artifact digest calculation failed\n")

    def test_current_recorded_facts_and_observation_boundary(self) -> None:
        artifact = self.manifest["artifact"]
        operator = self.manifest["operator_observations"]
        lifecycle = operator["oauth_lifecycle"]
        self.assertEqual(self.manifest["schema_version"], 2)
        self.assertEqual(self.manifest["evidence_kind"], "macos-live-oauth-development")
        self.assertEqual(
            self.manifest["candidate"],
            {
                "commit": "98fdfa455d02c8278b024dead93f34df1df04895",
                "tree": "bc9060d62e64ad96363b6966ec8827ccb9f87939",
            },
        )
        self.assertEqual(artifact["attribution"], "live-artifact")
        self.assertEqual(artifact["verification"], "locally-recomputed-from-live-artifact")
        self.assertEqual(
            artifact["bundle_regular_file_manifest_sha256"],
            "52916f779a2633cf5a1e4ea21cd78e852cb690a7fb55b2e4aff11b503163e1ae",
        )
        self.assertEqual(
            artifact["main_binary_sha256"],
            "2eacceb1f3ca07ca685f7e5ccada362d56354605be5e86682fb5da6a66307a43",
        )
        self.assertEqual(
            artifact["token_broker_binary_sha256"],
            "21038117225f610c4d54cb1151ea82bad80c05af47018fbc1f567505f4658047",
        )
        self.assertEqual(operator["attestation"], "operator-attested-not-locally-recomputable")
        self.assertTrue(operator["token_path"]["attested_not_proven"])
        self.assertTrue(operator["production_archive_surface"]["attested_not_proven"])
        self.assertEqual(
            self.manifest["record_provenance"],
            {
                "emitted_by_capture_at_candidate": False,
                "producer_validator": "later-tooling-canonicalization",
            },
        )
        self.assertEqual(lifecycle["initial_sync"], {"message_count": 50, "outcome": "pass"})
        self.assertEqual(lifecycle["stored_credential_refresh"], {"outcome": "pass", "temperature": "warm"})
        self.assertEqual(
            lifecycle["stored_credential_refresh_after_relaunch"],
            {"observed": False, "outcome": "not-run"},
        )

    def test_scope_outcomes_artifact_attribution_and_refresh_boundaries_fail_closed(self) -> None:
        cases: list[tuple[tuple[object, ...], object]] = [
            (("evidence_kind",), "different-evidence"),
            (("artifact", "attribution"), "fixed-placeholder-development-artifact"),
            (("wrong_group_probes", "observed_on"), "fixed-placeholder-development-artifact"),
            (("wrong_group_probes", "rerun_on_live_artifact"), False),
            (("operator_observations", "oauth_lifecycle", "authorization_request_scope"), "openid"),
            (("operator_observations", "oauth_lifecycle", "callback_scopes"), ["openid"]),
            (("operator_observations", "oauth_lifecycle", "exchange"), "failed"),
            (("operator_observations", "oauth_lifecycle", "stored_credential_refresh", "temperature"), "cold"),
            (("operator_observations", "oauth_lifecycle", "stored_credential_refresh_after_relaunch", "observed"), True),
            (("related_fixed_placeholder_development_capture", "same_artifact_as_live_artifact"), True),
            (("related_fixed_placeholder_development_capture", "used_for_item5_colocation"), True),
        ]
        for path, replacement in cases:
            with self.subTest(path=path):
                payload = copy.deepcopy(self.manifest)
                cursor = payload
                for part in path[:-1]:
                    cursor = cursor[part]
                cursor[path[-1]] = replacement
                self.assert_invalid(payload)

    def test_record_provenance_pairs_are_closed_and_boolean_typed(self) -> None:
        cases = [
            {
                "producer_validator": "later-tooling-canonicalization",
                "emitted_by_capture_at_candidate": True,
            },
            {
                "producer_validator": "capture-producer-at-current-candidate",
                "emitted_by_capture_at_candidate": False,
            },
            {
                "producer_validator": "unknown-producer-validator",
                "emitted_by_capture_at_candidate": False,
            },
            {
                "producer_validator": "capture-producer-at-current-candidate",
                "emitted_by_capture_at_candidate": 1,
            },
            {
                "producer_validator": "later-tooling-canonicalization",
                "emitted_by_capture_at_candidate": 0,
            },
        ]
        for provenance in cases:
            with self.subTest(provenance=provenance):
                payload = copy.deepcopy(self.manifest)
                payload["record_provenance"] = provenance
                self.assert_invalid(payload)
        capture_provenance = {
            "producer_validator": "capture-producer-at-current-candidate",
            "emitted_by_capture_at_candidate": True,
        }
        payload = copy.deepcopy(self.manifest)
        payload["record_provenance"] = capture_provenance
        result = self.validate_object(payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"validation=pass\n")
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('validate_record_provenance(data["record_provenance"])', script)
        self.assertIn(
            'require(type(data["emitted_by_capture_at_candidate"]) is bool)',
            script,
        )

    def test_redaction_rejects_sensitive_classes(self) -> None:
        for value in [
            "operator@example.test",
            "/private/redacted/observation.json",
            "1ABCDE1234",
            "Apple Development: Example",
            "account-identifier-42",
        ]:
            with self.subTest(value=value):
                payload = copy.deepcopy(self.manifest)
                payload["artifact"]["toolchain"]["macos_build_version"] = value
                self.assert_invalid(payload)

    def test_nonclaims_are_single_closed_validator_contract(self) -> None:
        payload = copy.deepcopy(self.manifest)
        payload["nonclaims"][0] = "Testing refresh tokens never expire."
        self.assert_invalid(payload)
        payload = copy.deepcopy(self.manifest)
        payload["nonclaims"].pop()
        self.assert_invalid(payload)

    def test_operator_and_recomputed_planes_cannot_be_mixed(self) -> None:
        payload = copy.deepcopy(self.manifest)
        payload["operator_observations"]["toolchain"] = payload["artifact"]["toolchain"]
        self.assert_invalid(payload)
        payload = copy.deepcopy(self.manifest)
        payload["artifact"]["token_path"] = payload["operator_observations"]["token_path"]
        self.assert_invalid(payload)

    def test_each_required_full_and_manual_field_removal_fails_closed(self) -> None:
        for label, source in [("full", self.manifest), ("manual", self.manual_observation())]:
            paths = required_paths(source)
            self.assertGreater(len(paths), 30)
            for path in paths:
                with self.subTest(label=label, path=path):
                    payload = copy.deepcopy(source)
                    delete_path(payload, path)
                    self.assert_invalid(payload)

    def test_static_contract_uses_a_closed_local_configuration_and_command_surface(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(script.count("local.xcconfig"), 1)
        self.assertIn('fixed(data["source"], "apple/local.xcconfig-values-redacted")', script)
        self.assertNotRegex(script, r"(?m)^\s*(?:with\s+)?open\(")
        for command in ("curl", "osascript", "security", "defaults"):
            self.assertNotIn(f"{command} ", script)
        self.assertIn("os.O_EXCL", script)
        self.assertIn("MANUAL_OBSERVATION_ABSOLUTE", script)
        self.assertIn("manual observation must be outside the repository", script)
        self.assertIn("capture output must be outside the repository", script)
        self.assertNotIn("install -m", script)

    def test_ci_and_documentation_expose_deterministic_validation_only(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        documentation = DOCUMENTATION.read_text(encoding="utf-8")
        self.assertIn("python3 -m unittest scripts/test_macos_live_oauth_dev_evidence.py", workflow)
        self.assertIn("sh -n apple/scripts/capture-macos-live-oauth-dev-evidence.sh", workflow)
        self.assertIn("--validate\n          docs/quality/evidence/98fdfa455d02c8278b024dead93f34df1df04895/macos-live-oauth-development.json", workflow)
        self.assertIn("/tmp/tersa-live-oauth-observation.json", documentation)
        self.assertIn("clean worktree", documentation)
        self.assertIn("operator-attested-not-locally-recomputable", documentation)


if __name__ == "__main__":
    unittest.main()
