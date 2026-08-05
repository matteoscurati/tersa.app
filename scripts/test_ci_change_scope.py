#!/usr/bin/env python3
"""Table-driven tests for scripts/ci-change-scope.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).with_name("ci-change-scope.py")
ROOT = SCRIPT.parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
DEVELOPMENT_DOC = ROOT / "docs" / "development.md"
SPEC = importlib.util.spec_from_file_location("ci_change_scope", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

NAMES = tuple(field.name for field in MODULE.fields(MODULE.Scope))
ALL = set(NAMES)
ACTIVE_OUTPUTS = ("rust_linux", "rust_macos", "policy", "product_apple", "notices")
RETIRED_SCOPE_NAMES = (
    "slint",
    "dioxus",
    "sqlcipher",
    "search",
    "mime",
    "mime_fuzz",
    "blob",
    "full_evidence",
    "run_full_evidence",
)
# Retired diagnostic CI routes, validators, and evidence helpers must not return.
RETIRED_WORKFLOW_TOKENS = (
    "workflow_dispatch",
    "evidence_suite",
    "EVIDENCE_COMMIT_SHA",
    "run_full_evidence",
    "manual_evidence_gate",
    "Manual evidence gate",
    "actions/upload-artifact@",
    "ci-change-scope.py --full",
    "ci-change-scope.py --baseline",
    "slint-apple-evidence",
    "dioxus-apple-evidence",
    "sqlcipher-apple-evidence",
    "search-apple-evidence",
    "mime-apple-evidence",
    "mime-parser-fuzz",
    "blob-apple-evidence",
    "Slint Apple evidence",
    "Dioxus Apple evidence",
    "SQLCipher Apple evidence",
    "Search Apple evidence",
    "MIME and HTML Apple evidence",
    "Deterministic MIME parser fuzz",
    "Crash-safe AEAD blob Apple evidence",
    "oauth-pkce-feasibility-evidence",
    "slint-spike-evidence",
    "dioxus-spike-evidence",
    "sqlcipher-feasibility-evidence",
    "encrypted-search-feasibility-evidence",
    "mime-html-feasibility-evidence",
    "mime-parser-fuzz-evidence",
    "crash-safe-aead-blob-feasibility-evidence",
    "verify-oauth-feasibility.sh",
    "verify-m0-gates.py",
    "capture-slint-evidence.sh",
    "capture-dioxus-evidence.sh",
    "capture-dioxus-device-evidence.sh",
    "build-slint-executable.sh",
    "build-dioxus-executable.sh",
    "prepare-verified-skia.sh",
    "verify-rust-skia-notices.py",
    "verify-dioxus-runtime.py",
    "verify-dioxus-vendor.py",
    "verify-dioxus-device-evidence.py",
    "write-evidence-manifest.py",
    "rust-skia",
    "SKIA_BINARIES_URL",
    "TersaSlintMac",
    "TersaSlintIOS",
    "TersaDioxusMac",
    "TersaDioxusIOS",
    "2026-08-15",
    "verify-sqlcipher-feasibility.sh",
    "verify-search-feasibility.sh",
    "verify-mime-feasibility.sh",
    "verify-mime-fuzz.sh",
    "verify-blob-feasibility.sh",
)
RETIRED_DEVELOPMENT_DOC_TOKENS = (
    "workflow_dispatch",
    "evidence_suite",
    "Manual evidence gate",
    "gh workflow run CI",
    "Apple evidence job",
    # Retired MIME/fuzz diagnostic runbooks and package names must not return.
    "tersa-mime-spike",
    "TersaMimeMac",
    "TersaMimeIOS",
    "verify-mime-feasibility.sh",
    "verify-mime-fuzz.sh",
    "cargo-fuzz",
    "libfuzzer-sys",
    # Combined OAuth verifier is obsolete after ADR-0024; do not recommend it.
    "After creating the unsigned base archives, run:",
    "```sh\nsh apple/scripts/verify-oauth-feasibility.sh\n```",
)
# Active product docs that must not reintroduce retired operational CI routes.
ACTIVE_PRODUCT_DOCS = (
    ROOT / "docs" / "history" / "m0-summary.md",
    ROOT / "docs" / "quality" / "macos-acceptance.md",
    ROOT / "docs" / "quality" / "macos-performance.md",
    ROOT / "docs" / "quality" / "ci-macos-consolidation.md",
    ROOT / "docs" / "release" / "apple-distribution.md",
    ROOT / "docs" / "development.md",
)
# Visible full-fanout product jobs (plus scope/gate) after macOS consolidation.
FULL_FANOUT_JOB_IDS = (
    "changes",
    "apple_product",
    "rust_linux",
    "policy",
    "macos_quality",
    "ci_gate",
)
RETIRED_MACOS_JOB_IDS = (
    "notices",
    "rust_macos",
)
RETIRED_MACOS_JOB_NAMES = (
    "Third-party notices",
    "Rust (macOS)",
)
RETIRED_PRODUCT_DOC_OPERATIONAL_CLAIMS = (
    "verify-m0-gates.py",
    "gate-register.json",
    "docs/m0/",
    "slint-apple-evidence",
    "dioxus-apple-evidence",
    "mime-apple-evidence",
    "mime-parser-fuzz",
    "blob-apple-evidence",
    "verify-oauth-feasibility.sh",
    "actions/upload-artifact@",
)
# Architecture docs that still carry operational CI/local evidence claims.
ARCHITECTURE_REGRESSION_DOCS = (
    ROOT / "docs" / "architecture" / "adr-0005-dioxus-diagnostic-runtime.md",
    ROOT / "docs" / "architecture" / "adr-0006-product-constraints.md",
    ROOT / "docs" / "architecture" / "adr-0010-dioxus-sandboxed-navigation-classification.md",
    ROOT / "docs" / "architecture" / "dependency-rules.md",
)
RETIRED_ARCHITECTURE_OPERATIONAL_CLAIMS = (
    "CI verifies every Apple target's resolved feature set",
    "while Apple CI\ncross-builds the same locked graphs",
    "so CI can retain evidence",
    "CI's policy job runs the Python gate validator",
    "python3 scripts/verify-m0-gates.py --self-test",
)


class ChangeScopeTests(unittest.TestCase):
    def test_active_scope_contract(self) -> None:
        self.assertEqual(NAMES, ACTIVE_OUTPUTS)
        for retired in RETIRED_SCOPE_NAMES:
            self.assertNotIn(retired, NAMES)

    def test_retired_ui_helpers_are_not_control_paths(self) -> None:
        for retired in (
            "scripts/write-evidence-manifest.py",
            "apple/scripts/prepare-verified-skia.sh",
            "apple/scripts/verify-rust-skia-notices.py",
            "apple/scripts/verify-dioxus-runtime.py",
            "apple/scripts/build-slint-executable.sh",
            "apple/scripts/build-dioxus-executable.sh",
            "apple/scripts/capture-slint-evidence.sh",
            "apple/scripts/capture-dioxus-evidence.sh",
            "apple/scripts/capture-dioxus-device-evidence.sh",
            "apple/scripts/verify-sqlcipher-feasibility.sh",
            "apple/scripts/verify-search-feasibility.sh",
            "apple/scripts/verify-blob-feasibility.sh",
        ):
            with self.subTest(path=retired):
                self.assertNotIn(retired, MODULE.CI_CONTROL_PATHS)

    def test_path_table(self) -> None:
        cases = (
            ("empty input fails closed", [], ALL),
            ("unknown path fails closed", ["new-area/input.txt"], ALL),
            ("ambiguous path fails closed", ["../Cargo.toml"], ALL),
            ("root manifest fans out", ["Cargo.toml"], ALL),
            (
                "Apple project enables xtask policy and product",
                ["apple/project.yml"],
                {"rust_linux", "policy", "product_apple"},
            ),
            (
                "token broker Swift enables xtask policy and product",
                ["apple/macos-token-broker/TokenBrokerProtocol.swift"],
                {"rust_linux", "policy", "product_apple"},
            ),
            (
                "entitlement plist enables xtask policy and product",
                ["apple/macos-token-broker/TersaMacTokenBroker.entitlements"],
                {"rust_linux", "policy", "product_apple"},
            ),
            (
                "product macOS AppDelegate enables xtask policy and product",
                ["apple/macos/AppDelegate.swift"],
                {"rust_linux", "policy", "product_apple"},
            ),
            (
                "product macOS view-model enables xtask policy and product",
                ["apple/macos/AccountConnectionViewModel.swift"],
                {"rust_linux", "policy", "product_apple"},
            ),
            (
                "retired MIME entitlements use generic Apple entitlement routing",
                ["apple/mime-macos/TersaMimeMac.entitlements"],
                {"rust_linux", "policy", "product_apple"},
            ),
            (
                "generic Apple entitlements enable xtask policy and product",
                ["apple/ios/TersaIOS.entitlements"],
                {"rust_linux", "policy", "product_apple"},
            ),
            ("shared Apple script fans out", ["apple/scripts/build-rust-staticlib.sh"], ALL),
            (
                "retired spike source fails closed without a named diagnostic lane",
                ["apps/slint-spike/ui/tersa.slint"],
                ALL,
            ),
            (
                "retired spike manifest fails closed without a named diagnostic lane",
                ["apps/dioxus-spike/Cargo.toml"],
                ALL,
            ),
            (
                "retired fuzz paths fail closed without a named diagnostic lane",
                ["fuzz/fuzz_targets/mime_display.rs"],
                ALL,
            ),
            (
                "retired MIME spike source fails closed without a named diagnostic lane",
                ["apps/mime-spike/src/main.rs"],
                ALL,
            ),
            (
                "retired MIME spike manifest fails closed without a named diagnostic lane",
                ["apps/mime-spike/Cargo.toml"],
                ALL,
            ),
            ("notices are isolated", ["apple/licenses/sqlcipher-notices.txt"], {"notices"}),
            ("product notice config", ["about-bridge.toml"], {"product_apple", "notices"}),
            (
                "retired spike notice config fails closed",
                ["about.toml"],
                ALL,
            ),
            (
                "retired dioxus notice config fails closed",
                ["about-dioxus.toml"],
                ALL,
            ),
            (
                "retired sqlcipher diagnostic notice config fails closed",
                ["about-sqlcipher.toml"],
                ALL,
            ),
            (
                "retired search diagnostic notice config fails closed",
                ["about-search.toml"],
                ALL,
            ),
            (
                "retired blob diagnostic notice config fails closed",
                ["about-blob.toml"],
                ALL,
            ),
            (
                "retired MIME diagnostic notice config fails closed",
                ["about-mime.toml"],
                ALL,
            ),
            (
                "retired sqlcipher spike source fails closed without a named diagnostic lane",
                ["apps/sqlcipher-spike/src/main.rs"],
                ALL,
            ),
            (
                "retired search spike source fails closed without a named diagnostic lane",
                ["apps/search-spike/src/main.rs"],
                ALL,
            ),
            (
                "retired blob spike source fails closed without a named diagnostic lane",
                ["apps/blob-spike/src/main.rs"],
                ALL,
            ),
            (
                "retired sqlcipher diagnostic notice output stays notices-only",
                ["apple/licenses/THIRD_PARTY_NOTICES-sqlcipher-macos.txt"],
                {"notices"},
            ),
            (
                "retired search diagnostic notice output stays notices-only",
                ["apple/licenses/THIRD_PARTY_NOTICES-search-macos.txt"],
                {"notices"},
            ),
            (
                "retired blob diagnostic notice output stays notices-only",
                ["apple/licenses/THIRD_PARTY_NOTICES-blob-macos.txt"],
                {"notices"},
            ),
            (
                "retired MIME diagnostic notice output stays notices-only",
                ["apple/licenses/THIRD_PARTY_NOTICES-mime-macos.txt"],
                {"notices"},
            ),
            (
                "shared domain enables product without diagnostic lanes",
                ["crates/domain/src/lib.rs"],
                {"rust_linux", "policy", "product_apple"},
            ),
            (
                "shared presentation enables product without diagnostic lanes",
                ["crates/presentation/src/lib.rs"],
                {"rust_linux", "policy", "product_apple"},
            ),
            (
                "adapter changes build product",
                ["adapters/keychain-macos/src/lib.rs"],
                {"rust_linux", "rust_macos", "policy", "product_apple"},
            ),
            (
                "adapter manifest also checks notices",
                ["adapters/keychain-macos/Cargo.toml"],
                {"rust_linux", "rust_macos", "policy", "product_apple", "notices"},
            ),
            (
                "Apple Rust bridge checks both hosts",
                ["apple/rust-bridge/src/lib.rs"],
                {"rust_linux", "rust_macos", "policy", "product_apple"},
            ),
            ("macOS CLI checks both hosts", ["apps/cli-macos/src/main.rs"], {"rust_linux", "rust_macos", "policy"}),
            (
                "ordinary non-macOS Apple path stays minimal",
                ["apple/ios/AppDelegate.swift"],
                {"product_apple"},
            ),
            (
                "rename source and destination cannot hide a product path",
                ["apple/macos/Removed.swift", "docs/Removed.md"],
                {"rust_linux", "policy", "product_apple"},
            ),
            ("docs stay out", ["docs/development.md"], set()),
            ("xtask is executable CI control and fans out", ["xtask/src/main.rs"], ALL),
            ("xtask cargo manifest is executable CI control and fans out", ["xtask/Cargo.toml"], ALL),
            ("workflow control fans out", [".github/workflows/ci.yml"], ALL),
            (
                "other workflow files fan out",
                [".github/workflows/release.yml"],
                ALL,
            ),
            ("DCO checker is executable CI control and fans out", ["scripts/check-dco.py"], ALL),
            ("DCO tests are executable CI control and fan out", ["scripts/test_check_dco.py"], ALL),
            ("scope classifier is executable CI control and fans out", ["scripts/ci-change-scope.py"], ALL),
            ("scope tests are executable CI control and fan out", ["scripts/test_ci_change_scope.py"], ALL),
            (
                "performance reporter is executable CI control and fans out",
                ["scripts/macos-performance-report.py"],
                ALL,
            ),
            (
                "performance tests are executable CI control and fan out",
                ["scripts/test_macos_performance_report.py"],
                ALL,
            ),
            (
                "GitHub issue templates stay lightweight",
                [".github/ISSUE_TEMPLATE/bug_report.md"],
                set(),
            ),
            (
                "GitHub pull request template stays lightweight",
                [".github/PULL_REQUEST_TEMPLATE.md"],
                set(),
            ),
            (
                "GitHub CODEOWNERS stays lightweight",
                [".github/CODEOWNERS"],
                set(),
            ),
            (
                "GitHub composite actions fail closed through full fanout",
                [".github/actions/ci/action.yml"],
                ALL,
            ),
            (
                "unknown GitHub control path fails closed through full fanout",
                [".github/unknown-control.yml"],
                ALL,
            ),
            (
                "retired M0 gate helper fails closed through unknown-path fallback",
                ["scripts/verify-m0-gates.py"],
                ALL,
            ),
            (
                "consolidated M0 history is docs-only",
                ["docs/history/m0-summary.md"],
                set(),
            ),
            (
                "active macOS acceptance protocol is docs-only",
                ["docs/quality/macos-acceptance.md"],
                set(),
            ),
            (
                "active macOS performance protocol is docs-only",
                ["docs/quality/macos-performance.md"],
                set(),
            ),
            (
                "active CI macOS consolidation protocol is docs-only",
                ["docs/quality/ci-macos-consolidation.md"],
                set(),
            ),
            (
                "active Apple distribution protocol is docs-only",
                ["docs/release/apple-distribution.md"],
                set(),
            ),
            (
                "retired evidence-manifest helper is not a control path",
                ["scripts/write-evidence-manifest.py"],
                ALL,
            ),
            (
                "retired rust-skia notice stays isolated to the notices lane",
                ["apple/licenses/rust-skia-notices.txt"],
                {"notices"},
            ),
            (
                "multiple product paths union scopes",
                ["apple/licenses/sqlcipher-notices.txt", "xtask/src/main.rs"],
                ALL,
            ),
        )
        for label, paths, expected in cases:
            with self.subTest(label=label):
                scope = MODULE.classify(paths)
                actual = {name for name in NAMES if getattr(scope, name)}
                self.assertEqual(actual, expected)

    def test_cli_rejects_retired_modes(self) -> None:
        for flag in ("--full", "--baseline"):
            with self.subTest(flag=flag):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), flag],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_cli_reads_stdin_and_emits_github_output_format(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input="apple/rust-bridge/src/lib.rs\n",
            text=True,
            capture_output=True,
            check=True,
        )
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), len(ACTIVE_OUTPUTS))
        self.assertEqual([line.split("=", 1)[0] for line in lines], list(ACTIVE_OUTPUTS))
        values = dict(line.split("=", 1) for line in lines)
        self.assertEqual(
            values,
            {
                "rust_linux": "true",
                "rust_macos": "true",
                "policy": "true",
                "product_apple": "true",
                "notices": "false",
            },
        )
        self.assertTrue(all(value in {"true", "false"} for value in values.values()))

    def test_workflow_disables_rename_detection(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            'git diff --no-renames --name-only "$merge_base" "$HEAD_SHA"',
            workflow,
        )

    def test_workflow_runs_expensive_pr_jobs_only_after_draft(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("types: [opened, synchronize, reopened, ready_for_review]", workflow)
        self.assertIn("github.event.pull_request.draft == false", workflow)

    def test_workflow_is_product_only_pull_request_and_merge_queue_ci(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("\n  push:\n", workflow)
        self.assertNotIn("github.event_name == 'push'", workflow)
        self.assertIn("\n  pull_request:\n", workflow)
        self.assertIn("\n  merge_group:\n", workflow)
        self.assertIn("\n    name: CI gate\n", workflow)
        merge_group_start = workflow.index("            merge_group)\n")
        merge_group_end = workflow.index("            pull_request)\n", merge_group_start)
        merge_group_branch = workflow[merge_group_start:merge_group_end]
        self.assertIn(
            'python3 scripts/ci-change-scope.py < /dev/null >> "$GITHUB_OUTPUT"',
            merge_group_branch,
        )
        self.assertNotIn("git diff", merge_group_branch)
        self.assertNotIn("|", merge_group_branch)
        self.assertNotIn("--full", merge_group_branch)
        self.assertNotIn("--baseline", merge_group_branch)
        for token in RETIRED_WORKFLOW_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token, workflow)

    def test_workflow_disables_all_github_actions_caches(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        rust_setup_count = workflow.count("uses: actions-rust-lang/setup-rust-toolchain@")
        self.assertGreater(rust_setup_count, 0)
        self.assertEqual(workflow.count("          cache: false\n"), rust_setup_count)
        self.assertNotIn("actions/cache@", workflow)
        self.assertNotIn("Swatinem/rust-cache@", workflow)
        self.assertNotIn("cache-save-if:", workflow)
        self.assertNotIn("cache-on-failure:", workflow)

    def test_workflow_path_scopes_active_jobs(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for output in ACTIVE_OUTPUTS:
            self.assertIn(f"      {output}: ${{{{ steps.scope.outputs.{output} }}}}", workflow)
        # Per-lane jobs keep direct output gates; macOS quality ORs rust_macos and notices.
        for output in ("rust_linux", "policy", "product_apple"):
            self.assertIn(f"if: ${{{{ needs.changes.outputs.{output} == 'true' }}}}", workflow)
        self.assertIn(
            "if: ${{ needs.changes.outputs.rust_macos == 'true' || needs.changes.outputs.notices == 'true' }}",
            workflow,
        )
        self.assertNotIn("matrix:\n        os: [ubuntu-24.04, macos-15]", workflow)
        for job_id in RETIRED_MACOS_JOB_IDS:
            self.assertNotIn(f"\n  {job_id}:\n", workflow)
        for job_name in RETIRED_MACOS_JOB_NAMES:
            self.assertNotIn(f"name: {job_name}", workflow)

    def test_workflow_keeps_dco_in_the_required_control_job(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        changes_start = workflow.index("  changes:\n")
        changes_end = workflow.index("\n  apple_product:\n", changes_start)
        changes_job = workflow[changes_start:changes_end]
        self.assertIn("    timeout-minutes: 5\n", changes_job)
        self.assertIn("python3 scripts/check-dco.py", changes_job)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/test_ci_change_scope.py", changes_job)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/test_check_dco.py", changes_job)
        self.assertIn(
            "PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/test_macos_performance_report.py",
            changes_job,
        )
        self.assertNotIn("verify-m0-gates.py", workflow)
        self.assertNotIn("write-evidence-manifest.py", workflow)
        self.assertNotIn("prepare-verified-skia.sh", workflow)
        self.assertNotIn("rust-skia", workflow)
        self.assertNotIn("SKIA_BINARIES_URL", workflow)
        self.assertNotIn("TersaSlint", workflow)
        self.assertNotIn("TersaDioxus", workflow)
        self.assertNotIn("2026-08-15", workflow)
        self.assertNotIn("cargo run --locked --package xtask -- dco", workflow)

    def test_development_doc_drops_retired_manual_ci_interface(self) -> None:
        development = DEVELOPMENT_DOC.read_text(encoding="utf-8")
        for token in RETIRED_DEVELOPMENT_DOC_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token, development)

    def test_active_product_docs_drop_retired_operational_ci_claims(self) -> None:
        for path in ACTIVE_PRODUCT_DOCS:
            text = path.read_text(encoding="utf-8")
            for claim in RETIRED_PRODUCT_DOC_OPERATIONAL_CLAIMS:
                with self.subTest(path=path.name, claim=claim):
                    self.assertNotIn(claim, text)

    def test_retired_m0_validator_is_not_a_control_path(self) -> None:
        self.assertNotIn("scripts/verify-m0-gates.py", MODULE.CI_CONTROL_PATHS)

    def test_architecture_docs_drop_retired_operational_ci_claims(self) -> None:
        for path in ARCHITECTURE_REGRESSION_DOCS:
            text = path.read_text(encoding="utf-8")
            for claim in RETIRED_ARCHITECTURE_OPERATIONAL_CLAIMS:
                with self.subTest(path=path.name, claim=claim):
                    self.assertNotIn(claim, text)

    def test_optional_baselines_remain_visible_to_the_required_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        needs = "needs: [changes, apple_product, rust_linux, policy, macos_quality]"
        self.assertEqual(workflow.count(needs), 1)
        for result in (
            "APPLE_PRODUCT_RESULT",
            "RUST_LINUX_RESULT",
            "POLICY_RESULT",
            "MACOS_QUALITY_RESULT",
        ):
            self.assertEqual(workflow.count(f'case "${result}" in'), 1)
        self.assertNotIn("NOTICES_RESULT", workflow)
        self.assertNotIn("RUST_MACOS_RESULT", workflow)

    def test_product_lane_keeps_pr_macos_tests_ios_simulator_and_built_symbols(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs = dict(self._workflow_job_blocks(workflow))
        apple = jobs["apple_product"]
        # Parallel step keeps complete TersaMac test + TersaIOS simulator build
        # with distinct DerivedData directories and deterministic failure propagation.
        self.assertIn("Test macOS and build iOS simulator in parallel", apple)
        self.assertIn(
            "xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac",
            apple,
        )
        self.assertIn(
            "xcodebuild -project apple/Tersa.xcodeproj -scheme TersaIOS",
            apple,
        )
        self.assertIn("-derivedDataPath apple/build/DerivedData-macos", apple)
        self.assertIn("-derivedDataPath apple/build/DerivedData-ios", apple)
        self.assertIn("-destination 'platform=macOS,arch=arm64'", apple)
        self.assertIn("-destination 'generic/platform=iOS Simulator'", apple)
        self.assertIn("CODE_SIGNING_ALLOWED=NO", apple)
        self.assertRegex(apple, r"TERSA_OAUTH_REDIRECT_SCHEME=.* test")
        self.assertRegex(apple, r"TERSA_OAUTH_REDIRECT_SCHEME=.* build")
        self.assertIn('wait "$macos_pid" || macos_status=$?', apple)
        self.assertIn('wait "$ios_pid" || ios_status=$?', apple)
        self.assertIn('cat "$log_dir/macos-test.log"', apple)
        self.assertIn('cat "$log_dir/ios-build.log"', apple)
        self.assertIn('if [ "$macos_status" -ne 0 ]; then', apple)
        self.assertIn('if [ "$ios_status" -ne 0 ]; then', apple)
        self.assertNotIn("Build unsigned macOS debug application", workflow)
        self.assertIn("name: Verify built Rust bridge symbols", workflow)
        self.assertIn(
            "apple/build/DerivedData-macos/Build/Products/Debug/Tersa.app/Contents/MacOS/Tersa.debug.dylib",
            workflow,
        )
        self.assertIn(
            "apple/build/DerivedData-ios/Build/Products/Debug-iphonesimulator/Tersa.app/Tersa.debug.dylib",
            workflow,
        )
        # Shared DerivedData must not return (would race under parallel xcodebuild).
        self.assertNotIn("-derivedDataPath apple/build/DerivedData ", apple)
        self.assertNotIn("apple/build/DerivedData/Build/Products/", workflow)
        for retired_step in (
            "Build unsigned iOS device debug application",
            "Archive unsigned macOS debug application",
            "Archive unsigned iOS debug application",
            "Verify archived Rust bridge symbols",
            "Verify OAuth PKCE and sandbox feasibility",
        ):
            self.assertNotIn(f"- name: {retired_step}", workflow)

    def test_workflow_jobs_match_full_fanout_inventory(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs_start = workflow.index("\njobs:\n")
        jobs_section = workflow[jobs_start + len("\njobs:\n") :]
        job_ids = []
        for line in jobs_section.splitlines():
            if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
                job_ids.append(line.strip()[:-1])
        # Exactly the six visible jobs: scope, Linux, policy, macOS quality,
        # Apple product, and gate — no unclassified extra lane.
        self.assertEqual(job_ids, list(FULL_FANOUT_JOB_IDS))

    def test_every_workflow_job_has_an_explicit_timeout(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        job_blocks = self._workflow_job_blocks(workflow)
        self.assertEqual([job_id for job_id, _ in job_blocks], list(FULL_FANOUT_JOB_IDS))
        for job_id, block in job_blocks:
            with self.subTest(job=job_id):
                self.assertRegex(block, r"(?m)^    timeout-minutes: \d+$")

    def _workflow_job_blocks(self, workflow: str) -> list[tuple[str, str]]:
        jobs_start = workflow.index("\njobs:\n")
        jobs_section = workflow[jobs_start + len("\njobs:\n") :]
        job_blocks: list[tuple[str, str]] = []
        current_id: str | None = None
        current_lines: list[str] = []
        for line in jobs_section.splitlines():
            if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
                if current_id is not None:
                    job_blocks.append((current_id, "\n".join(current_lines)))
                current_id = line.strip()[:-1]
                current_lines = [line]
            elif current_id is not None:
                current_lines.append(line)
        if current_id is not None:
            job_blocks.append((current_id, "\n".join(current_lines)))
        return job_blocks

    def test_macos_quality_consolidates_rust_and_notices_without_duplicate_setup(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs = dict(self._workflow_job_blocks(workflow))
        job = jobs["macos_quality"]
        self.assertIn("name: macOS quality", job)
        self.assertEqual(job.count("uses: actions/checkout@"), 1)
        self.assertEqual(job.count("uses: actions-rust-lang/setup-rust-toolchain@"), 1)
        self.assertEqual(job.count("cache: false"), 1)
        # Cold CI inlines the `ci-macos` command sequence; do not compile xtask.
        self.assertNotIn("cargo run --locked --package xtask -- ci-macos", job)
        self.assertNotIn("cargo run --locked --package xtask -- verify", job)
        self.assertNotIn("cargo check --", job)
        self.assertNotIn("cargo fmt", job)
        self.assertNotIn("architecture", job)
        # Exact `ci-macos` / `verify`-subset flags (no weakened filters).
        self.assertIn(
            "cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings",
            job,
        )
        self.assertIn(
            "cargo test --locked --workspace --all-targets --all-features",
            job,
        )
        self.assertIn(
            "cargo test --locked --workspace --doc --all-features",
            job,
        )
        self.assertIn(
            'RUSTDOCFLAGS="--deny warnings"',
            job,
        )
        self.assertIn(
            "cargo doc --locked --workspace --no-deps --all-features",
            job,
        )
        # Sequential Clippy → tests → doctests → rustdoc on the default target
        # directory (shared artifacts; no dual cold compiles under contention).
        clippy_at = job.index(
            "cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings"
        )
        tests_at = job.index("cargo test --locked --workspace --all-targets --all-features")
        doctests_at = job.index("cargo test --locked --workspace --doc --all-features")
        rustdoc_at = job.index("cargo doc --locked --workspace --no-deps --all-features")
        self.assertLess(clippy_at, tests_at)
        self.assertLess(tests_at, doctests_at)
        self.assertLess(doctests_at, rustdoc_at)
        # No per-lane CARGO_TARGET_DIR overrides or dual-target concurrency.
        self.assertNotIn("CARGO_TARGET_DIR", job)
        self.assertNotIn("target-ci-macos-clippy", job)
        self.assertNotIn("target-ci-macos-test", job)
        self.assertNotIn("clippy_pid", job)
        self.assertNotIn("tests_pid", job)
        self.assertNotIn("clippy_status", job)
        self.assertNotIn("tests_status", job)
        self.assertNotIn("doc_status", job)
        self.assertNotIn("clippy.log", job)
        self.assertNotIn("tests.log", job)
        # Notices is the sole background PID; wait even if Rust fails, emit logs,
        # then deterministically propagate rust then notices failures.
        self.assertIn("notices_pid=$!", job)
        self.assertIn('wait "$notices_pid" || notices_status=$?', job)
        self.assertIn(') >"$log_dir/rust.log" 2>&1 || rust_status=$?', job)
        self.assertIn('cat "$log_dir/rust.log"', job)
        self.assertIn('cat "$log_dir/notices.log"', job)
        self.assertIn('if [ "$rust_status" -ne 0 ]; then', job)
        self.assertIn('if [ "$notices_status" -ne 0 ]; then', job)
        # Notices starts before the sequential Rust suite so fetch/generation can
        # overlap; only one background `&` for the notices subshell.
        notices_bg = job.index(") >\"$log_dir/notices.log\" 2>&1 &")
        rust_seq = job.index("echo \"Running Clippy check...\"")
        self.assertLess(notices_bg, rust_seq)
        self.assertEqual(job.count(" 2>&1 &"), 1)
        self.assertIn('RUN_RUST: ${{ needs.changes.outputs.rust_macos }}', job)
        self.assertIn('RUN_NOTICES: ${{ needs.changes.outputs.notices }}', job)
        self.assertIn("if: ${{ needs.changes.outputs.notices == 'true' }}", job)
        self.assertIn("tool: cargo-about@0.9.1", job)
        self.assertIn("cargo fetch --locked", job)
        self.assertIn("sh apple/scripts/generate-third-party-notices.sh --check", job)
        # No second complete verify / full Rust suite on macOS; at most two macOS jobs.
        macos_jobs = [
            block for _job_id, block in self._workflow_job_blocks(workflow) if "runs-on: macos-" in block
        ]
        self.assertEqual(len(macos_jobs), 2)
        self.assertEqual(
            sum("cargo run --locked --package xtask -- verify" in block for block in macos_jobs),
            0,
        )
        self.assertEqual(
            sum(block.count("uses: actions-rust-lang/setup-rust-toolchain@") for block in macos_jobs),
            2,
        )
        self.assertEqual(workflow.count("runs-on: macos-"), 2)

    def test_workflow_macos_quality_commands_match_xtask_ci_macos(self) -> None:
        """Pin workflow cargo invocations as exactly equivalent to xtask ci-macos."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        xtask = (ROOT / "xtask" / "src" / "main.rs").read_text(encoding="utf-8")
        # Locate the ci_macos function body in xtask.
        start = xtask.index("fn ci_macos() -> TaskResult {")
        end = xtask.index("\nfn cargo<", start)
        body = xtask[start:end]
        for fragment in (
            '"clippy"',
            '"--locked"',
            '"--workspace"',
            '"--all-targets"',
            '"--all-features"',
            '"--deny"',
            '"warnings"',
            '"test"',
            '"--doc"',
            '"doc"',
            '"--no-deps"',
            '"RUSTDOCFLAGS"',
            '"--deny warnings"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, body)
        jobs = dict(self._workflow_job_blocks(workflow))
        job = jobs["macos_quality"]
        # Workflow must not reintroduce architecture/format/check on macOS.
        for banned in (
            "cargo fmt",
            "cargo check --",
            "cargo run --locked --package xtask -- verify",
            "cargo run --locked --package xtask -- architecture",
            "cargo run --locked --package xtask -- ci-macos",
        ):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, job)
        # Developer-facing command remains implemented in xtask.
        self.assertIn('Some("ci-macos")', xtask)
        self.assertIn("fn ci_macos()", xtask)

    def test_workflow_forbids_cache_artifact_and_manual_triggers(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("actions/cache@", workflow)
        self.assertNotIn("Swatinem/rust-cache@", workflow)
        self.assertNotIn("actions/upload-artifact@", workflow)
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertNotIn("\n  push:\n", workflow)
        # Every setup-rust-toolchain invocation must disable cache.
        rust_setup_count = workflow.count("uses: actions-rust-lang/setup-rust-toolchain@")
        self.assertEqual(workflow.count("          cache: false\n"), rust_setup_count)
        self.assertGreater(rust_setup_count, 0)

    def test_executable_ci_control_paths_select_full_fanout(self) -> None:
        control_paths = sorted(MODULE.CI_CONTROL_PATHS) + [
            ".github/workflows/ci.yml",
            ".github/workflows/any-workflow.yml",
            "xtask/src/main.rs",
            "xtask/Cargo.toml",
        ]
        for path in control_paths:
            with self.subTest(path=path):
                scope = MODULE.classify([path])
                actual = {name for name in NAMES if getattr(scope, name)}
                self.assertEqual(actual, ALL)


if __name__ == "__main__":
    unittest.main()
