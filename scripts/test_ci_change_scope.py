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
# Helper script names stay out of this list: the changes job intentionally
# self-tests the transitional verify-m0-gates helper while the frozen register
# remains tracked.
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
    # Temporary unautomated fuzz policy gap pending PR4 removal.
    "checked through its own locked verifier and deny policy",
    # Combined OAuth verifier is obsolete after ADR-0024; do not recommend it.
    "After creating the unsigned base archives, run:",
    "```sh\nsh apple/scripts/verify-oauth-feasibility.sh\n```",
)
# Present-tense operational claims only. Past-tense historical run locators
# (for example owner-attested dates) stay allowed in the M0 study records.
M0_FEASIBILITY_DOCS = (
    ROOT / "docs" / "m0" / "ui-feasibility.md",
    ROOT / "docs" / "m0" / "dioxus-ui-feasibility.md",
    ROOT / "docs" / "m0" / "mime-html-feasibility.md",
    ROOT / "docs" / "m0" / "blob-feasibility.md",
    ROOT / "docs" / "m0" / "oauth-pkce-feasibility.md",
    ROOT / "docs" / "m0" / "search-feasibility.md",
)
RETIRED_M0_OPERATIONAL_CLAIMS = (
    "slint-apple-evidence",
    "dioxus-apple-evidence",
    "mime-apple-evidence",
    "mime-parser-fuzz",
    "blob-apple-evidence",
    "CI owns the simulator",
    "The separate Dioxus Apple CI job",
    "artifact upload",
    "retains the aggregate artifact for 90 days",
    "binds aggregate evidence to the immutable source commit",
    "binds `result.txt` to the source commit",
    "CI treats screenshots",
    "uses `lsof` against both live processes",
    "It builds the macOS, iOS device, and iOS simulator targets",
    "CI uses a public non-functional client identifier",
    "The CI host profile",
    # Fuzz verifier does not automate license/source/advisory policy.
    "validates the independent fuzz lock against its isolated license, source, and advisory policy",
    # Combined OAuth verifier is stale after the ADR-0024 token-broker cutover.
    "deterministic fake callbacks through\n`sh apple/scripts/verify-oauth-feasibility.sh`",
    # Notice CI compares committed apple/licenses sources, not Xcode packages.
    "compares them byte-for-byte with the resources packaged by Xcode",
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
                "retired spike entitlements use generic Apple entitlement routing",
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
                "fuzz paths fail closed without a named diagnostic lane",
                ["fuzz/fuzz_targets/mime_display.rs"],
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
            ("xtask runs the portable baseline and policy", ["xtask/src/main.rs"], {"rust_linux", "policy"}),
            ("workflow stays out", [".github/workflows/ci.yml"], set()),
            ("DCO checker stays in the control lane", ["scripts/check-dco.py"], set()),
            ("DCO tests stay in the control lane", ["scripts/test_check_dco.py"], set()),
            ("scope classifier stays in the control lane", ["scripts/ci-change-scope.py"], set()),
            ("scope tests stay in the control lane", ["scripts/test_ci_change_scope.py"], set()),
            ("performance reporter stays in its tested control lane", ["scripts/macos-performance-report.py"], set()),
            ("performance tests stay in the control lane", ["scripts/test_macos_performance_report.py"], set()),
            (
                "transitional M0 gate helper stays in the control lane",
                ["scripts/verify-m0-gates.py"],
                set(),
            ),
            (
                "retired evidence-manifest helper is not a control path",
                ["scripts/write-evidence-manifest.py"],
                ALL,
            ),
            (
                "retired rust-skia notice path fails closed",
                ["apple/licenses/rust-skia-notices.txt"],
                {"notices"},
            ),
            (
                "multiple product paths union scopes",
                ["apple/licenses/sqlcipher-notices.txt", "xtask/src/main.rs"],
                {"rust_linux", "policy", "notices"},
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
            self.assertIn(f"if: ${{{{ needs.changes.outputs.{output} == 'true' }}}}", workflow)
        self.assertNotIn("matrix:\n        os: [ubuntu-24.04, macos-15]", workflow)

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
        self.assertIn("python3 scripts/verify-m0-gates.py --self-test", changes_job)
        self.assertEqual(workflow.count("verify-m0-gates.py"), 1)
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

    def test_m0_feasibility_docs_drop_retired_operational_ci_claims(self) -> None:
        for path in M0_FEASIBILITY_DOCS:
            text = path.read_text(encoding="utf-8")
            for claim in RETIRED_M0_OPERATIONAL_CLAIMS:
                with self.subTest(path=path.name, claim=claim):
                    self.assertNotIn(claim, text)

    def test_architecture_docs_drop_retired_operational_ci_claims(self) -> None:
        for path in ARCHITECTURE_REGRESSION_DOCS:
            text = path.read_text(encoding="utf-8")
            for claim in RETIRED_ARCHITECTURE_OPERATIONAL_CLAIMS:
                with self.subTest(path=path.name, claim=claim):
                    self.assertNotIn(claim, text)

    def test_optional_baselines_remain_visible_to_the_required_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        needs = "needs: [changes, apple_product, notices, rust_linux, rust_macos, policy]"
        self.assertEqual(workflow.count(needs), 1)
        for result in ("RUST_LINUX_RESULT", "RUST_MACOS_RESULT", "POLICY_RESULT"):
            self.assertEqual(workflow.count(f'case "${result}" in'), 1)

    def test_product_lane_keeps_pr_macos_tests_ios_simulator_and_built_symbols(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("      - name: Test unsigned macOS debug application")
        end = workflow.index("      - name: Build unsigned iOS simulator debug application", start)
        macos_step = workflow[start:end]
        self.assertIn(" xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac", macos_step)
        self.assertTrue(macos_step.rstrip().endswith("test"))
        self.assertNotIn("Build unsigned macOS debug application", workflow)
        self.assertIn("name: Verify built Rust bridge symbols", workflow)
        self.assertIn(
            "apple/build/DerivedData/Build/Products/Debug/Tersa.app/Contents/MacOS/Tersa.debug.dylib",
            workflow,
        )
        self.assertIn(
            "apple/build/DerivedData/Build/Products/Debug-iphonesimulator/Tersa.app/Tersa.debug.dylib",
            workflow,
        )
        for retired_step in (
            "Build unsigned iOS device debug application",
            "Archive unsigned macOS debug application",
            "Archive unsigned iOS debug application",
            "Verify archived Rust bridge symbols",
            "Verify OAuth PKCE and sandbox feasibility",
        ):
            self.assertNotIn(f"- name: {retired_step}", workflow)


if __name__ == "__main__":
    unittest.main()
