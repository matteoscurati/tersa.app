#!/usr/bin/env python3
"""Table-driven tests for scripts/ci-change-scope.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).with_name("ci-change-scope.py")
WORKFLOW = SCRIPT.parent.parent / ".github" / "workflows" / "ci.yml"
SPEC = importlib.util.spec_from_file_location("ci_change_scope", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

NAMES = tuple(field.name for field in MODULE.fields(MODULE.Scope))
ALL = set(NAMES)


class ChangeScopeTests(unittest.TestCase):
    def test_path_table(self) -> None:
        cases = (
            ("empty input fails closed", [], ALL),
            ("unknown path fails closed", ["new-area/input.txt"], ALL),
            ("ambiguous path fails closed", ["../Cargo.toml"], ALL),
            ("root manifest fans out", ["Cargo.toml"], ALL),
            ("Apple project builds only the product lane", ["apple/project.yml"], {"product_apple"}),
            ("shared Apple script fans out", ["apple/scripts/build-rust-staticlib.sh"], ALL),
            ("Slint component", ["apps/slint-spike/ui/tersa.slint"], {"rust_linux", "policy", "slint"}),
            ("Slint manifest also checks notices", ["apps/slint-spike/Cargo.toml"], {"rust_linux", "policy", "slint", "notices"}),
            ("Dioxus component", ["apps/dioxus-spike/src/main.rs"], {"rust_linux", "policy", "dioxus"}),
            ("SQLCipher component", ["apps/sqlcipher-spike/migrations/global/0001_initial.sql"], {"rust_linux", "policy", "sqlcipher"}),
            ("search component", ["apps/search-spike/src/main.rs"], {"rust_linux", "policy", "search"}),
            ("MIME component", ["apps/mime-spike/src/lib.rs"], {"rust_linux", "policy", "mime"}),
            ("blob component", ["apps/blob-spike/src/format.rs"], {"rust_linux", "policy", "blob"}),
            ("fuzz requires MIME and fuzz", ["fuzz/fuzz_targets/mime_display.rs"], {"rust_linux", "policy", "mime", "mime_fuzz"}),
            ("MIME fuzz verifier", ["scripts/verify-mime-fuzz.sh"], {"rust_linux", "policy", "mime", "mime_fuzz"}),
            ("notices are isolated", ["apple/licenses/rust-skia-notices.txt"], {"notices"}),
            ("Slint notice config", ["about.toml"], {"slint", "notices"}),
            ("product notice config", ["about-bridge.toml"], {"product_apple", "notices"}),
            ("Dioxus notice config", ["about-dioxus.toml"], {"dioxus", "notices"}),
            ("shared domain has UI reverse dependants", ["crates/domain/src/lib.rs"], {"rust_linux", "policy", "product_apple", "slint", "dioxus"}),
            ("shared presentation has UI reverse dependants", ["crates/presentation/src/lib.rs"], {"rust_linux", "policy", "product_apple", "slint", "dioxus"}),
            ("adapter changes build product", ["adapters/keychain-macos/src/lib.rs"], {"rust_linux", "rust_macos", "policy", "product_apple"}),
            ("adapter manifest also checks notices", ["adapters/keychain-macos/Cargo.toml"], {"rust_linux", "rust_macos", "policy", "product_apple", "notices"}),
            ("Apple Rust bridge checks both hosts", ["apple/rust-bridge/src/lib.rs"], {"rust_linux", "rust_macos", "policy", "product_apple"}),
            ("macOS CLI checks both hosts", ["apps/cli-macos/src/main.rs"], {"rust_linux", "rust_macos", "policy"}),
            ("Apple product UI host", ["apple/dioxus-ios/Info.plist"], {"product_apple", "dioxus"}),
            ("generic Apple product file", ["apple/macos/AppDelegate.swift"], {"product_apple"}),
            (
                "rename source and destination cannot hide a product path",
                ["apple/macos/Removed.swift", "docs/Removed.md"],
                {"product_apple"},
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
            ("M0 gate verifier stays in its self-tested control lane", ["scripts/verify-m0-gates.py"], set()),
            ("evidence manifest stays in its self-tested control lane", ["scripts/write-evidence-manifest.py"], set()),
            ("multiple paths union scopes", ["apps/blob-spike/src/main.rs", "apps/search-spike/src/main.rs"], {"rust_linux", "policy", "blob", "search"}),
        )
        for label, paths, expected in cases:
            with self.subTest(label=label):
                scope = MODULE.classify(paths)
                actual = {name for name in NAMES if getattr(scope, name)}
                self.assertEqual(actual, expected)

    def test_full_mode_forces_every_scope(self) -> None:
        scope = MODULE.classify(["docs/development.md"], full=True)
        self.assertEqual({name for name in NAMES if getattr(scope, name)}, ALL)

    def test_baseline_mode_adds_portable_rust_and_policy(self) -> None:
        scope = MODULE.classify(["apple/licenses/rust-skia-notices.txt"], baseline=True)
        actual = {name for name in NAMES if getattr(scope, name)}
        self.assertEqual(actual, {"rust_linux", "policy", "notices"})

    def test_cli_reads_stdin_and_emits_github_output_format(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input="apps/mime-spike/src/main.rs\n",
            text=True,
            capture_output=True,
            check=True,
        )
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), len(NAMES))
        self.assertEqual(dict(line.split("=", 1) for line in lines)["mime"], "true")
        values = (line.split("=", 1)[1] for line in lines)
        self.assertTrue(all(value in {"true", "false"} for value in values))

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

    def test_workflow_keeps_deep_evidence_manual(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("\n  push:\n", workflow)
        self.assertNotIn("github.event_name == 'push'", workflow)
        self.assertIn("if: github.event_name == 'workflow_dispatch'", workflow)
        self.assertIn("\n    name: CI gate\n", workflow)
        self.assertIn("\n    name: Manual evidence gate\n", workflow)
        self.assertIn(
            "github.event_name != 'workflow_dispatch'",
            workflow,
        )
        self.assertEqual(
            workflow.count("needs: [changes, manual_evidence_gate]"),
            7,
        )
        self.assertNotIn("needs: [changes, ci_gate]", workflow)

    def test_workflow_disables_all_github_actions_caches(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        rust_setup_count = workflow.count("uses: actions-rust-lang/setup-rust-toolchain@")
        self.assertGreater(rust_setup_count, 0)
        self.assertEqual(workflow.count("          cache: false\n"), rust_setup_count)
        self.assertNotIn("actions/cache@", workflow)
        self.assertNotIn("Swatinem/rust-cache@", workflow)
        self.assertNotIn("cache-save-if:", workflow)
        self.assertNotIn("cache-on-failure:", workflow)

    def test_workflow_path_scopes_baseline_jobs(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for output in ("rust_linux", "rust_macos", "policy"):
            self.assertIn(f"      {output}: ${{{{ steps.scope.outputs.{output} }}}}", workflow)
            self.assertIn(f"if: ${{{{ needs.changes.outputs.{output} == 'true' }}}}", workflow)
        self.assertIn("python3 scripts/ci-change-scope.py --baseline", workflow)
        self.assertNotIn("matrix:\n        os: [ubuntu-24.04, macos-15]", workflow)

    def test_workflow_keeps_dco_in_the_required_control_job(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        changes_start = workflow.index("  changes:\n")
        changes_end = workflow.index("\n  apple_product:\n", changes_start)
        changes_job = workflow[changes_start:changes_end]
        self.assertIn("python3 scripts/check-dco.py", changes_job)
        self.assertIn("python3 scripts/verify-m0-gates.py --self-test", changes_job)
        self.assertIn("python3 scripts/write-evidence-manifest.py --self-test", changes_job)
        self.assertNotIn("cargo run --locked --package xtask -- dco", workflow)

    def test_optional_baselines_remain_visible_to_both_gates(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        needs = "needs: [changes, apple_product, notices, rust_linux, rust_macos, policy]"
        self.assertEqual(workflow.count(needs), 2)
        for result in ("RUST_LINUX_RESULT", "RUST_MACOS_RESULT", "POLICY_RESULT"):
            self.assertEqual(workflow.count(f'case "${result}" in'), 2)

    def test_pull_request_product_lane_does_not_repeat_archives(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("name: Verify built Rust bridge symbols", workflow)
        self.assertIn(
            "apple/build/DerivedData/Build/Products/Debug/Tersa.app/Contents/MacOS/Tersa.debug.dylib",
            workflow,
        )
        for step in (
            "Build unsigned iOS device debug application",
            "Archive unsigned macOS debug application",
            "Archive unsigned iOS debug application",
            "Verify archived Rust bridge symbols",
            "Verify OAuth PKCE and sandbox feasibility",
        ):
            marker = f"- name: {step}\n        if: github.event_name == 'workflow_dispatch'"
            self.assertIn(marker, workflow)

    def test_product_lane_runs_macos_tests_in_its_single_debug_build(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("      - name: Test unsigned macOS debug application")
        end = workflow.index("      - name: Build unsigned iOS simulator debug application", start)
        macos_step = workflow[start:end]
        self.assertIn(" xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac", macos_step)
        self.assertTrue(macos_step.rstrip().endswith("test"))
        self.assertNotIn("Build unsigned macOS debug application", workflow)


if __name__ == "__main__":
    unittest.main()
