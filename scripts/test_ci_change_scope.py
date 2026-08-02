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
            ("Slint component", ["apps/slint-spike/ui/tersa.slint"], {"slint"}),
            ("Slint manifest also checks notices", ["apps/slint-spike/Cargo.toml"], {"slint", "notices"}),
            ("Dioxus component", ["apps/dioxus-spike/src/main.rs"], {"dioxus"}),
            ("SQLCipher component", ["apps/sqlcipher-spike/migrations/global/0001_initial.sql"], {"sqlcipher"}),
            ("search component", ["apps/search-spike/src/main.rs"], {"search"}),
            ("MIME component", ["apps/mime-spike/src/lib.rs"], {"mime"}),
            ("blob component", ["apps/blob-spike/src/format.rs"], {"blob"}),
            ("fuzz requires MIME and fuzz", ["fuzz/fuzz_targets/mime_display.rs"], {"mime", "mime_fuzz"}),
            ("MIME fuzz verifier", ["scripts/verify-mime-fuzz.sh"], {"mime", "mime_fuzz"}),
            ("notices are isolated", ["apple/licenses/rust-skia-notices.txt"], {"notices"}),
            ("Slint notice config", ["about.toml"], {"slint", "notices"}),
            ("product notice config", ["about-bridge.toml"], {"product_apple", "notices"}),
            ("Dioxus notice config", ["about-dioxus.toml"], {"dioxus", "notices"}),
            ("shared domain has UI reverse dependants", ["crates/domain/src/lib.rs"], {"product_apple", "slint", "dioxus"}),
            ("shared presentation has UI reverse dependants", ["crates/presentation/src/lib.rs"], {"product_apple", "slint", "dioxus"}),
            ("adapter changes build product", ["adapters/keychain-macos/src/lib.rs"], {"product_apple"}),
            ("adapter manifest also checks notices", ["adapters/keychain-macos/Cargo.toml"], {"product_apple", "notices"}),
            ("Apple product UI host", ["apple/dioxus-ios/Info.plist"], {"product_apple", "dioxus"}),
            ("generic Apple product file", ["apple/macos/AppDelegate.swift"], {"product_apple"}),
            (
                "rename source and destination cannot hide a product path",
                ["apple/macos/Removed.swift", "docs/Removed.md"],
                {"product_apple"},
            ),
            ("docs stay out", ["docs/development.md"], set()),
            ("xtask stays out", ["xtask/src/main.rs"], set()),
            ("workflow stays out", [".github/workflows/ci.yml"], set()),
            ("scope classifier stays in the control lane", ["scripts/ci-change-scope.py"], set()),
            ("scope tests stay in the control lane", ["scripts/test_ci_change_scope.py"], set()),
            ("multiple paths union scopes", ["apps/blob-spike/src/main.rs", "apps/search-spike/src/main.rs"], {"blob", "search"}),
        )
        for label, paths, expected in cases:
            with self.subTest(label=label):
                scope = MODULE.classify(paths)
                actual = {name for name in NAMES if getattr(scope, name)}
                self.assertEqual(actual, expected)

    def test_full_mode_forces_every_scope(self) -> None:
        scope = MODULE.classify(["docs/development.md"], full=True)
        self.assertEqual({name for name in NAMES if getattr(scope, name)}, ALL)

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
        self.assertIn("cache-save-if: ${{ github.event_name == 'workflow_dispatch' }}", workflow)
        self.assertIn("\n    name: CI gate\n", workflow)
        self.assertIn("\n    name: Manual evidence gate\n", workflow)
        self.assertIn(
            "github.event_name != 'workflow_dispatch'",
            workflow,
        )

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


if __name__ == "__main__":
    unittest.main()
