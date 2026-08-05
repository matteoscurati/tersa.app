#!/usr/bin/env python3
"""Table-driven tests for scripts/ci-change-scope.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
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
    # Retired standalone lane names and pre-consolidation classifier promises.
    # Keep these narrow so historical/baseline docs and legitimate local guidance
    # (for example notice-script runbooks) are not falsely matched.
    "Rust (macOS)",
    "Third-party notices",
    "five path-scoped active lanes",
    "Documentation, workflow, and exact self-tested CI-control changes stop",
    "self-tested control paths avoid build jobs",
    "xtask-only changes run the portable",
    "A dedicated macOS lane owns",
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


# Executable-looking ``cargo`` token: not part of ``cargo-about`` / ``mycargo``,
# and still matched when bare at end of line (folded YAML scalars such as
# ``run: >-`` / ``cargo`` / ``build ...``).
_CARGO_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])cargo(?![A-Za-z0-9_-])")


def _macos_quality_cargo_inventory(job_text: str) -> list[str]:
    """Ordered inventory of executable-looking cargo lines in a job body.

    Non-comment lines containing an executable-looking ``cargo`` token at a
    token boundary are collected, including bare end-of-line ``cargo`` (folded
    YAML scalars). Only two prefixes before that token are normalized: empty
    (block-scalar shell) and exact ``run: `` (single-line YAML ``run`` scalar).
    Any other prefix — tabs, quotes, env assignments, command wrappers — keeps
    the full stripped line so exact equality against the pinned sequence fails
    rather than silently dropping execution modifiers. Non-command strings such
    as ``cargo-about`` are not matched.
    """
    inventory: list[str] = []
    for raw_line in job_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _CARGO_TOKEN_RE.search(stripped)
        if match is None:
            continue
        cargo_at = match.start()
        prefix = stripped[:cargo_at]
        if prefix == "" or prefix == "run: ":
            inventory.append(stripped[cargo_at:])
        else:
            inventory.append(stripped)
    return inventory


def _macos_quality_non_comment_lines_ending_backslash(job_text: str) -> list[str]:
    """Physical non-comment lines that end with a shell continuation backslash."""
    offenders: list[str] = []
    for raw_line in job_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            offenders.append(raw_line)
    return offenders


def _named_step_env_entries(job_text: str, step_name: str) -> dict[str, str]:
    """Exact env key/value map for a named job step (no YAML dependency).

    Parses only the ``env:`` block of the step whose ``- name:`` matches
    *step_name*. Sibling keys at the step indent (for example ``run:``) end the
    map. Any added, removed, or changed key is visible to exact equality.
    """
    header = f"      - name: {step_name}"
    lines = job_text.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if line == header:
            start = index + 1
            break
    if start is None:
        raise AssertionError(f"step not found: {step_name}")

    entries: dict[str, str] = {}
    in_env = False
    for line in lines[start:]:
        # Next step at the same indent ends this step.
        if line.startswith("      - name: "):
            break
        if line == "        env:":
            in_env = True
            continue
        if not in_env:
            # Allow other step keys before env; once env ends we stop below.
            continue
        if line.startswith("          ") and not line.startswith("           "):
            body = line[10:]
            key, sep, value = body.partition(": ")
            if not sep or not key:
                raise AssertionError(f"unparsable env entry in {step_name}: {line!r}")
            entries[key] = value
            continue
        if line.startswith("        ") and not line.startswith("         "):
            # Sibling step key (run, if, with, ...): end of env map.
            break
        if not line.strip() or line.strip().startswith("#"):
            continue
        raise AssertionError(f"unexpected env block line in {step_name}: {line!r}")
    return entries


def _named_step_sibling_keys(job_text: str, step_name: str) -> list[str]:
    """Ordered top-level keys of a named step (``name``, ``env``, ``run``, ...).

    Detects added ``if:``, ``continue-on-error:``, ``shell:``, ``with:``, or any
    other sibling that could bypass or re-shell the pinned ``run: |`` block.
    """
    header = f"      - name: {step_name}"
    lines = job_text.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if line == header:
            start = index
            break
    if start is None:
        raise AssertionError(f"step not found: {step_name}")

    keys = ["name"]
    for line in lines[start + 1 :]:
        if line.startswith("      - name: "):
            break
        # Next job id at two-space indent ends the job (and therefore the step).
        if (
            line.startswith("  ")
            and not line.startswith("    ")
            and line.rstrip().endswith(":")
            and not line.strip().startswith("#")
        ):
            break
        # Step-level key: exactly eight spaces then ``key:``.
        if line.startswith("        ") and not line.startswith("         "):
            body = line[8:].rstrip()
            if not body or body.startswith("#"):
                continue
            key, sep, _ = body.partition(":")
            if not sep or not key or key != key.strip() or " " in key:
                raise AssertionError(
                    f"unparsable step sibling key in {step_name}: {line!r}"
                )
            keys.append(key)
    return keys


def _named_step_block_scalar_script(job_text: str, step_name: str) -> str:
    """Extract the ``run: |`` block-scalar body for a named step (no YAML dep).

    Returns the raw indented script text under ``run: |``. Stops at the next
    step, job, or step-level sibling key. Does not evaluate shell.
    """
    header = f"      - name: {step_name}"
    lines = job_text.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if line == header:
            start = index + 1
            break
    if start is None:
        raise AssertionError(f"step not found: {step_name}")

    run_start: int | None = None
    for index, line in enumerate(lines[start:], start=start):
        if line.startswith("      - name: "):
            break
        if line == "        run: |":
            run_start = index + 1
            break
    if run_start is None:
        raise AssertionError(f"run: | block not found in step: {step_name}")

    body: list[str] = []
    for line in lines[run_start:]:
        if line.startswith("      - name: "):
            break
        if (
            line.startswith("  ")
            and not line.startswith("    ")
            and line.rstrip().endswith(":")
            and not line.strip().startswith("#")
        ):
            break
        # Block-scalar content is indented deeper than the step key column.
        if line.startswith("          ") or not line.strip():
            body.append(line)
            continue
        if line.startswith("        ") and not line.startswith("         "):
            # Sibling step key ends the scalar.
            break
        if not line.strip() or line.strip().startswith("#"):
            continue
        raise AssertionError(
            f"unexpected run block line in {step_name}: {line!r}"
        )
    return "\n".join(body)


def _executable_physical_lines(script: str) -> list[str]:
    """Ordered non-comment executable physical lines of a shell script.

    Normalizes only common leading indentation and trailing whitespace. Blank
    and comment-only lines are dropped so comments may change without failing
    the pin; every control, command, heredoc, exit, conditional, wrapper,
    marker, awk, trap, or redirection line remains and is compared exactly.
    """
    raw_lines = script.splitlines()
    non_blank = [line for line in raw_lines if line.strip()]
    if not non_blank:
        return []

    def leading_spaces(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    min_indent = min(leading_spaces(line) for line in non_blank)
    executable: list[str] = []
    for line in raw_lines:
        trimmed = line.rstrip()
        if not trimmed.strip():
            continue
        if len(trimmed) >= min_indent and trimmed[:min_indent] == (" " * min_indent):
            content = trimmed[min_indent:]
        else:
            content = trimmed.lstrip(" ")
        if content.lstrip().startswith("#"):
            continue
        executable.append(content)
    return executable


def _workflow_level_env_entries(workflow: str) -> dict[str, str]:
    """Exact top-level workflow ``env`` map (before ``jobs:``)."""
    lines = workflow.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if line == "env:":
            start = index + 1
            break
    if start is None:
        raise AssertionError("workflow-level env: not found")

    entries: dict[str, str] = {}
    for line in lines[start:]:
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            # Next top-level key (for example jobs:).
            break
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line.startswith("  ") and not line.startswith("   "):
            body = line[2:]
            key, sep, value = body.partition(": ")
            if not sep or not key:
                raise AssertionError(f"unparsable workflow env entry: {line!r}")
            entries[key] = value
            continue
        raise AssertionError(f"unexpected workflow env line: {line!r}")
    return entries


def _job_has_job_level_env(job_text: str) -> bool:
    """True when the job declares a job-level ``env:`` key (not step env)."""
    for line in job_text.splitlines():
        if line == "    env:":
            return True
    return False


def _xtask_fn_body(xtask: str, fn_name: str) -> str:
    """Body text of ``fn <name>() -> TaskResult { ... }`` (brace-balanced)."""
    header = f"fn {fn_name}() -> TaskResult {{"
    start = xtask.index(header) + len(header)
    depth = 1
    index = start
    while index < len(xtask) and depth > 0:
        char = xtask[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        index += 1
    if depth != 0:
        raise AssertionError(f"unbalanced braces in fn {fn_name}")
    return xtask[start : index - 1]


def _cargo_arg_lists(fn_body: str) -> list[list[str]]:
    """Ordered ``cargo(&[...])`` argument arrays from an xtask function body."""
    return [
        re.findall(r'"([^"]*)"', args_block)
        for args_block in re.findall(
            r"cargo\(\s*\[(.*?)\]\s*\)",
            fn_body,
            flags=re.DOTALL,
        )
    ]


# Exact ordered executable physical lines of the ``Run macOS quality checks``
# ``run: |`` block. The pin is the current workflow script with relative
# indentation preserved; blank and comment-only lines are omitted because the
# normalizer drops them. Any added/removed/changed control, command, heredoc,
# exit, conditional, wrapper, marker, awk, trap, or redirection line fails the
# equality check. No hash is used so the pin remains independently readable.
_MACOS_QUALITY_RUN_SCRIPT_PIN = r"""
set -euo pipefail
log_dir="${RUNNER_TEMP}/macos-quality-logs"
rust_log="$log_dir/rust.log"
notices_log="$log_dir/notices.log"
mkdir -p "$log_dir"
_logs_flushed=0
flush_logs() {
  if [ "${_logs_flushed}" -ne 0 ]; then
    return 0
  fi
  _logs_flushed=1
  if [ -f "$rust_log" ]; then
    echo "----- Rust suite -----"
    cat "$rust_log" || true
  fi
  if [ -f "$notices_log" ]; then
    echo "----- third-party notices -----"
    cat "$notices_log" || true
  fi
  return 0
}
trap 'rc=$?; flush_logs || true; exit "$rc"' EXIT
trap 'flush_logs || true; trap - EXIT; exit 130' INT
trap 'flush_logs || true; trap - EXIT; exit 143' TERM
if [ "$RUN_RUST" != "true" ] && [ "$RUN_NOTICES" != "true" ]; then
  echo "macOS quality: neither RUN_RUST nor RUN_NOTICES is exactly true (RUN_RUST=${RUN_RUST:-}; RUN_NOTICES=${RUN_NOTICES:-}); refusing no-op success." >&2
  trap - EXIT INT TERM
  exit 1
fi
rust_pid=""
notices_pid=""
rust_status=0
notices_status=0
if [ "$RUN_NOTICES" = "true" ]; then
  (
    set -euo pipefail
    cargo fetch --locked
    sh apple/scripts/generate-third-party-notices.sh --check
  ) >"$notices_log" 2>&1 &
  notices_pid=$!
fi
if [ "$RUN_RUST" = "true" ]; then
  (
    set -euo pipefail
    echo "Running Clippy check..."
    cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings
    echo "Running tests check..."
    cargo test --locked --workspace --all-targets --all-features
    echo "Running documentation tests check..."
    cargo test --locked --workspace --doc --all-features
    echo "Running documentation check..."
    export RUSTDOCFLAGS="--deny warnings"
    cargo doc --locked --workspace --no-deps --all-features
    echo "macOS CI verification passed."
  ) >"$rust_log" 2>&1 &
  rust_pid=$!
fi
if [ -n "$rust_pid" ]; then
  wait "$rust_pid" || rust_status=$?
fi
if [ -n "$notices_pid" ]; then
  wait "$notices_pid" || notices_status=$?
fi
if [ "$rust_status" -ne 0 ] || [ "$notices_status" -ne 0 ]; then
  flush_logs
  trap - EXIT INT TERM
  if [ "$rust_status" -ne 0 ]; then
    exit "$rust_status"
  fi
  exit "$notices_status"
fi
trap - EXIT INT TERM
if [ "$RUN_RUST" = "true" ] && [ "$RUN_NOTICES" = "true" ]; then
  echo "macOS quality: Rust suite and third-party notices succeeded."
elif [ "$RUN_RUST" = "true" ]; then
  echo "macOS quality: Rust suite succeeded."
elif [ "$RUN_NOTICES" = "true" ]; then
  echo "macOS quality: third-party notices succeeded."
else
  echo "macOS quality: neither RUN_RUST nor RUN_NOTICES is exactly true; refusing no-op success." >&2
  exit 1
fi
if [ "$RUN_RUST" = "true" ]; then
  tests_summary=""
  doctests_summary=""
  if [ -f "$rust_log" ]; then
    tests_summary="$(
      awk '
        $0 == "Running tests check..." { in_phase=1; next }
        $0 == "Running documentation tests check..." { in_phase=0 }
        in_phase && index($0, "test result: ok.") {
          line_passed = ""
          line_failed = ""
          for (i = 2; i <= NF; i++) {
            if ($i ~ /^passed/) line_passed = $(i-1)
            if ($i ~ /^failed/) line_failed = $(i-1)
          }
          if (line_passed !~ /^[0-9]+$/ || line_failed !~ /^[0-9]+$/) {
            unparsable = 1
            next
          }
          summaries++
          passed += line_passed + 0
          failed += line_failed + 0
        }
        END {
          if (!unparsable && summaries > 0)
            print "summaries=" summaries " passed=" passed " failed=" failed
        }
      ' "$rust_log"
    )" || true
    doctests_summary="$(
      awk '
        $0 == "Running documentation tests check..." { in_phase=1; next }
        $0 == "Running documentation check..." { in_phase=0 }
        in_phase && index($0, "test result: ok.") {
          line_passed = ""
          line_failed = ""
          for (i = 2; i <= NF; i++) {
            if ($i ~ /^passed/) line_passed = $(i-1)
            if ($i ~ /^failed/) line_failed = $(i-1)
          }
          if (line_passed !~ /^[0-9]+$/ || line_failed !~ /^[0-9]+$/) {
            unparsable = 1
            next
          }
          summaries++
          passed += line_passed + 0
          failed += line_failed + 0
        }
        END {
          if (!unparsable && summaries > 0)
            print "summaries=" summaries " passed=" passed " failed=" failed
        }
      ' "$rust_log"
    )" || true
  fi
  if [ -n "$tests_summary" ]; then
    echo "Cargo tests: $tests_summary"
  else
    echo "Cargo tests: summary unavailable (log format changed)."
  fi
  if [ -n "$doctests_summary" ]; then
    echo "Cargo doc-tests: $doctests_summary"
  else
    echo "Cargo doc-tests: summary unavailable (log format changed)."
  fi
fi
"""

MACOS_QUALITY_RUN_EXECUTABLE_LINES = tuple(
    _executable_physical_lines(_MACOS_QUALITY_RUN_SCRIPT_PIN)
)


# POSIX/BSD-compatible Cargo phase aggregation (mirrors workflow awk field parse).
_CARGO_PHASE_AGGREGATE_AWK = r"""
in_phase && index($0, "test result: ok.") {
  line_passed = ""
  line_failed = ""
  for (i = 2; i <= NF; i++) {
    if ($i ~ /^passed/) line_passed = $(i-1)
    if ($i ~ /^failed/) line_failed = $(i-1)
  }
  if (line_passed !~ /^[0-9]+$/ || line_failed !~ /^[0-9]+$/) {
    unparsable = 1
    next
  }
  summaries++
  passed += line_passed + 0
  failed += line_failed + 0
}
END {
  if (!unparsable && summaries > 0)
    print "summaries=" summaries " passed=" passed " failed=" failed
}
"""


class ChangeScopeTests(unittest.TestCase):
    def _assert_rust_macos_implies_rust_linux(
        self, enabled: set[str], *, label: str
    ) -> None:
        """Load-bearing invariant: any macOS Rust selection also selects Linux."""
        if "rust_macos" in enabled:
            self.assertIn(
                "rust_linux",
                enabled,
                f"{label}: rust_macos without rust_linux is forbidden",
            )

    def _path_table_cases(self) -> tuple[tuple[str, list[str], set[str]], ...]:
        """Table-driven classifier cases shared by equality and invariant checks."""
        return (
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

    def test_active_scope_contract(self) -> None:
        self.assertEqual(NAMES, ACTIVE_OUTPUTS)
        for retired in RETIRED_SCOPE_NAMES:
            self.assertNotIn(retired, NAMES)
        # Active output matrix always lists both host lanes; macOS cannot exist alone.
        self.assertIn("rust_linux", ACTIVE_OUTPUTS)
        self.assertIn("rust_macos", ACTIVE_OUTPUTS)
        self.assertLess(
            ACTIVE_OUTPUTS.index("rust_linux"),
            ACTIVE_OUTPUTS.index("rust_macos"),
        )

    def test_retired_ui_helpers_are_not_control_paths(self) -> None:
        for retired in (
            "scripts/write-evidence-manifest.py",
            "apple/scripts/prepare-verified-skia.sh",
            "apple/scripts/verify-rust-skia-notices.py",
            "apple/scripts/verify-dioxus-runtime.py",
            "apple/scripts/build-slint-executable.sh",
            "apple/scripts/build-dioxus-executable.sh",
            "apple/scripts/capture-slint-evidence.sh",
            "apple/scripts/capture-dioxus-device-evidence.sh",
            "apple/scripts/capture-dioxus-evidence.sh",
            "apple/scripts/verify-sqlcipher-feasibility.sh",
            "apple/scripts/verify-search-feasibility.sh",
            "apple/scripts/verify-blob-feasibility.sh",
        ):
            with self.subTest(path=retired):
                self.assertNotIn(retired, MODULE.CI_CONTROL_PATHS)

    def test_path_table(self) -> None:
        for label, paths, expected in self._path_table_cases():
            with self.subTest(label=label):
                scope = MODULE.classify(paths)
                actual = {name for name in NAMES if getattr(scope, name)}
                self.assertEqual(actual, expected)
                # Expected rows and live classify results both encode the host
                # invariant so a future macOS-only rule cannot be blessed by
                # merely adding a table row.
                self._assert_rust_macos_implies_rust_linux(expected, label=f"{label} expected")
                self._assert_rust_macos_implies_rust_linux(actual, label=f"{label} actual")

    def test_rust_macos_implies_rust_linux_over_all_classifier_surfaces(self) -> None:
        """Property: every result enabling rust_macos also enables rust_linux.

        Covers the full path table, executable control-path matrix, and CLI
        emission so a macOS-only classifier change fails without relying on a
        single blessed equality row.
        """
        for label, paths, expected in self._path_table_cases():
            with self.subTest(surface="path_table", label=label):
                self._assert_rust_macos_implies_rust_linux(expected, label=label)
                actual = {
                    name
                    for name in NAMES
                    if getattr(MODULE.classify(paths), name)
                }
                self._assert_rust_macos_implies_rust_linux(actual, label=label)

        control_paths = sorted(MODULE.CI_CONTROL_PATHS) + [
            ".github/workflows/ci.yml",
            ".github/workflows/any-workflow.yml",
            "xtask/src/main.rs",
            "xtask/Cargo.toml",
        ]
        for path in control_paths:
            with self.subTest(surface="control_path", path=path):
                actual = {
                    name
                    for name in NAMES
                    if getattr(MODULE.classify([path]), name)
                }
                self._assert_rust_macos_implies_rust_linux(actual, label=path)

        # Active output name set and full-fanout set also obey the invariant.
        self._assert_rust_macos_implies_rust_linux(set(ACTIVE_OUTPUTS), label="ACTIVE_OUTPUTS")
        self._assert_rust_macos_implies_rust_linux(ALL, label="ALL")
        # Classifier enable sites that list rust_macos must list rust_linux.
        classifier = SCRIPT.read_text(encoding="utf-8")
        for match in re.finditer(
            r'scope\.enable\(([^)]*)\)',
            classifier,
        ):
            args = match.group(1)
            if "rust_macos" in args:
                with self.subTest(surface="enable_site", args=args):
                    self.assertIn("rust_linux", args)
        # CLI GitHub-output emission for a rust_macos path also enables rust_linux.
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input="apple/rust-bridge/src/lib.rs\n",
            text=True,
            capture_output=True,
            check=True,
        )
        values = dict(line.split("=", 1) for line in result.stdout.splitlines())
        enabled = {name for name, value in values.items() if value == "true"}
        self._assert_rust_macos_implies_rust_linux(enabled, label="cli_github_output")
        self.assertEqual(values.get("rust_macos"), "true")
        self.assertEqual(values.get("rust_linux"), "true")

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
        # Parallel step: macOS-first launch, both lanes buffered to separate logs
        # with EXIT/INT/TERM flush traps. Distinct DerivedData + dual statuses.
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
        # Index-store generation is not product coverage on ephemeral CI runners.
        self.assertEqual(apple.count("COMPILER_INDEX_STORE_ENABLE=NO"), 2)
        self.assertRegex(apple, r"TERSA_OAUTH_REDIRECT_SCHEME=.* test")
        self.assertRegex(apple, r"TERSA_OAUTH_REDIRECT_SCHEME=.* build")
        self.assertIn("set -euo pipefail", apple)
        # Separate buffered logs (no live tee of multi-MB Xcode output).
        self.assertIn('macos_log="$log_dir/macos-test.log"', apple)
        self.assertIn('ios_log="$log_dir/ios-build.log"', apple)
        self.assertIn(') >"$macos_log" 2>&1 &', apple)
        self.assertIn(') >"$ios_log" 2>&1 &', apple)
        # No live full-output streaming (buffered redirect only).
        self.assertNotIn("| tee", apple)
        self.assertNotIn("tee \"", apple)
        self.assertNotIn("tee '", apple)
        # flush_logs: idempotent, missing-log safe, status-preserving traps.
        self.assertIn("flush_logs()", apple)
        self.assertIn('if [ -f "$macos_log" ]; then', apple)
        self.assertIn('if [ -f "$ios_log" ]; then', apple)
        self.assertIn('cat "$macos_log" || true', apple)
        self.assertIn('cat "$ios_log" || true', apple)
        self.assertIn('if [ "${_logs_flushed}" -ne 0 ]; then', apple)
        self.assertIn(
            """trap 'rc=$?; flush_logs || true; exit "$rc"' EXIT""",
            apple,
        )
        self.assertIn(
            """trap 'flush_logs || true; trap - EXIT; exit 130' INT""",
            apple,
        )
        self.assertIn(
            """trap 'flush_logs || true; trap - EXIT; exit 143' TERM""",
            apple,
        )
        # Topology: traps arm before launch; macOS first, then iOS; both PIDs.
        trap_exit = apple.index(
            """trap 'rc=$?; flush_logs || true; exit "$rc"' EXIT"""
        )
        macos_xcode = apple.index(
            "xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac"
        )
        macos_index = apple.index("COMPILER_INDEX_STORE_ENABLE=NO", macos_xcode)
        macos_bg = apple.index(') >"$macos_log" 2>&1 &')
        macos_pid = apple.index("macos_pid=$!")
        ios_xcode = apple.index(
            "xcodebuild -project apple/Tersa.xcodeproj -scheme TersaIOS"
        )
        ios_index = apple.index("COMPILER_INDEX_STORE_ENABLE=NO", ios_xcode)
        ios_bg = apple.index(') >"$ios_log" 2>&1 &')
        ios_pid = apple.index("ios_pid=$!")
        self.assertLess(trap_exit, macos_xcode)
        self.assertLess(macos_xcode, macos_index)
        self.assertLess(macos_index, macos_bg)
        self.assertLess(macos_bg, macos_pid)
        self.assertLess(macos_pid, ios_xcode)
        self.assertLess(ios_xcode, ios_index)
        self.assertLess(ios_index, ios_bg)
        self.assertLess(ios_bg, ios_pid)
        # Both lanes redirect-background (exactly two).
        self.assertEqual(apple.count(" 2>&1 &"), 2)
        # Unconditional waits for both; capture statuses before deciding.
        wait_macos = apple.index('wait "$macos_pid" || macos_status=$?')
        wait_ios = apple.index('wait "$ios_pid" || ios_status=$?')
        # Failure path: dump both full logs once before trap cleanup / status exit.
        failure_gate = apple.index(
            'if [ "$macos_status" -ne 0 ] || [ "$ios_status" -ne 0 ]; then',
            wait_ios,
        )
        flush_on_fail = apple.index("\n            flush_logs\n", failure_gate)
        trap_clear_fail = apple.index("trap - EXIT INT TERM", flush_on_fail)
        fail_macos = apple.index(
            'if [ "$macos_status" -ne 0 ]; then',
            trap_clear_fail,
        )
        exit_macos = apple.index('exit "$macos_status"', fail_macos)
        exit_ios = apple.index('exit "$ios_status"', exit_macos)
        # Success path: disarm traps without full dump; concise summary plus
        # extracted TersaMac test-count evidence (not the full buffered log).
        trap_clear_ok = apple.index("trap - EXIT INT TERM", exit_ios)
        success_summary = apple.index(
            'echo "Apple product: macOS tests and iOS simulator build succeeded."',
            trap_clear_ok,
        )
        tersa_mac_extract = apple.index(
            "grep -E 'Executed [0-9]+ tests?, with [0-9]+ failures' \"$macos_log\"",
            success_summary,
        )
        tersa_mac_echo = apple.index(
            'echo "TersaMac tests: $tersa_mac_summary"',
            tersa_mac_extract,
        )
        tersa_mac_fallback = apple.index(
            'echo "TersaMac tests: summary unavailable (log format changed)."',
            tersa_mac_echo,
        )
        self.assertLess(ios_pid, wait_macos)
        self.assertLess(wait_macos, wait_ios)
        self.assertLess(wait_ios, failure_gate)
        self.assertLess(failure_gate, flush_on_fail)
        self.assertLess(flush_on_fail, trap_clear_fail)
        self.assertLess(trap_clear_fail, fail_macos)
        self.assertLess(fail_macos, exit_macos)
        self.assertLess(exit_macos, exit_ios)
        self.assertLess(exit_ios, trap_clear_ok)
        self.assertLess(trap_clear_ok, success_summary)
        self.assertLess(success_summary, tersa_mac_extract)
        self.assertLess(tersa_mac_extract, tersa_mac_echo)
        self.assertLess(tersa_mac_echo, tersa_mac_fallback)
        # Full logs only in the failure branch (not on the all-success path).
        # Definition + trap bodies are excluded by matching the indented call.
        self.assertEqual(apple.count("\n            flush_logs\n"), 1)
        self.assertEqual(apple.count("\n          flush_logs\n"), 0)
        # Success path must not cat the full buffered logs.
        self.assertNotIn('cat "$macos_log"', apple[trap_clear_ok:])
        self.assertNotIn('cat "$ios_log"', apple[trap_clear_ok:])
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
        # Two-child topology: both Rust and notices are background children with
        # interruptible wait (Bash defers traps while a foreground command runs,
        # so the old `) >"$rust_log" 2>&1 || rust_status=$?` shape is forbidden).
        self.assertIn('rust_log="$log_dir/rust.log"', job)
        self.assertIn('notices_log="$log_dir/notices.log"', job)
        self.assertIn("rust_pid=$!", job)
        self.assertIn("notices_pid=$!", job)
        self.assertIn('wait "$rust_pid" || rust_status=$?', job)
        self.assertIn('wait "$notices_pid" || notices_status=$?', job)
        self.assertIn(') >"$rust_log" 2>&1 &', job)
        self.assertIn(') >"$notices_log" 2>&1 &', job)
        # Reject the old foreground Rust suite shape.
        self.assertNotIn(') >"$rust_log" 2>&1 || rust_status=$?', job)
        self.assertNotIn(') >"$rust_log" 2>&1 ||', job)
        # No live full-output streaming (buffered redirect only).
        self.assertNotIn("| tee", job)
        self.assertNotIn("tee \"", job)
        self.assertNotIn("tee '", job)
        # flush_logs: idempotent, missing-log safe, status-preserving traps.
        self.assertIn("flush_logs()", job)
        self.assertIn('if [ -f "$rust_log" ]; then', job)
        self.assertIn('if [ -f "$notices_log" ]; then', job)
        self.assertIn('cat "$rust_log" || true', job)
        self.assertIn('cat "$notices_log" || true', job)
        self.assertIn('if [ "${_logs_flushed}" -ne 0 ]; then', job)
        self.assertIn(
            """trap 'rc=$?; flush_logs || true; exit "$rc"' EXIT""",
            job,
        )
        self.assertIn(
            """trap 'flush_logs || true; trap - EXIT; exit 130' INT""",
            job,
        )
        self.assertIn(
            """trap 'flush_logs || true; trap - EXIT; exit 143' TERM""",
            job,
        )
        self.assertIn('if [ "$rust_status" -ne 0 ]; then', job)
        self.assertIn('exit "$notices_status"', job)
        # Traps arm before launch; selector validation before children; notices
        # starts before sequential Rust suite; both children background;
        # unconditional waits/reaps; Rust-first status.
        trap_exit = job.index(
            """trap 'rc=$?; flush_logs || true; exit "$rc"' EXIT"""
        )
        selector_gate = job.index(
            'if [ "$RUN_RUST" != "true" ] && [ "$RUN_NOTICES" != "true" ]; then',
            trap_exit,
        )
        selector_diag = job.index(
            "neither RUN_RUST nor RUN_NOTICES is exactly true",
            selector_gate,
        )
        selector_clear = job.index("trap - EXIT INT TERM", selector_diag)
        selector_exit = job.index("exit 1", selector_clear)
        notices_bg = job.index(') >"$notices_log" 2>&1 &', selector_exit)
        notices_pid = job.index("notices_pid=$!", notices_bg)
        rust_seq = job.index('echo "Running Clippy check..."', notices_pid)
        rust_bg = job.index(') >"$rust_log" 2>&1 &', rust_seq)
        rust_pid = job.index("rust_pid=$!", rust_bg)
        wait_rust = job.index('wait "$rust_pid" || rust_status=$?', rust_pid)
        wait_notices = job.index(
            'wait "$notices_pid" || notices_status=$?', wait_rust
        )
        # Failure path: dump both available full logs once before trap cleanup.
        failure_gate = job.index(
            'if [ "$rust_status" -ne 0 ] || [ "$notices_status" -ne 0 ]; then',
            wait_notices,
        )
        flush_on_fail = job.index("\n            flush_logs\n", failure_gate)
        trap_clear_fail = job.index("trap - EXIT INT TERM", flush_on_fail)
        fail_rust = job.index('if [ "$rust_status" -ne 0 ]; then', trap_clear_fail)
        exit_rust = job.index('exit "$rust_status"', fail_rust)
        exit_notices = job.index('exit "$notices_status"', exit_rust)
        # Success path: disarm traps without full dump; concise selected-lane
        # summary plus phase-aggregate Cargo evidence (not full logs).
        trap_clear_ok = job.index("trap - EXIT INT TERM", exit_notices)
        summary_both = job.index(
            'echo "macOS quality: Rust suite and third-party notices succeeded."',
            trap_clear_ok,
        )
        summary_rust = job.index(
            'echo "macOS quality: Rust suite succeeded."',
            summary_both,
        )
        summary_notices_gate = job.index(
            'elif [ "$RUN_NOTICES" = "true" ]; then',
            summary_rust,
        )
        summary_notices = job.index(
            'echo "macOS quality: third-party notices succeeded."',
            summary_notices_gate,
        )
        summary_noop_else = job.index(
            "neither RUN_RUST nor RUN_NOTICES is exactly true; refusing no-op success.",
            summary_notices,
        )
        summary_noop_exit = job.index("exit 1", summary_noop_else)
        # Phase-specific aggregates: normal tests then doc-tests. Count every
        # `test result: ok.` summary and sum passed/failed fields inside each
        # marker window. Reject last-line-only scrape of the final crate.
        tests_phase_start = job.index(
            '$0 == "Running tests check..." { in_phase=1; next }',
            summary_noop_exit,
        )
        tests_phase_end = job.index(
            '$0 == "Running documentation tests check..." { in_phase=0 }',
            tests_phase_start,
        )
        tests_aggregate = job.index(
            'in_phase && index($0, "test result: ok.") {',
            tests_phase_end,
        )
        tests_field_parse = job.index(
            'if ($i ~ /^passed/) line_passed = $(i-1)',
            tests_aggregate,
        )
        tests_failed_parse = job.index(
            'if ($i ~ /^failed/) line_failed = $(i-1)',
            tests_field_parse,
        )
        tests_unparsable = job.index("unparsable = 1", tests_failed_parse)
        tests_summaries_inc = job.index("summaries++", tests_unparsable)
        tests_print = job.index(
            'print "summaries=" summaries " passed=" passed " failed=" failed',
            tests_summaries_inc,
        )
        tests_extract_nonfatal = job.index(')" || true', tests_print)
        doctests_phase_start = job.index(
            '$0 == "Running documentation tests check..." { in_phase=1; next }',
            tests_extract_nonfatal,
        )
        doctests_phase_end = job.index(
            '$0 == "Running documentation check..." { in_phase=0 }',
            doctests_phase_start,
        )
        doctests_aggregate = job.index(
            'in_phase && index($0, "test result: ok.") {',
            doctests_phase_end,
        )
        doctests_field_parse = job.index(
            'if ($i ~ /^passed/) line_passed = $(i-1)',
            doctests_aggregate,
        )
        doctests_failed_parse = job.index(
            'if ($i ~ /^failed/) line_failed = $(i-1)',
            doctests_field_parse,
        )
        doctests_unparsable = job.index("unparsable = 1", doctests_failed_parse)
        doctests_summaries_inc = job.index("summaries++", doctests_unparsable)
        doctests_print = job.index(
            'print "summaries=" summaries " passed=" passed " failed=" failed',
            doctests_summaries_inc,
        )
        doctests_extract_nonfatal = job.index(')" || true', doctests_print)
        tests_echo = job.index(
            'echo "Cargo tests: $tests_summary"',
            doctests_extract_nonfatal,
        )
        tests_fallback = job.index(
            'echo "Cargo tests: summary unavailable (log format changed)."',
            tests_echo,
        )
        doctests_echo = job.index(
            'echo "Cargo doc-tests: $doctests_summary"',
            tests_fallback,
        )
        doctests_fallback = job.index(
            'echo "Cargo doc-tests: summary unavailable (log format changed)."',
            doctests_echo,
        )
        # Reject last-line-only and whole-log tail approaches that hide crates.
        self.assertNotIn("last=$0", job)
        self.assertNotIn("{ last=$0 }", job)
        self.assertNotIn("tail -n 4", job)
        self.assertNotIn("cargo_ok_lines", job)
        self.assertNotIn('grep -F \'test result: ok.\' "$rust_log"', job)
        self.assertNotIn('printf \'%s\\n\' "$cargo_ok_lines"', job)
        # No GNU awk three-argument match in phase aggregation.
        self.assertNotIn("match($0,", job)
        self.assertLess(trap_exit, selector_gate)
        self.assertLess(selector_gate, selector_diag)
        self.assertLess(selector_diag, selector_clear)
        self.assertLess(selector_clear, selector_exit)
        self.assertLess(selector_exit, notices_bg)
        self.assertLess(notices_bg, notices_pid)
        self.assertLess(notices_pid, rust_seq)
        self.assertLess(rust_seq, rust_bg)
        self.assertLess(rust_bg, rust_pid)
        self.assertLess(rust_pid, wait_rust)
        self.assertLess(wait_rust, wait_notices)
        self.assertLess(wait_notices, failure_gate)
        self.assertLess(failure_gate, flush_on_fail)
        self.assertLess(flush_on_fail, trap_clear_fail)
        self.assertLess(trap_clear_fail, fail_rust)
        self.assertLess(fail_rust, exit_rust)
        self.assertLess(exit_rust, exit_notices)
        self.assertLess(exit_notices, trap_clear_ok)
        self.assertLess(trap_clear_ok, summary_both)
        self.assertLess(summary_both, summary_rust)
        self.assertLess(summary_rust, summary_notices_gate)
        self.assertLess(summary_notices_gate, summary_notices)
        self.assertLess(summary_notices, summary_noop_else)
        self.assertLess(summary_noop_else, summary_noop_exit)
        self.assertLess(summary_noop_exit, tests_phase_start)
        self.assertLess(tests_phase_start, tests_phase_end)
        self.assertLess(tests_phase_end, tests_aggregate)
        self.assertLess(tests_aggregate, tests_field_parse)
        self.assertLess(tests_field_parse, tests_failed_parse)
        self.assertLess(tests_failed_parse, tests_unparsable)
        self.assertLess(tests_unparsable, tests_summaries_inc)
        self.assertLess(tests_summaries_inc, tests_print)
        self.assertLess(tests_print, tests_extract_nonfatal)
        self.assertLess(tests_extract_nonfatal, doctests_phase_start)
        self.assertLess(doctests_phase_start, doctests_phase_end)
        self.assertLess(doctests_phase_end, doctests_aggregate)
        self.assertLess(doctests_aggregate, doctests_field_parse)
        self.assertLess(doctests_field_parse, doctests_failed_parse)
        self.assertLess(doctests_failed_parse, doctests_unparsable)
        self.assertLess(doctests_unparsable, doctests_summaries_inc)
        self.assertLess(doctests_summaries_inc, doctests_print)
        self.assertLess(doctests_print, doctests_extract_nonfatal)
        self.assertLess(doctests_extract_nonfatal, tests_echo)
        self.assertLess(tests_echo, tests_fallback)
        self.assertLess(tests_fallback, doctests_echo)
        self.assertLess(doctests_echo, doctests_fallback)
        # Exactly two background children (Rust + notices).
        self.assertEqual(job.count(" 2>&1 &"), 2)
        # Full logs only in the failure branch (not on the all-success path).
        self.assertEqual(job.count("\n            flush_logs\n"), 1)
        self.assertEqual(job.count("\n          flush_logs\n"), 0)
        # Success path must not cat the full buffered logs.
        self.assertNotIn('cat "$rust_log"', job[trap_clear_ok:])
        self.assertNotIn('cat "$notices_log"', job[trap_clear_ok:])
        # Unavailable fallbacks stay non-fatal; the only success-path exit 1 is
        # the explicit no-op selector fail-closed else (early gate is pre-launch).
        success_path = job[trap_clear_ok:]
        self.assertEqual(success_path.count("exit 1"), 1)
        self.assertIn(
            "neither RUN_RUST nor RUN_NOTICES is exactly true; refusing no-op success.",
            success_path,
        )
        self.assertEqual(success_path.count("|| true"), 2)
        # Exact step env pin: only RUN_RUST and RUN_NOTICES with expected values.
        self.assertEqual(
            _named_step_env_entries(job, "Run macOS quality checks"),
            {
                "RUN_RUST": "${{ needs.changes.outputs.rust_macos }}",
                "RUN_NOTICES": "${{ needs.changes.outputs.notices }}",
            },
        )
        # No shell continuation lines anywhere in the executable job body.
        self.assertEqual(_macos_quality_non_comment_lines_ending_backslash(job), [])
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
        body = _xtask_fn_body(xtask, "ci_macos")

        # Extract ordered cargo(&[...]) argument arrays (formatting-tolerant).
        cargo_arg_lists = _cargo_arg_lists(body)
        self.assertEqual(len(cargo_arg_lists), 4)
        xtask_commands = ["cargo " + " ".join(args) for args in cargo_arg_lists]
        # Exact ordered reconstruction must match the four workflow pins. Removing
        # --locked / --all-targets / --all-features from any cargo call fails here.
        pinned_commands = [
            "cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings",
            "cargo test --locked --workspace --all-targets --all-features",
            "cargo test --locked --workspace --doc --all-features",
            "cargo doc --locked --workspace --no-deps --all-features",
        ]
        self.assertEqual(xtask_commands, pinned_commands)

        jobs = dict(self._workflow_job_blocks(workflow))
        job = jobs["macos_quality"]
        # Exact executable Cargo inventory: bare block-scalar lines and single-line
        # `run: cargo ...` scalars only. Equality catches appended, removed,
        # reordered, or replaced flags; undeclared single-line `run: cargo`,
        # env/command-prefixed cargo, and extra invocations fail rather than
        # normalize away. Notices path contributes leading `cargo fetch --locked`.
        workflow_cargo_lines = _macos_quality_cargo_inventory(job)
        self.assertEqual(
            workflow_cargo_lines,
            ["cargo fetch --locked", *pinned_commands],
        )

        # rustdoc environment equivalence (workflow export vs xtask Command::env).
        self.assertIn('.env("RUSTDOCFLAGS", "--deny warnings")', body)
        self.assertIn('export RUSTDOCFLAGS="--deny warnings"', job)

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

    def test_xtask_verify_retains_portable_checks_absent_from_ci_macos(self) -> None:
        """Linux verify keeps architecture/fmt/check that justify thinner macOS."""
        xtask = (ROOT / "xtask" / "src" / "main.rs").read_text(encoding="utf-8")
        verify_body = _xtask_fn_body(xtask, "verify")
        ci_macos_body = _xtask_fn_body(xtask, "ci_macos")

        # Portable checks appear in verify in order before Clippy/tests/doc/rustdoc.
        arch_at = verify_body.index("check_architecture()?")
        first_cargo_at = verify_body.index("cargo(")
        self.assertLess(arch_at, first_cargo_at)

        verify_cargo = _cargo_arg_lists(verify_body)
        self.assertEqual(len(verify_cargo), 6)
        verify_commands = ["cargo " + " ".join(args) for args in verify_cargo]
        # Exact ordered portable trio, then Clippy/tests/doc-tests/rustdoc.
        self.assertEqual(
            verify_commands,
            [
                "cargo fmt --all --check",
                "cargo check --locked --workspace --all-targets --all-features",
                "cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings",
                "cargo test --locked --workspace --all-targets --all-features",
                "cargo test --locked --workspace --doc --all-features",
                "cargo doc --locked --workspace --no-deps --all-features",
            ],
        )
        self.assertEqual(verify_cargo[0], ["fmt", "--all", "--check"])
        self.assertEqual(
            verify_cargo[1],
            ["check", "--locked", "--workspace", "--all-targets", "--all-features"],
        )

        # Exact ci_macos equivalence: only the four host suite commands.
        ci_macos_cargo = _cargo_arg_lists(ci_macos_body)
        self.assertEqual(
            ["cargo " + " ".join(args) for args in ci_macos_cargo],
            [
                "cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings",
                "cargo test --locked --workspace --all-targets --all-features",
                "cargo test --locked --workspace --doc --all-features",
                "cargo doc --locked --workspace --no-deps --all-features",
            ],
        )
        # The three portable checks must remain absent from ci_macos.
        self.assertNotIn("check_architecture", ci_macos_body)
        self.assertNotIn(["fmt", "--all", "--check"], ci_macos_cargo)
        self.assertNotIn(
            ["check", "--locked", "--workspace", "--all-targets", "--all-features"],
            ci_macos_cargo,
        )
        self.assertTrue(all(args and args[0] != "fmt" for args in ci_macos_cargo))
        self.assertTrue(all(args and args[0] != "check" for args in ci_macos_cargo))

    def test_macos_quality_cargo_inventory_prefix_rules(self) -> None:
        """Bare and run: normalize; other prefixes, folds, tabs, quotes fail-closed."""
        sample = "\n".join(
            (
                # Allowed current shapes (normalize).
                "              cargo fetch --locked",
                "        run: cargo clippy --locked --workspace",
                # Folded YAML scalar: bare cargo at end of physical line.
                "        run: >-",
                "          cargo",
                "          build --release --locked",
                # Tab between run: and cargo (must not normalize as run: ).
                "        run:\tcargo test --locked",
                # Quoted / modified cargo (keep full line).
                "        'cargo' build",
                '        "cargo" test',
                "        FOO=1 cargo build --release",
                "        env cargo test",
                "        command: cargo doc",
                "        sh -c 'cargo check'",
                # Comments and non-command strings must not match.
                "        # cargo ignored as comment",
                "        # cargo",
                "        tool: cargo-about@0.9.1",
                "        uses: cargo-about@0.9.1",
                "        run: env cargo build",
            )
        )
        self.assertEqual(
            _macos_quality_cargo_inventory(sample),
            [
                "cargo fetch --locked",
                "cargo clippy --locked --workspace",
                # Bare end-of-line cargo from folded scalar (breaks exact pin).
                "cargo",
                "run:\tcargo test --locked",
                "'cargo' build",
                '"cargo" test',
                "FOO=1 cargo build --release",
                "env cargo test",
                "command: cargo doc",
                "sh -c 'cargo check'",
                "run: env cargo build",
            ],
        )
        # cargo-about and comment-only cargo must never enter the inventory.
        self.assertNotIn("cargo-about", "\n".join(_macos_quality_cargo_inventory(sample)))
        # Allowed workflow lines alone still normalize to the bare cargo command.
        self.assertEqual(
            _macos_quality_cargo_inventory(
                "              cargo test --locked --workspace --all-targets --all-features\n"
            ),
            ["cargo test --locked --workspace --all-targets --all-features"],
        )
        self.assertEqual(
            _macos_quality_cargo_inventory(
                "        run: cargo doc --locked --workspace --no-deps --all-features\n"
            ),
            ["cargo doc --locked --workspace --no-deps --all-features"],
        )
        # Folded bare `cargo` alone is inventoried and would fail exact equality.
        self.assertEqual(_macos_quality_cargo_inventory("          cargo\n"), ["cargo"])
        # Non-command identifier must not match.
        self.assertEqual(
            _macos_quality_cargo_inventory("        tool: cargo-about@0.9.1\n"),
            [],
        )

    def test_macos_quality_forbids_shell_continuation_and_pins_step_env(self) -> None:
        """Adjacent-line and step-env bypasses fail closed without YAML deps."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs = dict(self._workflow_job_blocks(workflow))
        job = jobs["macos_quality"]

        # Current job body must need no continuation lines.
        self.assertEqual(_macos_quality_non_comment_lines_ending_backslash(job), [])
        # Regression: `true || \` before a pinned cargo line is detected.
        bypass = job.replace(
            "              cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings",
            "              true || \\\n"
            "              cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings",
        )
        offenders = _macos_quality_non_comment_lines_ending_backslash(bypass)
        self.assertTrue(any(line.rstrip().endswith("\\") for line in offenders))
        # Comment-only trailing backslash is ignored.
        self.assertEqual(
            _macos_quality_non_comment_lines_ending_backslash(
                "          # intentional comment \\\n              cargo test --locked\n"
            ),
            [],
        )

        expected_env = {
            "RUN_RUST": "${{ needs.changes.outputs.rust_macos }}",
            "RUN_NOTICES": "${{ needs.changes.outputs.notices }}",
        }
        self.assertEqual(
            _named_step_env_entries(job, "Run macOS quality checks"),
            expected_env,
        )
        # Added step env key (for example RUSTFLAGS override) must not match pin.
        with_extra = job.replace(
            "          RUN_NOTICES: ${{ needs.changes.outputs.notices }}\n",
            "          RUN_NOTICES: ${{ needs.changes.outputs.notices }}\n"
            "          RUSTFLAGS: ''\n",
        )
        self.assertNotEqual(
            _named_step_env_entries(with_extra, "Run macOS quality checks"),
            expected_env,
        )
        self.assertIn(
            "RUSTFLAGS",
            _named_step_env_entries(with_extra, "Run macOS quality checks"),
        )
        # Removed or changed values also fail exact equality.
        missing = job.replace(
            "          RUN_NOTICES: ${{ needs.changes.outputs.notices }}\n",
            "",
        )
        self.assertNotEqual(
            _named_step_env_entries(missing, "Run macOS quality checks"),
            expected_env,
        )
        changed = job.replace(
            "          RUN_RUST: ${{ needs.changes.outputs.rust_macos }}\n",
            "          RUN_RUST: 'true'\n",
        )
        self.assertNotEqual(
            _named_step_env_entries(changed, "Run macOS quality checks"),
            expected_env,
        )
        # Existing cargo inventory + folded/tab/quoted regressions remain active.
        self.assertEqual(
            _macos_quality_cargo_inventory(job),
            [
                "cargo fetch --locked",
                "cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings",
                "cargo test --locked --workspace --all-targets --all-features",
                "cargo test --locked --workspace --doc --all-features",
                "cargo doc --locked --workspace --no-deps --all-features",
            ],
        )

    def test_macos_quality_run_executable_lines_match_exact_pin(self) -> None:
        """Every non-comment executable physical line of the run block is pinned."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs = dict(self._workflow_job_blocks(workflow))
        job = jobs["macos_quality"]
        script = _named_step_block_scalar_script(job, "Run macOS quality checks")
        actual = _executable_physical_lines(script)
        self.assertEqual(tuple(actual), MACOS_QUALITY_RUN_EXECUTABLE_LINES)
        # Pin is non-empty and includes the load-bearing suite markers.
        self.assertGreater(len(MACOS_QUALITY_RUN_EXECUTABLE_LINES), 50)
        self.assertIn("set -euo pipefail", MACOS_QUALITY_RUN_EXECUTABLE_LINES)
        self.assertIn(
            """trap 'rc=$?; flush_logs || true; exit "$rc"' EXIT""",
            MACOS_QUALITY_RUN_EXECUTABLE_LINES,
        )
        # Nested suite commands keep relative indent after normalization.
        self.assertTrue(
            any(
                line.lstrip()
                == "cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings"
                for line in MACOS_QUALITY_RUN_EXECUTABLE_LINES
            ),
            msg="pinned executable lines must include the Clippy suite command",
        )
        # Comment-only edits to the live script must not fail the pin.
        with_comment = script.replace(
            "          set -euo pipefail\n",
            "          set -euo pipefail\n"
            "          # comment-only change must not fail the executable pin\n",
        )
        self.assertEqual(
            tuple(_executable_physical_lines(with_comment)),
            MACOS_QUALITY_RUN_EXECUTABLE_LINES,
        )
        # Blank-line insertion is also ignored.
        with_blank = script.replace(
            "          set -euo pipefail\n",
            "          set -euo pipefail\n\n",
        )
        self.assertEqual(
            tuple(_executable_physical_lines(with_blank)),
            MACOS_QUALITY_RUN_EXECUTABLE_LINES,
        )

    def test_macos_quality_run_executable_lines_reject_shell_neutralization(
        self,
    ) -> None:
        """if-false wrappers, heredocs, and early exit 0 fail full-line equality."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs = dict(self._workflow_job_blocks(workflow))
        job = jobs["macos_quality"]
        script = _named_step_block_scalar_script(job, "Run macOS quality checks")
        baseline = tuple(_executable_physical_lines(script))
        self.assertEqual(baseline, MACOS_QUALITY_RUN_EXECUTABLE_LINES)

        # Multi-line neutralization: wrap the suite in a never-taken branch.
        if_false = script.replace(
            "          set -euo pipefail\n",
            "          set -euo pipefail\n"
            "          if false; then\n",
            1,
        )
        # Close the wrapper just before the natural end of the script body.
        if_false = if_false.rstrip("\n") + "\n          fi\n"
        self.assertNotEqual(
            tuple(_executable_physical_lines(if_false)),
            MACOS_QUALITY_RUN_EXECUTABLE_LINES,
        )
        self.assertIn(
            "if false; then",
            _executable_physical_lines(if_false),
        )
        self.assertIn("fi", _executable_physical_lines(if_false)[-1:])

        # Heredoc that swallows a cargo command so the pin line vanishes.
        heredoc = script.replace(
            "              cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings\n",
            "              cat <<'EOF'\n"
            "              cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings\n"
            "              EOF\n",
        )
        heredoc_lines = _executable_physical_lines(heredoc)
        self.assertNotEqual(tuple(heredoc_lines), MACOS_QUALITY_RUN_EXECUTABLE_LINES)
        self.assertTrue(
            any("cat <<'EOF'" in line or "cat <<EOF" in line for line in heredoc_lines)
            or any(line.strip() == "EOF" for line in heredoc_lines),
            msg=f"heredoc markers missing from mutated inventory: {heredoc_lines!r}",
        )

        # Early success: exit 0 before any suite work.
        early_exit = script.replace(
            "          set -euo pipefail\n",
            "          set -euo pipefail\n"
            "          exit 0\n",
        )
        early_lines = _executable_physical_lines(early_exit)
        self.assertNotEqual(tuple(early_lines), MACOS_QUALITY_RUN_EXECUTABLE_LINES)
        self.assertIn("exit 0", early_lines)

        # Cargo-only inventory still cannot see if-false neutralization alone when
        # cargo lines remain present — full executable equality is the guard.
        if_false_cargo_only = _macos_quality_cargo_inventory(
            "              if false; then\n"
            "              cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings\n"
            "              fi\n"
        )
        self.assertEqual(
            if_false_cargo_only,
            [
                "cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings",
            ],
        )

    def test_macos_quality_mapping_and_step_keys_reject_bypasses(self) -> None:
        """Workflow/job/step mapping pins close env and step-level bypasses."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs = dict(self._workflow_job_blocks(workflow))
        job = jobs["macos_quality"]

        # Workflow-level env is exactly the two global diagnostic settings.
        expected_workflow_env = {
            "CARGO_TERM_COLOR": "always",
            "RUST_BACKTRACE": "1",
        }
        self.assertEqual(_workflow_level_env_entries(workflow), expected_workflow_env)
        # Extra workflow-level RUSTFLAGS must fail the pin.
        with_workflow_rustflags = workflow.replace(
            "  RUST_BACKTRACE: 1\n",
            "  RUST_BACKTRACE: 1\n"
            "  RUSTFLAGS: --cap-lints=allow\n",
        )
        self.assertNotEqual(
            _workflow_level_env_entries(with_workflow_rustflags),
            expected_workflow_env,
        )
        self.assertIn(
            "RUSTFLAGS",
            _workflow_level_env_entries(with_workflow_rustflags),
        )

        # macos_quality must not declare a job-level env map.
        self.assertFalse(_job_has_job_level_env(job))
        with_job_env = job.replace(
            "    timeout-minutes: 15\n",
            "    timeout-minutes: 15\n"
            "    env:\n"
            "      RUSTFLAGS: --cap-lints=allow\n",
        )
        self.assertTrue(_job_has_job_level_env(with_job_env))

        # Named step siblings are exactly name, env, run (no if / shell / …).
        expected_keys = ["name", "env", "run"]
        self.assertEqual(
            _named_step_sibling_keys(job, "Run macOS quality checks"),
            expected_keys,
        )
        # Step-level if: ${{ false }} must fail the sibling-key pin.
        with_step_if = job.replace(
            "      - name: Run macOS quality checks\n",
            "      - name: Run macOS quality checks\n"
            "        if: ${{ false }}\n",
        )
        self.assertNotEqual(
            _named_step_sibling_keys(with_step_if, "Run macOS quality checks"),
            expected_keys,
        )
        self.assertEqual(
            _named_step_sibling_keys(with_step_if, "Run macOS quality checks"),
            ["name", "if", "env", "run"],
        )
        # continue-on-error and shell overrides are also rejected.
        with_continue = job.replace(
            "      - name: Run macOS quality checks\n",
            "      - name: Run macOS quality checks\n"
            "        continue-on-error: true\n",
        )
        self.assertIn(
            "continue-on-error",
            _named_step_sibling_keys(with_continue, "Run macOS quality checks"),
        )
        with_shell = job.replace(
            "        run: |\n",
            "        shell: bash\n"
            "        run: |\n",
        )
        # Only the quality-checks step uses this env+run shape; still assert.
        self.assertIn(
            "shell",
            _named_step_sibling_keys(with_shell, "Run macOS quality checks"),
        )

        # Ordinary job-level if: on macos_quality (classifier gate) remains.
        self.assertIn(
            "if: ${{ needs.changes.outputs.rust_macos == 'true' || needs.changes.outputs.notices == 'true' }}",
            job,
        )
        # Other jobs may still use job-level env (Apple product) without failing.
        apple = jobs["apple_product"]
        self.assertTrue(_job_has_job_level_env(apple))

    def test_macos_quality_selector_fail_closed_without_selected_lanes(self) -> None:
        """Job must not claim notices success when neither selector is true."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs = dict(self._workflow_job_blocks(workflow))
        job = jobs["macos_quality"]
        # Early validation before children launch.
        early = job.index(
            'if [ "$RUN_RUST" != "true" ] && [ "$RUN_NOTICES" != "true" ]; then'
        )
        early_exit = job.index("exit 1", early)
        notices_launch = job.index('if [ "$RUN_NOTICES" = "true" ]; then', early_exit)
        rust_launch = job.index('if [ "$RUN_RUST" = "true" ]; then', notices_launch)
        self.assertLess(early, early_exit)
        self.assertLess(early_exit, notices_launch)
        self.assertLess(notices_launch, rust_launch)
        # Final summary is trifurcated; bare else no longer claims notices success.
        self.assertIn('elif [ "$RUN_NOTICES" = "true" ]; then', job)
        # Notices-only success string only appears under the notices elif arm.
        notices_success = 'echo "macOS quality: third-party notices succeeded."'
        self.assertEqual(job.count(notices_success), 1)
        notices_elif = job.index('elif [ "$RUN_NOTICES" = "true" ]; then')
        self.assertLess(notices_elif, job.index(notices_success, notices_elif))
        # Valid mode gates remain exact-true checks.
        self.assertIn('if [ "$RUN_RUST" = "true" ] && [ "$RUN_NOTICES" = "true" ]; then', job)
        self.assertIn('elif [ "$RUN_RUST" = "true" ]; then', job)
        self.assertIn('if [ "$RUN_RUST" = "true" ]; then', job)
        self.assertIn('if [ "$RUN_NOTICES" = "true" ]; then', job)

    def test_cargo_phase_aggregation_sums_all_crate_summaries(self) -> None:
        """Aggregate awk counts every ok summary; last-line-only is insufficient."""
        # Multi-crate normal-test window: last crate alone would report only 1
        # passed, while the real suite passed 6 across three summaries.
        tests_log = "\n".join(
            (
                "Running tests check...",
                "running 3 tests",
                "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s",
                "running 2 tests",
                "test result: ok. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s",
                "running 1 test",
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
                "Running documentation tests check...",
                "test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
                "",
            )
        )
        # Doc-test window includes compile-fail crates after an empty xtask line.
        doctests_log = "\n".join(
            (
                "Running documentation tests check...",
                "running 0 tests",
                "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
                "running 2 tests",
                "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s",
                "Running documentation check...",
                "test result: ok. 50 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
                "",
            )
        )
        empty_log = "Running tests check...\nRunning documentation tests check...\n"
        unparsable_log = "\n".join(
            (
                "Running tests check...",
                "test result: ok. not-a-number passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
                "Running documentation tests check...",
                "",
            )
        )

        def run_phase_awk(script_prefix: str, log_text: str) -> str:
            program = script_prefix + _CARGO_PHASE_AGGREGATE_AWK
            result = subprocess.run(
                ["awk", program],
                input=log_text,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                msg=f"awk failed: {result.stderr!r}",
            )
            return result.stdout

        tests_prefix = (
            '$0 == "Running tests check..." { in_phase=1; next }\n'
            '$0 == "Running documentation tests check..." { in_phase=0 }\n'
        )
        doctests_prefix = (
            '$0 == "Running documentation tests check..." { in_phase=1; next }\n'
            '$0 == "Running documentation check..." { in_phase=0 }\n'
        )
        self.assertEqual(
            run_phase_awk(tests_prefix, tests_log),
            "summaries=3 passed=6 failed=1\n",
        )
        self.assertEqual(
            run_phase_awk(doctests_prefix, doctests_log),
            "summaries=2 passed=2 failed=0\n",
        )
        # Windows isolate phases: doc-test totals must not leak into tests.
        self.assertEqual(
            run_phase_awk(tests_prefix, doctests_log),
            "",
        )
        # Empty / unparsable phases emit nothing (workflow prints unavailable).
        self.assertEqual(run_phase_awk(tests_prefix, empty_log), "")
        self.assertEqual(run_phase_awk(tests_prefix, unparsable_log), "")
        # Last-line-only logic would wrongly report only the final crate.
        last_only = subprocess.run(
            [
                "awk",
                (
                    '$0 == "Running tests check..." { in_phase=1; next }\n'
                    '$0 == "Running documentation tests check..." { in_phase=0 }\n'
                    'in_phase && index($0, "test result: ok.") { last=$0 }\n'
                    'END { if (last != "") print last }\n'
                ),
            ],
            input=tests_log,
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        self.assertIn("1 passed", last_only)
        self.assertNotIn("summaries=3", last_only)
        # Workflow embeds the same aggregation field-parse contract twice.
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs = dict(self._workflow_job_blocks(workflow))
        job = jobs["macos_quality"]
        self.assertEqual(job.count("summaries++"), 2)
        self.assertEqual(job.count('if ($i ~ /^passed/) line_passed = $(i-1)'), 2)
        self.assertEqual(job.count('if ($i ~ /^failed/) line_failed = $(i-1)'), 2)
        self.assertEqual(
            job.count(
                'print "summaries=" summaries " passed=" passed " failed=" failed'
            ),
            2,
        )
        self.assertEqual(
            job.count('echo "Cargo tests: summary unavailable (log format changed)."'),
            1,
        )
        self.assertEqual(
            job.count(
                'echo "Cargo doc-tests: summary unavailable (log format changed)."'
            ),
            1,
        )
        self.assertNotIn("last=$0", job)

    def test_ci_macos_consolidation_doc_records_measured_exact_head_sample(self) -> None:
        """Budget is measured; identical-workflow variance must stay visible."""
        doc = (ROOT / "docs" / "quality" / "ci-macos-consolidation.md").read_text(
            encoding="utf-8"
        )
        # Normative exact-head sample evidence from Actions run 31001855133.
        self.assertIn("31001855133", doc)
        self.assertIn("a0c8a91f7f3606ef4139bd84005e3f8894694e98", doc)
        self.assertIn("127 seconds", doc)
        self.assertIn("101 seconds", doc)
        self.assertIn("111 seconds", doc)
        self.assertIn("212", doc)
        self.assertIn("exactly 2", doc)
        self.assertIn("exactly 6", doc)
        self.assertIn("8 seconds", doc)
        self.assertIn("Exact-head sample (measured)", doc)
        self.assertIn("Exact-head measurement procedure", doc)
        self.assertIn("Identical-workflow variance", doc)
        # Baseline, budgets, coverage matrix, and self-reference remain.
        self.assertIn("Baseline (pre-consolidation)", doc)
        self.assertIn("Acceptance budgets (post-consolidation)", doc)
        self.assertIn("Coverage matrix and ownership", doc)
        self.assertIn("30977712430", doc)
        self.assertIn("≤ 220", doc)
        # Final-head same-workflow evidence (run 31002144453): both attempts.
        self.assertIn("31002144453", doc)
        self.assertIn("148 seconds", doc)
        self.assertIn("129 seconds", doc)
        self.assertIn("116 seconds", doc)
        self.assertIn("245 seconds", doc)
        self.assertIn("104 seconds", doc)
        self.assertIn("86 seconds", doc)
        self.assertIn("90 seconds", doc)
        self.assertIn("176 seconds", doc)
        # Range may use ASCII hyphen or en-dash.
        self.assertTrue(
            "176-245" in doc or "176–245" in doc,
            msg="expected identical-workflow aggregate range 176-245",
        )
        self.assertIn("attempt 1", doc)
        self.assertIn("attempt 2", doc)
        self.assertRegex(doc, r"(?i)breach")
        # Phrase may wrap across Markdown lines (for example bold `runner\nvariance`).
        self.assertRegex(doc, r"(?i)runner\s+variance")
        self.assertRegex(doc, r"(?i)identical[- ]workflow")
        # Must not claim the 8-second sample headroom describes the distribution.
        self.assertNotIn("sample headroom describes the distribution", doc)
        self.assertNotIn(
            "The eight-second\naggregate headroom means runner variance or small suite regressions can still\nbreach the budget; re-run the measurement procedure after material changes.",
            doc,
        )
        # Superseded normative sample (run 30997714456) must not remain.
        for superseded in (
            "30997714456",
            "9c7ecad2169b9b9b31f4ab30e2fb47f775fcac69",
            "132 seconds",
            "3 seconds",
        ):
            with self.subTest(superseded=superseded):
                self.assertNotIn(superseded, doc)
        # Stale "unmeasured" budget claims must not return.
        for stale in (
            "does **not** claim that the\nacceptance budget has been measured",
            "treat the budgets below as targets only",
            "Budget pass/fail requires a\nrepresentative exact-head pull-request run after this change lands",
            "unmeasured",
        ):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, doc)

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
