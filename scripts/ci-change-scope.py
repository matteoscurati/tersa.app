#!/usr/bin/env python3
"""Classify changed repository paths into conservative product CI scopes.

Read newline-delimited paths from standard input, or pass paths as positional
arguments.  The output uses the ``key=true`` format accepted by GitHub Actions
when redirected to ``$GITHUB_OUTPUT``.  Any unrecognised path is intentionally
treated as a change that enables every active product scope.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, fields
import sys
from typing import Iterable


@dataclass
class Scope:
    rust_linux: bool = False
    rust_macos: bool = False
    policy: bool = False
    product_apple: bool = False
    notices: bool = False

    def enable(self, *names: str) -> None:
        for name in names:
            setattr(self, name, True)


# Shared domain crates feed the product surface, so they also require the
# product Apple build rather than guessing reverse dependants from Cargo
# metadata at CI runtime.
SHARED_UI_CRATES = ("crates/domain/", "crates/application/", "crates/presentation/")
APPLE_ADAPTERS = "adapters/"
# Non-executable documentation stays lightweight. Executable CI control inputs
# (workflow YAML, composite actions, classifier/DCO/performance scripts and their
# tests) fail closed to every product lane so a control-plane change cannot skip
# the lanes it alters.
DOCS_ONLY_PREFIXES = ("docs/",)
# Explicit non-executable GitHub metadata. Markdown under .github/ is already
# lightweight via the .md suffix; unrecognised .github/ paths fail closed.
GITHUB_LIGHTWEIGHT_PATHS = {
    ".github/CODEOWNERS",
}
GITHUB_LIGHTWEIGHT_PREFIXES = (
    ".github/ISSUE_TEMPLATE/",
    ".github/PULL_REQUEST_TEMPLATE/",
)
CI_CONTROL_PATHS = {
    "scripts/check-dco.py",
    "scripts/ci-change-scope.py",
    "scripts/macos-performance-report.py",
    "scripts/test_check_dco.py",
    "scripts/test_ci_change_scope.py",
    "scripts/test_macos_performance_report.py",
}
FULL_FANOUT_PATHS = {
    "Cargo.toml",
    "Cargo.lock",
}
FULL_FANOUT_PREFIXES = (
    "apple/scripts/",
    "apple/build/",
    "vendor/",
    "patches/",
    ".github/workflows/",
)


def enable_all(scope: Scope) -> None:
    scope.enable(*(field.name for field in fields(Scope)))


def normalise_path(path: str) -> str | None:
    """Return a repository-relative path, rejecting ambiguous input."""
    path = path.strip()
    if not path or path.startswith("/") or path.startswith("../") or "/../" in path:
        return None
    while path.startswith("./"):
        path = path[2:]
    return path or None


def classify(paths: Iterable[str]) -> Scope:
    """Return the union of product CI scopes needed for *paths*.

    Empty input, malformed input, and unknown paths fail closed to every scope.
    """
    scope = Scope()
    seen = False

    for raw_path in paths:
        seen = True
        path = normalise_path(raw_path)
        if path is None:
            enable_all(scope)
            continue
        if path in FULL_FANOUT_PATHS or path.startswith(FULL_FANOUT_PREFIXES):
            enable_all(scope)
            continue
        if path in CI_CONTROL_PATHS:
            # Executable CI control scripts and their tests alter how lanes are
            # selected or enforced; fail closed to every active product scope.
            enable_all(scope)
            continue
        if path.startswith(DOCS_ONLY_PREFIXES) or path.endswith(".md"):
            continue
        if path in GITHUB_LIGHTWEIGHT_PATHS or path.startswith(GITHUB_LIGHTWEIGHT_PREFIXES):
            # Issue/PR templates and CODEOWNERS are non-executable metadata.
            continue
        if path.startswith(".github/"):
            # Workflow YAML already matched FULL_FANOUT_PREFIXES. Composite
            # actions and any other unrecognised GitHub control input fail closed.
            enable_all(scope)
            continue
        if path.endswith("/Cargo.toml"):
            scope.enable("rust_linux", "policy", "notices")
        if path.startswith("apple/licenses/"):
            scope.enable("notices")
            continue
        # Security-critical Apple packaging inputs can drift the fail-closed
        # policy checked by `cargo xtask verify`, so they also enable the
        # portable Rust and policy lanes. `apple/macos/**` hosts the product
        # client XPC-wiring guards; the token broker, XcodeGen project, and
        # entitlements are the other exact-scoped inputs.
        is_component_entitlement = path.startswith("apple/") and path.endswith(
            ".entitlements"
        )
        if (
            path.startswith("apple/macos-token-broker/")
            or path.startswith("apple/macos/")
            or path == "apple/project.yml"
            or is_component_entitlement
        ):
            scope.enable("rust_linux", "policy", "product_apple")
            continue
        if path.startswith(SHARED_UI_CRATES):
            scope.enable("rust_linux", "policy", "product_apple")
            continue
        if path.startswith("crates/platform/") or path.startswith(APPLE_ADAPTERS):
            scope.enable("rust_linux", "rust_macos", "policy", "product_apple")
            continue
        if path.startswith("apple/rust-bridge/"):
            scope.enable("rust_linux", "rust_macos", "policy", "product_apple")
            continue
        if path.startswith("apps/cli-macos/"):
            scope.enable("rust_linux", "rust_macos", "policy")
            continue
        if path.startswith("xtask/"):
            # xtask implements both `verify` and `ci-macos`, so any path under
            # xtask/ is an executable CI control input. Fail closed to every
            # active product scope, including macOS quality.
            enable_all(scope)
            continue
        if path.startswith("apple/"):
            scope.enable("product_apple")
            continue
        if path == "about-bridge.toml":
            scope.enable("product_apple", "notices")
            continue
        enable_all(scope)

    if not seen:
        enable_all(scope)
    return scope


def read_paths(arguments: list[str]) -> list[str]:
    return arguments if arguments else sys.stdin.read().splitlines()


def recommend_preflight_classes(paths: Iterable[str], scope: Scope) -> list[str]:
    """Suggest agent playbook preflight class names for *paths*.

    Presentation only: CI continues to use the boolean scope fields alone.
    """
    ordered: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        if name not in seen:
            seen.add(name)
            ordered.append(name)

    for raw_path in paths:
        path = normalise_path(raw_path)
        if path is None:
            add("policy")
            continue
        if path.startswith("xtask/") or path in CI_CONTROL_PATHS or path.startswith(
            FULL_FANOUT_PREFIXES
        ) or path in FULL_FANOUT_PATHS:
            add("policy")
            continue
        if path.startswith("docs/") or path.endswith(".md"):
            add("docs")
            continue
        if path.startswith("crates/domain/"):
            add("domain")
        elif path.startswith("crates/application/"):
            add("application")
        elif path.startswith("crates/presentation/"):
            add("presentation")
        elif path.startswith("apple/rust-bridge/"):
            add("bridge")
        elif path.startswith("apple/macos-token-broker/") or path.startswith(
            "adapters/token-broker-"
        ):
            add("token-broker")
        elif path.startswith("adapters/"):
            add("adapter")
        elif path.startswith("apple/macos/") or path.startswith("apple/macos-tests/"):
            add("swift-ui")
        elif path.startswith("apple/"):
            add("swift-ui")
        elif path.startswith("apps/cli-macos/"):
            add("adapter")
        elif path.startswith("crates/platform/"):
            add("application")

    if not ordered:
        if any(getattr(scope, field.name) for field in fields(Scope)):
            add("policy")
        else:
            add("docs")
    return ordered


def print_github_output(scope: Scope) -> None:
    for field in fields(Scope):
        print(f"{field.name}={'true' if getattr(scope, field.name) else 'false'}")


def print_agent_report(scope: Scope, paths: list[str]) -> None:
    """Human/agent-oriented view; classification matches CI for the same paths."""
    enabled = [field.name for field in fields(Scope) if getattr(scope, field.name)]
    preflights = recommend_preflight_classes(paths, scope)
    # Docs-only changes leave every scope false; full verify is not required.
    full_verify = any(getattr(scope, field.name) for field in fields(Scope))
    print("mode=agent")
    print("scopes:")
    for field in fields(Scope):
        print(f"  {field.name}={'true' if getattr(scope, field.name) else 'false'}")
    print(f"enabled={','.join(enabled) if enabled else '(none)'}")
    print(f"full_verify_recommended={'true' if full_verify else 'false'}")
    print(f"product_apple_lane={'true' if scope.product_apple else 'false'}")
    print("recommended_preflight:")
    for name in preflights:
        print(f"  - {name}")
    if full_verify:
        print("note=run cargo xtask verify before ready-for-review")
    if scope.product_apple:
        print("note=budget for macOS product and quality CI lanes")
    if not full_verify:
        print("note=docs-only or empty product scopes; CI classifier lane is enough")


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify changed paths for fail-closed product CI.")
    parser.add_argument(
        "--agent",
        action="store_true",
        help="Print a human/agent report (scopes + recommended preflight). Classification is identical to CI.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="Changed repository-relative paths; when omitted, read newline-delimited paths from standard input.",
    )
    arguments = parser.parse_args()
    paths = read_paths(arguments.paths)
    scope = classify(paths)
    if arguments.agent:
        print_agent_report(scope, paths)
    else:
        print_github_output(scope)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
