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
DOCS_ONLY_PREFIXES = ("docs/", ".github/")
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
        if path in CI_CONTROL_PATHS or path.startswith(DOCS_ONLY_PREFIXES) or path.endswith(".md"):
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
            scope.enable("rust_linux", "policy")
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify changed paths for fail-closed product CI.")
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="Changed repository-relative paths; when omitted, read newline-delimited paths from standard input.",
    )
    arguments = parser.parse_args()
    scope = classify(read_paths(arguments.paths))
    for field in fields(Scope):
        print(f"{field.name}={'true' if getattr(scope, field.name) else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
