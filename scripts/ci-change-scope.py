#!/usr/bin/env python3
"""Classify changed repository paths into conservative CI evidence scopes.

Read newline-delimited paths from standard input, or pass paths as positional
arguments.  The output uses the ``key=true`` format accepted by GitHub Actions
when redirected to ``$GITHUB_OUTPUT``.  Any unrecognised path is intentionally
treated as a full-evidence change.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, fields
import sys
from typing import Iterable


@dataclass
class Scope:
    product_apple: bool = False
    slint: bool = False
    dioxus: bool = False
    sqlcipher: bool = False
    search: bool = False
    mime: bool = False
    mime_fuzz: bool = False
    blob: bool = False
    notices: bool = False
    full_evidence: bool = False

    def enable(self, *names: str) -> None:
        for name in names:
            setattr(self, name, True)


COMPONENT_PATHS = {
    "apps/slint-spike/": ("slint",),
    "apps/dioxus-spike/": ("dioxus",),
    "apps/sqlcipher-spike/": ("sqlcipher",),
    "apps/search-spike/": ("search",),
    "apps/mime-spike/": ("mime",),
    "apps/blob-spike/": ("blob",),
}

# These crates feed both current UI spikes.  They are production code, so they
# also require the product build; the two reverse dependants are enumerated
# instead of guessing from arbitrary Cargo metadata at CI runtime.
SHARED_UI_CRATES = ("crates/domain/", "crates/application/", "crates/presentation/")
APPLE_ADAPTERS = "adapters/"
DOCS_ONLY_PREFIXES = ("docs/", "xtask/", ".github/")
CI_CONTROL_PATHS = {
    "scripts/ci-change-scope.py",
    "scripts/test_ci_change_scope.py",
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


def enable_full(scope: Scope) -> None:
    scope.enable(*(field.name for field in fields(Scope)))


def normalise_path(path: str) -> str | None:
    """Return a repository-relative path, rejecting ambiguous input."""
    path = path.strip()
    if not path or path.startswith("/") or path.startswith("../") or "/../" in path:
        return None
    while path.startswith("./"):
        path = path[2:]
    return path or None


def classify(paths: Iterable[str], *, full: bool = False) -> Scope:
    """Return the union of evidence scopes needed for *paths*.

    Empty input, malformed input, and unknown paths fail closed to every scope.
    """
    scope = Scope()
    seen = False
    if full:
        enable_full(scope)
        return scope

    for raw_path in paths:
        seen = True
        path = normalise_path(raw_path)
        if path is None:
            enable_full(scope)
            continue
        if path in FULL_FANOUT_PATHS or path.startswith(FULL_FANOUT_PREFIXES):
            enable_full(scope)
            continue
        if path in CI_CONTROL_PATHS or path.startswith(DOCS_ONLY_PREFIXES) or path.endswith(".md"):
            continue
        if path.endswith("/Cargo.toml"):
            scope.enable("notices")
        component = next(
            (names for prefix, names in COMPONENT_PATHS.items() if path.startswith(prefix)),
            None,
        )
        if component is not None:
            scope.enable(*component)
            continue
        if path.startswith("fuzz/") or path == "scripts/verify-mime-fuzz.sh":
            scope.enable("mime", "mime_fuzz")
            continue
        if path.startswith("apple/licenses/"):
            scope.enable("notices")
            continue
        if path.startswith("apple/slint-"):
            scope.enable("product_apple", "slint")
            continue
        if path.startswith("apple/dioxus-"):
            scope.enable("product_apple", "dioxus")
            continue
        if path.startswith("apple/mime-") or path.startswith("apple/mime-common/"):
            scope.enable("product_apple", "mime")
            continue
        if path.startswith(SHARED_UI_CRATES):
            scope.enable("product_apple", "slint", "dioxus")
            continue
        if path.startswith("crates/platform/") or path.startswith(APPLE_ADAPTERS):
            scope.enable("product_apple")
            continue
        if path.startswith("apple/"):
            scope.enable("product_apple")
            continue
        if path == "about.toml":
            scope.enable("slint", "notices")
            continue
        if path == "about-bridge.toml":
            scope.enable("product_apple", "notices")
            continue
        if path == "about-dioxus.toml":
            scope.enable("dioxus", "notices")
            continue
        if path == "about-sqlcipher.toml":
            scope.enable("sqlcipher", "notices")
            continue
        if path == "about-search.toml":
            scope.enable("search", "notices")
            continue
        if path == "about-mime.toml":
            scope.enable("mime", "notices")
            continue
        if path == "about-blob.toml":
            scope.enable("blob", "notices")
            continue
        enable_full(scope)

    if not seen:
        enable_full(scope)
    return scope


def read_paths(arguments: list[str]) -> list[str]:
    return arguments if arguments else sys.stdin.read().splitlines()


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify changed paths for fail-closed CI evidence.")
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="Changed repository-relative paths; when omitted, read newline-delimited paths from standard input.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Force every evidence scope (for main, merge groups, or manual runs).",
    )
    arguments = parser.parse_args()
    scope = classify(read_paths(arguments.paths), full=arguments.full)
    for field in fields(Scope):
        print(f"{field.name}={'true' if getattr(scope, field.name) else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
