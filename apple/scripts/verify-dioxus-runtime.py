#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Verify the locked Dioxus diagnostic runtime and its transport boundary."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


DIOXUS_VERSION = "0.7.9"
LOOPBACK_BIND = "TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))"
LOOPBACK_URL = "ws://127.0.0.1:{port}/{webview_id}/{key_hex}"
MUTUAL_KEY_SIZE = "const KEY_SIZE: usize = 256;"


APPLE_TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
)
NON_APPLE_ADVISORY_PACKAGES = {
    ("atk", "0.18.2"),
    ("atk-sys", "0.18.2"),
    ("fxhash", "0.2.1"),
    ("gdk", "0.18.2"),
    ("gdk-sys", "0.18.2"),
    ("gdkwayland-sys", "0.18.2"),
    ("gdkx11-sys", "0.18.2"),
    ("glib", "0.18.5"),
    ("gtk", "0.18.2"),
    ("gtk-sys", "0.18.2"),
    ("gtk3-macros", "0.18.2"),
    ("proc-macro-error", "1.0.4"),
    ("rand", "0.7.3"),
}


def cargo_metadata(workspace: Path, target: str) -> dict[str, Any]:
    command = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--filter-platform",
        target,
        "--locked",
        "--offline",
    ]
    result = subprocess.run(
        command,
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def package(metadata: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [item for item in metadata["packages"] if item["name"] == name]
    if len(matches) != 1:
        raise SystemExit(f"Expected one resolved {name} package, found {len(matches)}")
    return matches[0]


def resolved_features(metadata: dict[str, Any], package_id: str) -> set[str]:
    resolve = metadata.get("resolve")
    if resolve is None:
        raise SystemExit("Cargo metadata did not include a dependency resolution")
    matches = [node for node in resolve["nodes"] if node["id"] == package_id]
    if len(matches) != 1:
        raise SystemExit("Dioxus Desktop is missing from the resolved dependency graph")
    return set(matches[0]["features"])


def resolved_packages(metadata: dict[str, Any]) -> set[tuple[str, str]]:
    resolve = metadata.get("resolve")
    if resolve is None:
        raise SystemExit("Cargo metadata did not include a dependency resolution")
    node_ids = {node["id"] for node in resolve["nodes"]}
    return {
        (item["name"], item["version"])
        for item in metadata["packages"]
        if item["id"] in node_ids
    }


def main() -> None:
    workspace = Path(__file__).resolve().parents[2]
    metadata_by_target = {
        target: cargo_metadata(workspace, target) for target in APPLE_TARGETS
    }
    for target, target_metadata in metadata_by_target.items():
        reachable = NON_APPLE_ADVISORY_PACKAGES.intersection(
            resolved_packages(target_metadata)
        )
        if reachable:
            raise SystemExit(
                f"Non-Apple advisory packages became reachable from {target}: "
                f"{sorted(reachable)}"
            )

    metadata = metadata_by_target["aarch64-apple-darwin"]
    names = {item["name"] for item in metadata["packages"]}
    forbidden = names.intersection({"manganis", "dioxus-devtools", "dioxus-web"})
    if forbidden:
        raise SystemExit(f"Forbidden Dioxus runtime packages are resolved: {sorted(forbidden)}")

    dioxus = package(metadata, "dioxus")
    desktop = package(metadata, "dioxus-desktop")
    if dioxus["version"] != DIOXUS_VERSION or desktop["version"] != DIOXUS_VERSION:
        raise SystemExit("The Dioxus diagnostic graph is not pinned to 0.7.9")

    features = resolved_features(metadata, desktop["id"])
    if features != {"tokio_runtime"}:
        raise SystemExit(
            "Dioxus Desktop must enable only its required tokio_runtime feature; "
            f"resolved {sorted(features)}"
        )

    dioxus_features = resolved_features(metadata, dioxus["id"])
    expected_dioxus_features = {"hooks", "html", "macro", "signals"}
    if dioxus_features != expected_dioxus_features:
        raise SystemExit(
            "The Dioxus facade must keep its minimal diagnostic feature set; "
            f"resolved {sorted(dioxus_features)}"
        )

    source = Path(desktop["manifest_path"]).parent
    edits = (source / "src" / "edits.rs").read_text(encoding="utf-8")
    for marker in (LOOPBACK_BIND, LOOPBACK_URL, MUTUAL_KEY_SIZE):
        if marker not in edits:
            raise SystemExit(f"Dioxus transport invariant changed: missing {marker!r}")

    app = (workspace / "apps" / "dioxus-spike" / "src" / "main.rs").read_text(
        encoding="utf-8"
    )
    required_app_markers = (
        ".with_navigation_handler(|_| false)",
        ".with_custom_index(INDEX.to_owned())",
        '<html lang="en">',
        "<title>tersa.app — Dioxus M0 diagnostic</title>",
        "TERSA-DIOXUS-M0-THREAD",
        "TERSA_DIOXUS_EVIDENCE",
        "viewport-fit=cover",
        "const INBOX_ROWS: usize = 10_000;",
    )
    for marker in required_app_markers:
        if marker not in app:
            raise SystemExit(f"Dioxus application policy changed: missing {marker!r}")
    if "href:" in app or re.search(r"(?m)^\s*a\s*\{", app):
        raise SystemExit("External navigation elements are forbidden in the diagnostic UI")

    print("Dioxus runtime and loopback transport policy passed.")


if __name__ == "__main__":
    main()
