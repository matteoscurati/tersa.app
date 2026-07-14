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
CLIENT_KEY = "client_key: [u8; KEY_SIZE],"
SERVER_KEY = "server_key: [u8; KEY_SIZE],"
SECURE_KEY_CREATION = "rand::rngs::StdRng::from_os_rng()"
CONSTANT_TIME_COMPARE = "subtle::ConstantTimeEq::ct_eq("
SERVER_KEY_RESPONSE = ".send(tungstenite::Message::Text(hex_encoded_server_key.into()))"


APPLE_TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
)
NON_APPLE_UNMAINTAINED_PACKAGE_NAMES = {
    "atk",
    "atk-sys",
    "fxhash",
    "gdk",
    "gdk-sys",
    "gdkwayland-sys",
    "gdkx11-sys",
    "gtk",
    "gtk-sys",
    "gtk3-macros",
    "proc-macro-error",
}


def semver_triplet(version: str) -> tuple[int, int, int]:
    core = version.split("-", maxsplit=1)[0]
    parts = core.split(".")
    if len(parts) != 3:
        raise SystemExit(f"Expected a three-part semantic version, found {version!r}")
    major, minor, patch = (int(part) for part in parts)
    return major, minor, patch


def has_ignored_non_apple_advisory(name: str, version: str) -> bool:
    if name in NON_APPLE_UNMAINTAINED_PACKAGE_NAMES:
        return True
    if name == "glib":
        parsed = semver_triplet(version)
        return (0, 15, 0) <= parsed < (0, 20, 0)
    if name == "rand":
        parsed = semver_triplet(version)
        return (0, 7, 0) <= parsed < (0, 8, 6) or (
            (0, 9, 0) <= parsed < (0, 9, 3)
        )
    return False


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


def resolved_features(
    metadata: dict[str, Any], package_id: str, package_name: str
) -> set[str]:
    resolve = metadata.get("resolve")
    if resolve is None:
        raise SystemExit("Cargo metadata did not include a dependency resolution")
    matches = [node for node in resolve["nodes"] if node["id"] == package_id]
    if len(matches) != 1:
        raise SystemExit(f"{package_name} is missing from the resolved dependency graph")
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
        reachable = {
            (name, version)
            for name, version in resolved_packages(target_metadata)
            if has_ignored_non_apple_advisory(name, version)
        }
        if reachable:
            raise SystemExit(
                f"Non-Apple advisory packages became reachable from {target}: "
                f"{sorted(reachable)}"
            )

    ios_device_packages = resolved_packages(metadata_by_target["aarch64-apple-ios"])
    ios_simulator_packages = resolved_packages(
        metadata_by_target["aarch64-apple-ios-sim"]
    )
    if ios_device_packages != ios_simulator_packages:
        raise SystemExit(
            "The shared iOS notice cannot cover different device and simulator graphs"
        )

    for target, metadata in metadata_by_target.items():
        names = {item["name"] for item in metadata["packages"]}
        forbidden = names.intersection({"manganis", "dioxus-devtools", "dioxus-web"})
        if forbidden:
            raise SystemExit(
                f"Forbidden Dioxus runtime packages are resolved for {target}: "
                f"{sorted(forbidden)}"
            )

        dioxus = package(metadata, "dioxus")
        desktop = package(metadata, "dioxus-desktop")
        if dioxus["version"] != DIOXUS_VERSION or desktop["version"] != DIOXUS_VERSION:
            raise SystemExit(f"The Dioxus graph for {target} is not pinned to 0.7.9")

        features = resolved_features(metadata, desktop["id"], "Dioxus Desktop")
        if features != {"tokio_runtime"}:
            raise SystemExit(
                "Dioxus Desktop must enable only its required tokio_runtime "
                f"feature for {target}; resolved {sorted(features)}"
            )

        dioxus_features = resolved_features(metadata, dioxus["id"], "Dioxus")
        expected_dioxus_features = {"hooks", "html", "macro", "signals"}
        if dioxus_features != expected_dioxus_features:
            raise SystemExit(
                "The Dioxus facade must keep its minimal diagnostic feature set "
                f"for {target}; resolved {sorted(dioxus_features)}"
            )

    metadata = metadata_by_target["aarch64-apple-darwin"]
    desktop = package(metadata, "dioxus-desktop")
    source = Path(desktop["manifest_path"]).parent
    edits = (source / "src" / "edits.rs").read_text(encoding="utf-8")
    transport_markers = (
        LOOPBACK_BIND,
        LOOPBACK_URL,
        MUTUAL_KEY_SIZE,
        CLIENT_KEY,
        SERVER_KEY,
        SECURE_KEY_CREATION,
        CONSTANT_TIME_COMPARE,
        SERVER_KEY_RESPONSE,
    )
    for marker in transport_markers:
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
        '"data-expected-rows": "{rendered_rows}"',
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
