#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Render deterministic Apple notices from cargo-about JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


RUST_SKIA_CRATES = {"skia-bindings", "skia-safe"}


def normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def package_key(item: dict[str, Any]) -> tuple[str, str]:
    package = item["package"]
    return package["name"], package["version"]


def used_by_key(item: dict[str, Any]) -> tuple[str, str]:
    crate = item["crate"]
    return crate["name"], crate["version"]


def render(data: dict[str, Any], target: str, supplemental: str) -> str:
    lines = [
        "tersa.app third-party notices",
        "================================",
        "",
        "This file lists the third-party Rust packages linked into the diagnostic",
        "application for this target selection:",
        f"- {target}",
        "",
        "It is generated from Cargo.lock by cargo-about 0.9.1 and a deterministic",
        "repository renderer. CI requires a byte-for-byte",
        "match with this target-specific application resource.",
        "",
        "Third-party Rust packages",
        "-------------------------",
        "",
    ]

    for item in sorted(data["crates"], key=package_key):
        package = item["package"]
        repository = package.get("repository")
        suffix = f" - {repository}" if repository else ""
        lines.append(
            f"- {package['name']} {package['version']}: {item['license']}{suffix}"
        )

    lines.extend(["", "Full license texts", "------------------", ""])

    normalized_licenses = []
    for license_item in data["licenses"]:
        used_by = [
            item
            for item in license_item["used_by"]
            if item["crate"]["name"] not in RUST_SKIA_CRATES
        ]
        if used_by:
            normalized_licenses.append((license_item, sorted(used_by, key=used_by_key)))

    normalized_licenses.sort(
        key=lambda item: (item[0]["id"], item[0]["name"], item[0]["text"])
    )

    for license_item, used_by in normalized_licenses:
        lines.extend(
            [
                "--------------------------------------------------------------------------------",
                f"{license_item['name']} ({license_item['id']})",
                "Used by:",
            ]
        )
        for item in used_by:
            crate = item["crate"]
            repository = crate.get("repository")
            suffix = f" - {repository}" if repository else ""
            lines.append(f"- {crate['name']} {crate['version']}{suffix}")
        lines.extend(["", normalize_newlines(license_item["text"]).rstrip(), ""])

    lines.append(normalize_newlines(supplemental).rstrip())
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("supplemental", type=Path)
    parser.add_argument("target")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    data = json.loads(args.input.read_text(encoding="utf-8"))
    supplemental = args.supplemental.read_text(encoding="utf-8")
    args.output.write_text(
        render(data, args.target, supplemental), encoding="utf-8", newline="\n"
    )


if __name__ == "__main__":
    main()
