#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Rebuild and byte-compare the patched Dioxus Desktop vendor tree."""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path


PACKAGE = "dioxus-desktop"
VERSION = "0.7.9"


def locked_checksum(checksum_file: Path) -> str:
    expected_suffix = f"  {PACKAGE}-{VERSION}.crate"
    value = checksum_file.read_text(encoding="utf-8").strip()
    if not value.endswith(expected_suffix):
        raise SystemExit(f"Malformed pristine checksum record: {checksum_file}")
    checksum = value.removesuffix(expected_suffix)
    if len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum):
        raise SystemExit(f"Malformed SHA-256 checksum in {checksum_file}")
    return checksum


def default_archive() -> Path:
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    matches = sorted(cargo_home.glob(f"registry/cache/*/{PACKAGE}-{VERSION}.crate"))
    if len(matches) != 1:
        raise SystemExit(
            "Expected exactly one cached dioxus-desktop-0.7.9 crate; provide --archive "
            "with an explicitly downloaded archive instead"
        )
    return matches[0]


def verify_checksum(archive: Path, checksum: str) -> None:
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != checksum:
        raise SystemExit(f"Archive checksum mismatch for {archive}: expected {checksum}, got {digest}")


def compare_trees(expected: Path, actual: Path) -> None:
    expected_files = {path.relative_to(expected) for path in expected.rglob("*") if path.is_file()}
    actual_files = {path.relative_to(actual) for path in actual.rglob("*") if path.is_file()}
    if expected_files != actual_files:
        raise SystemExit(
            "Vendored dioxus-desktop differs from the verified archive plus patch: "
            f"missing={sorted(expected_files - actual_files)}, "
            f"unexpected={sorted(actual_files - expected_files)}"
        )
    mismatches = [
        relative
        for relative in sorted(expected_files)
        if not filecmp.cmp(expected / relative, actual / relative, shallow=False)
    ]
    if mismatches:
        raise SystemExit(
            "Vendored dioxus-desktop byte comparison failed for: "
            f"{mismatches}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="Verified crates.io archive to use instead of Cargo cache")
    arguments = parser.parse_args()

    workspace = Path(__file__).resolve().parents[2]
    archive = arguments.archive or default_archive()
    if not archive.is_file():
        raise SystemExit(f"Archive does not exist: {archive}")
    checksum_file = workspace / "patches" / "dioxus-desktop-0.7.9.lock-checksum"
    verify_checksum(archive, locked_checksum(checksum_file))

    patch = workspace / "patches" / "dioxus-desktop-0.7.9-tersa-m0.patch"
    vendor = workspace / "vendor" / "dioxus-desktop-0.7.9"
    if not patch.is_file() or not vendor.is_dir():
        raise SystemExit("Missing Dioxus Desktop patch file or vendor directory")

    with tempfile.TemporaryDirectory(prefix="tersa-dioxus-vendor-") as temporary_directory:
        temporary = Path(temporary_directory)
        with tarfile.open(archive, "r:gz") as crate:
            crate.extractall(temporary, filter="data")
        extracted = temporary / f"{PACKAGE}-{VERSION}"
        if not extracted.is_dir():
            raise SystemExit("Verified archive did not contain the expected package directory")
        subprocess.run(
            ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch)],
            cwd=extracted,
            check=True,
        )
        compare_trees(extracted, vendor)

    print("Verified dioxus-desktop vendor tree against the locked registry checksum and patch.")


if __name__ == "__main__":
    main()
