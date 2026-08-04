#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Create a redacted, commit-bound manifest for a CI evidence directory."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path


COMMIT = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_NAME = "manifest.json"
RETENTION_MARGIN = dt.timedelta(days=89)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(directory: Path, commit: str, now: dt.datetime) -> Path:
    if not COMMIT.fullmatch(commit):
        raise ValueError("commit must be an exact lowercase 40-character SHA")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("manifest timestamp must include a timezone")
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink():
        raise ValueError("evidence directory cannot be a symbolic link")
    destination = directory / MANIFEST_NAME
    if destination.is_symlink():
        raise ValueError("evidence manifest cannot be a symbolic link")

    files = []
    for path in sorted(directory.rglob("*")):
        if path == destination or path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unsupported evidence entry: {path.name}")
        files.append(
            {
                "path": path.relative_to(directory).as_posix(),
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
        )

    generated_at = now.astimezone(dt.timezone.utc).replace(microsecond=0)
    manifest = {
        "schema_version": 1,
        "commit": commit,
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "retained_until": (generated_at + RETENTION_MARGIN)
        .isoformat()
        .replace("+00:00", "Z"),
        "files": files,
    }
    destination.write_text(
        json.dumps(manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def self_test() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        (directory / "result.txt").write_text("synthetic evidence\n", encoding="utf-8")
        now = dt.datetime(2026, 7, 15, 4, 0, tzinfo=dt.timezone.utc)
        manifest_path = write_manifest(directory, "a" * 40, now)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["commit"] == "a" * 40
        assert manifest["generated_at"] == "2026-07-15T04:00:00Z"
        assert manifest["retained_until"] == "2026-10-12T04:00:00Z"
        assert manifest["files"] == [
            {
                "path": "result.txt",
                "sha256": sha256(directory / "result.txt"),
                "size": 19,
            }
        ]
    print("Evidence manifest self-test passed.")


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if len(sys.argv) != 3:
        print("usage: write-evidence-manifest.py <directory> <commit>", file=sys.stderr)
        return 2
    now = dt.datetime.now(tz=dt.timezone.utc)
    destination = write_manifest(Path(sys.argv[1]), sys.argv[2], now)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
