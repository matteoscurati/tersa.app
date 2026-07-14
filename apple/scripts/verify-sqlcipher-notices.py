#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Verify the checksum-bound bundled SQLCipher supplemental notice."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


EXPECTED_LICENSE_SHA256 = (
    "ea4fcb309f14a22065e1ea45362d494d320012249ed865fe9c7c0946db754131"
)
LICENSE_START = "Copyright (c) 2008-2020 Zetetic LLC\n"
EXPECTED_VERSION_LINE = (
    "SQLCipher 4.10.0 community source bundled by libsqlite3-sys 0.37.0"
)
EXPECTED_LIBSQLITE3_SYS_VERSION = "0.37.0"


def main() -> None:
    notice = Path(sys.argv[1]).read_text(encoding="utf-8")
    lockfile = Path(sys.argv[2]).read_text(encoding="utf-8")
    if EXPECTED_VERSION_LINE not in notice:
        raise SystemExit("SQLCipher supplemental notice has an unexpected version")
    versions = re.findall(
        r'\[\[package\]\]\nname = "libsqlite3-sys"\nversion = "([^"]+)"',
        lockfile,
    )
    if versions != [EXPECTED_LIBSQLITE3_SYS_VERSION]:
        raise SystemExit("Cargo.lock has an unexpected libsqlite3-sys version")
    start = notice.find(LICENSE_START)
    if start < 0:
        raise SystemExit("SQLCipher supplemental notice is missing its license text")
    license_text = notice[start:].encode()
    digest = hashlib.sha256(license_text).hexdigest()
    if digest != EXPECTED_LICENSE_SHA256:
        raise SystemExit("SQLCipher supplemental license checksum mismatch")


if __name__ == "__main__":
    main()
