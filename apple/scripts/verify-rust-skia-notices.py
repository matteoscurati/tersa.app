#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Verify the pinned native license sections appended to rust-skia notices."""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from pathlib import Path


SEPARATOR = "-" * 80


@dataclass(frozen=True)
class Component:
    name: str
    revision: str
    license_path: str
    license_sha256: str


COMPONENTS = (
    Component(
        "Expat",
        "8e49998f003d693213b538ef765814c7d21abada",
        "third_party/externals/expat/COPYING",
        "31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87",
    ),
    Component(
        "HarfBuzz",
        "08b52ae2e44931eef163dbad71697f911fadc323",
        "third_party/externals/harfbuzz/COPYING",
        "ba8f810f2455c2f08e2d56bb49b72f37fcf68f1f4fade38977cfd7372050ad64",
    ),
    Component(
        "ICU",
        "364118a1d9da24bb5b770ac3d762ac144d6da5a4",
        "third_party/externals/icu/LICENSE",
        "17510cf7a58b4879b887ec05a45d72cf1b73544dd9ec7e72f20110ed104229ee",
    ),
    Component(
        "libjpeg-turbo",
        "e14cbfaa85529d47f9f55b0f104a579c1061f9ad",
        "third_party/externals/libjpeg-turbo/LICENSE.md",
        "96f5b328adbb78eeaaec6980d73fd558cb1e4d62560ed615646bc3cf5e532430",
    ),
    Component(
        "libpng",
        "ed217e3e601d8e462f7fd1e04bed43ac42212429",
        "third_party/externals/libpng/LICENSE",
        "7317e078e2d3b5d7ba5a6159e650945153262b44b76f6700f8e9edb261c5143e",
    ),
    Component(
        "Wuffs",
        "e3f919ccfe3ef542cfc983a82146070258fb57f8",
        "third_party/externals/wuffs/LICENSE",
        "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    ),
    Component(
        "zlib",
        "646b7f569718921d7d4b5b8e22572ff6c76f2596",
        "third_party/externals/zlib/LICENSE",
        "e1cfcc55c325b3f78cf55df9664abaa066e2271dffe8213347d9fccdfbac8f2c",
    ),
)


def marker(component: Component) -> str:
    return "\n".join(
        (
            SEPARATOR,
            component.name,
            f"Source revision: {component.revision}",
            f"License source: {component.license_path}",
            f"License SHA-256: {component.license_sha256}",
            "",
            "",
        )
    )


def verify(path: Path) -> None:
    notice = path.read_text(encoding="utf-8")
    positions: list[tuple[Component, int, int]] = []

    for component in COMPONENTS:
        section_marker = marker(component)
        if notice.count(section_marker) != 1:
            raise ValueError(f"expected one complete {component.name} notice marker")
        marker_start = notice.index(section_marker)
        positions.append((component, marker_start, marker_start + len(section_marker)))

    if positions != sorted(positions, key=lambda item: item[1]):
        raise ValueError("native component notices are not in canonical order")

    for index, (component, _, license_start) in enumerate(positions):
        license_end = positions[index + 1][1] if index + 1 < len(positions) else len(notice)
        license_text = notice[license_start:license_end].rstrip() + "\n"
        digest = hashlib.sha256(license_text.encode("utf-8")).hexdigest()
        if digest != component.license_sha256:
            raise ValueError(
                f"{component.name} license digest is {digest}, "
                f"expected {component.license_sha256}"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("notice", type=Path)
    args = parser.parse_args()
    verify(args.notice)


if __name__ == "__main__":
    main()
