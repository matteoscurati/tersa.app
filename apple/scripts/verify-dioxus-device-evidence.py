#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Validate redacted, aggregate Dioxus physical-device observations."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import struct
import sys
import tempfile
import zlib
from pathlib import Path


COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
RECORD_ID = re.compile(r"[0-9a-f]{32}")
OS_VERSION = re.compile(r"iOS [0-9]+[.][0-9]+(?:[.][0-9]+)?")
APP_VERSION = re.compile(r"[0-9]+(?:[.][0-9]+){1,2}")
BUILD_NUMBER = re.compile(r"[0-9]+")
TEST_IDS = (
    "marked-text-ime",
    "autocorrect",
    "dictation",
    "selection",
    "copy-paste",
    "undo-redo",
    "hardware-keyboard",
    "voiceover-order-state",
    "dynamic-type",
    "full-keyboard-access",
    "switch-control",
)
COMPETENCE = {"accessibility", "apple-platform"}
LABEL = "DEVICE-SIGNED OBSERVATIONS - INDEPENDENT REVIEW REQUIRED"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("hashed evidence must be regular and non-symbolic")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_keys(value: dict[str, object], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{context} fields differ from the fixed schema")


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("JSON objects must not contain duplicate fields")
        value[key] = item
    return value


def timestamp(value: object) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamps must be UTC RFC 3339 values")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.microsecond:
        raise ValueError("timestamps must use whole seconds")
    return parsed


def successful_result(value: object, command_type: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("devicectl output must be an object")
    info = value.get("info")
    result = value.get("result")
    if (
        not isinstance(info, dict)
        or info.get("outcome") != "success"
        or info.get("commandType") != command_type
        or info.get("jsonVersion") != 3
        or not isinstance(result, dict)
    ):
        raise ValueError("devicectl command outcome or result schema is invalid")
    return result


def verify_device_details(value: object, os_version: str, device_class: str) -> None:
    if not OS_VERSION.fullmatch(os_version) or device_class not in {"iphone", "ipad"}:
        raise ValueError("expected device details use an invalid fixed value")
    result = successful_result(value, "devicectl.device.info.details")
    candidates: list[object] = []
    if isinstance(result.get("device"), dict):
        candidates.append(result["device"])
    if isinstance(result.get("devices"), list):
        candidates.extend(result["devices"])
    if "deviceProperties" in result and "hardwareProperties" in result:
        candidates.append(result)
    if len(candidates) != 1 or not isinstance(candidates[0], dict):
        raise ValueError("devicectl device result must contain exactly one device")
    device = candidates[0]
    properties = device.get("deviceProperties")
    hardware = device.get("hardwareProperties")
    if not isinstance(properties, dict) or not isinstance(hardware, dict):
        raise ValueError("devicectl device properties are incomplete")
    expected = os_version.removeprefix("iOS ")
    if properties.get("osVersionNumber") != expected:
        raise ValueError("device operating-system version does not match the safe argument")
    actual_class = hardware.get("deviceType")
    product_type = hardware.get("productType")
    if not (
        isinstance(actual_class, str)
        and actual_class.lower() == device_class
        and isinstance(product_type, str)
        and product_type.lower().startswith(device_class)
    ):
        raise ValueError("physical device class does not match the safe argument")


def verify_installed_app(value: object, bundle_id: str) -> None:
    result = successful_result(value, "devicectl.device.info.apps")
    apps = result.get("apps")
    if not isinstance(apps, list):
        raise ValueError("devicectl application result has no application list")
    matches = [
        app
        for app in apps
        if isinstance(app, dict)
        and app.get("bundleIdentifier", app.get("bundleID")) == bundle_id
    ]
    if len(matches) != 1:
        raise ValueError("installed application identity was not found exactly once")


def verify_launch_process(
    launch_value: object,
    processes_value: object,
    bundle_id: str,
    executable_name: str,
) -> None:
    launch = successful_result(launch_value, "devicectl.device.process.launch")
    launch_process = launch.get("process")
    identifiers = [launch.get("processIdentifier")]
    if isinstance(launch_process, dict):
        identifiers.append(launch_process.get("processIdentifier"))
    identifiers = [item for item in identifiers if type(item) is int and item > 0]
    if len(set(identifiers)) != 1:
        raise ValueError("device launch did not return one documented process identifier")
    expected_pid = identifiers[0]

    result = successful_result(processes_value, "devicectl.device.info.processes")
    process_lists: list[object] = [result.get("processes"), result.get("runningProcesses")]
    devices = result.get("devices")
    if isinstance(devices, list):
        if len(devices) != 1 or not isinstance(devices[0], dict):
            raise ValueError("devicectl process result must contain at most one device")
        process_lists.extend(
            [devices[0].get("processes"), devices[0].get("runningProcesses")]
        )
    records = [
        record
        for process_list in process_lists
        if isinstance(process_list, list)
        for record in process_list
        if isinstance(record, dict)
    ]

    def has_identity(record: dict[str, object]) -> bool:
        if record.get("bundleIdentifier", record.get("bundleID")) == bundle_id:
            return True
        for key in ("executable", "executablePath", "executableURL", "name"):
            identity = record.get(key)
            if isinstance(identity, str) and (
                identity == executable_name
                or identity.rstrip("/").endswith("/" + executable_name)
            ):
                return True
        return False

    matches = [
        record
        for record in records
        if type(record.get("processIdentifier", record.get("pid"))) is int
        and record.get("processIdentifier", record.get("pid")) == expected_pid
        and has_identity(record)
    ]
    if len(matches) != 1:
        raise ValueError("launched PID is not bound to one expected application process")


def nearest_png_predictor(left: int, up: int, upper_left: int) -> int:
    estimate = left + up - upper_left
    distances = (abs(estimate - left), abs(estimate - up), abs(estimate - upper_left))
    return (left, up, upper_left)[distances.index(min(distances))]


def png_rows(path: Path) -> tuple[int, int, int, list[bytes]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("redacted screenshot must be a regular file")
    if path.stat().st_size > 12 * 1024 * 1024:
        raise ValueError("redacted screenshot must be a bounded PNG")
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("redacted screenshot must be a bounded PNG")
    offset = len(PNG_SIGNATURE)
    width = height = channels = 0
    compressed = bytearray()
    seen_header = False
    seen_data = False
    seen_end = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated PNG chunk")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        checksum = data[offset + 8 + length : offset + 12 + length]
        if len(payload) != length or len(checksum) != 4:
            raise ValueError("truncated PNG payload")
        if zlib.crc32(kind + payload) != struct.unpack(">I", checksum)[0]:
            raise ValueError("invalid PNG checksum")
        if kind not in {b"IHDR", b"IDAT", b"IEND"}:
            raise ValueError("redacted screenshot contains forbidden metadata")
        if kind == b"IHDR":
            if seen_header or seen_data or offset != len(PNG_SIGNATURE) or length != 13:
                raise ValueError("redacted screenshot has a misplaced PNG header")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            if depth != 8 or color not in {2, 6} or (compression, filtering, interlace) != (0, 0, 0):
                raise ValueError("redacted screenshot must be non-interlaced 8-bit RGB/RGBA")
            channels = 3 if color == 2 else 4
            seen_header = True
        elif kind == b"IDAT":
            if not seen_header or seen_end:
                raise ValueError("redacted screenshot has misplaced image data")
            seen_data = True
            compressed.extend(payload)
        elif kind == b"IEND":
            if not seen_header or not seen_data or length != 0:
                raise ValueError("redacted screenshot has a malformed PNG end")
            seen_end = True
            offset += 12 + length
            break
        offset += 12 + length
    if not seen_end or offset != len(data):
        raise ValueError("redacted screenshot has missing or trailing PNG data")
    if not (320 <= width <= 4096 and 480 <= height <= 4096 and compressed):
        raise ValueError("redacted screenshot dimensions are outside the fixed bounds")
    stride = width * channels
    if stride * height > 32 * 1024 * 1024:
        raise ValueError("redacted screenshot decoded size is outside the fixed bounds")
    expected_length = height * (stride + 1)
    decoder = zlib.decompressobj()
    raw = decoder.decompress(bytes(compressed), expected_length + 1)
    if (
        len(raw) != expected_length
        or not decoder.eof
        or decoder.unconsumed_tail
        or decoder.unused_data
    ):
        raise ValueError("redacted screenshot has an unexpected data length")
    rows: list[bytes] = []
    previous = bytes(stride)
    for row_index in range(height):
        start = row_index * (stride + 1)
        mode = raw[start]
        encoded = raw[start + 1 : start + 1 + stride]
        decoded = bytearray(stride)
        if mode not in {0, 1, 2, 3, 4}:
            raise ValueError("unsupported PNG row filter")
        for index, byte in enumerate(encoded):
            left = decoded[index - channels] if index >= channels else 0
            up = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if mode == 0:
                predictor = 0
            elif mode == 1:
                predictor = left
            elif mode == 2:
                predictor = up
            elif mode == 3:
                predictor = (left + up) // 2
            else:
                predictor = nearest_png_predictor(left, up, upper_left)
            decoded[index] = (byte + predictor) & 0xFF
        rows.append(bytes(decoded))
        previous = rows[-1]
    return width, height, channels, rows


def verify_redaction(path: Path) -> None:
    width, height, channels, rows = png_rows(path)
    top = max(1, height * 8 // 100)
    bottom = max(1, height * 4 // 100)
    for row in rows[:top] + rows[-bottom:]:
        for index in range(0, width * channels, channels):
            if row[index : index + 3] != b"\0\0\0":
                raise ValueError("screenshot status or home band is not fully redacted")
    if not any(
        row[index : index + 3] != b"\0\0\0"
        for row in rows[top:-bottom]
        for index in range(0, width * channels, channels)
    ):
        raise ValueError("redacted screenshot has no visible synthetic content")


def verify_test_outcomes(tests: object, device_class: str) -> None:
    if not isinstance(tests, list) or [item.get("id") for item in tests if isinstance(item, dict)] != list(TEST_IDS):
        raise ValueError("test observations are missing or out of order")
    for item in tests:
        if not isinstance(item, dict) or set(item) != {"id", "outcome"}:
            raise ValueError("test observations must use the fixed aggregate vocabulary")
        expected_outcomes = {"pass", "fail"}
        if item["id"] == "hardware-keyboard" and device_class == "iphone":
            expected_outcomes = {"not-applicable"}
        if item["outcome"] not in expected_outcomes:
            raise ValueError("test outcome is inconsistent with the device and fixed vocabulary")


def verify_machine_results(path: Path, device_class: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("machine results must be a regular non-symbolic file")
    if device_class not in {"iphone", "ipad"}:
        raise ValueError("machine results require an exact device class")
    pattern = re.compile(
        rf"({'|'.join(re.escape(test_id) for test_id in TEST_IDS)})="
        r"(pass|fail|not-applicable)"
    )
    tests = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.fullmatch(line)
        if match is None:
            raise ValueError("machine result line differs from the fixed contract")
        tests.append({"id": match.group(1), "outcome": match.group(2)})
    verify_test_outcomes(tests, device_class)


def verify(directory: Path, expected_commit: str) -> None:
    if not COMMIT.fullmatch(expected_commit):
        raise ValueError("expected commit must be an exact lowercase SHA")
    observation_path = directory / "observations.json"
    screenshot_path = directory / "device-redacted.png"
    if directory.is_symlink() or observation_path.is_symlink() or not observation_path.is_file():
        raise ValueError("evidence paths must be regular and non-symbolic")
    value = json.loads(
        observation_path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
    )
    require_keys(value, {"schema_version", "label", "commit", "candidate", "device", "application", "capture", "tests"}, "root")
    if (value["schema_version"], value["label"], value["commit"], value["candidate"]) != (1, LABEL, expected_commit, "dioxus-diagnostic"):
        raise ValueError("observation identity differs from the fixed values")

    device = value["device"]
    if not isinstance(device, dict):
        raise ValueError("device summary must be an object")
    require_keys(device, {"class", "viewport", "os"}, "device")
    if (
        device["class"] not in {"iphone", "ipad"}
        or device["viewport"] not in {"compact", "regular"}
        or (device["class"] == "iphone" and device["viewport"] != "compact")
        or not isinstance(device["os"], str)
        or not OS_VERSION.fullmatch(device["os"])
    ):
        raise ValueError("device summary must contain a consistent class, viewport, and iOS version")

    application = value["application"]
    if not isinstance(application, dict):
        raise ValueError("application summary must be an object")
    require_keys(application, {"bundle_id", "version", "build", "app_bundle_sha256", "signature", "entitlements", "installation", "launch", "launch_arguments", "evidence_screen", "displayed_commit"}, "application")
    if application["bundle_id"] != "app.tersa.dioxus-spike.ios" or not isinstance(application["app_bundle_sha256"], str) or not SHA256.fullmatch(application["app_bundle_sha256"]):
        raise ValueError("application identity or bundle hash is invalid")
    if not isinstance(application["version"], str) or not APP_VERSION.fullmatch(application["version"]) or not isinstance(application["build"], str) or not BUILD_NUMBER.fullmatch(application["build"]):
        raise ValueError("application version or build is invalid")
    if [application[key] for key in ("signature", "entitlements", "installation")] != ["verified"] * 3 or application["launch"] != "verified-running":
        raise ValueError("application preflight and process liveness were not completely verified")
    if application["launch_arguments"] != ["--tersa-device-evidence"]:
        raise ValueError("launch arguments differ from the fixed evidence mode")
    if application["evidence_screen"] != "observer-confirmed" or application["displayed_commit"] != expected_commit:
        raise ValueError("evidence screen or displayed commit was not observer-confirmed")

    capture = value["capture"]
    if not isinstance(capture, dict):
        raise ValueError("capture summary must be an object")
    require_keys(capture, {"started_at", "completed_at", "observer_record_id", "observer_competence", "screenshot", "screenshot_sha256", "redaction"}, "capture")
    if timestamp(capture["completed_at"]) < timestamp(capture["started_at"]):
        raise ValueError("capture timestamps are reversed")
    if not isinstance(capture["observer_record_id"], str) or not RECORD_ID.fullmatch(capture["observer_record_id"]):
        raise ValueError("observer record ID must be 32 lowercase hexadecimal characters")
    if capture["observer_competence"] not in COMPETENCE or capture["screenshot"] != "device-redacted.png" or capture["redaction"] != "solid-black-status-and-home-bands":
        raise ValueError("capture metadata differs from the fixed vocabulary")
    if capture["screenshot_sha256"] != sha256(screenshot_path):
        raise ValueError("redacted screenshot hash does not match")

    verify_test_outcomes(value["tests"], device["class"])
    verify_redaction(screenshot_path)


def png(
    width: int,
    height: int,
    metadata: bool = False,
    redacted: bool = True,
    trailing_stream: bool = False,
) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))
    top = height * 8 // 100
    bottom = height * 4 // 100
    rows = b"".join(
        b"\0" + (b"\0\0\0" if redacted and (row < top or row >= height - bottom) else b"\xff\xff\xff") * width
        for row in range(height)
    )
    extra = chunk(b"tEXt", b"device=forbidden") if metadata else b""
    compressed = zlib.compress(rows)
    if trailing_stream:
        compressed += zlib.compress(b"forbidden trailing stream")
    return PNG_SIGNATURE + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + extra + chunk(b"IDAT", compressed) + chunk(b"IEND", b"")


def self_test() -> None:
    def command(command_type: str, result: dict[str, object]) -> dict[str, object]:
        return {
            "info": {
                "commandType": command_type,
                "jsonVersion": 3,
                "outcome": "success",
            },
            "result": result,
        }

    verify_device_details(
        command(
            "devicectl.device.info.details",
            {
                "deviceProperties": {
                    "osVersionNumber": "18.5",
                },
                "hardwareProperties": {
                    "deviceType": "iPhone",
                    "productType": "iPhone17,1",
                },
            },
        ),
        "iOS 18.5",
        "iphone",
    )
    try:
        verify_device_details(
            command(
                "devicectl.device.info.details",
                {
                    "deviceProperties": {"osVersionNumber": "18.5"},
                    "hardwareProperties": {
                        "deviceType": "iPhone",
                        "productType": "iPhone17,1",
                    },
                },
            ),
            "iOS 18.5",
            "ipad",
        )
    except ValueError as error:
        assert "class" in str(error)
    else:
        raise AssertionError("mismatched device class unexpectedly passed")
    verify_installed_app(
        command(
            "devicectl.device.info.apps",
            {"apps": [{"bundleIdentifier": "app.tersa.dioxus-spike.ios"}]},
        ),
        "app.tersa.dioxus-spike.ios",
    )
    launch = command(
        "devicectl.device.process.launch",
        {"process": {"processIdentifier": 731}},
    )
    processes = command(
        "devicectl.device.info.processes",
        {
            "processes": [
                {
                    "processIdentifier": 731,
                    "executable": "/private/app/tersa-dioxus-spike",
                }
            ]
        },
    )
    verify_launch_process(
        launch,
        processes,
        "app.tersa.dioxus-spike.ios",
        "tersa-dioxus-spike",
    )
    adversarial_launch = command(
        "devicectl.device.process.launch",
        {"metadata": {"processIdentifier": 731}},
    )
    try:
        verify_launch_process(
            adversarial_launch,
            processes,
            "app.tersa.dioxus-spike.ios",
            "tersa-dioxus-spike",
        )
    except ValueError as error:
        assert "documented process identifier" in str(error)
    else:
        raise AssertionError("nested unrelated launch PID unexpectedly passed")
    split_identity = command(
        "devicectl.device.info.processes",
        {
            "processes": [
                {"processIdentifier": 731, "executable": "/private/app/other"},
                {
                    "processIdentifier": 999,
                    "bundleIdentifier": "app.tersa.dioxus-spike.ios",
                },
            ]
        },
    )
    try:
        verify_launch_process(
            launch,
            split_identity,
            "app.tersa.dioxus-spike.ios",
            "tersa-dioxus-spike",
        )
    except ValueError as error:
        assert "bound" in str(error)
    else:
        raise AssertionError("PID and identity from separate records unexpectedly passed")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        screenshot = directory / "device-redacted.png"
        screenshot.write_bytes(png(320, 480))
        now = "2026-07-15T12:00:00Z"
        observation = {
            "schema_version": 1, "label": LABEL, "commit": "a" * 40, "candidate": "dioxus-diagnostic",
            "device": {"class": "iphone", "viewport": "compact", "os": "iOS 18.5"},
            "application": {"bundle_id": "app.tersa.dioxus-spike.ios", "version": "1.0", "build": "1", "app_bundle_sha256": "b" * 64, "signature": "verified", "entitlements": "verified", "installation": "verified", "launch": "verified-running", "launch_arguments": ["--tersa-device-evidence"], "evidence_screen": "observer-confirmed", "displayed_commit": "a" * 40},
            "capture": {"started_at": now, "completed_at": now, "observer_record_id": "c" * 32, "observer_competence": "accessibility", "screenshot": screenshot.name, "screenshot_sha256": sha256(screenshot), "redaction": "solid-black-status-and-home-bands"},
            "tests": [
                {
                    "id": test_id,
                    "outcome": "not-applicable"
                    if test_id == "hardware-keyboard"
                    else "pass",
                }
                for test_id in TEST_IDS
            ],
        }
        (directory / "observations.json").write_text(json.dumps(observation), encoding="utf-8")
        verify(directory, "a" * 40)
        observation["device"]["viewport"] = "regular"
        (directory / "observations.json").write_text(json.dumps(observation), encoding="utf-8")
        try:
            verify(directory, "a" * 40)
        except ValueError as error:
            assert "consistent class" in str(error)
        else:
            raise AssertionError("inconsistent iPhone viewport unexpectedly passed")
        observation["device"] = {"class": "ipad", "viewport": "regular", "os": "iOS 18.5"}
        (directory / "observations.json").write_text(json.dumps(observation), encoding="utf-8")
        try:
            verify(directory, "a" * 40)
        except ValueError as error:
            assert "inconsistent with the device" in str(error)
        else:
            raise AssertionError("iPad not-applicable hardware keyboard unexpectedly passed")
        observation["device"] = {"class": "iphone", "viewport": "compact", "os": "iOS 18.5"}
        screenshot.write_bytes(png(320, 480, metadata=True))
        observation["capture"]["screenshot_sha256"] = sha256(screenshot)
        (directory / "observations.json").write_text(json.dumps(observation), encoding="utf-8")
        try:
            verify(directory, "a" * 40)
        except ValueError as error:
            assert "forbidden metadata" in str(error)
        else:
            raise AssertionError("metadata-bearing screenshot unexpectedly passed")
        screenshot.write_bytes(png(320, 480, redacted=False))
        observation["capture"]["screenshot_sha256"] = sha256(screenshot)
        (directory / "observations.json").write_text(json.dumps(observation), encoding="utf-8")
        try:
            verify(directory, "a" * 40)
        except ValueError as error:
            assert "not fully redacted" in str(error)
        else:
            raise AssertionError("unredacted screenshot bands unexpectedly passed")
        screenshot.write_bytes(png(320, 480, trailing_stream=True))
        observation["capture"]["screenshot_sha256"] = sha256(screenshot)
        (directory / "observations.json").write_text(json.dumps(observation), encoding="utf-8")
        try:
            verify(directory, "a" * 40)
        except ValueError as error:
            assert "unexpected data length" in str(error)
        else:
            raise AssertionError("trailing compressed stream unexpectedly passed")
        screenshot.write_bytes(png(320, 480))
        observation["capture"]["screenshot_sha256"] = sha256(screenshot)
        serialized = json.dumps(observation)
        duplicated = serialized.replace(
            '"schema_version": 1,',
            '"schema_version": 1, "schema_version": 1,',
            1,
        )
        (directory / "observations.json").write_text(duplicated, encoding="utf-8")
        try:
            verify(directory, "a" * 40)
        except ValueError as error:
            assert "duplicate fields" in str(error)
        else:
            raise AssertionError("duplicate JSON field unexpectedly passed")
    print("Dioxus device evidence verifier and redaction negative self-tests passed.")


def main() -> int:
    def load_json_file(raw_path: str, label: str) -> object:
        source = Path(raw_path)
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"{label} must be a regular non-symbolic file")
        return json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )

    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "--verify-device-details":
        value = load_json_file(sys.argv[2], "device details")
        verify_device_details(value, sys.argv[3], sys.argv[4])
        print("Physical device class and operating-system version verified.")
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "--verify-installed-app":
        value = load_json_file(sys.argv[2], "installed application details")
        verify_installed_app(value, sys.argv[3])
        print("Installed application identity verified.")
        return 0
    if len(sys.argv) == 6 and sys.argv[1] == "--verify-launch-process":
        launch = load_json_file(sys.argv[2], "launch result")
        processes = load_json_file(sys.argv[3], "process list")
        verify_launch_process(launch, processes, sys.argv[4], sys.argv[5])
        print("Launched application identity and process liveness verified.")
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "--verify-machine-results":
        verify_machine_results(Path(sys.argv[2]), sys.argv[3])
        print("Machine result lines match the device-specific evidence contract.")
        return 0
    if len(sys.argv) != 3:
        print(
            "usage: verify-dioxus-device-evidence.py <directory> <commit> | "
            "--verify-device-details <json> <os> <class> | "
            "--verify-installed-app <json> <bundle> | "
            "--verify-launch-process <launch-json> <processes-json> <bundle> <executable> | "
            "--verify-machine-results <results> <class>",
            file=sys.stderr,
        )
        return 2
    verify(Path(sys.argv[1]), sys.argv[2])
    print("Dioxus device evidence aggregate verified; independent review remains required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
