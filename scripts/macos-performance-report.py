#!/usr/bin/env python3
"""Capture and validate privacy-safe macOS Step-4 pre-measurements."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
import subprocess
import sys
from typing import Sequence


SCHEMA_VERSION = 1
RECORDED_RUNS = 5
APP_BUDGET_BYTES = 16 * 1024 * 1024
DMG_BUDGET_BYTES = 8 * 1024 * 1024
QUERY_BUDGET_MS = 100.0
SAMPLE = re.compile(
    r"^TERSA_PERF_SAMPLE open_list_us=(\d+) query_us=(\d+) "
    r"reconcile_us=(\d+) rows=100$"
)
PEAK = re.compile(r"^\s*(\d+)\s+maximum resident set size\s*$", re.MULTILINE)
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class ReportError(ValueError):
    """A capture or report violated the closed performance contract."""


@dataclass(frozen=True)
class Sample:
    open_list_ms: float
    query_ms: float
    reconcile_ms: float
    process_peak_mib: float


def nearest_rank_p95(values: Sequence[float]) -> float:
    """Return the conservative nearest-rank p95 for non-empty values."""
    if not values:
        raise ReportError("at least one value is required")
    ordered = sorted(values)
    rank = math.ceil(0.95 * len(ordered))
    return ordered[rank - 1]


def median(values: Sequence[float]) -> float:
    """Return the median for non-empty values."""
    if not values:
        raise ReportError("at least one value is required")
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2


def parse_sample(stdout: str, stderr: str) -> Sample:
    """Parse one exact safe marker and macOS time(1) peak RSS output."""
    markers = [line for line in stdout.splitlines() if line.startswith("TERSA_PERF_SAMPLE")]
    if len(markers) != 1:
        raise ReportError("the probe must emit exactly one performance marker")
    match = SAMPLE.fullmatch(markers[0])
    peak = PEAK.search(stderr)
    if match is None or peak is None:
        raise ReportError("the probe emitted an invalid or incomplete sample")
    open_us, query_us, reconcile_us = (int(value) for value in match.groups())
    peak_bytes = int(peak.group(1))
    if min(open_us, query_us, reconcile_us, peak_bytes) <= 0:
        raise ReportError("sample values must be positive")
    return Sample(
        open_list_ms=open_us / 1000,
        query_ms=query_us / 1000,
        reconcile_ms=reconcile_us / 1000,
        process_peak_mib=peak_bytes / (1024 * 1024),
    )


def run_probe(executable: Path) -> Sample:
    """Run the exact ignored Rust probe under macOS time(1)."""
    result = subprocess.run(
        [
            "/usr/bin/time",
            "-l",
            str(executable),
            "--exact",
            "macos::tests::performance_harness_sample",
            "--ignored",
            "--nocapture",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ReportError("the Rust performance probe failed")
    return parse_sample(result.stdout, result.stderr)


def file_bytes(path: Path) -> int:
    """Return an artifact file size, rejecting absent and empty files."""
    if not path.is_file():
        raise ReportError("the compressed DMG is missing")
    size = path.stat().st_size
    if size <= 0:
        raise ReportError("the compressed DMG is empty")
    return size


def bundle_bytes(path: Path) -> int:
    """Return the sum of regular-file bytes in an application bundle."""
    if not path.is_dir():
        raise ReportError("the application bundle is missing")
    size = sum(
        candidate.stat().st_size
        for candidate in path.rglob("*")
        if candidate.is_file() and not candidate.is_symlink()
    )
    if size <= 0:
        raise ReportError("the application bundle is empty")
    return size


def aggregate(samples: Sequence[Sample], app_bytes: int, dmg_bytes: int, commit: str) -> dict[str, object]:
    """Build the aggregate-only unsigned report and enforce merge tripwires."""
    if len(samples) != RECORDED_RUNS:
        raise ReportError(f"exactly {RECORDED_RUNS} recorded runs are required")
    if COMMIT.fullmatch(commit) is None:
        raise ReportError("commit must be an exact lowercase 40-character SHA")
    if min(app_bytes, dmg_bytes) <= 0:
        raise ReportError("artifact sizes must be positive")

    def metric(values: Sequence[float]) -> dict[str, float]:
        return {
            "median": round(median(values), 3),
            "p95": round(nearest_rank_p95(values), 3),
        }

    query = metric([sample.query_ms for sample in samples])
    observations = {
        "local_top_50_query": "within" if query["p95"] < QUERY_BUDGET_MS else "breach",
        "installed_app_size": "within" if app_bytes <= APP_BUDGET_BYTES else "breach",
        "compressed_dmg_size": "within" if dmg_bytes <= DMG_BUDGET_BYTES else "breach",
    }
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "evidence_tier": "device-unsigned",
        "commit": commit,
        "warmup_runs": 1,
        "recorded_runs": RECORDED_RUNS,
        "fixture": {"kind": "synthetic", "cached_envelopes": 100, "query_matches": 50},
        "metrics": {
            "encrypted_store_open_and_top_50_list_ms": metric(
                [sample.open_list_ms for sample in samples]
            ),
            "local_top_50_query_ms": query,
            "bounded_reconcile_100_ms": metric(
                [sample.reconcile_ms for sample in samples]
            ),
            "probe_process_peak_mib": metric(
                [sample.process_peak_mib for sample in samples]
            ),
            "installed_app_bytes": app_bytes,
            "compressed_dmg_bytes": dmg_bytes,
        },
        "budget_observations": observations,
        "unmeasured": [
            "cached_inbox_interactive_cold_start",
            "inbox_scroll_frame_pacing",
            "idle_inbox_memory",
            "live_sync_index_peak_memory",
        ],
        "gate_status": "unchanged",
        "non_claim": (
            "Unsigned synthetic pre-measurements are not release-equivalent UI, "
            "accessibility, sandbox, cache-budget, or distribution evidence."
        ),
    }
    if "breach" in observations.values():
        raise ReportError("an unsigned merge-time performance or size tripwire was breached")
    return report


def capture(args: argparse.Namespace) -> int:
    """Take one warm-up plus five recorded runs and print aggregate JSON."""
    executable = Path(args.executable).resolve()
    if not executable.is_file():
        raise ReportError("the Rust test executable is missing")
    run_probe(executable)
    samples = [run_probe(executable) for _ in range(RECORDED_RUNS)]
    report = aggregate(
        samples,
        bundle_bytes(Path(args.app)),
        file_bytes(Path(args.dmg)),
        args.commit,
    )
    json.dump(report, sys.stdout, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--executable", required=True)
    capture_parser.add_argument("--app", required=True)
    capture_parser.add_argument("--dmg", required=True)
    capture_parser.add_argument("--commit", required=True)
    capture_parser.set_defaults(handler=capture)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.handler(args)
    except (OSError, ReportError) as error:
        print(f"macOS performance capture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
