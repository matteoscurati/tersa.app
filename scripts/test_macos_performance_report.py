#!/usr/bin/env python3
"""Tests for scripts/macos-performance-report.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).with_name("macos-performance-report.py")
SPEC = importlib.util.spec_from_file_location("macos_performance_report", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PerformanceReportTests(unittest.TestCase):
    def sample(self, value: float = 10.0) -> object:
        return MODULE.Sample(value, value, value, 40.0)

    def test_nearest_rank_p95_is_conservative_for_five_runs(self) -> None:
        self.assertEqual(MODULE.nearest_rank_p95([1.0, 2.0, 3.0, 4.0, 5.0]), 5.0)

    def test_parse_sample_accepts_only_the_fixed_marker(self) -> None:
        sample = MODULE.parse_sample(
            "TERSA_PERF_SAMPLE open_list_us=1000 query_us=2000 reconcile_us=3000 rows=100\n",
            " 41943040  maximum resident set size\n",
        )
        self.assertEqual(sample.open_list_ms, 1.0)
        self.assertEqual(sample.process_peak_mib, 40.0)
        with self.assertRaises(MODULE.ReportError):
            MODULE.parse_sample("TERSA_PERF_SAMPLE query=secret\n", "")

    def test_aggregate_is_redacted_and_marks_non_claims(self) -> None:
        report = MODULE.aggregate(
            [self.sample() for _ in range(5)],
            7 * 1024 * 1024,
            3 * 1024 * 1024,
            "a" * 40,
        )
        self.assertEqual(report["evidence_tier"], "device-unsigned")
        self.assertEqual(report["gate_status"], "unchanged")
        self.assertNotIn("runs", report)
        self.assertEqual(report["budget_observations"]["local_top_50_query"], "within")

    def test_aggregate_requires_exact_run_count_and_commit(self) -> None:
        with self.assertRaises(MODULE.ReportError):
            MODULE.aggregate([self.sample()] * 4, 1, 1, "a" * 40)
        with self.assertRaises(MODULE.ReportError):
            MODULE.aggregate([self.sample()] * 5, 1, 1, "HEAD")

    def test_aggregate_fails_on_any_tripwire_breach(self) -> None:
        with self.assertRaises(MODULE.ReportError):
            MODULE.aggregate(
                [self.sample(100.0) for _ in range(5)],
                7 * 1024 * 1024,
                3 * 1024 * 1024,
                "b" * 40,
            )
        with self.assertRaises(MODULE.ReportError):
            MODULE.aggregate(
                [self.sample() for _ in range(5)],
                MODULE.APP_BUDGET_BYTES + 1,
                3 * 1024 * 1024,
                "b" * 40,
            )


if __name__ == "__main__":
    unittest.main()
