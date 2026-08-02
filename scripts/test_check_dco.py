#!/usr/bin/env python3
"""Deterministic tests for scripts/check-dco.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).with_name("check-dco.py")
SPEC = importlib.util.spec_from_file_location("check_dco", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def record(commit: str, author: str, email: str, signers: list[str]) -> str:
    return MODULE.FIELD_SEPARATOR.join(
        (commit, author, email, MODULE.SIGNER_SEPARATOR.join(signers))
    ) + MODULE.RECORD_SEPARATOR


class DcoTests(unittest.TestCase):
    def test_matching_author_signoff_passes(self) -> None:
        log = record(
            "abc123",
            "Ada Lovelace",
            "ada@example.test",
            ["Ada Lovelace <ada@example.test>"],
        )
        self.assertEqual(MODULE.unsigned_commits(log), [])

    def test_email_comparison_is_case_insensitive(self) -> None:
        log = record(
            "abc123",
            "Ada Lovelace",
            "ADA@example.test",
            ["Ada Lovelace <ada@EXAMPLE.test>"],
        )
        self.assertEqual(MODULE.unsigned_commits(log), [])

    def test_one_matching_signoff_among_multiple_passes(self) -> None:
        log = record(
            "abc123",
            "Ada Lovelace",
            "ada@example.test",
            ["Reviewer <reviewer@example.test>", "Ada Lovelace <ada@example.test>"],
        )
        self.assertEqual(MODULE.unsigned_commits(log), [])

    def test_different_signer_fails(self) -> None:
        log = record(
            "abc123",
            "Ada Lovelace",
            "ada@example.test",
            ["Reviewer <reviewer@example.test>"],
        )
        self.assertEqual(MODULE.unsigned_commits(log), ["abc123"])

    def test_missing_signoff_fails(self) -> None:
        log = record("abc123", "Ada", "ada@example.test", [])
        self.assertEqual(MODULE.unsigned_commits(log), ["abc123"])

    def test_malformed_record_fails_closed(self) -> None:
        with self.assertRaises(MODULE.DcoError):
            MODULE.unsigned_commits("abc123\x1fAda\x1e")

    def test_malformed_signoff_does_not_match(self) -> None:
        log = record("abc123", "Ada", "ada@example.test", ["Ada ada@example.test"])
        self.assertEqual(MODULE.unsigned_commits(log), ["abc123"])

    def test_email_without_at_sign_does_not_match(self) -> None:
        log = record("abc123", "Ada", "invalid-email", ["Ada <invalid-email>"])
        self.assertEqual(MODULE.unsigned_commits(log), ["abc123"])

    def test_non_ascii_case_folding_does_not_match(self) -> None:
        log = record("abc123", "Ada", "ada@\u212a.test", ["Ada <ada@k.test>"])
        self.assertEqual(MODULE.unsigned_commits(log), ["abc123"])

    def test_signer_name_is_trimmed_like_the_rust_checker(self) -> None:
        log = record("abc123", "Ada", "ada@example.test", ["Ada   <ada@example.test>"])
        self.assertEqual(MODULE.unsigned_commits(log), [])


if __name__ == "__main__":
    unittest.main()
