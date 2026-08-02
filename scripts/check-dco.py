#!/usr/bin/env python3
"""Check DCO author sign-offs without compiling the Rust workspace."""

from __future__ import annotations

import argparse
import subprocess
import sys


FIELD_SEPARATOR = "\x1f"
SIGNER_SEPARATOR = "\x1d"
RECORD_SEPARATOR = "\x1e"
LOG_FORMAT = (
    "%H%x1f%an%x1f%ae%x1f"
    "%(trailers:key=Signed-off-by,valueonly,separator=%x1d)%x1e"
)


class DcoError(ValueError):
    """Raised when Git output cannot be validated safely."""


def parse_identity(identity: str) -> tuple[str, str] | None:
    """Return a ``(name, email)`` pair from a DCO identity."""
    identity = identity.strip()
    if " <" not in identity or not identity.endswith(">"):
        return None
    name, email = identity.rsplit(" <", 1)
    name = name.strip()
    email = email[:-1]
    if not name or "@" not in email:
        return None
    return name, email


def ascii_fold(value: str) -> str:
    """Fold only ASCII letters, matching Rust's ``eq_ignore_ascii_case``."""
    return "".join(
        chr(ord(character) + 32) if "A" <= character <= "Z" else character
        for character in value
    )


def unsigned_commits(log: str) -> list[str]:
    """Return commit hashes that are not signed off by their author."""
    unsigned: list[str] = []
    for record in log.split(RECORD_SEPARATOR):
        record = record.strip("\r\n")
        if not record:
            continue
        fields = record.split(FIELD_SEPARATOR)
        if len(fields) != 4:
            raise DcoError("git log record does not contain exactly four fields")
        commit, author_name, author_email, sign_offs = fields
        if not commit or not author_name or not author_email:
            raise DcoError("git log record contains an empty required field")
        signed_by_author = any(
            signer_name == author_name and ascii_fold(signer_email) == ascii_fold(author_email)
            for signer in sign_offs.split(SIGNER_SEPARATOR)
            if (identity := parse_identity(signer)) is not None
            for signer_name, signer_email in (identity,)
        )
        if not signed_by_author:
            unsigned.append(commit)
    return unsigned


def git_log(base: str, head: str) -> str:
    """Read author and sign-off metadata for ``base..head``."""
    result = subprocess.run(
        ["git", "log", f"--format={LOG_FORMAT}", f"{base}..{head}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise DcoError(f"git log failed for {base}..{head}: {detail}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description="Check DCO sign-offs in a commit range.")
    parser.add_argument("base", help="Exclusive base commit")
    parser.add_argument("head", help="Inclusive head commit")
    arguments = parser.parse_args()

    try:
        unsigned = unsigned_commits(git_log(arguments.base, arguments.head))
    except (DcoError, UnicodeError) as error:
        print(f"DCO check failed closed: {error}", file=sys.stderr)
        return 1

    commit_range = f"{arguments.base}..{arguments.head}"
    if unsigned:
        print(
            "commits missing a valid Signed-off-by trailer: " + ", ".join(unsigned),
            file=sys.stderr,
        )
        return 1
    print(f"DCO sign-off check passed for {commit_range}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
