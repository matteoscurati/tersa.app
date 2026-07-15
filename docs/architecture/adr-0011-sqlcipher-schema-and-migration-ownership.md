<!--
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0011: SQLCipher schema and migration ownership

- Status: Accepted for the M0 host diagnostic
- Date: 2026-07-15

## Context

tersa.app needs separate encrypted persistence boundaries for installation-wide
configuration and account-scoped mail state. A database must never be silently
claimed when its ownership or schema is unknown, and a crash during an upgrade
must leave either the old canonical schema or the new canonical schema.

This decision covers only the bounded SQLCipher feasibility executable. The
schemas are synthetic, illustrative, and intentionally smaller than a product
schema.

## Decision

The diagnostic compiles two independent, contiguous migration chains:

- the global database owns account references and application preferences; and
- each account database owns cached threads, messages, labels, label relations,
  and temporary pending-operation intent.

Each database kind has a distinct fixed SQLite `application_id`. SQLite
`user_version` is the only migration cursor. A migration-history table is
deferred until the production repository design establishes its audit and
recovery requirements.

Only an empty database with `application_id = 0`, `user_version = 0`, and an
empty `sqlite_schema` may be claimed. Existing databases must have the expected
nonzero application ID, a supported version, and an exact canonical normalized
schema for that kind and version. Downgrades, future versions, noncontiguous
compiled migrations, unknown ownership, and structural mismatches are rejected.

Each migration runs in its own transaction. Migration one sets the application
ID atomically. The `user_version` update is the final database statement before
commit. Foreign-key enforcement is enabled on every connection, and the
diagnostic verifies foreign keys plus SQLite and SQLCipher integrity after each
meaningful recovery or upgrade boundary.

Gmail remains authoritative for server messages and labels. Cached account
tables are reconstructible local representations. `pending_operations` stores
temporary local intent until Gmail confirms or rejects it; it does not become a
second authoritative mail store.

## Crash evidence

For migration two of both database kinds, the host diagnostic creates canonical
version one and truncates the committed WAL baseline. A child opens the database,
executes the version-two DDL and version bump inside an uncommitted transaction,
then uses SQLite's non-SQL cache-flush API to expose uncommitted WAL frames. It
fsyncs a ready marker and parks before commit. The parent requires both the
marker and a non-empty WAL, sends `SIGKILL`, and verifies signal 9.

Reopen must recover exact canonical version one with unchanged ownership and
version. A normal open then applies migration two and reaches exact canonical
version two. This is deterministic process-crash evidence on the macOS host; it
is not power-loss, filesystem-failure, or iOS protected-data evidence.

## Consequences

- Fresh-to-latest and close/reopen incremental upgrades must converge exactly.
- Reopening the latest schema applies no migration and changes no schema state.
- Product schema fields, indexes, triggers, FTS, blobs, Gmail identifiers, and
  repository APIs remain deliberately undecided.
- `M0-STORAGE-001` remains open because its required evidence tier is a signed
  physical device, while this diagnostic is host-only.
