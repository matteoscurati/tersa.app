<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0017: Production macOS account store

- Status: Accepted
- Date: 2026-07-16

## Context

The mailbox contract needs a production local implementation without widening
the shared application or domain layers. Account data must be encrypted at rest,
bound to one local account, and reject unknown schema ownership.

## Decision

`tersa-store-sqlcipher-macos` implements `MailboxStore` for exactly one
`AccountId` and one caller-selected SQLCipher file. It accepts a zeroizing
32-byte database key, applies the raw SQLCipher key before schema access, and
uses WAL, foreign keys, in-memory temporary storage, secure deletion, a bounded
busy timeout, canonical schema validation, `SQLite` and `SQLCipher` integrity
checks, and no-follow opening of the canonicalized database leaf.
Connection-local safeguards are applied before ownership checks, but durable
WAL and secure-delete configuration occurs only after a fresh or already-owned
canonical store has been established; a foreign file is rejected unchanged.

The adapter is synchronous internally but returns lazy, runtime-free futures.
Later orchestration must poll it on a bounded blocking executor; it must not be
run on a latency-sensitive async executor thread. Each write is one SQLCipher
transaction, and a dropped unpolled future has no effect.

Schema v1 owns a singleton account binding and message envelopes with nullable
RFC 5322 content. Only an exactly empty database may be claimed. Ownership,
version, schema, integrity, and decoded domain values are revalidated and map to
opaque corruption errors; operational failures map to opaque storage errors.
An envelope without content is a valid partial cache entry, so `message`
returns `None` until complete content is stored. Reads preflight SQLite types
and byte lengths before materializing user-controlled text or message bytes.

Blob and attachment encryption are intentionally deferred. This adapter does
not use `chacha20poly1305` or `hmac` until a real blob/attachment port and a
cross-file commit protocol are accepted. ADR 0011 engine crash evidence remains
the applicable SQLCipher engine evidence until that protocol exists.

Deterministic adapter tests cover exact schema convergence and no-op reopen,
wrong-key and foreign/future/noncanonical schema rejection, transaction
rollback, lazy cancellation, corrupted row rejection, mutex poisoning, symlink
denial, and absence of plaintext sentinels from the database and sidecars. A
new process-crash harness is deferred until the store adds a commit protocol
beyond one SQLCipher transaction.

## Consequences

The adapter is macOS-only and has no keychain, global database, cache, search,
mobile, retry, pool, or sync-orchestration behavior. Its path, key, account,
headers, identifiers, and message bodies are never included in errors or debug
output.
