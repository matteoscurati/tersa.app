# M0 SQLCipher storage feasibility evidence

## Decision

The bounded storage probe passes on arm64 macOS with SQLCipher 4.10.0 community,
SQLite 3.50.4, and the CommonCrypto provider. The same executable cross-builds
and links for arm64 macOS, iOS devices, and iOS simulators. This proves the
selected native dependency can support the encrypted database boundary; it is
not a production store implementation.

The probe uses `rusqlite` 0.39.0 with default features disabled and only the
`bundled-sqlcipher` feature enabled. Version 0.40.1 was evaluated first but its
`libsqlite3-sys` 0.38.1 build script requires the `cfg_select` library feature,
which is unavailable on the repository's pinned Rust 1.91.1 toolchain. M0 keeps
the toolchain stable and pins the latest compatible dependency instead.

## Automated contract

The macOS evidence executable uses only random synthetic values and proves:

- `cipher_provider` is `commoncrypto` and `cipher_version` is exactly
  `4.10.0 community`;
- WAL mode, `secure_delete`, disabled WAL auto-checkpointing, and
  `temp_store=MEMORY` are active;
- a committed transaction survives a real `SIGKILL` while its non-empty WAL is
  still present, then recovers the exact rows on reopen;
- schema reads without a key and with a wrong key fail with `SQLITE_NOTADB`;
- SQLite `integrity_check` succeeds and SQLCipher `cipher_integrity_check`
  returns no failure rows;
- random sentinels do not occur in any visible regular database, WAL, SHM, or
  controlled temporary-directory file before or after recovery;
- the encrypted main database does not expose the `SQLite format 3` header;
- the same scanner detects a sentinel in an unkeyed plaintext SQLite control,
  preventing a vacuous absence result; and
- a large in-memory temporary-table workload creates no controlled filesystem
  artifact;
- separate compiled, contiguous global and per-account migration chains use
  distinct fixed application IDs and `user_version` as their only cursor;
- only an exactly empty, unowned database is claimed, while unknown ownership,
  future versions, downgrades, and noncanonical schemas are rejected;
- fresh-to-latest and close/reopen incremental upgrades converge to the same
  exact normalized `sqlite_schema`, while latest-version reopen is a no-op;
- each migration is transactional, with the version bump as the final database
  statement before commit and the application ID set atomically in migration
  one; and
- deterministic `SIGKILL` before migration-two commit recovers canonical version
  one for both global and account databases, then a normal open reaches canonical
  version two.

The illustrative global schema contains only account references and preferences.
The illustrative account schema contains only threads, messages, labels,
message-label relations, and pending-operation intent. It has no production
Gmail fields, explicit indexes, triggers, FTS, blobs, or migration-history
table. Gmail remains authoritative for server mail and labels; pending
operations represent temporary local intent.

The parent sends the random key to its child over a private stdin pipe. Keys,
sentinels, SQL, file paths, and raw database artifacts are never written to the
evidence output. The output contains only fixed pass, provider, version, and
journal-mode lines. Failures emit only a fixed parent or child stage code, which
supports CI triage without exposing the underlying error or sensitive values.
Temporary probe files are removed on normal and error exits.

## Security boundary and open work

The residue scan proves absence of known synthetic markers only in visible
files under a controlled directory. It does not prove absence from RAM, swap,
APFS snapshots, crash reports, backups, deleted or anonymously unlinked files,
or a compromised process. WAL and SHM format metadata can remain plaintext;
the gate concerns application payloads, not structural headers.

File-backed SQLite temporary storage is prohibited by this result. The
production store must retain `temp_store=MEMORY` and must not weaken the check
to permit a file spill. The diagnostic sets its key through a SQLCipher pragma;
this can create transient library-owned SQL copies that Rust cannot reliably
zeroize. A production adapter must use a narrowly audited keying boundary.

Runtime durability and the migration crash protocol are exercised on macOS only.
iOS device and simulator builds prove compilation and linkage, not protected-data
lifecycle, background access, power-loss behavior, or filesystem policy. The
host `SIGKILL` proof does not model power failure, disk-full behavior, or APFS
failure semantics.

Deferred work includes the production storage repository API and schema,
migration-history policy, Keychain and Data Protection integration, key
derivation and rotation, rekey and plaintext migration, corruption and disk-full
recovery, backup and restore behavior, blob encryption, search, and app lock.

The ownership and migration boundary is recorded in
[ADR 0011](../architecture/adr-0011-sqlcipher-schema-and-migration-ownership.md).
`M0-STORAGE-001` remains open: host migration evidence does not satisfy its
signed physical-device requirement.

## Reproduce locally

Install the three Apple Rust targets, then run:

```sh
sh apple/scripts/verify-sqlcipher-feasibility.sh
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked \
  --package tersa-sqlcipher-spike --target aarch64-apple-ios
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked \
  --package tersa-sqlcipher-spike --target aarch64-apple-ios-sim
```

CI also verifies the checksum-bound bundled SQLCipher BSD-3-Clause notice and
byte-for-byte target-specific dependency notices.
