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
  artifact.

The parent sends the random key to its child over a private stdin pipe. Keys,
sentinels, SQL, file paths, and raw database artifacts are never written to the
evidence output. The output contains only fixed pass, provider, version, and
journal-mode lines. Temporary probe files are removed on normal and error exits.

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

Runtime durability is exercised on macOS only. iOS device and simulator builds
prove compilation and linkage, not protected-data lifecycle, background access,
power-loss behavior, or filesystem policy.

Deferred work includes the storage repository API, schema and migrations,
Keychain and Data Protection integration, key derivation and rotation,
per-account databases, rekey and plaintext migration, corruption and disk-full
recovery, backup and restore behavior, blob encryption, search, and app lock.

## Reproduce locally

Install the three Apple Rust targets, then run:

```sh
sh apple/scripts/verify-sqlcipher-feasibility.sh
cargo build --locked --package tersa-sqlcipher-spike --target aarch64-apple-ios
cargo build --locked --package tersa-sqlcipher-spike --target aarch64-apple-ios-sim
```

CI also verifies the checksum-bound bundled SQLCipher BSD-3-Clause notice and
byte-for-byte target-specific dependency notices.
