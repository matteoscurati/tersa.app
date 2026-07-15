# M0 encrypted-search feasibility evidence

## Decision

The bounded Apple diagnostic establishes host-side correctness and privacy
evidence for SQLCipher FTS5 and Tantivy 0.26.1. It is an isolated feasibility
probe, not production search and not an iPhone performance result.

## Contract

- Both engines return the same exact synthetic message-ID match set. Result
  order and ranking parity are intentionally not asserted.
- Tantivy reads and writes through a custom SQLCipher `Directory` that stores
  immutable file generations as fixed-size database chunks. Range reads query
  only the intersecting chunk ordinals; open handles retain generation IDs, not
  decrypted whole-file snapshots. It does not use memory mapping, temporary
  index files, compression, or a production storage API.
- An already-open handle survives replacement and deletion. `open_write`
  immediately creates a readable empty file, each flush publishes an immutable
  generation, and a database uniqueness constraint preserves WORM behavior
  across independent connections. Tantivy's writer lock rejects a second
  writer while an existing reader remains usable on another thread; blocking
  locks wait for release; metadata watches can re-enter the directory without
  retaining its SQLCipher mutex; and a sliced read proves that only one
  intersecting SQLCipher chunk was loaded.
- Missing and wrong SQLCipher keys fail closed, both `integrity_check` and
  `cipher_integrity_check` succeed, and a random per-run sentinel is first
  retrieved from Tantivy and then proven absent from database, WAL, and SHM
  artifacts before and after reopen. A separate plaintext positive control
  proves the scanner can detect its input.
- The emitted evidence contains only aggregate profile and host timing values.
  It contains no key, sentinel, SQL, path, result identifier, database byte, or
  ranking output.

## Profiles and remaining device gate

The CI host profile contains 10,000 messages and at least 128 MiB of normalized
text. The opt-in manual host profile contains 100,000 messages and at least
2 GiB. Both are explicitly labeled `NOT A DEVICE-GATE RESULT`.

Locked Rust 1.91.1 builds for macOS arm64, iOS arm64, and iOS simulator arm64
are required. They do not prove iOS runtime behavior, durability,
protected-data handling, performance, or a production search architecture.

The M0 physical-iPhone gate remains open. On the target iPhone, the 100,000
message/2 GiB corpus must demonstrate top-50 query p95 below 150 ms, incremental
RSS below 40 MiB, and current index bytes below 40% of normalized text. This PR
does not claim those thresholds have passed.
