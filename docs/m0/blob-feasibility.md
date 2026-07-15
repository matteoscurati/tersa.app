<!--
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
-->

# Crash-safe chunked-AEAD blob feasibility

## Decision status

This M0 slice validates a bounded candidate encrypted-blob format and a
deterministic process-crash publication protocol using synthetic data. It is a
portable diagnostic in `apps/blob-spike`, not a production storage component.
Every successful host run prints exactly:

```text
Blob AEAD M0 feasibility PASS
Blob format version 1
NOT A DEVICE-GATE RESULT
```

Failures expose only a fixed parent or child stage code. They do not print a
key, nonce, account, blob ID, sentinel, plaintext, content identifier, or path.

## Automated contract

The locked diagnostic proves:

- 0, 1, 65,535, 65,536, 65,537, multi-chunk, and 4 MiB bounded round trips;
- a single authenticated zero-plaintext record for an empty blob;
- range reads across a chunk boundary that decrypt exactly two records;
- fresh random 192-bit nonces with run-wide duplicate rejection, including the
  synchronized crash-child record;
- per-account content identifiers, same-account equality, and cross-account
  separation;
- authenticated reuse only for the same account and blob-ID binding, while a
  different blob ID, corrupt existing final, or symlink entry at the same
  content path is rejected and preserved without replacement or symlink
  traversal;
- descriptor-bound collision validation: `lstat`, no-follow open, regular-file
  and device/inode equality checks, then authentication through that same open
  descriptor; a deterministic post-`lstat` symlink swap is rejected without
  reading its valid authenticated target;
- ordinary published reads also use a no-follow regular-file descriptor and
  reject a canonical 64-hex symlink without reading its valid blob target;
- nonblocking descriptor opens reject canonical-name FIFOs and FIFOs swapped
  into a collision after `lstat` promptly, without requiring a FIFO writer;
- atomic same-directory no-replace hard-link publication, including a final
  created after staging starts but before publication; the conflict remains
  byte-identical and staging is removed;
- unlinking the staging hard link after successful publication preserves the
  published hard link;
- wrong-key, cross-account, wrong-blob-ID, header, authentication, ordering,
  duplication, deletion, replay, truncation, append, hostile-size,
  staging-open, and manifest-directed filename-swap rejection;
- exact canonical file-size validation before random-access output;
- no allocation proportional to the header-declared total during open, with a
  fixed 64 KiB streaming write buffer;
- staging-file and directory synchronization, `SIGKILL` after one durable
  staged record, preservation of an unrelated valid final, narrow staging-only
  cleanup, and successful normal publication after recovery; and
- random plaintext-sentinel absence in every controlled file, backed by a
  plaintext positive control for the scanner.

The parent generates independent AEAD and HMAC keys for each of two synthetic
accounts. The crash child receives only its bounded private protocol over
standard input and moves the received key buffers into the diagnostic's
zeroizing key owner. No derivation or production key hierarchy is implied.

## Reproduction

On macOS with the pinned Rust toolchain and Apple targets installed:

```sh
cargo test --locked --package tersa-blob-spike
sh apple/scripts/verify-blob-feasibility.sh
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked --release \
  --package tersa-blob-spike --target aarch64-apple-ios
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked --release \
  --package tersa-blob-spike --target aarch64-apple-ios-sim
```

The dedicated `blob-apple-evidence` job regenerates all target-specific
notices, cross-builds the release diagnostic for macOS, iOS device, and iOS
simulator, runs the macOS arm64 process-crash protocol, binds `result.txt` to
the source commit, and retains the aggregate artifact for 90 days.

## Non-claims and remaining gates

No Keychain, File Protection, device/simulator runtime, signing, backup, APFS power-loss, disk-full, eviction, production key lifecycle/derivation, manifest binding, or performance claims. No claims about RAM, swap, snapshots, deleted blocks, root compromise, or defects inside the pinned libraries. Whole-blob rollback freshness excluded (manifest work). Within-account content-equality and blob-size leakage documented as accepted diagnostic-scope metadata exposure. iOS/simulator artifacts are compile evidence only.

The candidate cannot move into a production crate until a separate reviewed
ADR defines authenticated manifest semantics, atomic database/blob commit
ordering, key derivation and rotation, quota and eviction behavior, backup and
restore policy, File Protection classes, disk-full handling, and signed
physical-device evidence. This diagnostic makes no general cross-logical-blob
deduplication claim; such reuse requires those future authenticated manifest
semantics. Its filesystem evidence is limited to a same-directory,
same-filesystem hard-link protocol on the macOS host.
The descriptor check does not provide a filesystem snapshot. Concurrent
external mutation of the already-open inode is outside this process-crash
diagnostic boundary, and reuse still requires complete authentication.
