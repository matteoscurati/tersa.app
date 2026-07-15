<!--
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0012: Candidate chunked encrypted-blob format

- Status: Accepted for the M0 host diagnostic
- Date: 2026-07-15

## Context

tersa.app must eventually persist attachments, inline resources, thumbnails,
and parser products without materializing plaintext files. Large values need
bounded-memory streaming and authenticated random access. A crash must not
publish an incomplete value, and recovery must distinguish private staging
files from published blobs without broad directory deletion.

This decision covers only the portable, synthetic feasibility executable in
`apps/blob-spike`. The executable has no workspace dependencies and is not a
production blob store.

## Decision

Format version 1 is a bounded little-endian container. Its 21-byte header is:

| Field | Size |
|---|---:|
| Magic `TRSABLOB` | 8 bytes |
| Format version `1` | 1 byte |
| Total plaintext length | 8-byte unsigned integer |
| Chunk count | 4-byte unsigned integer |

The diagnostic uses 64 KiB plaintext chunks and a 4 MiB hard input limit. An
empty blob has exactly one authenticated record with zero plaintext. Every
record stores a fresh random 192-bit XChaCha20-Poly1305 nonce, ciphertext, and
the 16-byte authentication tag. Nonces come directly from `getrandom` 0.3.4,
and the harness rejects any duplicate observed in the parent or crash child.

Every record authenticates the version, 16-byte synthetic account context,
random 128-bit blob ID, chunk index, chunk plaintext length, total plaintext
length, and chunk count. The reader first validates the canonical header and
exact canonical file size using checked arithmetic. It then allocates only the
requested fixed-size records. Published reads use a nonblocking, no-follow
descriptor and require the opened object to be a regular file, so a FIFO is
rejected without waiting for a writer. Random reads decrypt only intersecting
chunks;
an exact size mismatch rejects a missing tail before any early chunk is
returned.

The diagnostic creates two independent random 256-bit keys per synthetic
account: one AEAD key and one content-identifier key. It intentionally does not
model production root-key derivation. The published filename is the full
lowercase hexadecimal HMAC-SHA-256 of the domain
`tersa-blob-content-id-v1`, account context, and plaintext, computed during the
same streaming pass. Comparisons use constant-time equality. The harness acts
as the candidate manifest by supplying the expected account and blob ID when a
file is opened.

## Publication and recovery

Writes use a cryptographically random, narrowly reserved
`pending.staging-<24 lowercase hex characters>` filename in the destination
directory. The writer streams and authenticates each record, synchronizes the
complete staging file, and calls `hard_link(staging, final)` in that same
directory. Creating the final hard link is atomic and cannot replace any
existing directory entry. After success, the writer unlinks only staging and
synchronizes the directory; the published hard link continues to own the same
inode. This protocol is intentionally limited to a same-directory,
same-filesystem host boundary.

`AlreadyExists` is the only publication error that can enter reuse handling.
The writer obtains a no-follow `lstat`, requires a regular file, opens the path
with `O_NOFOLLOW`, and requires the opened descriptor to remain a regular file
with the same device and inode as the `lstat` result. It never reopens the path.
The writer then authenticates that already-open descriptor chunk by chunk with
the current account, keys, and exact blob ID before recomputing its content
identifier in the same bounded-memory pass.
Only that same authenticated manifest binding may reuse the existing final. A
different blob ID, corrupt final, symlink, directory, or other link error fails
closed, preserves every existing final byte for byte, removes only the new
staging entry, and synchronizes the directory. Filename equality alone never
authorizes reuse.

For deterministic crash evidence, a child receives independent keys and IDs
over standard input, writes and synchronizes the first staged record, creates
and synchronizes a ready marker, and parks. The parent requires the durable
partial staging file, rejects it as published input, scans controlled files for
a random plaintext sentinel, sends `SIGKILL`, and verifies signal 9. Recovery
removes only the exact reserved staging name and preserves an unrelated valid
final. A subsequent normal write must publish and reconstruct the interrupted
plaintext.

The negative corpus covers wrong account, AEAD key, and blob ID; malformed or
noncanonical headers; nonce, ciphertext, and tag mutation; chunk reorder,
duplication, deletion, replay, partial and whole-record truncation; garbage and
well-formed-record append; hostile lengths and counts; staging-name opens; and
manifest-directed filename swaps. A deterministic publication race creates a
conflicting final after staging begins; the no-replace link must reject and
preserve it. A second deterministic barrier replaces that regular final with a
symlink after `lstat` but before open; the no-follow descriptor open rejects the
swap without reading the valid authenticated symlink target. Equivalent
ordinary-read and post-`lstat` FIFO tests prove rejection remains nonblocking
without a FIFO writer. A separate link-count test proves that removing the
staging hard link does not delete the published link.

## Consequences

- `chacha20poly1305` 0.10.1 and `hmac` 0.12.1 are exact-pinned and exclusive to
  `tersa-blob-spike`; this ADR does not approve them for production code.
- `rustix` 1.1.4 is exact-pinned as a direct `tersa-blob-spike` dependency with
  only its standard-library and filesystem features. It supplies the safe
  no-follow descriptor operations; it is not exclusive to this diagnostic
  because unrelated workspace dependency graphs already use it transitively.
- Within one account, identical plaintext has the same content identifier and
  therefore reveals content equality. Canonical file length reveals bounded
  blob size.
- This diagnostic does not deduplicate across logical blob IDs. Cross-blob
  reuse requires future manifest semantics that explicitly preserve and
  authenticate the ciphertext's blob-ID binding.
- A production ADR must define manifest ownership and atomicity, key
  derivation and rotation, eviction, quotas, backup, File Protection, and
  physical-device lifecycle behavior before this format can move into a core
  crate.
- Whole-blob rollback freshness is explicitly delegated to that future
  authenticated manifest; per-chunk authentication cannot provide it alone.
- Filesystem behavior beyond the same-directory host hard-link and directory
  synchronization protocol remains outside this diagnostic result.
- Descriptor identity closes path replacement between `lstat` and open, but it
  does not create a filesystem snapshot. An external actor that can modify the
  already-open inode during authentication remains outside the diagnostic's
  process-crash threat boundary; authentication is still required before reuse.

No Keychain, File Protection, device/simulator runtime, signing, backup, APFS power-loss, disk-full, eviction, production key lifecycle/derivation, manifest binding, or performance claims. No claims about RAM, swap, snapshots, deleted blocks, root compromise, or defects inside the pinned libraries. Whole-blob rollback freshness excluded (manifest work). Within-account content-equality and blob-size leakage documented as accepted diagnostic-scope metadata exposure. iOS/simulator artifacts are compile evidence only.
