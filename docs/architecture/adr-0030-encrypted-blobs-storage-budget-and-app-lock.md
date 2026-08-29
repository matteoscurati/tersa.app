<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0030: encrypted blobs, storage budget, and app lock

- Status: Proposed
- Date: 2026-08-29
- Owner intent: Approved; implementation is blocked pending independent
  architecture/security review and the prerequisite slices below.

## Context

The production SQLCipher store encrypts message data but has no production blob
format, attachment quota, or app-lock lifecycle. The former blob spike and its
format were retired diagnostic work; [ADR 0012](adr-0012-chunked-blob-format.md)
does not authorize a product implementation. The beta needs attachment and
inline-image storage without plaintext temporary files, while the 10 GiB macOS
cache constraint in [ADR 0006](adr-0006-product-constraints.md) needs a
recoverable enforcement model.

An app lock must also mean more than a Swift overlay. The current root-key
accessibility and a running unlocked process do not protect against privileged
malware; the product can nevertheless require fresh device-owner authentication
before reopening mailbox material and can require application-held plaintext
and derived keys to be evicted on lock.

## Prerequisite decision and policy slices

No blob, bundle, storage-budget, or app-lock implementation may start until
these independently reviewed slices are accepted:

1. **P30-dependency policy:** select and pin exact `chacha20poly1305` and
   `argon2` versions, targets, features, and allowed owners. Retain the verified
   workspace `rustix =1.1.4` API with its `fs` feature enabled for the additive
   direct-owner set `{tersa-keychain-macos, tersa-store-sqlcipher-macos,
   tersa-blob-aead-macos}`. The existing store owner is retained, never dropped.
   Amend `deny.toml`, dependency rules, and `xtask` owner fixtures accordingly.
   This ADR invents no new dependency version.
2. **P30-architecture amendments:** explicitly amend/supersede the retired
   diagnostic constraints in ADR 0012, ADR 0019, and ADR 0025 only for the new
   production path; record the direct `rustix` 1.1.4 `fs` ownership amendment,
   `renameat_with` no-replace policy, and exact fixtures in dependency/policy
   documentation.
3. **P30-composition:** approve the new inward edge from trusted
   `tersa-keychain-macos` composition to `tersa-blob-aead-macos`, its narrow
   `SecureBlobStore` capability, and the prohibition on raw-key bytes or public
   key callbacks.
4. **P30-security documentation:** update the security data flow and threat
   model for backup, key rotation, File Protection, deletion, diagnostics,
   allocated-byte accounting, and app-lock/locked-query semantics before code.

These are prerequisite amendments, not claims that the current retired or
dependency-policy records have already changed.

## Decision

### Per-account encrypted blobs

The domain layer adds `BlobId`, `BlobRef`, `BlobKind`, `BlobManifestV1`, and
`StorageClass`. `BlobRef` always carries `AccountId`; `StorageClass` is either
recoverable cache data or non-evictable local intent. The application adds
`SecureBlobStore` and `StorageBudgetStore` ports. The planned
`tersa-blob-aead-macos` adapter is the only production owner of
XChaCha20-Poly1305, direct `rustix` filesystem staging, and manifest
publication. It is constructed inside trusted `tersa-keychain-macos`
composition through P30-composition and returns only a narrow `SecureBlobStore`
capability; no raw key bytes, key callback, or public key-bearing constructor is
introduced.

The existing private Keychain/HKDF boundary gains the closed
`blob/account-content/v1` derivation purpose. It derives a 32-byte per-account
blob key without exposing root or derived bytes to callers. A blob receives a
random 128-bit `BlobId`, a separate random 24-byte XChaCha20 nonce for every
1 MiB plaintext chunk, and an encrypted/authenticated manifest. Each chunk's
associated data binds format version, `AccountId`, `BlobId`, chunk index, and
plaintext length. The manifest binds the same account/blob/version context,
chunk count/order, total length, `BlobKind`, and storage class. A chunk or
manifest from a different account, blob, index, or format must not decrypt.

The adapter writes only ciphertext to a validated owner-only staging directory
under the account's `blobs/` directory. It fsyncs chunks and manifest, then uses
the verified Rustix 1.1.4 primitive
`rustix::fs::renameat_with(..., RenameFlags::NOREPLACE)`, which maps on macOS to
`renameatx_np` with `RENAME_EXCL`, to publish the complete staging directory,
followed by parent fsync. An unavailable exclusive-rename primitive fails closed;
it never falls back to overwrite/replace. Directories are `0700`; files are
`0600`; all traversal is descriptor-relative and no-follow. It does not create
plaintext files, replace an existing final blob, recursively clean unowned data,
or claim power-loss atomicity beyond this staged publication protocol. A failed
write cleans only files/directories proven created by that attempt and otherwise
preserves redacted residue for recovery. This requires no libc or unsafe
amendment.

P30-architecture amendments supersede ADR 0019's interim active-graph
prohibition, ADR 0012's retired diagnostic-only status, and ADR 0025's retired
program boundary only for this exact policy-approved production adapter. They
also amend `deny.toml` and dependency/owner policy; no other ChaCha path is
authorized and no historical diagnostic evidence becomes production evidence.

### Budget and eviction

After P26-policy updates ADR 0006 A5, the per-account default budget is 10 GiB
with a 50 GiB installation aggregate; a user may lower an account budget, but
never below 1 GiB. Accounting uses allocated file bytes, not semantic SQLite
row sizes: it includes each account database, WAL, SHM, FTS files, blob
ciphertext/manifests, render/image cache, and registry metadata where allocated
to that account. A write preflights pessimistic allocated size, attempts bounded
eviction, and fails before partial publication when either budget remains
insufficient. Accounting divergence or a non-measurable allocated size preserves
data and fails closed; it never deletes protected content merely to repair a
counter.

Eviction is deterministic least-recently-used across recoverable message bodies,
received attachments, inline images, and derived render cache. It may evict
only data that Gmail can retrieve again. It never evicts drafts, outbox entries,
pending mailbox actions, account registry/profile/binding data, configured
budget, or a blob referenced by local intent. Downloaded attachments remain
on-demand; Save/Open is an explicit user-directed declassification and beta
does not preview hostile documents in-app.

Backup, key rotation, File Protection, deletion, and diagnostics have these
rules pending the P30-security documentation update: backup copies remain
encrypted but may be unreadable on another device because the root key is
device-bound; the beta performs no key rotation; a future rotation requires a
separate re-encryption/atomic-cutover ADR; macOS makes no unsupported File
Protection claim beyond owner-only files, encryption, and app-lock lifecycle;
deletion is validated descriptor-relative unlink plus reference removal, not
SSD secure erase; and diagnostics may record only aggregate sizes, versions,
and redacted outcome classes, never paths, BlobIds, account IDs, content, or
keys.

### App-lock lifecycle

App lock is opt-in and uses macOS device-owner authentication. Touch ID is used
when available; the system password/passcode path is the fallback. No biometric
template, authentication secret, or success token is stored by the app. The
domain adds `AppLockPolicy` with exactly `Immediate`, `OneMinute`, `FiveMinutes`,
and `FifteenMinutes`; the default is `FiveMinutes`.

The application `AppLockCoordinator` consumes an abstract authenticated/not-
authenticated result, not Apple framework types. When lock is enabled it:

1. locks immediately on sleep and after the selected inactivity timeout;
2. prevents new sync, render, blob, draft, and outbox work;
3. cancels/quiesces active workers, closes SQLCipher handles, clears UI models,
   and zeroizes or evicts application-held derived key material;
4. increments a lock generation that every asynchronous completion must match
   before it can publish state; and
5. requires a fresh successful device-owner authentication before deriving keys,
   reopening stores, or returning any mailbox document.

An already-dispatched Gmail operation may remain externally ambiguous; its
durable desired/outbox state survives and is reconciled after unlock. The lock
is not a second encryption root, does not revoke tokens, and does not claim to
protect content already available to a compromised unlocked process.

Lock closes every account store and registry-backed reader before it reports a
locked state. Any single-account or unified fan-out query returns only the
closed top-level `Locked` outcome while locked: it must not display rows from an
already-open account or report a partial-account result. Unlock starts a fresh
routed query after authentication and generation validation.

### Invariants and data flow

```text
Account-scoped attachment/image bytes
  -> SecureBlobStore staging ciphertext + authenticated manifest
  -> BlobRef in encrypted SQLCipher state
  -> explicit open/save declassification only

macOS sleep/timeout
  -> AppLockCoordinator generation fence
  -> stop work, close stores, evict keys/models
  -> device-owner authentication -> authorized reopen
```

- No blob, manifest, usage record, or key can be routed without a validated
  `AccountId`. Lock state carries no account identity and gates every account.
- The SQLCipher store is the transactional authority for `BlobRef` reachability,
  budget accounting, drafts/outbox protection, and eviction selection; the blob
  adapter owns only ciphertext files and verified publication/removal.
- A plaintext attachment exists only in bounded memory while explicitly opened,
  saved, composed, or parsed. The operation cannot silently export it.
- Lock generation fences apply to Swift UI, bridge replies, XPC replies, and
  Rust workers; an old unlocked completion cannot repopulate a locked view.
- Locked fan-out is all-or-nothing: stores are closed and no partial account
  display is permitted until fresh authentication completes.

### Implementation decomposition by change class

| Change class | Bounded implementation responsibility |
| --- | --- |
| `docs-only` | P30-architecture and P30-security amendments before implementation eligibility. |
| `policy-xtask` | P30 dependency/owner fixtures for Rustix 1.1.4 `fs`, no-replace staging, ABI, and lock-generation guards only. |
| `domain` | Add blob/reference/manifest/storage-class and app-lock policy values with redacted diagnostics. |
| `application` | Add `SecureBlobStore`, `StorageBudgetStore`, eviction use case, and `AppLockCoordinator` state/fence contract. |
| `adapter-rust — tersa-blob-aead-macos` | Implement chunk/manifest AEAD, no-replace staging, and ciphertext publication only. |
| `adapter-rust — tersa-store-sqlcipher-macos` | Implement allocated-byte accounting, BlobRef reachability, eviction selection, and reference transactions only. |
| `adapter-rust — tersa-keychain-macos` | Implement the private blob derivation/composition edge only. |
| `token-broker` | Preserve token authority; expose only closed lock quiesce/recovery status. |
| `bridge-ffi` | Add bounded BlobRef/budget/lock documents with atomic ABI fixture updates. |
| `swift-ui` | Implement settings, authentication prompt, locked state, and explicit Save/Open warning. |

Every BlobRef/budget/lock ABI change atomically updates the expected-export
allowlist, count, canonical header, Swift declarations, and positive/negative
fixtures. It carries no key, path, raw-byte, or store-handle capability.

## Failure handling

Manifest/tag/nonce/order validation failure marks the blob unavailable and
retains no decrypted output. Disk-full, quota, permission, or staging failure
does not publish a final blob or update its reference/accounting transaction.
An orphaned encrypted stage is never adopted blindly; recovery validates its
identity and otherwise preserves it for explicit cleanup. A corrupted usage
record or allocated-byte accounting divergence fails closed rather than evicting
protected intent.

Authentication cancellation/failure leaves the app locked. Worker cancellation
on lock preserves durable sync/outbox intent but prevents stale result delivery.
If a store cannot close or a worker cannot quiesce within its bounded shutdown
contract, the process remains locked and does not reopen content. Locking never
falls back to a UI-only mask or a plaintext cache, and a locked fan-out never
falls back to partial rows.

## Test and evidence gates

- Cryptographic tests cover wrong account/blob/key/nonce/index, manifest and
  chunk tampering, truncation, reordered chunks, malformed staging entries, and
  absence of plaintext sentinels from finals, stages, logs, and diagnostics.
- Crash and fault-injection tests cover every publish/accounting boundary,
  exclusive-rename failure, disk-full, concurrent writers, allocated-byte
  divergence, quota eviction, protected-intent preservation, and post-crash
  orphan handling.
- Cross-account tests prove a `BlobRef` cannot be read, evicted, or attached
  through another account. Budget tests cover default, 1 GiB minimum, and LRU
  behavior without evicting drafts/outbox/pending actions.
- Lifecycle tests cover timeout, sleep, failed authentication, all-store close,
  top-level locked fan-out/no partial rows, key/store/model eviction, and stale
  completion rejection for sync, worker, and bridge paths.
- A signed macOS candidate must perform lock/unlock, sleep/lock, attachment
  save warning, and accessibility walks. Unsigned or source tests do not prove
  device-owner authentication or final Keychain/process-isolation behavior.

## Non-claims

This ADR does not implement or approve any prerequisite slice, guarantee secure
deletion from SSD wear-leveling, add cloud backup/synchronization, preview or
execute attachments, claim lock protection against a compromised unlocked
process, change broker token ownership, add iOS/iPadOS, or pass distribution-
signing evidence. It does not revive the retired diagnostic blob format as
production proof or invent dependency versions.

## Consequences

The beta gains a single accountable encrypted attachment/cache path and a
storage budget that protects local intent before recoverable cache. App lock
becomes a lifecycle boundary with explicit residual limits, rather than a
cosmetic screen overlay.
