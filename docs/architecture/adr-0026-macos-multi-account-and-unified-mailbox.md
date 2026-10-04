<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0026: macOS multi-account and unified mailbox

- Status: Accepted
- Date: 2026-08-29

## Context

The delivered macOS product has one fixed `default` account profile, one
read-only Gmail grant, and one SQLCipher mailbox. That is sufficient for the
bounded-reader slice in [ADR 0023](adr-0023-step3-oauth-and-bounded-sync.md),
but it cannot safely add a second Google account or present a unified inbox.
In particular, an email address cannot be the local routing key, a global
plaintext index would defeat account isolation, and the current schema must not
be silently migrated while this pre-release product has no compatibility
promise.

The existing platform guarantees remain binding: the token-broker XPC service
is the refresh-token authority ([ADR 0024](adr-0024-macos-token-process-isolation.md));
the application owns profile and migration decisions through the private
Keychain/store composition ([ADR 0019](adr-0019-macos-key-provisioning-and-readonly-cli.md));
and each database is an encrypted account boundary. This ADR replaces only the
single-profile premise for the beta scope. It does not relax those boundaries.
The current shipped bridge also has two standalone subject-byte exports,
`tersa_mailbox_macos_broker_subject_store` and
`tersa_mailbox_macos_broker_subject_get`; neither is a safe multi-account
registry-deduplication mechanism.

## Decision

### Account identity, registry, and storage

Each added account receives a locally generated, opaque `AccountId`: 128 bits
from the platform CSPRNG, encoded as `acct_` followed by 32 lowercase hexadecimal
characters. It is not derived from, and never displays, an email address or
Google identifier. A collision is retried before any provider or store write.
The beta registry admits at most five accounts and rejects a sixth before OAuth
or any local write.

The domain layer adds these redacted, validated values:

- `AccountCapability`, initially `ReadOnly` or `Modify`;
- `AccountProfile`, containing the Gmail profile fields required by the UI; and
- `RegistryDedupTag`, which is never constructed from a caller-supplied key; and
- `UnifiedMailboxRow` / `UnifiedMailboxDocument`, whose every row carries its
  originating `AccountId`.

`AccountProfile` and the validated broker subject are persisted only in the
corresponding account's SQLCipher database. `IdentityHash` remains
account-bound and is not reused for cross-account duplicate detection.

The private Keychain composition instead derives one account-independent HMAC
key under `AccountKeyPurpose::RegistrySubjectDedupV1` and computes a redacted
`RegistryDedupTag` from a broker-validated subject. It also derives the distinct
`AccountKeyPurpose::RegistrySqlCipherV1` registry SQLCipher key. ADR 0019's
HKDF-info framing must be amended for these registry purposes: it uses a new
literal registry domain prefix plus length-framed ASCII purpose bytes, omits the
account-ID length and bytes entirely, and remains disjoint from every
account-bound framing. The keys and raw subject stay inside trusted composition;
no callback or raw key material is public.

The new `tersa-account-registry-sqlcipher-macos` adapter is constructed
privately by that Keychain composition with the registry SQLCipher key. Its
encrypted registry contains only `(AccountId, RegistryDedupTag)` for duplicate
rejection. It has no messages, profiles, raw subjects, tokens, labels, queries,
or blob data; it uses SQLCipher rather than a new AEAD metadata format. Sandbox
preferences store only account-ID ordering and selected account. They never
store a tag, email, subject, token, profile, message, label, query, or cache
data.

The encrypted tag is deliberately a same-install equality oracle: code that can
decrypt the registry metadata can learn that two attempted subjects are equal,
and the record reveals that a deduplicated account is resident on this install.
It is not portable across installations, is never exposed to UI/CLI/ABI/logs,
and does not reveal the subject without an infeasible HMAC preimage attack. This
limited residency/equality leakage is an accepted residual requiring independent
security review; it is not a claim that the registry is identity-free.

The canonical beta layout is:

```text
<App Group>/profiles/v2/
  registry.sqlite3  (SQLCipher AccountId + RegistryDedupTag only)
  accounts/<sha256(AccountId)>/
    mail.sqlite3
    blobs/
```

The existing `<App Group>/profiles/default/` layout is legacy-only. This ADR
proposes amending ADR 0019's fixed `default` profile rule for the beta layout:
the product application remains the sole descriptor-relative, no-follow
directory owner; the CLI receives no new profile, key, or mutation authority.
Every v2 account has a separately derived SQLCipher key under the existing
private derivation boundary and a separate blob namespace. No account database
stores another account's messages, profile, subject, search index, drafts,
pending actions, or blobs.

### Prerequisite decision and policy slices

No multi-account, reset, registry, or v2-profile implementation may begin until
all of these independently reviewed slices are accepted:

1. **P26-policy:** amend ADR 0019's `AccountKeyPurpose` and HKDF-info framing
   for the two registry purposes above; amend its absent-root/profile-tree
   enumeration to recognize fixed `profiles/v2/registry.sqlite3` and account
   entries without authorizing unsafe bootstrap; amend ADR 0006 A5 to state a
   10 GiB budget per account and a 50 GiB installation aggregate; and amend
   dependency/owner policy for `tersa-account-registry-sqlcipher-macos`, its
   private composition edge, and any direct `rusqlite` ownership. It confirms
   `tersa-keychain-macos` as an existing direct Rustix 1.1.4 owner with
   `fs`/`process`/`std`; the P26 delta authorizes use of
   `renameat_with(..., RenameFlags::NOREPLACE)` for quarantine only and adds
   exact `xtask` usage/mutation fixtures. No new AEAD is permitted for registry
   metadata.
2. **P26-signed prerequisite:** complete ADR 0019 PR33b and close issue #51
   with independently reviewed signed CLI and process-isolation evidence.
3. **P26-bridge/CLI:** after P26-policy and P26-signed prerequisite, add a v2
   read-only account-selector route to the CLI in one dedicated `bridge-ffi`
   slice and one dedicated `adapter-rust — tersa-cli-macos` slice. It must atomically
   update the C ABI expected-export allowlist, count, canonical header, Swift
   declarations, and positive/negative fixtures.
4. **P26-subject replacement:** replace the two existing standalone subject
   exports named above and subsume per-account broker subject store/load inside
   trusted Rust composition. In one atomic slice, retire Swift-visible subject
   reads from `MailboxSyncWorker` and `AccountConnectionViewModel`; update
   `apple/macos/TersaRustBridge.h`, the reviewed Swift-call table, exact ABI
   allowlist/count, Swift declarations, and positive/negative fixtures. The
   broker's stored-credential rung remains broker-owned and capability-gated;
   it must not fall back to a Swift-visible subject read. The new ABI invariant
   does not apply before this replacement is complete.
5. **P26-security documentation:** before the registry creates persistence,
   amend the security data flow and threat model for registry encryption, File
   Protection posture, backup, deletion/quarantine, app lock, diagnostics, and
   the same-install equality/residency residual.
6. **P26-FTS policy:** explicitly amend ADR 0021's `Decision` “Scope and the
   Step 2 / Step 3 boundary” paragraph that defers any production search engine
   indefinitely; its `Decision` “Decomposition into bounded, independently
   reviewed PRs” PR 2e row (`no FTS5, no Tantivy`); and the following Phase-1
   bounded-metadata-filter paragraph (`no production FTS5 or Tantivy`). If its
   `Non-claims` is also amended, the target is its sentence ending “or
   search-engine claim,” not a nonexistent FTS5 clause. It also amends ADR
   0017's `Decision`
   paragraph beginning “Deterministic adapter tests cover,” which contains
   foreign/future/noncanonical schema rejection, for schema-v2 ownership/reset.
   The slice requires target-specific FTS5 compile-option evidence before any
   store implementation.

The only readable legacy profile must not be removed, reset, or quarantined
before P26-signed prerequisite and the v2 CLI selector have passed their
respective evidence gates.

### Add, remove, reset, and unified reading

Adding an account begins OAuth through the broker. Only after the broker has a
valid grant and subject does private composition derive a `RegistryDedupTag` and
reject an existing tag. It then creates the account registry entry, profile
directory, and encrypted store, and obtains the Gmail profile for that account.
It rolls back only objects proven created by that attempt on failure before
registry commit. An existing account can remain readable while a different
account is added.

Removing an account uses the existing broker revoke/delete then local-purge
ordering for that `AccountId`; only a completed local purge removes the opaque
registry entry. An unconfirmed revoke or incomplete token deletion remains a
content-free recovery entry and is not shown as a clean removal. If the removed
account was selected, the registry selects its next ordered account or no
account when none remain.

Schema v2 is a deliberate pre-release reset, not a migration. On discovery of
any legacy `profiles/default` state, the app presents a mandatory reset before
opening a v2 mailbox for normal use. Under the owning application lock, reset
first renames the fixed legacy directory to the fixed-name
`profiles/legacy-reset-quarantine-v1` with
`rustix::fs::renameat_with(..., RenameFlags::NOREPLACE)`, descriptor-relative
no-follow identity checks before and after rename. In Rustix 1.1.4 this maps on
macOS to `renameatx_np` with `RENAME_EXCL`. P26-policy authorizes this use by
the existing Keychain Rustix owner and adds exact `xtask` usage/mutation
fixtures; no libc or unsafe amendment is needed. An occupied quarantine
destination, identity drift, or any rename failure preserves all state and fails
closed. The reset path must:

1. inspect legacy state without a write-open or schema migration;
2. attempt broker revoke and token deletion for the legacy grant;
3. visibly retain an unconfirmed-revoke recovery state if either remote or
   local credential removal is not confirmed;
4. retain the quarantine after user confirmation; and
5. require a new consent flow and a new opaque account ID.

It never copies a legacy database, silently reuses its identity, or treats a
failed revoke as a clean disconnect. It never recursively deletes the legacy
tree. A later P26-purge slice must define a bounded descriptor-relative,
identity-checked quarantine purge with an explicit fixed traversal budget;
until that slice passes review, the quarantine is preserved.

`UnifiedMailboxQuery` is an application use case, not a global store. It adds
a bounded `UnifiedMailboxContinuation` and a global page cap of 200 rows. For
an All Accounts inbox or search it requests only enough account-local rows to
fill that global cap, merges by `received_at DESC, account_id ASC, message_id
ASC`, and returns bounded per-account continuations for the next page. It never
issues an `N * 10,000` fan-out payload. Threads, drafts, actions, and settings
remain account-scoped even when the inbox is unified.

When unlocked, an account-local failure produces
`UnavailableAccount { account_id, state }`, where `state` is only
`AuthorizationRequired` or `StoreUnavailable`; it contributes no rows. The
document may show available-account rows plus these opaque availability states.
When app lock is active, all stores are closed and `UnifiedMailboxQuery` returns
only the top-level `Locked` state without account identity: it performs no
fan-out and displays no partial rows. After unlock, it restarts the query from
its supplied continuation rather than reusing a locked in-memory result.

Each SQLCipher v2 store owns an encrypted FTS5 index only after P26-FTS policy
has recorded target-specific FTS5 compile-option evidence. The future
`LocalMailboxSearch` port indexes subject, sender, recipient, plain body,
sanitized-render text, and attachment filenames only in that account's store.
It does not extract document text in this beta and does not create an index
outside SQLCipher. P26-FTS policy supersedes ADR 0021's indefinite Phase-1/MVP
FTS5 exclusion, not merely its Step-2 scope; it does not introduce Tantivy or a
global search database.

### Invariants and data flow

```text
Swift account intent
  -> narrow versioned bridge route (opaque AccountId)
  -> application AccountRegistry / UnifiedMailboxQuery
  -> one account-scoped SQLCipher store and one account-scoped adapter session
  -> versioned document with AccountId on every returned row
```

- Every mutating or reading route validates `AccountId` before selecting a
  store, key derivation, token-broker session, Gmail client, blob namespace, or
  bridge document.
- A broker subject is a private binding input. The account-independent registry
  HMAC creates the only cross-account equality tag; it is never displayed,
  placed in preferences, logged, or exposed in a new ABI payload.
- The broker returns only an access token and validated subject for the selected
  account. Refresh-token persistence remains broker-only.
- A unified view is a capped, paginated merge of isolated account results. It
  has no cross-account mailbox transaction, cache, FTS table, or worker.
- The exported C ABI remains closed and data-only. Any multi-account operation
  carries an opaque account route, bounded payload, and versioned document; no
  key, store object, token, callback, or provider identifier crosses it.

### Implementation decomposition by change class

| Change class | Bounded implementation responsibility |
| --- | --- |
| `docs-only` | P26-policy, P26-security documentation, and P26-FTS amendments before code is eligible. |
| `policy-xtask` | Prepare exact ABI/source-policy inventories and fixtures only; no product feature in this slice. |
| `domain` | Add account capability, profile, dedup-tag, page-continuation, availability, and unified-row values. |
| `application` | Add `AccountRegistry`, `AccountProfileStore`, `LocalMailboxSearch`, and capped `UnifiedMailboxQuery`. |
| `adapter-rust — tersa-account-registry-sqlcipher-macos` | Add encrypted tag-only registry persistence only. |
| `adapter-rust — tersa-store-sqlcipher-macos` | Add schema v2, compile-proven account-local FTS5, profile/binding persistence, and v2 store access. |
| `adapter-rust — tersa-keychain-macos` | Add private registry-purpose derivation and v2 descriptor-relative quarantine operations. |
| `adapter-rust — tersa-cli-macos` | Add only the v2 opaque account-selector route after P26-signed prerequisite. |
| `token-broker` | Extend capability information through the closed XPC protocol only. |
| `bridge-ffi` | Atomically replace standalone subject exports and add one versioned account route/document surface. |
| `swift-ui` | Build account switcher, add-account, reset-quarantine, locked, and partial-unavailable states. |

No implementation pull request mixes these change classes; cross-class slices
are sequenced through independently reviewed interfaces in the
[agent playbook](../development/agent-playbook.md).

## Failure handling

An account-add failure before registry commit leaves no usable registered
account. A duplicate dedup tag, corrupt registry metadata, missing account key, or
ambiguous profile identity fails closed for that account and never falls back to
another account. A selected-account preference that names no registered account
is cleared to an empty selection, not treated as an authorization request.

After a broker grant but before registry commit, setup failure invokes broker
revoke/delete. If confirmation fails, `AccountRegistry` retains only an opaque
setup-recovery route until the user resolves it; it never treats the grant as a
normal account or persists its subject/profile in preferences.

Legacy reset errors preserve the original or quarantined identity without a
recursive delete and do not retry provider revoke automatically. Store corruption
or quota failure in one account yields its closed unavailable state; it cannot
cross-populate the unified view. A locked app returns top-level `Locked`, never
rows from another account. Search and inbox cancellation drops unfinished
fan-out work and returns no partial durable mutation.

## Test and evidence gates

- Domain and application tests cover ID generation/validation, five-account cap,
  private dedup-tag equality, paginated 200-row merge, continuation bounds,
  unavailable/locked semantics, and no raw subject in preferences/documents.
- Registry/store/Keychain tests cover registry SQLCipher tag residency,
  registry-purpose framing, v2 schema and compile-proven FTS isolation,
  absent-root enumeration, no-write legacy detection, quarantine identity drift
  preservation, and the later bounded purge contract.
- Bridge/CLI tests cover atomic retirement of the two subject exports and
  Swift-visible reads, the stored-credential rung, the v2 selector route,
  opaque routing, and exact Swift-call-table/allowlist/header/count/fixture parity.
- A release candidate must exercise add, switch, remove, offline reopen, locked
  unified inbox, and a 200-row continuation with independent accessibility
  checks. It cannot proceed before PR33b and issue #51 evidence are closed.

## Non-claims

This ADR does not implement multi-account code, approve any prerequisite slice,
prove Google consent, distribution signing, notarization, FTS performance, or a
signed runtime. It does not add iOS/iPadOS, an account-sharing backend,
cross-account labels or threads, a mutating CLI/MCP interface, automatic legacy
migration, or recursive legacy deletion. It does not hide the registry's
same-install equality/residency oracle or claim raw-subject ABI removal before
the atomic replacement slice lands.

## Consequences

If the prerequisites are independently accepted and implemented, the beta gains
a capped, page-bounded account boundary before mailbox mutation, draft, outbox,
blob, or rich-content work. It preserves legacy data in a verified quarantine
rather than claiming deletion safety, and it makes the registry's narrow
cross-account equality linkage explicit.
