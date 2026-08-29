<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0028: drafts, outbox, and idempotent send

- Status: Proposed
- Date: 2026-08-29
- Owner intent: Approved; implementation is blocked pending independent
  architecture/security review and the prerequisite slices below.

## Context

The current macOS composer is intentionally in-memory only. A usable beta
needs local drafts, Gmail draft synchronization, attachments, and sending, but
a provider timeout after accepting a message makes a simple retry capable of
mailing a duplicate. The outbox must therefore be a durable Rust-owned state
machine, not a Swift queue or a best-effort network callback.

This ADR depends on the account/capability boundary in
[ADR 0026](adr-0026-macos-multi-account-and-unified-mailbox.md), the
`gmail.modify` command capability in
[ADR 0027](adr-0027-gmail-modify-history-and-mailbox-commands.md), the native
rich-composition model in
[ADR 0029](adr-0029-safe-html-native-rendering-and-rich-composition.md), and
encrypted blobs in
[ADR 0030](adr-0030-encrypted-blobs-storage-budget-and-app-lock.md).

## Prerequisite decision and policy slices

No draft, send, attachment, or export implementation may start until the
proposed ADRs 0026–0030 and their prerequisite policies are independently
accepted. A dedicated `docs-only` security ADR must additionally define an
importable encrypted draft-bundle format, explicit passphrase UI, versioning,
verification, import conflict behavior, and recovery. A separate `policy-xtask`
slice, coordinated with ADR 0030 P30-dependency policy, must select/pin the
Argon2id/XChaCha20-Poly1305 dependency path and add the required redaction/ABI
fixtures before bundle code is eligible.

Before draft/outbox persistence or Gmail send egress, **P28-security
documentation** must amend the security data flow and threat model for encrypted
drafts/outbox, File Protection posture, backup/export/import, deletion,
app-lock behavior, diagnostics, stable identifiers, and ambiguous-send recovery.

## Decision

### Local-first drafts

The domain layer adds `DraftId`, `OutboxItemId`, `GmailDraftId`,
`RfcMessageId`, `DraftSyncState`, `ConflictCopy`, `PossibleDuplicateTombstone`,
and the closed `OutboxState` set:
`Queued`, `Preparing`, `Uploading`, `AwaitingReconciliation`, `Sent`,
`RetryableFailure`, `PermanentFailure`, `Cancelled`, and
`AbandonedAmbiguous`. `DraftId` and `OutboxItemId` are opaque local CSPRNG
identifiers. `RfcMessageId` is generated exactly once when an item enters the
outbox and is formatted as
`<outbox-<OutboxItemId>@tersa.app>`; it is never regenerated during retry,
restart, or reconciliation.

`DraftStore` persists each account-scoped edit transactionally before the UI
reports it saved. It stores the structured `RichComposeDocument`, recipients,
references, attachment `BlobRef`s, local draft ID, optional replaceable Gmail
draft ID, and the last observed remote draft revision. There is no in-memory
only draft path after this ADR lands.

`GmailDraftTransport` synchronizes a local saved draft only when the account is
online and has `Modify` capability. A local dirty draft always wins over an
unseen remote update: when its recorded remote revision differs from the
current Gmail draft, the transport retains the local draft and creates a second
local `ConflictCopy` from the remote content. It does not overwrite either
version or silently upload a winner. `GmailDraftId` is replaceable but is the
primary remote send/reconciliation handle; stable `DraftId` remains the local
user route.

### Rust-owned outbox and send transport

The application layer adds `DraftStore`, `OutboxStore`, `GmailDraftTransport`,
`GmailSendTransport`, and `OutboxCoordinator` as runtime-neutral ports/use
cases. The coordinator is the sole production owner of state transitions and
is invoked on a bounded Rust worker; Swift observes versioned state documents
and submits intents only.

Sending transitions are exact:

1. `Queued` records the immutable `RfcMessageId` and selected draft revision.
2. `Preparing` first creates or updates the Gmail draft and persists its
   `GmailDraftId`, then reads encrypted draft/blob data, compiles the structured
   document into plain text plus allowed HTML, and builds the complete MIME
   source. A local-only queued draft never reaches `Uploading` without that
   persisted primary handle.
3. `Uploading` dispatches the Gmail request. Encoded MIME over 5 MiB uses
   resumable upload; smaller messages may use simple upload. Every encoded MIME
   source is capped at 20 MiB before dispatch.
4. A confirmed provider result becomes `Sent` only after the resulting message
   identity is persisted and History reconciliation observes it.
5. A timeout, connection loss, crash after dispatch, or incomplete provider
   response becomes `AwaitingReconciliation`, never an immediate retry.
6. Reconciliation first resolves the persisted `GmailDraftId`, then uses the
   stable RFC `Message-ID` only as a secondary correlation check in bounded
   Gmail search/History. It marks `Sent` when one matching accepted message is
   found; only a bounded, negative reconciliation moves the item to
   `RetryableFailure`.
7. User cancellation is allowed only before dispatch. Once a request may have
   reached Gmail, cancellation waits for reconciliation. A permanently rejected
   message becomes `PermanentFailure` with a redacted, closed reason.
8. After an offline or provider-unavailable ambiguous outcome, the user may
   explicitly acknowledge possible duplication. The coordinator then writes an
   encrypted `PossibleDuplicateTombstone` and moves the item to terminal
   `AbandonedAmbiguous`; it is never retried automatically or manually as the
   same send.

The MIME compiler creates `multipart/alternative` for plain text plus HTML,
`multipart/related` when inline CID resources exist, and `multipart/mixed` when
attachments exist. It accepts only the AST from ADR 0029, never raw editor HTML.
There is no blind second send, no mutable message-ID, and no provider retry
outside this state machine. The app resumes a durable outbox only while it is
running and has connectivity; it makes no scheduling or delivery guarantee
while the Mac is asleep, off, or the app is not running.

Disconnect is blocked when an account has a nonterminal draft/outbox obligation.
The user must explicitly send it, delete it, complete a verified encrypted
draft-bundle export, or acknowledge `AbandonedAmbiguous`. The future bundle is
importable through the separately approved versioned format and explicit
passphrase UI; verified export checks its manifest/authentication before
disconnect can proceed. Only after one of those resolutions can broker
revoke/delete and local account purge proceed.

### Invariants and data flow

```text
Native TextKit editor
  -> versioned compose document over the bridge
  -> DraftStore transaction in the account SQLCipher store
  -> OutboxCoordinator + encrypted BlobRef reads
  -> Gmail draft/send transport
  -> History/message-ID reconciliation
  -> closed state document back to Swift
```

- Drafts, outbox entries, attachments, remote draft IDs, and message-ID
  reconciliation are bound to one `AccountId`; a unified inbox never merges
  them.
- `OutboxStore` commits every transition atomically. A dropped future may leave
  an external outcome unknown but may not leave a partial local transition.
- The persisted Gmail draft ID is the primary remote send handle. RFC
  `Message-ID` is secondary correlation evidence and is never assumed to be a
  provider idempotency key.
- The broker continues to provide only transient access tokens. Tokens, keys,
  raw MIME, recipients, subject, and message IDs never appear in diagnostics or
  bridge error text.
- The 20 MiB limit measures the complete transfer-encoded MIME source, not
  only attachment files. Over-limit items remain editable local drafts and are
  never uploaded partially.
- Every draft/outbox C ABI addition must atomically update the exact expected
  export allowlist, export count, canonical header, Swift declarations, and
  positive/negative fixtures; no name-only allowance is valid.

### Implementation decomposition by change class

| Change class | Bounded implementation responsibility |
| --- | --- |
| `docs-only` | Define the importable bundle ADR and P28-security documentation before persistence/egress code. |
| `policy-xtask` | Select bundle dependencies and add outbound, ABI, redaction, and no-direct-Swift-send guards only. |
| `domain` | Add draft/outbox IDs, conflict/tombstone values, state machine, and redacted result types. |
| `application` | Add draft/outbox ports and the sole transition/reconciliation coordinator. |
| `adapter-rust — tersa-store-sqlcipher-macos` | Add account-scoped draft, outbox, tombstone, and atomic transition storage. |
| `adapter-rust — tersa-gmail-rest-macos` | Add Gmail draft, send, search, and upload transport under `gmail.modify`. |
| `bridge-ffi` | Expose one bounded draft/outbox document and intent surface with atomic ABI fixtures. |
| `swift-ui` | Replace the ephemeral composer with autosave, conflict, abandon, verified-export, and recovery UI. |
| `token-broker` | Consume ADR 0027 capability/status only; add no credential operation. |

## Failure handling

Blob/key/store failures leave the draft and outbox state durable and redacted;
they never substitute an attachment with plaintext or silently drop it. A
provider rejection classified as permanent does not destroy the draft. Ambiguous
send results consume no automatic retry budget until reconciliation completes.
If Gmail cannot be queried for reconciliation, the item remains
`AwaitingReconciliation`; the user may not force a duplicate send from that
state. They may only acknowledge `AbandonedAmbiguous`, which creates the
possible-duplicate tombstone and permits account disconnect without a retry.

Draft synchronization failures retain the local draft. A remote conflict makes
two recoverable local copies, not an overwrite. An upload that exceeds the
limit, loses permission, or loses its account route returns a closed failure
and cannot cross to another account. Disconnect recovery persists until all
obligations are explicitly resolved.

## Test and evidence gates

- Domain/application tests cover every legal and illegal state transition,
  `ConflictCopy`, primary draft-ID persistence, stable Message-ID generation,
  tombstone creation, cancellation at every boundary, and no retry before
  negative reconciliation.
- Store crash-injection tests stop before/during/after each transition and
  verify either the old or the complete new transaction state, never a partial
  one.
- Adapter fakes cover Gmail draft replacement, conflict copy, simple/resumable
  upload selection, encoded-size rejection, success with lost response, and
  draft-ID-first/Message-ID-secondary reconciliation.
- Swift tests cover autosave, accessible conflict/send recovery, blocked
  disconnect, and no direct network send path.
- A live Gmail send merge gate requires a separate owner authorization for one
  exact attempt that proves persisted-draft send, Message-ID round trip, and
  Gmail searchability/retrieval. If that evidence is absent or negative, an
  ambiguous send never receives a blind retry; it remains reconciling or may be
  abandoned with its possible-duplicate tombstone.

## Non-claims

This ADR does not implement sending, approve the bundle/security prerequisite,
grant `gmail.send`, guarantee delivery when the app is absent, support scheduled
send, aliases, permanent delete, unbounded attachments, plaintext export,
iOS/iPadOS, a mutating CLI/MCP path, or release evidence. It does not claim that
Gmail offers an idempotency key; duplicate prevention is the application's
reconciliation protocol and retains documented ambiguity until resolved or
explicitly abandoned.

## Consequences

Sending becomes recoverable local intent with a strict durability and
reconciliation cost, rather than a fast but duplicate-prone UI action. The
product gains conflict-visible Gmail-synced drafts and an honest limitation:
offline delivery resumes only while the app can run.
