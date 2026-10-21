<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0027: Gmail modify, History, and mailbox commands

- Status: Accepted
- Date: 2026-08-29

## Context

[ADR 0023](adr-0023-step3-oauth-and-bounded-sync.md) intentionally delivered a
bounded, `gmail.readonly` snapshot path. It has no History cursor, mailbox
mutations, labels, drafts, or retry semantics. The public beta needs recent
state to converge across devices and needs Gmail's non-destructive mailbox
actions, but it must not convert the current local cache into a second source
of truth or allow a permanent-delete operation.

The existing Gmail adapter is GET-only and the broker is the sole refresh-token
authority. Those are current implementation facts, not obstacles to a reviewed
extension: the new write transport and the capability upgrade must remain
separate from token custody, local store ownership, and the narrow ABI.

## Prerequisite decision and policy slices

No modify, History, or mailbox-command implementation may start until an
independent `docs-only`/`policy-xtask` sequence does all of the following:

1. amend ADR 0023's read-only enforcement so it remains strict for
   `ReadOnly` accounts and becomes an explicit, subject-validated
   `Modify` capability gate for upgraded accounts;
2. add **P27-oauth capability policy**: replace
   `crates/application/src/oauth.rs::REQUESTED_SCOPE`,
   `prepare_authorization`, and `AuthorizationSession::finish` scope predicate
   with a capability-parameterized request/predicate pair. `ReadOnly` requests
   and requires `gmail.readonly`; `Modify` requests and requires `gmail.modify`.
   The same requested capability must parameterize the
   `adapters/gmail-rest-macos` token-response scope predicate. Positive and
   negative fixtures prove both cross-capability mismatches fail closed;
3. amend ADR 0016's GET-only `GmailMailbox` decision by retaining that read
   component and introducing a separately allowlisted modify component, rather
   than silently teaching the existing GET-only object to write;
4. amend ADR 0018's History/mutation/outbox non-claims and define the bounded
   snapshot interaction below; and
5. repoint the ABI, adapter, dependency, and tracked-source guards to those
   exact read/modify components, with negative fixtures proving that a
   `ReadOnly` account cannot reach a modify endpoint; and
6. add **P27-security documentation** before new provider write egress or
   History persistence: amend the security data flow and threat model for
   encryption, File Protection posture, backup, deletion, app lock, diagnostics,
   desired state, and ambiguous command recovery.

These amendments are prerequisites, not claims that the existing ADRs or
guards have already changed.

## Decision

### Capability upgrade and provider boundaries

`AccountCapability::Modify` requests only `openid` and
`https://www.googleapis.com/auth/gmail.modify`. The product does not request
`gmail.send`, `mail.google.com`, or permanent-delete scope. `gmail.modify` is
the sole beta provider capability for reads and the closed mailbox-command set
approved by this ADR: label, archive, trash, spam, and other non-permanent-delete
commands. Although the provider scope can authorize broader operations, this ADR
exposes no draft, compose, or send transport; those remain downstream to ADR
0028 and its own prerequisites.

An existing read-only grant remains installed and usable until a new modify
grant has passed broker validation for the same account subject. Only then may
the broker atomically replace its refresh token and the encrypted account
profile record change capability. Consent denial, scope omission, or a
different subject leaves the old read-only grant untouched. A first-connect or
upgrade response explicitly omitting `gmail.modify` follows ADR 0024's
stranded-under-scoped-grant residual: it is not persisted or revoked in-app
because it has no validated identity/revocation handle. The UI presents manual
Google Account revocation guidance, preserves any old read-only grant, and
exposes no mutation capability. The broker protocol reports capability as a
closed status/document field; it never reports scope strings, a refresh token,
or token response data to Swift.

The Gmail adapter gains two account-bound inward ports:

- `GmailHistoryFeed` obtains a bounded `HistoryPage` from an opaque
  `HistoryCursor` and captures the current baseline cursor for snapshot
  fallback; and
- `RemoteMailboxCommands` performs an approved `MailboxCommand` for one account.

The domain layer adds `HistoryCursor`, `MailboxCommandId`, `MailboxCommand`,
`DesiredMailboxState`, and `LabelDefinition` as bounded, redacted values. The
application layer adds `HistoryCursorStore`, `MailboxCommandStore`, and
`MailboxCommandCoordinator`. These ports are runtime-free and have closed,
provider-data-free failures. They extend rather than weaken `RemoteMailbox` and
`MailboxStore`.

### History synchronization and desired state

Every account store persists its last successful `HistoryCursor`. `HistorySync`
requests at most 500 history records per provider page, validates pagination and
event shapes, applies affected messages/labels, and commits the reconciled data
and the resulting cursor in the same SQLCipher transaction. It never advances a
cursor after a partial, invalid, cancelled, or failed application.

If Gmail reports a gone/expired cursor (`404`), the coordinator first obtains
and retains a current baseline cursor for that account, then runs the bounded
full snapshot. It commits snapshot data and that baseline cursor together only
after the snapshot succeeds. Changes occurring after the baseline remain for a
later History replay; the fallback never installs a cursor fetched after an
incomplete snapshot. A transport, rate-limit, malformed-page, or authentication
failure preserves the old cursor and has no destructive fallback. History is
foreground/manual and on-app-resume work only; it adds no push subscription,
relay, or execution when the app is not running.

Before an outbound mailbox mutation, `MailboxCommandCoordinator` atomically
persists an account-scoped desired state and `MailboxCommandId`. It then invokes
the remote command and reconciles through History before finalizing the local
operation. Replaying an already-applied desired state is a no-op. Ambiguous
transport outcomes remain pending and are reconciled before a retry; no command
is blindly repeated merely because the connection closed.

`batchModify` has no assumed all-or-nothing timeout behavior. On any timeout,
connection loss, or bodyless transport failure, the coordinator marks the batch
`Ambiguous` and reconciles every requested message independently through
History and, where History has insufficient evidence, a bounded minimal GET.
Only per-message reconciled evidence can settle a desired state. The aggregate
result is `Complete`, `Partial`, or `Ambiguous`, always bound to one `AccountId`
and carrying only bounded aggregate counts/statuses to the UI.

The approved command set is closed:

- mark read or unread; add or remove star; archive; trash or restore; mark or
  clear spam;
- create, rename, delete, apply, or remove user labels; and
- perform the preceding message-state operations in account-partitioned batches
  of at most 1,000 message IDs.

Permanent delete is absent. A label-create or rename with an ambiguous provider
result is resolved by a bounded label reconciliation before another create; a
remote provider label identifier is never guessed. Every message ID, label ID,
and history cursor is validated before constructing a URL or local query.

### Invariants and data flow

```text
Swift user intent
  -> versioned bridge command (AccountId + bounded command document)
  -> MailboxCommandCoordinator
  -> SQLCipher desired-state transaction
  -> account-bound Gmail modify request
  -> Gmail History reconciliation + cursor transaction
  -> closed operation status document
```

- All command and History work is partitioned by `AccountId`; a unified inbox
  batches only by issuing one account-scoped operation per partition.
- The store remains the sole writer and migration owner. The coordinator has no
  raw SQL, token, or key capability.
- Gmail's provider state is authoritative after reconciliation. Local desired
  state exists only to make requests idempotent and recoverable.
- `Partial` and `Ambiguous` are per-account operation states, never a claim that
  a cross-account batch is atomic or a license to infer success for an omitted
  message.
- The main process continues to own Gmail mailbox access and SQLCipher. The
  broker retains OAuth exchange, refresh, rotation, revoke, and token deletion.
- Any new C ABI symbol is versioned, bounded, data-only, and accompanied by the
  exact export allowlist, count, canonical header, Swift declaration, reviewed
  Swift-call table, policy, and positive/negative fixture update required by
  ADR 0021.

### Implementation decomposition by change class

| Change class | Bounded implementation responsibility |
| --- | --- |
| `docs-only` | Amend ADRs 0016, 0018, and 0023 plus P27-security documentation before implementation. |
| `policy-xtask` | Parameterize scope/endpoint/ABI/dependency guards and add cross-capability fixtures only. |
| `domain` | Add cursor, command, desired-state, label, and per-account result values. |
| `application` | Add History/command ports and runtime-neutral coordinator state machines. |
| `adapter-rust — tersa-gmail-rest-macos` | Add the separately allowlisted History and modify transport components. |
| `adapter-rust — tersa-store-sqlcipher-macos` | Add cursor, desired-state, label, and atomic reconciliation transactions. |
| `token-broker` | Add the same-subject `ReadOnly` to `Modify` capability upgrade through XPC. |
| `bridge-ffi` | Add one reviewed command/history status surface after the contract slices. |
| `swift-ui` | Add capability-upgrade, pending, partial, ambiguous, and recovery states. |

## Failure handling

Under-scoped or denied consent keeps the previous capability. An explicitly
under-scoped modify grant remains the ADR-0024 stranded-grant residual: no
in-app persistence or revoke is attempted, manual Google revocation is shown,
and an older read-only grant remains usable without mutation. `invalid_grant`
continues to surface reconnect without wiping cached data. A command never
crosses into a different account after token refresh, cursor recovery, or UI
selection change. Missing/corrupt desired state and cursor data fail closed and
show a recoverable sync state; they do not infer success from local rows.

On a cursor `404`, a failed baseline capture or full snapshot leaves the old
cursor and all pending commands intact. On quota or storage failure, no cursor
or desired-state transition commits. A cancellation may leave a dispatched
provider request ambiguous, in which case the operation moves to reconciliation
rather than retrying. Provider `404` for an already-absent message is reconciled
as its desired final state only when per-message History/minimal-GET evidence
supports it.

## Test and evidence gates

- OAuth/token fixtures cover capability-parameterized request and finish
  predicates, both ReadOnly/Modify success cases, and both cross-capability
  mismatch cases; they also prove an under-scoped modify response neither
  persists nor invokes in-app revoke.
- Contract/fake tests cover pagination bounds, repeated cursors, malformed
  History, baseline-before-snapshot cursor capture, cursor-and-data atomicity,
  `404` fallback/replay, and no cursor advance on every other failure class.
- Command tests cover every desired-state transition, account-partitioned
  1,000-ID batches, every `Partial`/`Ambiguous` path, timeout reconciliation of
  each batch item, label ambiguity, no permanent-delete/mute route, and
  idempotent replay after restart.
- Adapter tests use bounded provider fixtures for every approved endpoint and
  reject a wrong account, ID, scope, URL, or response shape before mutation.
- A signed Apple Development run must demonstrate same-account capability
  upgrade, a command, History convergence, and both Keychain wrong-group
  denials before real modify use is treated as operational evidence. A Developer
  ID/notarized candidate remains required for release acceptance.

## Non-claims

This ADR does not implement the ports, approve the prerequisite amendments,
grant Google verification, prove a live modify exchange, add a relay/push
service, execute background jobs, support permanent delete or mute/unmute,
create a mutable CLI/MCP surface, or pass signed-distribution evidence. It does
not allow `gmail.send` or `mail.google.com`, and it does not promise lossless
full-mailbox synchronization beyond the bounded recovery protocol or claim
in-app cleanup of an ADR-0024 stranded under-scoped grant.

## Consequences

Mailbox state becomes an account-scoped, Gmail-authoritative desired-state
system rather than ad-hoc UI writes. The explicit capability upgrade makes the
scope expansion recoverable, while the transactional History cursor provides a
defined response to device changes and expired provider retention.
