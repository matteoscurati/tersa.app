# ADR 0015: mailbox contract seam

- Status: Accepted
- Date: 2026-07-16

## Context

The macOS-first product needs portable mailbox contracts before a Gmail
transport or SQLCipher-backed store exists. The contracts must avoid selecting
an async runtime or exposing user-controlled data in diagnostics.

## Decision

`tersa-domain` defines bounded, provider-neutral mailbox values. Opaque decoded
message content has a defensive maximum of 64 MiB. Header text, content, and
page tokens use manual redacted `Debug` output; user content is never displayed.

`tersa-application` defines two separate inward ports: `RemoteMailbox` for
provider retrieval and `MailboxStore` for local persistence. Both are object
safe and return standard-library boxed futures, so this seam adds no Tokio,
`async-trait`, futures crate, or runtime dependency. Dropping a returned future
cancels its pending operation; implementations must be drop-safe.

No revision, history, or checkpoint API is introduced. Any later revision
acquisition must be atomic with listing, never a separate post-list getter,
and belongs to a reviewed sync protocol.

## Consequences

Future macOS adapters implement these ports inward. This change makes no
iPhone or iPad implementation claim and adds no Gmail DTOs, OAuth exchange,
sync, mutations, labels, attachments, MIME structure, search, cache policy,
storage implementation, UI or Apple types. It makes no gate status changes.
