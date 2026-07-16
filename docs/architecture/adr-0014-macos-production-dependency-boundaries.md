# ADR 0014: macOS production dependency boundaries

- Status: Accepted
- Date: 2026-07-16

## Context

The existing workspace contains diagnostics for UI, SQLCipher, MIME, search,
and crash-safe AEAD blobs. Those diagnostics are not production adapters. The
macOS-first implementation needs a fail-closed boundary before any Gmail REST
or production store crate is introduced, without treating planned crate names
as present or authorized.

## Decision

`xtask` has a separate `RESERVED_FUTURE_POLICY` table for
`tersa-gmail-rest-macos` and `tersa-store-sqlcipher-macos`. These names are not
active dependency-policy entries. Workspace membership using either reserved
name fails architecture validation until a later, reviewed crate-introducing
pull request explicitly moves it from reserved to active policy.

The future adapters may have inward workspace edges only to
`tersa-application` and `tersa-domain`. Mailbox and storage ports will be
defined in a later pull request in `tersa-application`; adapters will
implement those inward-defined ports.
`tersa-application` and `tersa-domain` never depend on adapters.

The future macOS store adapter may own both SQLCipher and blob AEAD because
they share one commit and crash-safety protocol. Its declarations of
`rusqlite`, `libsqlite3-sys`, `chacha20poly1305`, and `hmac` must use the exact
target cfg `cfg(target_os = "macos")`. Untargeted, iOS-only, or iOS-inclusive
forms fail the policy check.

The present SQLCipher and AEAD diagnostic owner sets, plus Slint and Dioxus
isolation, remain unchanged. Gmail and network dependency exclusivity is not
yet enforceable because exact Gmail crates have not been selected and pinned.
This ADR deliberately adds no generic dependency-name pattern for network
dependencies.

## Consequences

No manifest, dependency, lockfile, shared/application source, mailbox
contract, Gmail transport, storage implementation, sync, CLI, UI, mobile code,
Apple target, CI, or gate changes are introduced. The reservation is policy
documentation and a tripwire only; it is not permission to add either adapter.

A later Gmail adapter pull request must select and pin exact dependencies before
its exclusivity can be checked. A later store adapter pull request must move its
name into active policy and retain the exact macOS target declarations.
