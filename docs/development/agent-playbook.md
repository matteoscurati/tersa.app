# Agent playbook

Operating map for coding agents. Classify the change, touch only the owned
surface, run the class's minimum loop, and run full `cargo xtask verify`
before review.

Product constraints that never relax: no project-operated backend, encrypted
local persistence, official Gmail API, sanitized terminal output, and no
production demo-data or fixture injection
([ADR 0031](../architecture/adr-0031-tui-only-pivot.md)).

## Change classes

One task maps to **one** class unless the lead explicitly splits work.
Unknown crates or paths: ask the lead.

| Class | Allowed paths | Min loop | Escalate when |
|-------|---------------|----------|---------------|
| `domain` | `crates/domain/**` | `cargo xtask preflight domain` | a port or store contract changes |
| `application` | `crates/application/**` (`domain` only if required) | `cargo xtask preflight application` | a port shape changes |
| `presentation` | `crates/presentation/**` | `cargo xtask preflight presentation` | the sanitized-text contract changes |
| `adapter-rust` | exactly one `adapters/<name>/**` | `cargo xtask preflight adapter --package <crate>` | `Cargo.toml` or `deny.toml` changes |
| `tui` | `apps/**` | `cargo xtask preflight tui` | a core or adapter API is needed |
| `policy-xtask` | `xtask/**`, `.github/**`, `deny.toml`, `_typos.toml` | `cargo xtask preflight policy`, then `verify` | always high scrutiny |
| `docs-only` | `docs/**`, root `*.md` | none | n/a |

## Workspace packages

| Path | Package | Layer |
|------|---------|-------|
| `crates/domain` | `tersa-domain` | core |
| `crates/platform` | `tersa-platform` | core |
| `crates/application` | `tersa-application` | core |
| `crates/presentation` | `tersa-presentation` | core |
| `crates/keys` | `tersa-keys` | core |
| `adapters/gmail-rest` | `tersa-gmail-rest` | adapter |
| `adapters/keychain-macos` | `tersa-keychain-macos` | adapter (replaced in T1) |
| `adapters/vault` | `tersa-vault` | adapter |
| `adapters/oauth-sync-macos` | `tersa-oauth-sync-macos` | adapter (becomes `sync-runtime` in T1) |
| `adapters/store-sqlcipher` | `tersa-store-sqlcipher` | adapter |
| `adapters/token-broker-core` | `tersa-token-broker-core` | adapter (in-process token service in T1) |
| `apps/cli-macos` | `tersa-cli-macos` | app (absorbed into `apps/tersa` in T1) |
| `xtask` | `xtask` | tool |

## Layering rules (`cargo xtask architecture`)

- Core crates depend only on the core crates allowed by `CORE_POLICY` in
  `xtask/src/main.rs`, declare `#![forbid(unsafe_code)]`, and never depend on
  I/O or OS crates (`tokio`, `reqwest`, `rusqlite`, `keyring`, `ratatui`, ...).
- Adapters may depend on core crates and other adapters, never on apps.
- Nothing depends on `apps/` or `xtask`.

## Anti-patterns

- Rendering a provider string in the TUI without the sanitized type.
- Fetching any remote resource referenced by message content.
- Storing secrets outside the keyring item or the encrypted databases.
- Writing tokens, addresses, queries, or message content to logs.
- Widening a PR beyond its class.

## Required return format

1. Change class
2. Files touched
3. Commands run
4. Residual risks
5. Explicit non-claims
