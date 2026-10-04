# Roadmap

tersa is a terminal Gmail client for macOS and Linux. The baseline is
[ADR 0031](architecture/adr-0031-tui-only-pivot.md). The Apple-era plan is
kept as [history](history/apple-era-roadmap.md).

Every milestone ships as reviewed pull requests that pass `cargo xtask verify`
on Linux and macOS. A failed milestone check changes the plan; it is not
accepted as temporary debt.

| Milestone | Scope | Done when |
|---|---|---|
| T0 — Pivot | ADR 0031; Apple sources, FFI crates, and Apple CI removed; minimal `xtask`; docs rewritten | Workspace verifies on Linux and macOS without `apple/` |
| T1 — Portable foundation | Adapters made portable and renamed; TLS and SQLCipher crypto from the OS on macOS and from one static vendored OpenSSL on Linux; `crates/keys`; `adapters/vault` (keyring, optional passphrase, passphrase-only fallback); XDG paths; Rust loopback OAuth; in-process token service; BYO OAuth client config | `tersa account add` completes real Google consent on macOS, Linux desktop, and headless Linux |
| T2 — Read-only TUI | `ratatui` shell; paged inbox; thread view; sanitized text; HTML to text; search; offline reopen; background sync with status; first performance harness | Hostile fixtures render safely; budgets measured in the PR |
| T3 — Multi-account | Encrypted registry; add, remove, reset; per-account sync workers; unified inbox | Two real accounts sync and display without cross-account leakage |
| T4 — Triage | `history.list` incremental sync; archive, read state, labels, trash, undo with pending actions | Offline actions reconcile after reconnect |
| T5 — Composition | `$EDITOR` flow; MIME building; local-first drafts synced to Gmail; reply, forward, attachments; idempotent outbox | Killing tersa mid-send never produces a duplicate |
| T6 — Cache and lock | Encrypted cache budget and eviction; `:lock` and idle lock | Budget holds under a large mailbox |
| T7 — Distribution | Release workflow for macOS and Linux (x86_64, aarch64); Homebrew tap | `brew install` works from a clean machine |

## Initial performance budgets

From ADR 0031, measured on a warm cache of at least 10,000 messages: first
frame under 100 ms, top-50 list query under 20 ms, idle resident memory under
50 MiB, stripped release binary under 15 MB.

## MVP exclusions

Full-mailbox offline, AI, MCP, OpenPGP, IMAP/SMTP, non-Gmail accounts, Google
Contacts, send-as aliases, snooze synchronization, server-side send-later,
Windows, and any GUI.
