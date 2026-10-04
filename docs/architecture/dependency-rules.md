# Dependency rules

The Apple-era per-crate dependency allowlists were retired by
[ADR 0031](adr-0031-tui-only-pivot.md); the previous text is available at the
`pre-tui-pivot` tag.

## Layers

| Layer | Location | May depend on |
|---|---|---|
| core | `crates/*` | other core crates listed in `CORE_POLICY` (`xtask/src/main.rs`) |
| adapter | `adapters/*` | core crates and other adapters |
| app | `apps/*` | core crates and adapters |
| tool | `xtask` | external crates only |

Nothing may depend on an app or on `xtask`.

## Core purity

Core crates hold domain types, ports, and pure policy. They must:

- declare `#![forbid(unsafe_code)]` at the crate root;
- never depend on I/O, runtime, terminal, or OS crates (the list is
  `CORE_FORBIDDEN_DEPENDENCIES` in `xtask/src/main.rs`);
- be added to `CORE_POLICY` with their allowed core dependencies before they
  build in CI.

`cargo xtask architecture` enforces these rules; `cargo xtask verify` runs it
first.

## Supply chain

`deny.toml` restricts the shipped graph to the macOS and Linux targets,
allows only OSI-approved licenses (ADR 0006 A4), denies yanked crates and
wildcard versions, and keeps retired UI runtimes out of the graph.
`cargo audit` runs on every pull request. A new production dependency needs a
justification in its pull request: why it is needed, its license, and its
maintenance status.
