# Development

## Prerequisites

- macOS or a current Linux distribution (x86_64 or aarch64)
- Rust 1.91.1, installed automatically through `rust-toolchain.toml`
- Optional: `cargo-deny`, `cargo-audit`, `cargo-hack`, and `typos` to run the
  CI policy checks locally

## Verification

Full merge-quality suite:

```sh
cargo xtask verify
```

It runs the layering check, `cargo fmt --check`, Clippy with warnings denied,
tests, doc tests, and rustdoc with warnings denied. CI runs it on Linux and
macOS and additionally runs `cargo deny check`, `cargo audit`,
`cargo hack check --feature-powerset`, `typos`, and DCO validation.

Scoped loops while iterating (see the
[agent playbook](development/agent-playbook.md)):

```sh
cargo xtask preflight domain
cargo xtask preflight adapter --package tersa-gmail-rest-macos
cargo xtask preflight tui
cargo xtask test-pkg tersa-application
cargo xtask clippy-pkg tersa-presentation
```

## Architecture

- [ADR 0031: terminal-only pivot](architecture/adr-0031-tui-only-pivot.md)
  is the current product and architecture baseline.
- [Dependency rules](architecture/dependency-rules.md) describe the layering
  enforced by `cargo xtask architecture` and `cargo deny`.
- Security boundaries: [threat model](security/threat-model.md) and
  [data flow](security/data-flow.md).

## Commits

Every commit needs a DCO `Signed-off-by` trailer matching the author
(`git commit -s`). See [CONTRIBUTING.md](../CONTRIBUTING.md).
