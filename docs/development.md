# Development

## Prerequisites

- macOS or a current Linux distribution (x86_64 or aarch64)
- Rust 1.91.1, installed automatically through `rust-toolchain.toml`
- Optional: `cargo-deny` and `typos` to run the CI policy checks locally

## Verification

Full merge-quality suite:

```sh
cargo xtask verify
```

It runs the layering check, `cargo fmt --check`, Clippy with warnings denied,
a default-feature check, tests, doc tests, and rustdoc with warnings denied.

CI is kept fast and cheap on purpose. It runs only for pull requests into
`main` and pushes to `main`, so a stacked pull request is checked on its first
push after it targets `main`; draft pull requests fail the gate until they are
ready for review. On Linux it runs DCO validation, `typos`,
`cargo deny --locked check`, and `cargo xtask verify` with a dependency cache
that only `main` writes; on macOS it runs `cargo xtask verify` for pull
requests only. Changes that touch only documentation skip both builds and
`cargo deny` (`scripts/ci-needs-build.sh`); DCO and `typos` still run.

`cargo xtask` runs with `--locked`, locally too. After changing a dependency,
update `Cargo.lock` first (for example with `cargo check` or
`cargo update --workspace`).

Scoped loops while iterating (see the
[agent playbook](development/agent-playbook.md)):

```sh
cargo xtask preflight domain
cargo xtask preflight adapter --package tersa-gmail-rest
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
