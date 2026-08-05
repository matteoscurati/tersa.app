# CI macOS consolidation

## Purpose and non-claims

This document records the macOS CI consolidation design: one `macOS quality`
job that shares checkout and the pinned Rust toolchain for the host Rust suite
and third-party notice checks. It preserves functional, Rust, Apple,
supply-chain, notice, and DCO coverage while reducing macOS fanout.

Performance-oriented orchestration (inlined `ci-macos` cargo commands on one
default Cargo target directory, notices overlapping that sequential Rust suite,
parallel Apple macOS test / iOS simulator build) removes measured cold-start
and serial overhead without dropping checks. The acceptance budgets below were
met by one exact-head full-fanout sample (see
[Exact-head sample (measured)](#exact-head-sample-measured)). That sample is
not a long-run statistical guarantee: aggregate macOS headroom was only three
seconds under the 220-second budget. Re-measure with the procedure below after
material workflow or runner changes.

## Baseline (pre-consolidation)

Representative full-fanout pull request **#106**, GitHub Actions run
**30977712430**:

| Metric | Value |
| --- | --- |
| Wall-clock | 2:16 |
| Concurrent macOS jobs | 3 (`Apple product`, `Rust (macOS)`, `Third-party notices`) |
| Aggregate macOS job seconds | approximately 248 |

## Acceptance budgets (post-consolidation)

| Budget | Limit |
| --- | --- |
| Wall-clock | ≤ 3:00 (180 seconds) |
| Concurrent macOS jobs | ≤ 2 |
| Aggregate macOS job seconds | ≤ 220 |

## Exact-head sample (measured)

One passing exact-head full-fanout sample from GitHub Actions run
**30997714456** at head
`9c7ecad2169b9b9b31f4ab30e2fb47f775fcac69` (all six visible jobs green):

| Metric | Value |
| --- | --- |
| Head commit | `9c7ecad2169b9b9b31f4ab30e2fb47f775fcac69` |
| Wall-clock | 132 seconds |
| `Apple product` job duration | 101 seconds |
| `macOS quality` job duration | 116 seconds |
| Aggregate macOS job seconds | 217 |
| Concurrent macOS jobs | exactly 2 |
| Visible jobs | exactly 6 (all green) |
| Aggregate macOS headroom vs 220 s | 3 seconds |

This is a single sample, not a multi-run distribution. The three-second
aggregate headroom means small runner or suite regressions can breach the
budget; re-run the measurement procedure after material changes.

## Coverage matrix and ownership

| Concern | Owner job | Notes |
| --- | --- | --- |
| Change scope, DCO, classifier/unit contracts | `Detect change scope` | Always required; fail-closed draft/DCO semantics unchanged |
| Architecture, format, check, Clippy, tests, doctests, rustdoc | `Rust (Linux)` via `cargo xtask verify` | Portable full baseline |
| Clippy, tests, doctests, rustdoc (host) | `macOS quality` when `rust_macos` | Workflow runs the exact `ci-macos` cargo sequence directly (no cold xtask compile): Clippy, tests, doctests, then warning-denied rustdoc, strictly sequential on the default Cargo target directory so artifacts are reused. Both selected lanes are background children with interruptible `wait`. `cargo xtask ci-macos` remains the developer entry point with identical flags. No architecture, format, or separate `cargo check` |
| Third-party notices (`cargo-about`) | `macOS quality` when `notices` | Install `cargo-about` when selected; fetch and `--check` run as a background child and may overlap the sequential Rust suite when both classifier outputs are true |
| Product Apple build/test/symbols | `Apple product` | Complete TersaMac tests and TersaIOS simulator build may run concurrently with distinct DerivedData paths; symbol inventories and the FFI probe stay after both succeed |
| Licenses, advisories, feature powerset, spelling | `Policy and supply chain` | Unchanged |
| Aggregate required status | `CI gate` | Sole required aggregate; optional lanes may be `skipped` |

Classifier outputs remain distinct: `rust_linux`, `rust_macos`, `policy`,
`product_apple`, and `notices`. The workflow runs `macOS quality` when either
`rust_macos` or `notices` is true. Executable CI control inputs (workflow YAML,
scope/DCO/performance scripts and their tests) fail closed to full fanout so a
control-plane change cannot skip the lanes it alters. Markdown and non-executable
GitHub templates stay lightweight.

Visible full-fanout jobs are exactly: scope, Linux, policy, macOS quality,
Apple product, and gate.

## Exact-head measurement procedure

Use this procedure for any future budget claim or re-measurement:

1. Open or update a pull request whose merge-base diff selects full fanout (for
   example a workflow or other executable CI control change).
2. Use the **exact head commit** of that pull request; do not compare against a
   rebased or differently scoped run.
3. Record wall-clock from the workflow run start to the `CI gate` completion.
4. **Job time** is the duration from each job’s start to completion (GitHub
   Actions job duration).
5. **Aggregate macOS seconds** is the sum of job durations for every job with a
   macOS runner (`Apple product` and `macOS quality` after consolidation).
6. Count concurrent macOS jobs as the number of macOS runner jobs present in the
   run (selected jobs only; skipped jobs do not count toward aggregate seconds).
7. Confirm exactly six visible jobs and that all selected lanes are green.

Record the Actions run ID, head SHA, wall-clock, per-job macOS durations,
aggregate macOS seconds, and concurrent macOS job count. Compare against the
acceptance budgets above.

## Future cache policy

Persistent cache, artifact upload, `push` triggers, and manual
`workflow_dispatch` interfaces remain out of product CI. Any future cache
proposal requires a separate design with:

- cold versus warm run comparison on representative full-fanout PRs;
- expected cache size and growth;
- key design (toolchain, lockfile, OS) and invalidation rules;
- eviction and thrashing analysis under concurrent PR load.

Until that proposal is accepted, keep `cache: false` on every Rust toolchain
setup and do not add `actions/cache` or equivalent.
