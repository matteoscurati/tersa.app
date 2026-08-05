# CI macOS consolidation

## Purpose and non-claims

This document records the macOS CI consolidation design: one `macOS quality`
job that shares checkout and the pinned Rust toolchain for the host Rust suite
and third-party notice checks. It preserves functional, Rust, Apple,
supply-chain, notice, and DCO coverage while reducing macOS fanout.

This document does **not** claim that the acceptance budget has been measured
or passed. Budget pass/fail requires a representative exact-head pull-request
run after this change lands. Until that run exists, treat the budgets below as
targets only.

## Baseline (pre-consolidation)

Representative full-fanout pull request **#106**, GitHub Actions run
**30977712430**:

| Metric | Value |
| --- | --- |
| Wall-clock | 2:16 |
| Concurrent macOS jobs | 3 (`Apple product`, `Rust (macOS)`, `Third-party notices`) |
| Aggregate macOS job seconds | approximately 248 |

## Acceptance budgets (post-consolidation targets)

| Budget | Limit |
| --- | --- |
| Wall-clock | ≤ 3:00 |
| Concurrent macOS jobs | ≤ 2 |
| Aggregate macOS job seconds | ≤ 220 |

## Coverage matrix and ownership

| Concern | Owner job | Notes |
| --- | --- | --- |
| Change scope, DCO, classifier/unit contracts | `Detect change scope` | Always required; fail-closed draft/DCO semantics unchanged |
| Architecture, format, check, Clippy, tests, doctests, rustdoc | `Rust (Linux)` via `cargo xtask verify` | Portable full baseline |
| Clippy, tests, doctests, rustdoc (host) | `macOS quality` via `cargo xtask ci-macos` when `rust_macos` | No architecture, format, or separate `cargo check` |
| Third-party notices (`cargo-about`) | `macOS quality` when `notices` | Conditional steps inside the same job |
| Product Apple build/test/symbols | `Apple product` | Unchanged |
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

Do not claim budget pass until this procedure is completed for a representative
exact-head full-fanout run and the three budgets above are met.

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
