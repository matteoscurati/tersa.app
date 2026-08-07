# Agent instructions

## Ownership and delegation

- The lead owns requirements, decisions, integration, verification, and the
  final response.
- Use no more than two direct workers at a time.
- Recursive delegation is prohibited.
- Give every worker a bounded task, explicit file ownership, acceptance checks,
  and a concise return format.
- Do not let multiple workers edit the same files concurrently.

## Operating contract (change classes)

Classify every implementation task as **one** change class. Own only that
class’s paths. Run the **minimum** verify loop for the class; escalate to full
`cargo xtask verify` and Apple product builds only at slice boundaries or when
the playbook requires it.

| Class | Own (typical) | Min loop | Do not touch without explicit task |
|-------|---------------|----------|-------------------------------------|
| `domain` | `crates/domain/**` | package tests / `preflight domain` | adapters, `apple/**`, `xtask/**` |
| `application` | `crates/application/**` | package tests / `preflight application` | Swift UI, FFI ABI |
| `presentation` | `crates/presentation/**` | package tests / `preflight presentation` | store/keychain/gmail |
| `adapter-rust` | one `adapters/<name>/**` | package tests for that crate | other adapters, broad UI |
| `bridge-ffi` | `apple/rust-bridge/**` (+ related header/FFI) | architecture + targeted bridge tests | broad Swift UI rewrite |
| `swift-ui` | `apple/macos/**`, tests | unsigned `TersaMac` `xcodebuild test` | Rust core, adapters, `xtask/**` |
| `token-broker` | broker crates + `macos-token-broker` + client map | architecture + broker tests | mailbox-sync production FFI |
| `policy-xtask` | `xtask/**` (and named policy files) | architecture, then full `verify` | product features in same PR |
| `docs-only` | `docs/**`, markdown | none / classifier | code |

Full map, anti-patterns, ADR pointers, and command examples:
[docs/development/agent-playbook.md](docs/development/agent-playbook.md).

### Hard rules

- Prefer scoped loops; full `verify` is merge-quality, not per-edit.
- Do not edit `xtask/**` unless the task is policy/tooling.
- Do not run full Apple product builds for pure Rust package work.
- Do not inject production demo fixtures ([ADR-0021](docs/architecture/adr-0021-macos-ui-vertical-slice.md)).
- Do not expand the exported C ABI without a dedicated bridge task.
- Unknown path or multi-class need → stop and ask the lead (fail closed to full fanout).

### Required implementer return format

1. Change class  
2. Files touched  
3. Commands run  
4. Residual risks  
5. Explicit non-claims  

## Implementation lanes

- Use `luna-clerk` for deterministic inventories, fixture transformations, and
  test-log summaries.
- Use `terra-builder` for bounded implementation with clear acceptance checks.
- Use `sol-reviewer` for material Rust correctness, concurrency, or security
  review.
- Use Claude Opus for UI taste, accessibility, and material security review.
- Use Fable only for architecture-moving plans or final verdicts, never as a
  resident code-writing worker.

## Review and integration

- An implementer must not approve their own work.
- Merge only after all required checks pass and an independent reviewer reports
  zero unresolved actionable findings.
- Any change after approval invalidates the approval. Conflict resolution
  requires a new review.
- Preserve user changes and keep unrelated work out of the active pull request.

## Language

All repository artifacts and developer-facing output must be in English. This
includes code, identifiers, comments, documentation, schemas, migrations,
tests, fixtures, commits, pull requests, issues, CI output, CLI help, logs, and
canonical web content.
