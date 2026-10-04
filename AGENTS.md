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
class’s paths. Run the **minimum** loop for the class; run full
`cargo xtask verify` at slice boundaries and before review.

| Class | Own (typical) | Min loop | Do not touch without explicit task |
|-------|---------------|----------|-------------------------------------|
| `domain` | `crates/domain/**` | `cargo xtask preflight domain` | adapters, apps, `xtask/**` |
| `application` | `crates/application/**` | `cargo xtask preflight application` | adapters, apps |
| `presentation` | `crates/presentation/**` | `cargo xtask preflight presentation` | store, secrets, Gmail adapters |
| `adapter-rust` | one `adapters/<name>/**` | `cargo xtask preflight adapter --package <crate>` | other adapters, apps |
| `tui` | `apps/**` | `cargo xtask preflight tui` | core crates, adapters, `xtask/**` |
| `policy-xtask` | `xtask/**`, CI, `deny.toml`, `_typos.toml` | `cargo xtask preflight policy`, then full `verify` | product features in the same PR |
| `docs-only` | `docs/**`, markdown | none (`typos` if installed) | code |

Full map, anti-patterns, and ADR pointers:
[docs/development/agent-playbook.md](docs/development/agent-playbook.md).

### Hard rules

- Prefer scoped loops; full `verify` is merge quality, not per edit.
- Do not edit `xtask/**` unless the task is policy/tooling.
- Core crates stay free of I/O, OS crates, and `unsafe` (`cargo xtask architecture`).
- Provider-derived text reaches the terminal only through the sanitized type
  ([ADR 0031](docs/architecture/adr-0031-tui-only-pivot.md)).
- Do not inject production demo fixtures.
- Unknown path or multi-class need → stop and ask the lead.

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
