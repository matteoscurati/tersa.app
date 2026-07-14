# Agent instructions

## Ownership and delegation

- The lead owns requirements, decisions, integration, verification, and the
  final response.
- Use no more than two direct workers at a time.
- Recursive delegation is prohibited.
- Give every worker a bounded task, explicit file ownership, acceptance checks,
  and a concise return format.
- Do not let multiple workers edit the same files concurrently.

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
