# Contributing to tersa.app

Thank you for helping build tersa.app. The project is in feasibility work, so
approved architecture and milestone gates take precedence over feature volume.

## Repository language

English is mandatory for code, identifiers, comments, documentation, commits,
pull requests, issues, tests, fixtures, logs, CLI output, and canonical web
content. See the [language policy](docs/governance/language-policy.md).

## Before making a change

1. Confirm that the change belongs to the current milestone.
2. Keep one pull request focused on one coherent behavior.
3. Target fewer than 1,000 handwritten changed lines, excluding generated
   artifacts, lockfiles, and fixtures. Split larger work before review.
4. Never include Gmail content, OAuth tokens, API keys, private diagnostics, or
   other user data in source, tests, fixtures, issues, or pull requests.

## Commits and certification

Use Conventional Commits, for example `feat: add account identifier` or
`docs: define security reporting`. Every commit must include a Developer
Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Create it with `git commit -s`. The sign-off certifies the contribution under
the [Developer Certificate of Origin 1.1](https://developercertificate.org/).

## Verification and review

Run every check relevant to the change and record the commands and results in
the pull request. Once the Rust workspace exists, the baseline includes format,
Clippy, tests, dependency policy, security audit, feature checks, documentation,
and Apple builds when applicable.

The implementer cannot approve their own work. A pull request may merge only
when required checks pass and an independent reviewer reports zero unresolved
actionable findings, including non-blocking findings. Any post-approval change
invalidates approval; conflict resolution requires a fresh review.

Security and language-policy findings cannot be waived.
