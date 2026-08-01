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

Squash merge messages must contain a real blank line before the trailer.
Literal backslash-n sequences such as `\n\nSigned-off-by:` are not a valid Git
trailer. After a squash merge, verify the immutable merge commit before
treating the main build
as complete:

```sh
cargo xtask dco HEAD^ HEAD
```

If a transport error makes an otherwise certified published commit
unparsable, do not rewrite shared history. Record a public signed attestation
in the pull request and in
[`docs/governance/dco-attestations.md`](docs/governance/dco-attestations.md).

## Post-merge local hygiene

Treat the remote default branch as the source of truth after a pull request is
merged. Before starting the next slice, require a clean worktree, fast-forward
the local default branch, and inventory linked worktrees:

```sh
git status --short --branch
git fetch origin --prune
git switch main
git pull --ff-only origin main
git worktree list
```

Remove a linked worktree only after `git status --short` is empty inside that
worktree. Delete its local topic branch only after GitHub reports the pull
request as merged. Because this repository uses squash merges, Git may not
recognize the original topic commit as an ancestor of `main`; before using a
forced local branch deletion, compare the topic tree with the immutable pull
request merge commit and keep the remote branch until the result is verified.

Never clean, reset, or delete an unrelated dirty worktree. Local OAuth build
configuration and credentials remain ignored machine state and must not be
staged as part of post-merge cleanup.

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
