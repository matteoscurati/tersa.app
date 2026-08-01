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
merged. Inventory linked worktrees before switching branches because another
worktree may already own `main`. Identify that worktree first, then run every
state-changing or state-validating command from it. Require a clean ordinary
state, fast-forward it, and prove that it exactly matches the remote branch:

```sh
git fetch origin --prune
git worktree list
# Replace this path with the worktree that owns main.
cd /absolute/path/to/main-worktree
git status --short --branch
git pull --ff-only origin main
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
```

If `main` is not checked out anywhere, switch to it without overriding another
worktree. If the final equality check fails, stop and preserve any unpublished
local commits; never reset them merely to make the check pass.

Before removing a linked worktree, inspect both ordinary and ignored state:

```sh
git -C <worktree> status --short
git -C <worktree> ls-files --others --ignored --exclude-standard
```

An empty ordinary status alone is insufficient: worktree removal can delete
ignored machine configuration. Preserve every needed ignored file outside the
worktree and explicitly account for disposable build output before removal.

Delete a local topic branch only after GitHub reports the pull request as
merged. Because this repository uses squash merges, Git may not recognize the
original topic commit as an ancestor of `main`. Before using a forced local
branch deletion, verify the immutable pull request merge commit, its patch,
and any topic-only commits; ancestry or a whole-tree comparison alone may be
inconclusive after the base branch advances. Keep the remote branch until that
verification is complete.

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
