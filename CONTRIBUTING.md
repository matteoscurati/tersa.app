# Contributing to tersa

Thank you for helping build tersa. The project is in early development, so
the accepted architecture and the current milestone take precedence over
feature volume. Maintainer-only workflows are in
[development](docs/development.md#maintainer-post-merge-hygiene).

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
python3 scripts/check-dco.py HEAD^ HEAD
```

If a transport error makes an otherwise certified published commit
unparsable, do not rewrite shared history. Record a public signed attestation
in the pull request and in
[`docs/governance/dco-attestations.md`](docs/governance/dco-attestations.md).

## Verification and review

Run every check relevant to the change and record the commands and results in
the pull request. The baseline is `cargo xtask verify` (layering, format,
Clippy, a default-feature check, tests, documentation), which CI runs on Linux
and macOS, plus `cargo deny` (dependency policy and RustSec advisories),
`typos`, and DCO, which CI runs on Linux. Documentation-only changes skip the
builds and `cargo deny`; see [development](docs/development.md).

The implementer cannot approve their own work. A pull request may merge only
when required checks pass and an independent reviewer reports zero unresolved
actionable findings, including non-blocking findings. Any post-approval change
invalidates approval; conflict resolution requires a fresh review.

Security and language-policy findings cannot be waived.
