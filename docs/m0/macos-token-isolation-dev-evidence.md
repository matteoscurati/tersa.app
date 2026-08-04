# macOS token-isolation development-signed evidence runbook

## Purpose and non-claim

This runbook documents the opt-in, operator-run Apple Development evidence
capture harness for ADR-0024 *Required implementation and evidence* Item 5. On
an exact Apple Development signed build the harness proves that normal broker
token operations succeed (the owner-driven positive control) and that both
fixed-purpose negative probes receive `errSecMissingEntitlement`: the broker
probing the installation root/store group and the main app probing the token
group.

This is **development evidence only**. It is not Developer ID signing,
notarization, distribution, or closure of ADR-0024 Item 6. It is opt-in, never
runs in CI, and fails closed without recording a live claim on any unresolved
precondition.

**No live Point-6 PASS is claimed** by this runbook or by the harness. A PASS
is recorded only after the harness succeeds end to end on a clean exact commit
**and** an independent reviewer reports zero unresolved actionable findings
against that capture. Until then, ADR-0024 Item 5 development-signed isolation
evidence remains open. The harness is source only: its existence in the
repository does not pre-record a result.

The dedicated token Keychain group (`app.tersa.token`) and an explicitly
authorizing Apple Development profile are external runtime preconditions that
the harness gates on (ADR-0024 Item 1). That external registration is separate
from source inspection and cannot be produced or attested by reading the
repository; only its presence is checked at capture time.

## Prerequisites

| # | Requirement | How the harness enforces it |
|---|---|---|
| 1 | Native arm64 macOS, not a Rosetta-translated process | `uname -m` is `arm64` and `sysctl.proc_translated` is `0` |
| 2 | A clean worktree, commit-bound capture | `git status --porcelain --untracked-files=all` is empty; the build is a `git archive` of `HEAD` |
| 3 | Exactly one valid Apple Development identity | `security find-identity` selects exactly one `Apple Development` hash; the identity, team, and profile are never printed |
| 4 | An effective Apple Team Identifier under that identity | resolved by a throwaway signed team probe and matched to `^[A-Z0-9]{10}$` |
| 5 | Exactly one current Apple Development profile authorizing `app.tersa.mac` with the `app.tersa.shared` Keychain and application groups | provisioned-profile scan; a wildcard-only profile is not accepted |
| 6 | Exactly one current Apple Development profile **explicitly** authorizing the dedicated token group `app.tersa.token` | the Item 1 gate; a wildcard keychain group does not satisfy it and is rejected |

Any unmet prerequisite aborts before a build, before any signing, and before
any live claim.

## Exact command

Run, at the exact commit under review, from the repository root:

```
sh apple/scripts/capture-macos-token-isolation-dev-evidence.sh
```

## Owner-only Google consent boundary

The harness never touches Google credentials, authorization codes, tokens,
account data, or mail content. The positive-control steps are owner-driven in
the running app: the browser consent flow and any credentials stay owner-only.
The only harness-recorded positive-control outcome is the commit-bound operator
attestation that the bounded flow succeeded (see *Positive control*). No
credential, token, account identifier, or mail datum is written by the harness.

## Negative controls — exact pass conditions

The harness launches each real signed executable directly (not a subshell),
bounded to 40 s, with the single opt-in argument
`--tersa-keychain-isolation-probe-v1`. The probe derives the one group its
principal is forbidden from — the other principal's group, by keeping the team
prefix and swapping the suffix between `.app.tersa.shared` and `.app.tersa.token`
— and issues exactly one query-only `SecItemCopyMatching` against that group,
requesting no item data and no attributes.

Both probes must pass, each with all four conditions:

1. The probe exits `0`.
2. It emits exactly one line on stdout.
3. That line is exactly (substituting the principal):
   `{"schema_version":1,"principal":"token-broker","result":"missing-entitlement"}`
   for the broker, and
   `{"schema_version":1,"principal":"main-app","result":"missing-entitlement"}`
   for the main app.
4. The result is not one of the non-pass labels
   (`item-not-found`, `unexpected-status`, `configuration-invalid`).

The broker probe proves the broker cannot reach the installation root/store
group; the main-app probe proves the main app cannot reach the token group. A
probe that times out, exits nonzero, emits the wrong number of lines, emits
different content, or returns any non-pass label fails the capture.

## Positive control

After both probes pass, the harness launches the signed app and presents an
interactive checklist. The operator completes, in the running app:

1. **CONNECT** — sign in to Google through the token broker. Observe the broker
   complete the code exchange (or a stored-token refresh) and hand the
   short-lived access token to the main process.
2. **SYNC/RENDER** — observe Gmail synchronization succeed and the inbox render.
3. **DISCONNECT** — disconnect the account and observe the decided teardown
   ordering succeed: broker revoke, broker token delete, local purge, marker
   clear, ending in a clean disconnect — not an unconfirmed failure.

The operator confirms ONLY by typing the exact source commit shown by the
harness. Any other input (or no interactive terminal) aborts the capture
without recording a live positive-control claim.

## Evidence record — location and handling

On full success the harness writes a redacted, commit-bound record to a
**gitignored** path under the build directory:

```
apple/build/dev-evidence/token-isolation-evidence.txt
```

It is not version-controlled and is not committed. The harness prints the path
with the instruction to inspect and selectively record. The record contains:
schema version, exact source commit, architecture, build source, signing tier
and order, redacted profile presence, the exact entitlement summaries, the
Hardened Runtime / library-validation / forbidden-exception posture, both probe
evidence lines, the positive-control attestation, and the explicit non-claim.
A failed capture writes no record.

## Independent review

Per the physical-device and distribution protocol and the agent ownership rules,
the evidence producer cannot approve their own capture. A PASS requires a
different named reviewer, with reviewed competence identifiers
(`apple-platform`, `security`, or `release-engineering`), who verifies the
captured record against the exact commit, confirms the redaction, and reports
zero unresolved actionable findings. Any change after approval invalidates the
approval.

## Failure interpretation

Every `fail` aborts the run with a nonzero exit before recording a live claim.
A failed or partial run is non-authoritative and is never a partial PASS:
it does not prove isolation, and the absence of a record means nothing was
attested. The harness records a positive-control claim only after the
commit-typed confirmation, so a run that stops at a precondition, a probe, a
signature/entitlement check, or an unconfirmed positive control proves nothing
about signed runtime isolation. The most common failure sources are a dirty
worktree, more or fewer than one Apple Development identity, a missing or
ambiguous provisioning profile, the token group not explicitly authorized
(ADR-0024 Item 1), a probe returning a non-pass status or timing out, or a
positive control not confirmed.

## Privacy constraints

- Apple identity, team identifier, and provisioning-profile identifiers are
  resolved at capture time and never printed; the record states only redacted
  presence.
- No Google credential, authorization code, refresh or access token, account
  identifier, or mail content is read, logged, or recorded by the harness.
- The record is redacted, commit-bound, and gitignored; it excludes device,
  machine, and filesystem identifiers and any secret material.
- Recording any captured record into the repository is a separate, reviewed
  decision and must preserve the redaction and the exact-commit binding.
