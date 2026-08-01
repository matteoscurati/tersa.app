# macOS Step-4 performance harness

## Scope

This is the protocol-grade collection mechanism for macOS performance data and
the unsigned pre-measurement runner required by Step 4 of the macOS-first plan.
It does not pass `M0-CACHE-001`, `P1-MACOS-001`, `P1-MACOS-002`, or
`P1-MACOS-003`. The final gates still require the exact release-equivalent
Developer ID candidate, the manual UI observations below, immutable retained
evidence, and an independent reviewer.

Run the privacy-safe unsigned probe on an Apple Silicon Mac:

```sh
sh apple/scripts/capture-macos-performance.sh > macos-performance.json
```

The script builds the real Release application unsigned, creates a compressed
UDZO DMG, compiles the production SQLCipher adapter in Release mode, discards
one warm-up sample, and records five samples. It rejects a dirty worktree before
building so its exact commit cannot conceal staged, unstaged, or untracked
source. Its fixture contains exactly 100 synthetic envelopes under
`example.invalid`; it never opens the product Keychain, account profile, Gmail
cache, or network. The committed report tool emits aggregate values only and
rejects an invalid commit, missing sample, malformed marker, or threshold
breach.

## Automated pre-measurements

The synthetic runner records:

- strict encrypted-store open plus the production top-50 inbox listing;
- the production bounded metadata search returning 50 matches;
- a fenced 100-envelope reconciliation;
- peak RSS for the isolated Rust probe process;
- installed Release `.app` bytes and compressed DMG bytes.

Only local top-50 query latency maps exactly to a canonical performance metric.
The open/list, reconcile, and probe-process RSS values are diagnostic proxies;
they are deliberately named as such and cannot be substituted for interactive
cold start, live sync peak, or idle application RSS.

The aggregate uses a conservative nearest-rank p95 (the maximum of five
recorded samples) and the ordinary median. Raw samples remain in the temporary
directory and are deleted when the command exits. The report contains no
device, account, certificate, team, filesystem, message, key, token, or
notarization identifier.

## Release-equivalent completion

For `P1-MACOS-001`, use the exact Developer ID candidate and the canonical
[macOS Phase 1 acceptance protocol](macos-phase-1-acceptance-protocol.md). After
one warm-up, record at least five runs for every metric. Instruments or an
equivalent Apple tool must supply cached-inbox interactive cold start, inbox
scroll frame pacing and bounded materialization, idle inbox RSS, and live
sync/index peak RSS. The automated query and size collection may be reused only
when it runs against that same immutable candidate and its result is included
in the retained, redacted evidence manifest.

A development or unsigned result is a merge-time tripwire, never a gate status.
A breach blocks the pull request until fixed or accepted by an independent
reviewer with the conditions recorded. A distribution-signed threshold miss
fails the gate unless a separately accepted ADR changes the budget.

## Size-budget baseline

The initial unsigned arm64 Release observation on 2026-08-01 was 7,772,552
regular-file bytes for `Tersa.app` and 3,335,559 bytes for its compressed UDZO
DMG. The reviewed ceilings of 16 MiB installed and 8 MiB compressed preserve
substantial implementation headroom while remaining low enough to detect an
accidental runtime, framework, or resource expansion. These unsigned values
justify the budget selection only; they are not distribution evidence.
