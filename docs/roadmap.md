# Roadmap

tersa.app is delivered as installable vertical slices. A failed gate changes
the architecture or stops dependent work; it is not accepted as temporary debt.

## M0 — Feasibility and governance

Validate Apple distribution, the selected UI candidate on physical devices,
OAuth PKCE, encrypted storage, search, hostile MIME/HTML handling, licenses,
security policy, and Google API compliance.

The SQLCipher diagnostic now proves CommonCrypto linkage, encrypted main/WAL
payloads, abrupt-exit recovery, wrong-key rejection, integrity checks, and an
in-memory temporary-store policy on macOS. It also proves exact synthetic global
and account schema ownership, contiguous transactional migrations, fresh and
incremental convergence, no-op latest reopen, and deterministic rollback from
an uncommitted migration-two WAL on the host. The schema remains illustrative,
not production. iOS protected-data runtime, Keychain, Data Protection,
production schema/repositories, migration-history policy, and production key
handling remain M0 work; `M0-STORAGE-001` remains open.

The portable blob diagnostic now proves a bounded versioned
XChaCha20-Poly1305 chunk format, authenticated random access, exact-size
validation, per-account HMAC content identifiers, run-wide nonce uniqueness,
authenticated same-blob-ID reuse with fail-closed preservation of conflicting
or corrupt finals, atomic same-directory no-replace hard-link publication, and
descriptor-bound no-follow rejection of pre-open path swaps, and deterministic
host process-crash recovery with narrow staging cleanup. It makes
no cross-logical-blob deduplication claim and is not a production blob store.
Manifest binding, cross-blob reuse, rollback freshness, filesystem behavior
beyond the host same-filesystem boundary, key derivation and rotation,
eviction, disk-full, backup, File Protection, signed-device runtime, and
performance remain M0 work.
Concurrent external mutation of an already-open inode also remains outside the
process-crash diagnostic boundary.

The search diagnostic proves host-side synthetic exact-match sets for SQLCipher
FTS5 and Tantivy 0.26.1, immutable open handles after delete/replace,
cross-connection WORM writes with flush-visible generations, blocking and
nonblocking locks, one writer with concurrent readers, metadata watches,
re-entrant callback safety, chunk-local range reads, wrong-key rejection, both
integrity checks, and a retrievable random sentinel with redacted controls.
Host evidence is not a device-gate result. Physical-iPhone runtime and
performance, search-index schema/migration ownership, garbage collection,
backup behavior, and production key handling remain M0 gates.

The hostile-content diagnostic now bounds encoded input, headers, MIME depth,
part count, and decoded display bytes before producing a typed `SafeHtml`
value. It excludes attachment bodies, strips every URL-bearing attribute, and
preserves CID references only as inert metadata. A separate native macOS probe
loads Rust-sanitized and raw hostile controls in a nonpersistent WKWebView with
JavaScript disabled, block-all network rules, navigation denial, no server
entitlement, an in-app transport-control loopback canary, and website-data
residue checks. iOS device and simulator artifacts are compile evidence only.
The synthetic corpus is now supplemented by a deterministic finite host fuzz
regression: every seed is replayed before a fixed-seed budget of 10,000 total
libFuzzer target executions, including corpus initialization, and each input
must produce the same typed result twice while respecting output and CID
invariants. This does not establish exhaustive parser safety, sustained fuzz
coverage, memory-pressure behavior, WebKit device behavior, physical-iPhone
containment, accessibility, or a production renderer. `M0-MIME-001` therefore
remains open at its device-signed evidence requirement.

The portable PKCE state machine and Apple callback transports are implemented
with deterministic evidence. Real consumer and Workspace authorization, code
exchange, Keychain persistence, revocation, and Google verification remain M0
work and are not implied by the transport feasibility result.

The Slint diagnostic packages successfully, but its production gate failed
because the locked Winit accessibility adapter is a no-op on iOS. The planned
Dioxus 0.7.9 fallback also packages successfully and is suitable for continued
diagnostic work, but it is not a production baseline: persistent WebKit state,
navigation interception, runtime footprint, and physical-device evidence are
unresolved. The sandboxed-loopback host diagnostic is recorded, but it is not
device-signed, distribution, production sandbox compatibility, or sandboxed
navigation/storage evidence. M0 must resolve those blockers or
reopen the UI constraint before M1 product screens begin. M1 remains blocked
because no production UI baseline has passed; the authoritative
[M0 gate register](m0/gate-register.json) records current HEAD-checkable
evidence and the cache measurement gate.

## Phase 1 — macOS-first product path

Phase 1 is planned delivery work, not an M0 or M1 pass. Its order is fixed by
the accepted [macOS-first phasing ADR](architecture/adr-0013-macos-first-phasing.md):

1. Split governance gates and define the macOS acceptance protocol without
   passing any gate.
2. Amend the dependency boundary for production Gmail, macOS SQLCipher, and
   AEAD dependencies.
3. Add shared mailbox contracts with no I/O.
4. Add the official Gmail REST adapter behind ports, using fake transport and
   deterministic tests with no network or credentials.
5. Add an encrypted macOS store behind ports.
6. Add bounded sync and cache orchestration.
7. Add a read-only macOS CLI and its owning product profile in three
   independently reviewed slices: first the deterministic CLI source contract
   and private retrieval-only Keychain-to-SQLCipher composition; then a
   credentialless, source-only product-application bootstrap that reuses the
   existing Keychain provisioner and validated read-write SQLCipher path; then
   the real Developer ID signed and notarized bundled distribution. The
   product application remains the sole logical owner and migration authority,
   the trusted Keychain composition is its exclusive executor, the SQLCipher
   writer owns database-leaf migration, and the CLI remains retrieval-only and
   non-owning. This item stays open until the final credential-dependent
   evidence passes.
8. Build a macOS UI baseline and signed/notarized vertical slice only after its
   separately pinned macOS UI and release gates pass.

The target slice connects one account, synchronizes a bounded recent mailbox,
shows an encrypted cached inbox and thread, supports the planned bounded
mailbox state flow, reopens offline, and exposes the same core through the
read-only CLI. It retains the existing product boundaries: no required
proprietary backend, encrypted local persistence, shared Rust core, open source,
and Gmail through the official API.

This phase does not pass, delete, or downgrade M0 gates. A macOS baseline never
satisfies `M1-UI-001` and never changes the mobile-inclusive
`ui_baseline_approved` flag. The current cache budgets remain constraints, not
passes. Real Google authorization and verification also remain open until their
own reviewed evidence exists.

The bootstrap-source implementation does not edit or pass the M0 gate register,
add a new executable, Xcode, signing, entitlement, package, or distribution
surface, or imply OAuth, token, network, or real-account behavior. Its fake and
deterministic evidence cannot satisfy runtime, signing, App Group, Data
Protection Keychain interoperability, UI, or release gates. The canonical
`AccountId`, fixed `default` profile, existing `tersa-keychain-macos` provisioner,
and direct validated read-write SQLCipher composition are mandatory; no
production override or second provisioning channel is permitted. The only new
workspace-to-workspace dependency edge is the macOS-gated existing
`tersa-apple-bridge` composition root to `tersa-keychain-macos`; the exact
store-to-rustix external-package edge is separately constrained below. The
existing `TersaMac` target is the sole production invoker. The bridge only
validates C ABI pointer/length safety,
copies at most 256 opaque account-identifier bytes, and calls the Keychain
adapter's single validating bootstrap entry. That entry creates the canonical
`AccountId` or returns `invalid_account_identifier` before Apple Keychain or
filesystem access. Source policy forbids domain validation, an `AccountId`
construction, or alternate bootstrap entry in the bridge. The bridge receives
only narrow one-shot authority and a closed status, with no raw key,
caller-selected path, profile or configuration override, database handle, store
object, or returned storage capability. Fixed-directory descriptor checks
bracket the existing
pathname-based SQLCipher opener; no directory descriptor is transferred into
SQLite and no end-to-end descriptor-bound opener is claimed. Directory cleanup
stops before the store is invoked; PR 33a.5 must harden the existing store,
which alone owns identity-checked cleanup of fresh leaf files. Each slice
requires independent review with zero unresolved actionable findings on its
exact head.

PR 33a.5 reuses exact `rustix =1.1.4` as its sole newly activated external
package and adds direct macOS declarations to Keychain and SQLCipher-store. The
two declarations use canonical atomic `cfg(target_os = "macos")`. The Keychain
member directly adds only `process` atop workspace `fs`/`std` for `geteuid`;
the store and existing blob request only inherited `fs`/`std`.
Direct owners are exactly blob, Keychain, and store. Cargo feature unification
does not change direct requests. CLI and bridge may reach rustix only through
their exact macOS Keychain or Keychain-to-store paths. Exact declarations,
resolved paths, targets, and negative fixtures require `xtask` enforcement.

The bridge's resolved HMAC and SQLCipher reachability is allowed on
`aarch64-apple-darwin` only through bridge-to-Keychain-to-HKDF/HMAC and
bridge-to-Keychain-to-store/rusqlite/libsqlite3-sys respectively. The bridge is
not a general crypto or SQLCipher owner, and direct or alternate workspace paths
fail. Target checks enforce the canonical atomic macOS structure while ignoring
equivalent whitespace or quote spelling normalized by `cargo_metadata`.

Every cooperative product bootstrap serializes from Keychain provisioning
through final status on the fixed `.tersa-profile-bootstrap-v1.lock` App Group
file. The synchronous C ABI runs on a bounded dedicated worker, never the main
thread; the Rust boundary uses the narrowly authorized Foundation `NSThread`
feature to reject a direct main-thread call. Process-mutex and nonblocking
advisory-lock acquisition share a fixed 30-second monotonic deadline. Lock
creation requests `O_EXCL` mode `0600` and normalizes its returned descriptor.
For an existing same-user regular lock, no-follow `statat`, bounded no-follow
`chmodat` recovery of `0000`, `0200`, or `0400`, then no-follow open and exact
identity/mode revalidation precede locking. Execute/group/other bits or any type,
owner, identity, or final-mode drift fail without repair. A deterministic
post-open mode-race fixture proves exact `0600` remains mandatory. This
converges after restrictive
umasks or a crash before `fchmod`, including an otherwise unopenable `0000`
file, and all work remains inside the deadline. Mutable-name normalization gaps
remain an explicit same-user local-malware residual.
Only deadline expiry or bounded process/advisory-lock contention maps to
`bootstrap_busy_or_unavailable`; a poisoned process mutex and malformed,
unsafe, or operational lock failure map to `bootstrap_unavailable`.
After validated Keychain item-not-found and before provisioning, only an absent
tree or empty fixed profile skeleton is accepted; any existing state returns
`root_missing_with_existing_profile` without Keychain, profile-tree, or store
mutation. The permanent validated lock file is the sole possible preceding
filesystem effect.

PR 33a.5 pins the worker's concurrency-one and one-pending source contract with
`apple/macos/BootstrapWorker.swift`, its sole call site in
`apple/macos/AppDelegate.swift`, and `xtask` fixtures, then only
credentiallessly builds the existing target. It adds no Xcode test
target or policy exception. Runtime dispatch/overflow evidence remains PR 33b.
PR 33a.5 Rust tests prove invalid C ABI null/zero/oversized input mapping and
background-thread boundary mapping without Keychain access; they do not execute
a valid main-thread bootstrap call. They also cover locking.

Before SQLite open, the store retains a validated account-directory descriptor
and snapshots exactly `mail.sqlite3`, `mail.sqlite3-journal`,
`mail.sqlite3-wal`, and `mail.sqlite3-shm` through that descriptor. All four
absent is a fresh leaf eligible for bounded failed-open cleanup. A present main
with any combination of the three sidecars uses the existing opener/migration
path, which may still reject it, and is never cleanup eligible. An absent main
with any sidecar fails before open without cleanup.
This classification is enforced over all three sidecar suffixes; fixtures
preserve `absent_with_sidecar` and `empty_with_sidecar` journal behavior
and cover every relevant combination.

After a failed fresh open closes SQLite handles, the store may clean fixed
entries that were absent pre-open only when it first proved main-file authorship
with `O_EXCL`. Without that proof no main or sidecar cleanup runs, preserving a
racing main plus WAL/SHM. The authorized path uses rustix `statat` and `unlinkat`
beneath the retained descriptor and never re-resolves a parent pathname or calls
`std::fs::remove_file`. Candidate cleanup also revalidates the recorded
`O_EXCL` main identity inside the unlink helper immediately before every unlink;
a main replacement preserves all remaining candidates. SQLite remains
pathname-based; no descriptor-bound SQLite opener is claimed. An immutable
main-file preflight falls back to a non-checkpointing read-only logical
validation when a fresh main has a complete WAL/SHM pair. If SHM is missing,
the store validates identity-bound encrypted main/WAL copies in O_EXCL `0600`
staging files beneath one exclusively created directory selected from exactly
eight fixed `.tersa-wal-recovery-v1-*` slots. The directory is identity-bound,
normalized to exact `0700`, and opened no-follow even under umasks `0777`,
`0577`, or `0377`. Directory and copied-file identities are bound before the
actual read-only/no-follow SQLite handle and revalidated with the opened-main
moved check before key or page reads; checkpoint-on-close is disabled. Normal
setup, copy, key, and validation failures clean only the proven stage. Tampered
or mismatched staging residue is preserved fail closed. A crash can leave at
most eight encrypted owner-only stages; retry never adopts an occupied slot,
and exhaustion creates no unbounded name. The owning writer then rebuilds an
exact `0600` SHM; the staging preflight has no mutation, cleanup, or repair
authority over the original main/WAL pair. Existing main/WAL/SHM modes are checked at exact `0600` before
access and revalidated after open. A canonical main without sidecars normalizes
only its newly created pair, and a logical fresh WAL state left immediately
before migration converges with or without SHM. The
stated cleanup residuals are same-user sidecar insertion after
the proven main claim, which can be misattributed to SQLite, and same-user
replacement between revalidation and `unlinkat`; deterministic hooks cover both
non-prevention gaps and intermediate mismatch preservation. A retry re-enters
the same matrix: a main-present residual may
converge only through all existing-opener invariants, while any sidecar-only
residual fails before open; tests cover every nonempty subset. No retry receives
fresh-cleanup or repair authority. The descriptor is released on every return.
The CLI remains behaviorally retrieval-only, but its
Keychain dependency makes provisioning APIs compile-reachable; an `xtask`
tracked-source allowlist is defense in depth, not a compiler boundary. A future
facade/crate boundary requires its own ADR. This governance slice activates no
manifest, policy, runtime edge, or gate.

## Phase 2 — iPhone and iPad implementation

Phase 2 contains all iPhone and iPad product implementation. It resumes under
separately accepted mobile governance and covers mobile-specific Keychain and
protected-data behavior; physical-device accessibility, input, lifecycle, and
performance; TestFlight and App Store release work; best-effort background
refresh; and closure of the existing device-signed mobile gates.

No Phase 1 source, host, macOS UI, signing, or notarization evidence can close
a Phase 2 device-signed mobile gate. M1 remains blocked in the authoritative
[M0 gate register](m0/gate-register.json) until its existing mobile-inclusive
requirements are independently satisfied; this roadmap does not imply that it
is unblocked or passed.

## Platform MVP completion

This platform-specific completion work carries forward the previous combined
M2 and M3 roadmap scope. Existing governance references to M3 apply to the
relevant platform MVP completion work.

The macOS public MVP may proceed after the Phase 1 acceptance conditions. Add
multi-account UX, composition, drafts, attachments, send and offline outbox,
mailbox actions, encrypted search, storage controls, app lock, safe HTML,
accessibility, English and Italian localization, performance budgets, recovery,
independent security remediation, Google verification, public policy content,
and a signed and notarized macOS release.

The iPhone and iPad public MVP may proceed only after the separate Phase 2
acceptance conditions. Deferring Phase 2 does not block the macOS public MVP,
and a macOS release does not supply or waive any mobile evidence.

## MVP exclusions

The MVP excludes full-mailbox offline, AI, MCP, OpenPGP, production Tantivy, `maild`, arbitrary rules,
snooze synchronization, Gmail send-as aliases, Google Contacts, IMAP/SMTP,
non-Gmail accounts, Mac Intel, Mac App Store distribution, reliable iOS push,
and guaranteed send-later scheduling.
