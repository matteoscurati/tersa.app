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

The bootstrap-source authorization does not edit or pass the M0 gate register,
add a new executable, Xcode, signing, entitlement, package, or distribution
surface, or imply OAuth, token, network, or real-account behavior. Its fake and
deterministic evidence cannot satisfy runtime, signing, App Group, Data
Protection Keychain interoperability, UI, or release gates. The canonical
`AccountId`, fixed `default` profile, existing `tersa-keychain-macos` provisioner,
and direct validated read-write SQLCipher composition are mandatory; no
production override or second provisioning channel is permitted. The only new
dependency edge is the macOS-gated existing `tersa-apple-bridge` composition
root to `tersa-keychain-macos`; the existing `TersaMac` target is the sole
production invoker. The bridge receives only narrow one-shot authority to
request fixed-profile bootstrap for a validated `AccountId` and receive a
closed status. It receives no raw key, caller-selected path, profile or
configuration override, database handle, store object, or returned storage
capability. Fixed-directory descriptor checks bracket the existing
pathname-based SQLCipher opener; no directory descriptor is transferred into
SQLite and no end-to-end descriptor-bound opener is claimed. Directory cleanup
stops before the store is invoked; PR 33a.5 must harden the existing store,
which alone owns identity-checked cleanup of fresh leaf files. Each slice
requires independent review with zero unresolved actionable findings on its
exact head.

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
