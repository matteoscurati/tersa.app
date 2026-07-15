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
residue checks. iOS device and simulator artifacts are compile evidence only. The
synthetic corpus and macOS host run do not close parser fuzzing, WebKit device,
physical-iPhone, accessibility, or production renderer gates.

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

## M1 — Vertical slice

Connect one account, sync a bounded recent mailbox, show an encrypted cached
inbox and thread, modify read/archive state, reopen offline, and exercise the
same core through a read-only CLI.

## M2 — MVP alpha

Add multi-account UX, composition, drafts, attachments, send and offline outbox,
mailbox actions, encrypted search, storage controls, app lock, safe HTML, and
best-effort iOS background refresh.

## M3 — Public MVP

Complete accessibility, English and Italian localization, performance budgets,
recovery, independent security remediation, Google verification, public policy
content, and signed Apple releases.

## MVP exclusions

The MVP excludes full-mailbox offline, AI, MCP, OpenPGP, production Tantivy, `maild`, arbitrary rules,
snooze synchronization, Gmail send-as aliases, Google Contacts, IMAP/SMTP,
non-Gmail accounts, Mac Intel, Mac App Store distribution, reliable iOS push,
and guaranteed send-later scheduling.
