# Roadmap

tersa.app is delivered as installable vertical slices. A failed gate changes
the architecture or stops dependent work; it is not accepted as temporary debt.

## M0 — Feasibility and governance

Validate Apple distribution, the selected UI candidate on physical devices,
OAuth PKCE, encrypted storage, search, hostile MIME/HTML handling, licenses,
security policy, and Google API compliance.

The SQLCipher diagnostic now proves CommonCrypto linkage, encrypted main/WAL
payloads, abrupt-exit recovery, wrong-key rejection, integrity checks, and an
in-memory temporary-store policy on macOS. iOS runtime, Keychain, Data
Protection, schema, migrations, and production key handling remain M0 work.

The search diagnostic proves host-side synthetic exact-match sets for SQLCipher
FTS5 and Tantivy 0.26.1, immutable open handles after delete/replace,
unpublished staged generations, one writer with concurrent readers, chunk-local
range reads, wrong-key rejection, both integrity checks, and redacted random
sentinel controls. Host evidence is not a device-gate result. Physical-iPhone
runtime and performance, schema/migration ownership, garbage collection,
backup behavior, and production key handling remain M0 gates.

The portable PKCE state machine and Apple callback transports are implemented
with deterministic evidence. Real consumer and Workspace authorization, code
exchange, Keychain persistence, revocation, and Google verification remain M0
work and are not implied by the transport feasibility result.

The Slint diagnostic packages successfully, but its production gate failed
because the locked Winit accessibility adapter is a no-op on iOS. The planned
Dioxus 0.7.9 fallback also packages successfully and is suitable for continued
diagnostic work, but it is not a production baseline: persistent WebKit state,
navigation interception, sandboxed loopback transport, runtime footprint, and
physical-device evidence are unresolved. M0 must resolve those blockers or
reopen the UI constraint before M1 product screens begin.

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

The MVP excludes AI, MCP, OpenPGP, production Tantivy, `maild`, arbitrary rules,
snooze synchronization, Gmail send-as aliases, Google Contacts, IMAP/SMTP,
non-Gmail accounts, Mac Intel, Mac App Store distribution, reliable iOS push,
and guaranteed send-later scheduling.
