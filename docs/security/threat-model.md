# Threat model

## Scope and security objective

tersa.app is a consumer/prosumer Gmail client, not a regulated archive or
e-discovery system. The objective is to prevent mailbox content, credentials,
cryptographic material, and behavioral metadata from leaving their intended
trust boundary without explicit user action. A diagnostic pass is not a
production-security claim.

## Protected assets

| Asset | Required protection |
|---|---|
| OAuth authorization codes, refresh tokens, and AI provider keys | Short lifetime where applicable; device-only Keychain storage; never logs, process arguments, or repository files |
| Gmail messages, headers, addresses, labels, drafts, and local intent | Authenticated transport; encrypted local persistence; account isolation; bounded retention |
| Root and derived encryption keys | CSPRNG generation; Keychain wrapping; domain-separated derivation; no export or diagnostics |
| SQLCipher databases, WAL/journals, blobs, thumbnails, and search indexes | Application encryption at rest; controlled temporary storage; integrity checks; crypto-erasure |
| MIME, HTML, inline resources, and attachments | Bounded parsing; typed sanitized output; deny-by-default rendering; no automatic remote fetch |
| Exports, clipboard data, and notifications | Explicit user declassification; minimum disclosure; no claim of encryption after export |
| Logs, crash reports, and CI evidence | Aggregate and redacted; no content, queries, secrets, paths, or stable user identifiers |
| Release artifacts and dependency graph | Reproducible inputs where practical; signed distribution; notarization; SBOM and advisory review |

## Trust boundaries

1. The browser and Google OAuth/Gmail services are external trusted services;
   authorization responses and Gmail payloads remain untrusted input until
   protocol validation succeeds.
2. The Apple operating system, Keychain, protected-data state, WebKit, and
   signing services are platform boundaries, not components controlled by the
   project.
3. The shared Rust core owns domain invariants. Platform adapters own only
   unavoidable OS capabilities and may not leak Apple or UI types inward.
4. Each account database and blob namespace is an isolation boundary. The
   interim macOS CLI composition may receive only the envelope-only
   `MailboxReader`; UI, future CLI mutations, and future MCP access must go
   through authorized application use cases rather than widening direct store
   authority.
5. MIME parsers, WebKit, attachment decoders, exports, logs, and diagnostic
   evidence cross from hostile or sensitive data into narrower representations.

## Attacker capabilities

In scope are a remote sender crafting malicious MIME, HTML, images, links, or
attachments; a local unprivileged process racing loopback OAuth or inspecting
world-readable files; a stolen powered-off or locked device; a malicious or
compromised dependency; malformed Gmail history and retry outcomes; a prompt
injection embedded in email if AI is later enabled; and a tampered build or
evidence artifact. The model also includes accidental disclosure by logs,
exports, caches, screenshots, notifications, or reviewer evidence.

The attacker may control email bytes, timing, network failure, redirect input,
and files selected for import. They do not initially possess the user's device
passcode, Google credentials, signing identity, or an authorized local process.

## Threats, controls, and residual risk

| Threat | Required controls | Residual risk or open gate |
|---|---|---|
| OAuth interception, callback forgery, or token disclosure | Authorization Code with PKCE S256, exact state and redirect validation, literal loopback binding on macOS, system authentication session on iOS, refresh token in device-only Keychain | Real Google exchange, Keychain persistence, revocation, and physical-device flow remain open |
| Device theft and local file inspection | SQLCipher, persistent encrypted WAL, strict envelope-only read capability, chunked blob AEAD, Keychain root key, Apple File Protection, encrypted index/temp policy, key-first wipe | A running unlocked or compromised process can access plaintext in memory; the bundled VFS cannot prevent same-user sidecar swap-in/open/swap-back or deletion/recreation races |
| Malicious MIME/HTML and tracking pixels | Size/depth/part limits, attachment exclusion, typed `SafeHtml`, nonpersistent WKWebView, JavaScript/network/navigation denial, remote images blocked | Parser/WebKit zero-days and physical-device containment remain open |
| Malicious attachment or decompression bomb | On-demand fetch, byte/ratio/time/memory limits, no macro execution, sandboxed short-lived worker when needed | Complex production parsers and sandbox evidence are not implemented |
| Sync replay, ambiguity, or duplicate send | Transactional history cursor, idempotent desired state, bounded retries, stable RFC Message-ID, server reconciliation after ambiguous timeout | Production sync/outbox is not implemented |
| Cross-account or cross-surface access | `(account_id, gmail_id)` identity, per-account storage/key namespace, application authorization boundary, future single-writer host on macOS | Production repositories and IPC authorization remain open |
| Dependency or release compromise | Locked dependencies, license/advisory checks, target reachability, SBOM, checksum verification, DCO, exact-head review, signed and notarized distribution | Unknown upstream compromise and reproducibility gaps remain |
| Diagnostic, crash, clipboard, export, or notification leak | Redacted types, synthetic fixtures, aggregate evidence, explicit export boundary, minimum notification content, opt-in crash reporting | User-approved exports and OS-level observation are outside encrypted local storage |
| Future AI prompt injection or data exfiltration | Boundary remains closed; future per-operation consent, hostile-data delimiting, no autonomous tools, provider policy review | No AI feature is implemented or approved |
| Future MCP client misuse | Boundary remains closed; future per-client grants, stdio default, pagination, dry-run and two-phase send | No MCP feature is implemented or approved |
| OpenPGP misuse or downgrade | Boundary remains closed; future policy layer, interoperability suite, trust UX, fuzzing, independent audit | No OpenPGP feature is implemented or approved |

## Explicit exclusions

The initial model does not claim protection on a jailbroken/root-compromised
device, against privileged malware while the user has unlocked content, or
against advanced hardware attacks on a running device. It does not protect the
Google account after Google credentials are compromised, provide metadata
anonymity, satisfy regulated-retention regimes, or keep a user-selected export
encrypted after it crosses the application boundary.

Future AI, MCP, OpenPGP, relay, attachment-worker, and cross-device preference
sync are unopened boundaries. Each requires an accepted data-flow update,
abuse analysis, retention policy, and independent security review before code
may move into a production path.

## Review triggers

Revisit this model when a production UI is selected, a real Google token is
stored, a new plaintext or persistence surface is added, network egress changes,
a production parser/renderer is adopted, CLI/MCP/AI/OpenPGP becomes reachable,
Apple entitlements change, or the optional relay is designed.
