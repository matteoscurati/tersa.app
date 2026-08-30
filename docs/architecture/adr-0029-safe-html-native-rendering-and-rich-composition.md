<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0029: SafeHtml, native rendering, and rich composition

- Status: Proposed
- Date: 2026-08-29
- Owner intent: Approved; implementation is blocked pending independent
  architecture/security review and the prerequisite slices below.

## Context

The current MIME presentation path is temporary containment only: it extracts
best-effort plain text, may carry raw `body_html` across the Rust bridge, and
the Swift UI ignores it. The [security data flow](../security/data-flow.md) and
[threat model](../security/threat-model.md) explicitly reject treating this as
a hostile-content parser or safe renderer. Received HTML, tracking pixels,
attachments, and markup pasted into a composer are adversarial input.

The beta nevertheless needs readable rich messages and a rich editor. Reusing
a web view would reintroduce script, navigation, persistent storage, remote
content, and accessibility risks. Received content and composed content have
different trust origins and must not share an untyped HTML channel.

## Prerequisite decision and policy slices

No content worker, parser, renderer, remote-image fetcher, or rich-composition
code may start until these slices are independently reviewed:

1. **P29-class-policy:** a `policy-xtask` slice updates `AGENTS.md` and the
   [agent playbook](../development/agent-playbook.md) with the new
   `content-worker` class. It owns
   `apple/macos-content-worker/**` with
   `adapters/content-worker-ffi-macos/**`, and
   `apple/macos-remote-image-fetcher/**` with
   `adapters/remote-image-fetch-ffi-macos/**`. Each peer is one implementation
   slice with no mixed peer files. The policy also defines exact target/source
   inventory, scoped enforcement, and the verify/review lane before any
   content-worker code. It explicitly excludes both FFI adapter directories
   from the generic `adapter-rust` class and adds fail-closed change-classifier,
   `AGENTS.md`, and playbook tests for that exclusion before worker
   implementation.
2. **P29-parser policy:** a `policy-xtask` slice selects and pins the dedicated
   MIME parser and sanitizer dependencies, targets, and features; amends
   `deny.toml`, dependency rules, and exact owner fixtures before code. No
   dependency version is selected by this ADR.
3. **P29-containment policy:** amend `xtask` to permit `NSAttributedString` and
   `NSTextStorage` only in closed native presentation projections; retain denials
   for `NSHTMLTextDocumentType`, every `documentType` variant,
   `NSClassFromString`, every Markdown initializer, literal-fragment
   `LocalizedStringKey` construction, and WebKit. It must also deny every
   dangerous `NSAttributedString`/`NSTextStorage` document initializer or reader:
   HTML initializers, `contentsOf`, URL-loading constructors, RTF, `docFormat`,
   `read(from:options:documentAttributes:)`, and equivalent HTML/RTF/URL-loading
   variants even when no literal `documentType` appears. A negative fixture is
   required for each category, and all newly added Apple trees are scanned.
4. **P29-XPC/security:** amend `apple/project.yml` to declare/embed exactly
   `TersaContentWorker` and `TersaRemoteImageFetcher`, and amend `xtask`
   target/embed guards to validate those exact target/source/entitlement lists;
   pin exact ABI/signing inventories; require both peers to enable Hardened
   Runtime and library validation and to exclude `get-task-allow`, debugger,
   disabled-library-validation, and DYLD-environment exceptions; require every
   client connection to call `NSXPCConnection.setCodeSigningRequirement` with
   the approved peer requirement; forbid PID-based peer checks; and update the
   security data flow, threat model, and signed hostile-content acceptance
   procedure.
5. **P29-fetch policy:** select and pin the isolated remote-image transport
   dependency/allowlist and its resolved-address SSRF test corpus before it can
   make a network request.

These are future amendments, not a claim that current dependency or containment
policy already permits the proposed paths.

## Decision

### Safe received-content boundary

`SanitizedRenderDocument` and every typed render node live only in
`tersa-presentation`; neither `tersa-domain` nor `tersa-application` gains a
received-content model. The content worker returns bounded
`ContentWorkerWireV1` bytes, not a trusted typed document. The in-process
`PresentationRenderDeserializer` validates that wire payload after XPC and is
the sole constructor of `SanitizedRenderDocument`. It checks format version,
bounds, node kinds, nesting, text, links, and image placeholders before native
rendering; it is the trust boundary and must be fuzzed independently of the
worker.

The closed presentation tree contains plain text, paragraphs, headings,
emphasis, lists, block quotes, code/preformatted text, explicit links, and
image placeholders. Unsupported markup degrades to inert text or is omitted.
Scripts, event handlers, forms, frames, downloads, CSS, style URLs, embedded
objects, navigation, and executable data URLs never enter the typed model.

`TersaContentWorker` is a separately signed, sandboxed XPC peer that parses and
sanitizes only. It has no network entitlement, token/root Keychain group, App
Group entitlement, or store-opening authority. It receives one bounded raw
message buffer and emits only `ContentWorkerWireV1`. It must meet the
ADR-0024-equivalent peer posture: Hardened Runtime and library validation
enabled; `get-task-allow`, debugger, disabled-library-validation, and DYLD
environment exceptions absent; and exact target/source/entitlement inventories
checked before signing. The main app and the worker authenticate the XPC peer
with `NSXPCConnection.setCodeSigningRequirement`; PID checks are forbidden.
The worker accepts at most 32 MiB of raw MIME, 16 nested multipart levels,
1,024 parts, 256 KiB of text per rendered block, 50,000 total render nodes, and
two seconds of parse CPU time. A limit, decode, or sanitization failure returns
a closed content-unavailable wire status, never a partly trusted raw HTML
payload.

The native AppKit/SwiftUI renderer consumes only validated presentation nodes.
WebKit is not linked, instantiated, or used for received email. `body_html`
source removal occurs only after the typed path and unsigned hostile-content
tests pass; a later signed final candidate validates that removal and does not
retroactively make unsigned proof release evidence. Raw MIME may remain
encrypted in the Rust account store for reprocessing, but raw HTML does not
cross the final presentation ABI.

### Remote content

Remote content is blocked by default. `RemoteContentPolicyStore` stores an
encrypted account-scoped permission for one exact parsed sender address, never
a wildcard domain. The first approval shows a one-time warning that From does
not prove identity and that requests reveal IP/opening. Once the user consents,
future opens for that exact account/sender auto-fetch eligible image
placeholders; revoking the rule restores the default block.

`TersaRemoteImageFetcher` is a separate XPC peer with network authority only:
it has no Keychain group, App Group, account-store, blob-store, or parser
authority. It meets the same ADR-0024-equivalent release-blocking peer posture as
`TersaContentWorker`: Hardened Runtime and library validation enabled;
`get-task-allow`, debugger, disabled-library-validation, and DYLD-environment
exceptions absent; and exact target/source/entitlement inventories checked
before signing. It uses an ephemeral HTTPS-only transport with no cookies,
referrer, persistent cache, proxy, or authentication. The main app and this peer
use `NSXPCConnection.setCodeSigningRequirement` peer authentication; PID checks
are forbidden. Before every initial connection and every redirect/hop it
resolves the destination and rejects loopback, private, link-local, CGNAT,
multicast, and unspecified addresses for every resolved address family; it
rechecks the connected address rather than trusting only a hostname. It allows
at most three redirects, 20 images, and 10 MiB aggregate image bytes per
rendered message, and accepts only bounded image MIME data. Scripts, CSS URLs,
forms, documents, downloads, and non-image MIME types are rejected.
Accepted bytes return to the main process for encrypted `BlobRef` storage
under ADR 0030; no WebKit, URL, or plaintext cache is used. The parser worker
remains no-network.

### Native rich composition

The domain layer also adds `RichComposeDocument`, a closed structured AST with
paragraph, heading, list, quote, code, link, bold, italic, underline,
strikethrough, and inline CID-image/attachment references. It stores no raw
HTML. TextKit/AppKit is the macOS editing surface; paste is normalized into the
AST or into a plain attachment and cannot inject arbitrary markup.

`ComposeDocumentCodec` is the application boundary between the native editor,
draft storage, and the MIME compiler in ADR 0028. It deterministically derives
plain text and a limited HTML representation from the AST. The generated HTML
is outbound serialization, not an input or a received-message renderer. The
bridge carries only a bounded, versioned compose document; it carries neither
arbitrary HTML nor a WebKit state object.

### Invariants and data flow

```text
Received raw MIME -> no-network content worker -> ContentWorkerWireV1
                 -> in-process validating deserializer -> SanitizedRenderDocument
                 -> native SwiftUI/AppKit views

Native TextKit input -> RichComposeDocument -> DraftStore -> MIME compiler
                    -> Gmail transport
```

- The in-process presentation deserializer is the only typed-render constructor;
  no caller can unwrap a document to raw HTML.
- The content worker, renderer, remote-image fetcher, and compose serializer
  have distinct responsibilities. No worker has both hostile parsing and
  network authority.
- Every content result, image permission, and blob route includes `AccountId`.
  A sender rule or downloaded image cannot cross accounts.
- Links require an explicit user action; a rendered document never navigates,
  opens, downloads, or fetches on parse/layout.
- Existing token-broker XPC privileges do not transfer to the content worker,
  and no new received-content capability is exposed to the CLI or MCP.
- Every render/compose ABI addition atomically updates the expected-export
  allowlist, count, canonical header, Swift declarations, and positive/negative
  fixtures. No name-only allowance is valid.

### Implementation decomposition by change class

| Change class | Bounded implementation responsibility |
| --- | --- |
| `docs-only` | Security-document amendments after the separate P29 class-policy change. |
| `policy-xtask` | P29-class-policy, `project.yml`/target-embed, dependency, containment, ABI, and peer-auth guards only. |
| `domain` | Add `RichComposeDocument`, compose link/image references, and bounded editor values only. |
| `application` | Add wire-status, sender-rule, and compose-codec ports without a typed received render model. |
| `presentation` | Add `SanitizedRenderDocument` and the validating XPC-wire deserializer. |
| `content-worker — TersaContentWorker` | Implement only `apple/macos-content-worker/**` and `adapters/content-worker-ffi-macos/**`. |
| `content-worker — TersaRemoteImageFetcher` | Implement only `apple/macos-remote-image-fetcher/**` and `adapters/remote-image-fetch-ffi-macos/**`. |
| `bridge-ffi` | Add one versioned render/compose ABI with atomic allowlist/header/count/fixture updates. |
| `swift-ui` | Implement native rendering, sender consent/revocation, TextKit editor, and accessibility. |

## Failure handling

Malformed, oversized, deeply nested, timed-out, unsupported, or deserializer-
invalid MIME returns safe content-unavailable presentation with an optional
bounded plain-text fallback; it never makes raw HTML visible. A failed or
rejected remote image leaves its placeholder and cannot relax the sender rule.
DNS/address-policy or redirect failure leaves the image blocked. Permission
records are per account and fail closed on corruption.

The editor preserves the last valid structured draft on malformed paste or
codec failure; it does not serialize a partial raw-HTML buffer. A stale content-
worker reply, locked app, cancelled render request, or account switch is rejected
by the caller's route/generation fence before it changes the view. Every remote-
image-fetcher completion must match the current exact `AccountId`, message/render
route, generation, cancellation state, unlocked state, and still-effective
remote-content permission for the exact parsed sender before image publication
or encrypted `BlobRef` persistence. Account switch or permission revocation
rejects the completion and persists neither bytes nor a blob route. A worker or
fetcher crash is a recoverable unavailable state, not a reason to parse or fetch
in-process with wider privileges.

## Test and evidence gates

- Property and fuzz tests cover MIME framing, transfer encodings, nesting,
  node/byte/time limits, malformed HTML, link/image schemes, worker wire, and
  the in-process validating deserializer's rejection of every invalid model.
- XPC/signing tests prove both peers' hardened-runtime, library-validation,
  forbidden-debug/DYLD-entitlement posture, exact code-signing requirement peer
  authentication, and absence of PID-based checks. They separately prove the
  content worker's no-network/no-Keychain/no-App Group/no-store authority and the
  fetcher's network-only authority.
- Remote-fetcher tests cover every resolved address on every redirect/hop,
  loopback/private/link-local/CGNAT/multicast denial, image-count and aggregate
  byte caps, and no parser/store/Keychain authority. Completion tests reject
  mismatched account/route/generation, cancellation, lock, account switch, and
  sender-permission revocation before image publication or `BlobRef` persistence.
- Native renderer tests cover each closed tree node, no automatic request,
  VoiceOver, Full Keyboard Access, link confirmation, and no WebKit linkage.
- Editor tests cover rich formatting, IME, paste, undo/redo, selection,
  attachment insertion, deterministic plain/HTML serialization, and no raw
  HTML bridge field.
- The typed path and unsigned hostile corpus must pass before `body_html` source
  removal. A later signed candidate containment walk validates the final path;
  unsigned evidence cannot close that signed gate.

## Non-claims

This ADR does not implement or approve the prerequisite policies, a general
browser, PDF/document preview, remote content by default, full CSS
compatibility, a raw HTML editor, a WebKit email renderer, attachment execution,
iOS/iPadOS renderer, AI/MCP ingestion, or a signed release claim. It does not
assert that a sender-address rule authenticates the sender, and it does not make
raw MIME or HTML safe merely by encrypting it.

## Consequences

Received mail becomes a narrow, native, no-network rendering problem rather
than a browser embedding problem. Composition remains rich enough for beta
mail, but its structured model deliberately excludes the arbitrary HTML
round-trip behavior expected from a web editor.
