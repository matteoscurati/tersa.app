# MIME and hostile HTML feasibility

> **Historical record only (PR4).** The M0 MIME/hostile-HTML diagnostic
> executable (`apps/mime-spike` / `tersa-mime-spike`), isolated `fuzz/` project,
> Apple `TersaMimeMac` / `TersaMimeIOS` targets, `apple/scripts/verify-mime-feasibility.sh`,
> `scripts/verify-mime-fuzz.sh`, `about-mime.toml`, and
> `THIRD_PARTY_NOTICES-mime-*` outputs were removed by ADR-0025 housekeeping
> (PR4). Commands, package names, and paths below are non-executable historical
> text pending PR5 consolidation. This document does not claim an active MIME
> renderer, `SafeHtml` implementation, restricted WKWebView, parser, or
> diagnostic in the product graph. Hostile-content handling remains a product
> requirement tracked by the open `M0-MIME-001` gate.

## Decision status

This M0 slice validated a bounded, synthetic MIME-to-display path and the
minimum native WKWebView containment controls required before production mail
rendering can be designed. It was diagnostic code in the retired
`apps/mime-spike` tree and separate native Swift targets. It was not promoted
into the shared core.

Every historical host result is labeled `NOT A DEVICE-GATE RESULT`.

## Portable boundary (historical)

The retired `tersa-mime-spike` exclusively owned exact-pinned `mail-parser`
0.11.5 and `ammonia` 4.1.4. It had no workspace dependencies and performed no
network I/O. Before parser invocation it rejected an encoded message larger
than 512 KiB. The deterministic traversal then limited:

- MIME nesting to 12 containers;
- total MIME parts to 128;
- headers in each part to 96 and 24 KiB;
- singleton `Content-Type`, `Content-Disposition`, and
  `Content-Transfer-Encoding` fields in each part;
- decoded display content to 256 KiB;
- display charsets to UTF-8 and US-ASCII, with declared US-ASCII bytes
  enforced;
- transfer decoding to bounded ASCII-only 7bit, 8bit, binary, canonically
  padded base64, and quoted-printable input.

Attachment bodies and unsupported content types could not become display
output. `multipart/alternative` preferred sanitized HTML and fell back to
escaped plain text. The resulting markup was wrapped in a typed `SafeHtml`
value whose inner string was private. Active elements and all attributes were
removed; remote, JavaScript, data, file, and CID URLs never remained in markup.
CID references were reported only as inert typed placeholders.

The hostile synthetic corpus covered malformed boundaries, invalid encodings,
unsupported charsets, broken headers, excessive nesting and parts, active SVG
and script content, CSS URLs, forms, refresh directives, remote images, unsafe
schemes, CID references, attachment exclusion, duplicate security headers,
non-terminal or non-canonical base64 padding, invalid 7bit and US-ASCII bytes,
and deterministic output.

## Deterministic fuzz regression (historical)

The retired excluded `fuzz` Cargo project exercised the same public
`inspect_synthetic_mime` entry point. It exact-pinned nightly `2026-07-14`,
`cargo-fuzz` 0.13.2, and `libfuzzer-sys` 0.4.13 in a separate lockfile. Its
compact seed corpus covered empty input, input-size boundaries, multipart
boundaries and nesting, folded and duplicate headers, base64 and
quoted-printable edges, attachment exclusion, unsupported charsets, active
HTML and unsafe URLs, and CID extraction.

For every generated input, the target derived one of a small fixed set of
resource-limit combinations from a six-byte prefix, invoked the parser twice,
and required identical typed results. Successful results also had to keep HTML
within conservative input and decoded-display expansion bounds and return CID
placeholders that were nonempty, bounded, sorted, unique, and identical across
runs. The finite verifier replayed all committed seeds before requesting 10,000
total libFuzzer target executions, including corpus initialization, in one
process with fixed seed, maximum length, timeout, and RSS limits.

The fuzz graph was not part of any application workspace, binary, or
third-party notice. Its isolated deny policy allowed NCSA solely for
`libfuzzer-sys`; that license was not present in the shipping graph.

## Native Apple boundary (historical)

Both retired Apple diagnostic targets compiled the same reviewed policy source
with:

- `WKWebsiteDataStore.nonPersistent()`;
- `WKWebpagePreferences.allowsContentJavaScript = false`;
- a compiled content rule list that blocked every subresource class;
- a controlled inert document base with literal-loopback hostile URLs;
- an explicit inert navigation probe for fail-closed action handling, plus
  fail-closed response and new-window handling;
- aggregate-only evidence and an empty nonpersistent website-data inventory.

The macOS archive was ad-hoc signed with App Sandbox and network client
enabled, but had no network server entitlement. Keeping client access available
made the canary a meaningful WebKit-policy test instead of a sandbox-only
denial. The diagnostic target alone permitted arbitrary WebKit transport so App
Transport Security could not make the protected result pass vacuously. The
historical verifier first ran an in-app WKWebView without the content blocker
and required exactly one loopback request plus an observed response denial. It
then reset the canary, ran both Rust-sanitized and raw hostile documents with
the protected configuration, and required zero canary hits and zero TCP
listeners. Explicit inert probes also exercised action and new-window denial.
The broad transport exception was test-only and was not a production
entitlement or application setting.

## Historical evidence contract (non-executable)

MIME Apple diagnostic evidence was local-only through the retired
`sh apple/scripts/verify-mime-feasibility.sh` path; that path is
non-executable after PR4 and was never merge-blocking CI. After the locked
portable cross-builds and macOS archive existed, that historical script:

1. exported then-current Rust sanitizer output into the macOS app resource;
2. checked signed entitlements, the exact diagnostic-only ATS exception, in-app
   transport-control behavior, listeners, native policy flags, action,
   response, and new-window denial, independently derived output hashes, and
   website data;
3. wrote only aggregate text and JSON evidence locally.

MIME parser fuzz evidence was local-only through the retired
`sh scripts/verify-mime-fuzz.sh` path once the pinned nightly and fuzz driver
were installed. That historical script pinned the nightly toolchain and
cargo-fuzz version, verified seed count and checksums, detected lock mutation,
built the fuzz target, replayed every seed, and performed the fixed finite fuzz
run. It did not validate fuzz formatting, Clippy/lint, license, source, or
advisory policy. Those checks were never merge-blocking CI after diagnostic CI
retirement. The script did not modify application notices or the shipping
dependency graph.

No token, message content, hostile fixture, URL, filesystem path, or raw WebKit
log was an evidence artifact.

## Non-claims and remaining gates

The historical result did not prove, and this record does not claim:

- arbitrary or real-world MIME safety beyond the bounded synthetic corpus;
- production parsing correctness, international charset support, or RFC edge
  case interoperability;
- exhaustive or continuous fuzz coverage, memory-pressure, attachment parser,
  decompression-bomb, or worker sandbox safety;
- iOS simulator or physical-device runtime behavior;
- WebKit behavior under physical-device lifecycle, lock, backgrounding, or
  memory warnings;
- accessibility, remote-image consent UX, CID scheme handling, or link opening;
- a production renderer, cache policy, File Protection, or plaintext lifetime;
- absence of WebKit or parser zero-days;
- that any MIME parser, sanitizer, `SafeHtml` type, restricted WKWebView, or
  diagnostic remains in the active product tree.

M0 still requires a physical-iPhone hostile-content run, continuing corpus and
fuzz-budget expansion, lifecycle and protected-data tests, and a production
data-flow review before a hostile-content boundary can move into a production
mail-MIME path. `M0-MIME-001` remains open because its required evidence is
device-signed; the historical finite host regression does not alter the gate
register. Full M0 study consolidation is deferred to PR5.
