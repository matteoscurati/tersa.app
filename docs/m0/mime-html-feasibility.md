# MIME and hostile HTML feasibility

## Decision status

This M0 slice validates a bounded, synthetic MIME-to-display path and the
minimum native WKWebView containment controls required before production mail
rendering can be designed. It is diagnostic code in `apps/mime-spike` and
separate native Swift targets. It is not promoted into the shared core.

Every host result is labeled `NOT A DEVICE-GATE RESULT`.

## Portable boundary

`tersa-mime-spike` exclusively owns exact-pinned `mail-parser` 0.11.5 and
`ammonia` 4.1.3. It has no workspace dependencies and performs no network I/O.
Before parser invocation it rejects an encoded message larger than 512 KiB.
The deterministic traversal then limits:

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

Attachment bodies and unsupported content types cannot become display output.
`multipart/alternative` prefers sanitized HTML and falls back to escaped plain
text. The resulting markup is wrapped in a typed `SafeHtml` value whose inner
string is private. Active elements and all attributes are removed; remote,
JavaScript, data, file, and CID URLs never remain in markup. CID references are
reported only as inert typed placeholders.

The hostile synthetic corpus covers malformed boundaries, invalid encodings,
unsupported charsets, broken headers, excessive nesting and parts, active SVG
and script content, CSS URLs, forms, refresh directives, remote images, unsafe
schemes, CID references, attachment exclusion, duplicate security headers,
non-terminal or non-canonical base64 padding, invalid 7bit and US-ASCII bytes,
and deterministic output.

## Native Apple boundary

The Swift policy is independent of Dioxus and Wry. Both Apple targets compile
the same policy with:

- `WKWebsiteDataStore.nonPersistent()`;
- `WKWebpagePreferences.allowsContentJavaScript = false`;
- a compiled content rule list that blocks every subresource class;
- a controlled inert document base with literal-loopback hostile URLs;
- an explicit inert navigation probe for fail-closed action handling, plus
  fail-closed response and new-window handling;
- aggregate-only evidence and an empty nonpersistent website-data inventory.

The macOS archive is ad-hoc signed with App Sandbox and network client enabled,
but has no network server entitlement. Keeping client access available makes
the canary a meaningful WebKit-policy test instead of a sandbox-only denial.
The diagnostic target alone permits arbitrary WebKit transport so App
Transport Security cannot make the protected result pass vacuously. The
verifier first runs an in-app WKWebView without the content blocker and
requires exactly one loopback request plus an observed response denial. It
then resets the canary, runs both Rust-sanitized and raw hostile documents with
the protected configuration, and requires zero canary hits and zero TCP
listeners. Explicit inert probes also exercise action and new-window denial.
The broad transport exception is test-only and is not a production entitlement
or application setting.

## Evidence contract

The dedicated `mime-apple-evidence` CI job:

1. regenerates and compares target-specific third-party notices;
2. cross-builds the locked portable diagnostic for macOS, iOS device, and iOS
   simulator;
3. archives the native macOS and iOS targets and builds the simulator target;
4. exports current Rust sanitizer output into the macOS app resource;
5. checks signed entitlements, the exact diagnostic-only ATS exception, in-app
   transport-control behavior, listeners, native policy flags, action,
   response, and new-window denial, independently derived output hashes, and
   website data;
6. uploads only aggregate text and JSON evidence.

No token, message content, hostile fixture, URL, filesystem path, or raw WebKit
log is an evidence artifact.

## Non-claims and remaining gates

This result does not prove:

- arbitrary or real-world MIME safety beyond the bounded synthetic corpus;
- production parsing correctness, international charset support, or RFC edge
  case interoperability;
- fuzzing, memory-pressure, attachment parser, decompression-bomb, or worker
  sandbox safety;
- iOS simulator or physical-device runtime behavior;
- WebKit behavior under physical-device lifecycle, lock, backgrounding, or
  memory warnings;
- accessibility, remote-image consent UX, CID scheme handling, or link opening;
- a production renderer, cache policy, File Protection, or plaintext lifetime;
- absence of WebKit or parser zero-days.

M0 still requires a physical-iPhone hostile-content run, fuzzing and corpus
expansion, lifecycle and protected-data tests, and a production data-flow
review before this boundary can move into `crates/mail-mime`.
