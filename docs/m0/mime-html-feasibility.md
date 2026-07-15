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
- decoded display content to 256 KiB;
- display charsets to UTF-8 and US-ASCII;
- transfer decoding to bounded 7bit, 8bit, binary, base64, and
  quoted-printable input.

Attachment bodies and unsupported content types cannot become display output.
`multipart/alternative` prefers sanitized HTML and falls back to escaped plain
text. The resulting markup is wrapped in a typed `SafeHtml` value whose inner
string is private. Active elements and all attributes are removed; remote,
JavaScript, data, file, and CID URLs never remain in markup. CID references are
reported only as inert typed placeholders.

The hostile synthetic corpus covers malformed boundaries, invalid encodings,
unsupported charsets, broken headers, excessive nesting and parts, active SVG
and script content, CSS URLs, forms, refresh directives, remote images, unsafe
schemes, CID references, attachment exclusion, and deterministic output.

## Native Apple boundary

The Swift policy is independent of Dioxus and Wry. Both Apple targets compile
the same policy with:

- `WKWebsiteDataStore.nonPersistent()`;
- `WKWebpagePreferences.allowsContentJavaScript = false`;
- a compiled content rule list that blocks every subresource class;
- a controlled inert document base with literal-loopback hostile URLs;
- fail-closed navigation actions, responses, and new-window handling;
- aggregate-only evidence and an empty nonpersistent website-data inventory.

The macOS archive is ad-hoc signed with App Sandbox and network client enabled,
but has no network server entitlement. Keeping client access available makes
the canary a meaningful WebKit-policy test instead of a sandbox-only denial.
The verifier first sends a positive-control request to its external loopback
canary, resets the count, runs both Rust-sanitized and raw hostile documents,
then requires zero canary hits and zero TCP listeners. This distinguishes a
working detector from an
unobserved network attempt while adding sandbox enforcement to the WebKit
policy controls.

## Evidence contract

The dedicated `mime-apple-evidence` CI job:

1. regenerates and compares target-specific third-party notices;
2. cross-builds the locked portable diagnostic for macOS, iOS device, and iOS
   simulator;
3. archives the native macOS and iOS targets and builds the simulator target;
4. exports current Rust sanitizer output into the macOS app resource;
5. checks signed entitlements, positive-control canary behavior, listeners,
   native policy flags, navigation denial, output hashes, and website data;
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
