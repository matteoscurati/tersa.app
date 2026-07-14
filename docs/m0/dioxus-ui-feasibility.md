# M0 Dioxus WebView UI feasibility evidence

## Scope and verdict

`tersa-dioxus-spike` is an Apple-only diagnostic mock built with Dioxus 0.7.9,
Wry, and the operating system WebKit framework. It uses English synthetic data,
a handwritten 10,000-row virtualizer, semantic HTML, a search field, a
multiline composer, safe-area CSS, and lifecycle markers. Stable screenshot
markers are `TERSA-DIOXUS-M0-THREAD` and `INBOX / 10,000 ROWS`.

It has no Gmail, OAuth, backend, remote asset, message HTML, credentials, or
mail storage. The only runtime socket is Dioxus's authenticated ephemeral
WebSocket listener bound to `127.0.0.1`.

The current verdict is:

- **GO for the bounded diagnostic and physical-device investigation.**
- **NO-GO for production adoption.** The persistent WebKit data store,
  incomplete external-navigation interception, App Sandbox listener boundary,
  unavoidable Tokio runtime, feature-minimal macOS Release failure, lifecycle
  gaps, and physical-device evidence are unresolved blockers.

## Stable acceptance criteria

| ID | Criterion | Required result | Current status |
|---|---|---|---|
| `#M0-DIOXUS-001` | Locked dx-free Apple build | Exact Dioxus 0.7.9; direct Cargo; no `dx`, Manganis, Dioxus devtools package, backend, or remote assets | **PASS locally; required CI gate** |
| `#M0-DIOXUS-002` | Unsigned Apple packages | Debug macOS arm64, iOS simulator arm64, and iOS device arm64 packages and archives | **PASS locally; required CI gate; Release blocked** |
| `#M0-DIOXUS-003` | Live UI evidence | Mac and simulator screenshots with both stable OCR markers | **Required CI gate** |
| `#M0-DIOXUS-004` | Hand virtualization | Exactly 10,000 logical rows; visible range plus fixed overscan only; live rendered-row counter | **PASS by code; CI must prove at most 100 DOM rows before and after a synthetic scroll** |
| `#M0-DIOXUS-005` | Semantic structure | Landmarks, labels, list/listitem positions, focus treatment, live status, reduced motion | **PASS by code; VoiceOver unverified** |
| `#M0-DIOXUS-006` | Text input | Multiline textarea with spellcheck, autocapitalize, character status, no persistence | **CI must prove DOM input propagation; physical input remains unverified** |
| `#M0-DIOXUS-007` | Safe-area and lifecycle diagnostics | CSS environment insets plus Tao resumed/suspended markers | **CI must prove a notched simulator inset and active/inactive markers; rotations and lifecycle edges remain unverified** |
| `#M0-DIOXUS-008` | Loopback transport | Source pinned to `127.0.0.1`, 256-byte mutual keys, live listeners loopback-only | **PASS locally; required CI gate** |
| `#M0-DIOXUS-009` | Navigation boundary | No link surface in the mock; non-Dioxus schemes rejected; hostile production navigation fully interceptable | **FAIL for production** |
| `#M0-DIOXUS-010` | Ephemeral WebKit storage | Non-persistent `WKWebsiteDataStore` with no unmanaged cookies/cache/local storage | **FAIL in Dioxus 0.7.9** |
| `#M0-DIOXUS-011` | App Sandbox compatibility | Loopback transport works under minimal reviewed entitlements | **UNVERIFIED** |
| `#M0-DIOXUS-012` | Target notices | Locked target-specific Rust inventory bundled byte-for-byte | **PASS locally; required CI gate** |
| `#M0-DIOXUS-013` | Physical-device accessibility | VoiceOver, Dynamic Type, Full Keyboard Access, contrast, switch control | **UNVERIFIED** |
| `#M0-DIOXUS-014` | Physical-device input | IME, autocorrect, dictation, selection, copy/paste, and hardware keyboard | **UNVERIFIED** |
| `#M0-DIOXUS-015` | Lifecycle and resources | foreground/background, lock/unlock, memory warning, protected data, energy, memory | **UNVERIFIED; memory warning API missing** |
| `#M0-DIOXUS-016` | Signed distribution | TestFlight install, notarized Mac build, and App Review smoke test | **UNVERIFIED** |

The IDs are stable M0 placeholders until the repository issue tracker is
provisioned. A required CI gate fails on missing evidence; it is not converted
to a pass by documentation.

## Build and runtime boundary

The application is a standalone Rust executable. Tao owns the Apple event loop;
it is not called through the existing Swift `UIApplicationMain` bootstrap.
Both Xcode targets are source-free packages whose build phase copies the Cargo
binary and exact notice resource. This is the only supported dx-free path for
the spike.

`dioxus-desktop` starts one private WebSocket listener on an ephemeral
`127.0.0.1` port. It creates 256-byte random client and server keys, compares
the client key in constant time, and returns the server key to the WebView. CI
pins those source invariants and uses `lsof` against both live processes to
reject wildcard or IPv6-any listeners.

This socket is not a backend and carries only synthetic UI edits in the spike.
It is nevertheless a network server from the operating system's perspective.
The diagnostic Mac target does not claim App Sandbox compatibility.

## Evidence interpretation

Launch measurements in `metrics.json` cover time until a window or simulator
launch command is observed. They are not time-to-interactive claims. The
evidence-only script performs one programmatic list scroll and one programmatic
textarea input. OCR before and after those actions proves that Dioxus propagated
both DOM events and kept the sampled rendered-row count bounded. It does not
prove scrolling frame rate, bounds throughout arbitrary scrolling, operating
system keyboard behavior, accessibility quality, or physical input behavior.

The simulator and Mac evidence use only synthetic content. No diagnostic log
contains message data, addresses, credentials, paths, or user-generated text.

The local CoreSimulator runtime remains unavailable because the installed
framework is 1051.54 while Xcode 26.6 requires 1051.55. The separate Dioxus
Apple CI job owns simulator launch evidence. Every physical-device criterion
remains open regardless of simulator success.

See [ADR 0005](../architecture/adr-0005-dioxus-diagnostic-runtime.md) for the
production blockers and adoption decision.
