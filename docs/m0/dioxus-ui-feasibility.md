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

| ID | Criterion | Required result | Register status |
|---|---|---|---|
| `M0-DIOXUS-001` | Locked dx-free Apple build | Exact Dioxus 0.7.9; direct Cargo; no `dx`, Manganis, Dioxus devtools package, backend, or remote assets | `diagnostic` |
| `M0-DIOXUS-002` | Unsigned Apple packages | Debug macOS arm64, iOS simulator arm64, and iOS device arm64 packages and archives | `blocked` |
| `M0-DIOXUS-003` | Live UI evidence | Mac and simulator screenshots with both stable OCR markers | `open` |
| `M0-DIOXUS-004` | Hand virtualization | Exactly 10,000 logical rows; measured viewport plus fixed overscan; computed range and independent DOM count | `diagnostic` |
| `M0-DIOXUS-005` | Semantic structure | Landmarks, labels, list/listitem positions, focus treatment, live status, reduced motion | `diagnostic` |
| `M0-DIOXUS-006` | Text input | Multiline textarea with spellcheck, autocapitalize, derived character status, and no explicit application save | `open` |
| `M0-DIOXUS-007` | Safe-area and lifecycle diagnostics | CSS environment insets plus Tao resumed/suspended markers | `open` |
| `M0-DIOXUS-008` | Loopback transport | Source pinned to `127.0.0.1`, 256-byte mutual keys, live listeners loopback-only | `diagnostic` |
| `M0-DIOXUS-009` | Navigation boundary | No link surface in the mock; non-Dioxus schemes rejected; hostile production navigation fully interceptable | `failed` |
| `M0-DIOXUS-010` | Ephemeral WebKit storage | Non-persistent `WKWebsiteDataStore` with no unmanaged cookies/cache/local storage | `failed` |
| `M0-DIOXUS-011` | App Sandbox compatibility | Loopback transport works under minimal reviewed entitlements | `open` |
| `M0-DIOXUS-012` | Target notices | Locked target-specific Rust inventory bundled byte-for-byte | `diagnostic` |
| `M0-DIOXUS-013` | Physical-device accessibility | VoiceOver, Dynamic Type, Full Keyboard Access, contrast, switch control | `open` |
| `M0-DIOXUS-014` | Physical-device input | IME, autocorrect, dictation, selection, copy/paste, and hardware keyboard | `open` |
| `M0-DIOXUS-015` | Lifecycle and resources | foreground/background, lock/unlock, memory warning, protected data, energy, memory | `open` |
| `M0-DIOXUS-016` | Signed distribution | TestFlight install, notarized Mac build, and App Review smoke test | `open` |

The IDs are stable register identifiers, not claims that GitHub issues exist.
The authoritative status and evidence requirements are in
[`gate-register.json`](gate-register.json). Missing evidence is never a pass.

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

Launch measurements in `metrics.json` cover time until the Mac window/listener
harness or simulator launch command reports success. They include harness and
process-spawn overhead and are not time-to-interactive or cold-versus-warm
product comparisons. The evidence-only script activates one Dioxus
list-position control, performs its real DOM scroll, and injects one
programmatic textarea input. OCR before and after those actions verifies both
the computed range and a separate DOM query, and the derived character count
proves that Dioxus processed the input event. It does not prove scrolling frame
rate, bounds throughout arbitrary scrolling, operating system keyboard
behavior, accessibility quality, or physical input behavior. Tao lifecycle
markers are required from iOS transitions; the macOS path does not emit a
reliable initial `Resumed` event.

The simulator and Mac evidence use only synthetic content. No diagnostic log
contains message data, addresses, credentials, paths, or user-generated text.

The local CoreSimulator runtime remains unavailable because the installed
framework is 1051.54 while Xcode 26.6 requires 1051.55. The separate Dioxus
Apple CI job owns simulator launch evidence. Every physical-device criterion
remains open regardless of simulator success.

See [ADR 0005](../architecture/adr-0005-dioxus-diagnostic-runtime.md) for the
production blockers and adoption decision.
