# M0 Slint UI feasibility evidence

## Scope

`tersa-slint-spike` is an Apple-only diagnostic mock. It has English synthetic
data, a 10,000-row virtualized inbox, search input, and multiline composer.
Stable screenshot markers are `TERSA-SLINT-M0-THREAD` and `INBOX / 10,000 ROWS`.
It has no Gmail, OAuth, storage, network, HTML, WKWebView, or production claim.

The M0 Slint production gate is **failed on iOS accessibility**. Slint 1.16.1
routes Winit accessibility through `accesskit_winit` 0.30.0, whose iOS platform
adapter is a no-op. The diagnostic remains useful packaging evidence, but Slint
cannot be selected for production unless an upstreamable iOS accessibility
adapter passes the physical-device gate. Per the product plan, the next UI
feasibility candidate is Dioxus WebView. Its bounded spike is documented in
[Dioxus UI feasibility](dioxus-ui-feasibility.md); that spike is also a
production NO-GO until its listed blockers are resolved. WKWebView-over-Metal
composition and the remaining physical-device checks are still open evidence.

## Evidence

| ID | Check | Register status | Evidence or follow-up |
|---|---|---|---|
| `M0-SLINT-001` | macOS unsigned Rust/Slint package | `diagnostic` | Xcode 26.6 arm64 debug package and per-commit Release archive. |
| `M0-SLINT-002` | iOS device unsigned Rust/Slint package | `diagnostic` | Xcode 26.6 arm64 device package and per-commit Release archive. |
| `M0-SLINT-003` | Mac and simulator screenshots | `open` | Per-commit OCR-verified evidence artifact required. |
| `M0-SLINT-004` | Skia archive integrity | `diagnostic` | All supported Apple archives are verified before extraction. |
| `M0-SLINT-005` | Physical-device input | `open` | IME, autocorrect, dictation, selection, copy/paste, and hardware keyboard. |
| `M0-SLINT-006` | VoiceOver, Dynamic Type, and Full Keyboard Access | `failed` | `accesskit_winit` 0.30.0 selects its no-op iOS adapter. |
| `M0-SLINT-007` | Lifecycle, memory warning, and protected data | `open` | Physical-device evidence required. |
| `M0-SLINT-008` | Performance, RAM, and scroll behavior | `open` | Physical-device evidence required. |
| `M0-SLINT-009` | OAuth callback | `open` | Physical-device evidence required. |
| `M0-SLINT-010` | Hostile WKWebView composition | `open` | Physical-device evidence required. |
| `M0-SLINT-011` | Share sheet, file picker, and notifications | `open` | Physical-device evidence required. |
| `M0-SLINT-012` | Signed TestFlight and App Review | `open` | Signed-distribution evidence required. |

The stable IDs are gate-register identifiers, not claims that GitHub issues
exist. The authoritative status and evidence requirements are in
[`gate-register.json`](gate-register.json).

## Verified Skia archives

The shared archive helper downloads `rust-skia` 0.90.0 archives from the
official `rust-skia/skia-binaries` GitHub release path and verifies each
archive before making it available to `skia-bindings`. Xcode and every
workspace-wide macOS CI build call the same helper:

- macOS: `skia-binaries-da4579b39b75fa2187c5-aarch64-apple-darwin-gl-metal-pdf-textlayout.tar.gz`, SHA-256 `ffce3a615d922cb6358ec98cc3796541c350fbe0a67e1d46aaaa34d3483eee59`
- iOS device: `skia-binaries-da4579b39b75fa2187c5-aarch64-apple-ios-gl-metal-pdf-textlayout.tar.gz`, SHA-256 `dd62d2aeb55dffbdeedee9a2d095b7ac28e11ce0e86ec57e7c05e895bef267e2`
- iOS simulator: `skia-binaries-da4579b39b75fa2187c5-aarch64-apple-ios-sim-gl-metal-pdf-textlayout.tar.gz`, SHA-256 `9142067da699773e0cc042e27b8c90d8356db90203955be42a9bb27b4955e2d4`

Both URLs use the prefix
`https://github.com/rust-skia/skia-binaries/releases/download/0.90.0/`.

Target-specific third-party notices are generated from the locked diagnostic
runtime graph with `cargo-about` 0.9.1. CI regenerates them offline and compares
them byte-for-byte with the resources packaged by Xcode.

CI treats screenshots as evidence only when Vision OCR finds the product marker
and visible diagnostic rows. The exact 10,000-row label is also required in each
packaged binary and in the unobstructed macOS screenshot. This split keeps iOS
evidence valid when a first-boot system card covers the app header without
weakening the packaged row-budget assertion. Missing or blank evidence fails
the job and artifact upload.

The local CoreSimulator runtime could not be exercised because the installed
framework is 1051.54 while Xcode 26.6 requires 1051.55. CI owns the simulator
runtime evidence. Launch metrics in the CI artifact measure time until the
process or simulator launch command is observed; they are diagnostics, not
time-to-interactive performance claims.
