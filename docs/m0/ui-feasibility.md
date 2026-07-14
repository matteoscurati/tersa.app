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
feasibility candidate is Dioxus WebView. WKWebView-over-Metal composition and
the remaining physical-device checks are still open evidence.

## Evidence

| Check | Status | Evidence or follow-up |
|---|---|---|
| macOS unsigned Rust/Slint package | **PASS locally; required CI gate** | Xcode 26.6 arm64 debug package and per-commit Release archive; `#M0-SLINT-001` |
| iOS device unsigned Rust/Slint package | **PASS locally; required CI gate** | Xcode 26.6 arm64 device package and per-commit Release archive; `#M0-SLINT-002` |
| Mac and simulator screenshots | **Required CI gate** | Per-commit OCR-verified evidence artifact; `#M0-SLINT-003` |
| Skia archive integrity | **PASS locally; required CI gate** | All supported Apple archives are verified before extraction; `#M0-SLINT-004` |
| Physical-device IME, autocorrect, dictation, selection, copy/paste, hardware keyboard | **UNVERIFIED** | `#M0-SLINT-005` |
| VoiceOver accessibility tree | **FAIL by dependency inspection** | `accesskit_winit` 0.30.0 selects its no-op platform adapter on iOS; physical-device confirmation remains `#M0-SLINT-006` |
| Dynamic Type and Full Keyboard Access | **UNVERIFIED** | `#M0-SLINT-006` |
| Lifecycle, memory warning, protected data | **UNVERIFIED** | `#M0-SLINT-007` |
| Performance, RAM, scroll behavior | **UNVERIFIED** | `#M0-SLINT-008` |
| OAuth callback | **UNVERIFIED** | `#M0-SLINT-009` |
| Hostile WKWebView composition | **UNVERIFIED** | `#M0-SLINT-010` |
| Share sheet, file picker, notifications | **UNVERIFIED** | `#M0-SLINT-011` |
| Signed TestFlight and App Review | **UNVERIFIED** | `#M0-SLINT-012` |

Issue references are documented M0 placeholders until the repository issue
tracker is provisioned; they are stable names for the required follow-up work.

## Verified Skia archives

The build script downloads `rust-skia` 0.90.0 archives from the official
`rust-skia/skia-binaries` GitHub release path and verifies each archive before
making it available to `skia-bindings`:

- macOS: `skia-binaries-da4579b39b75fa2187c5-aarch64-apple-darwin-gl-metal-pdf-textlayout.tar.gz`, SHA-256 `ffce3a615d922cb6358ec98cc3796541c350fbe0a67e1d46aaaa34d3483eee59`
- iOS device: `skia-binaries-da4579b39b75fa2187c5-aarch64-apple-ios-gl-metal-pdf-textlayout.tar.gz`, SHA-256 `dd62d2aeb55dffbdeedee9a2d095b7ac28e11ce0e86ec57e7c05e895bef267e2`
- iOS simulator: `skia-binaries-da4579b39b75fa2187c5-aarch64-apple-ios-sim-gl-metal-pdf-textlayout.tar.gz`, SHA-256 `9142067da699773e0cc042e27b8c90d8356db90203955be42a9bb27b4955e2d4`

Both URLs use the prefix
`https://github.com/rust-skia/skia-binaries/releases/download/0.90.0/`.

Target-specific third-party notices are generated from the locked diagnostic
runtime graph with `cargo-about` 0.9.1. CI regenerates them offline and compares
them byte-for-byte with the resources packaged by Xcode.

CI treats screenshots as evidence only when Vision OCR finds both the product
marker and the 10,000-row marker. Missing or blank evidence fails the job and
artifact upload.

The local CoreSimulator runtime could not be exercised because the installed
framework is 1051.54 while Xcode 26.6 requires 1051.55. CI owns the simulator
runtime evidence. Launch metrics in the CI artifact measure time until the
process or simulator launch command is observed; they are diagnostics, not
time-to-interactive performance claims.
