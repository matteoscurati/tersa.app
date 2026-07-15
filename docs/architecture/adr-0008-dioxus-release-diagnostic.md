# ADR 0008: Dioxus Release diagnostic build

## Status

Accepted for the unsigned M0 diagnostic only. M1 remains blocked and
`ui_baseline_approved` remains false.

## Scope

This decision changes only the checksum-bound local `dioxus-desktop` 0.7.9
fork, its reproducible patch, and the Apple diagnostic build and evidence path.
It makes the feature-minimal Apple Release diagnostic compile without enabling
Wry's `devtools` feature or private WebKit APIs.

## Decision

Compile the existing `dioxus-toggle-dev-tools` menu-handler arm,
`show_devtools` state, initializer, and Help-menu devtools block only when
`debug_assertions` is enabled. The menu block uses a compile-time guard rather
than `cfg!`, so Release binaries omit the devtools strings deterministically.
Debug retains upstream behavior.

Build and archive the unsigned macOS, iOS simulator, and iOS device diagnostics
in Release. The runtime verifier pins each source guard and fails if `devtools`
appears in Wry's resolved feature set for any Apple target. The evidence script
fails closed when either macOS or iOS Release binary contains
`dioxus-toggle-dev-tools`, `Toggle Developer Tools`, `developerExtrasEnabled`,
or `_inspector`.

## Evidence

The vendor verifier reconstructs the fork from the crates.io 0.7.9 archive,
the immutable registry checksum record, and the patch with `--fuzz=0`, then
byte-compares it with `vendor/`. Locked Release Cargo builds cover macOS arm64,
iOS device arm64, and iOS simulator arm64. Unsigned Xcode archives and host or
simulator evidence remain diagnostic evidence only.

## Consequences

M0-DIOXUS-002 moves from `blocked` to `diagnostic` at the existing
`device-unsigned` evidence tier. Its required tier remains `device-signed`.
The patch is a maintained-drift risk: any upstream version, checksum, patch,
or relevant Wry feature change requires review and renewed evidence.

## Risks

String absence is a narrow negative control, not proof that every private API
or inspector capability is absent. Release compilation and unsigned packaging
do not prove Apple signing, notarization, TestFlight behavior, runtime
stability, sandbox compatibility, accessibility, or App Review acceptance.

## Exclusions and nonclaims

This decision does not approve Dioxus as the production UI, close any
physical-device gate, change the Tokio, transport, navigation, storage, or
sandbox blockers, or change ADR-0007's navigation-and-incognito decision.
M1-UI-001 remains blocked and `ui_baseline_approved` remains false.
