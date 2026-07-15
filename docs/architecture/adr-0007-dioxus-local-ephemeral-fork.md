# ADR 0007: Dioxus local ephemeral diagnostic fork

## Status

Accepted for M0 source and host diagnostics only. It does not approve a
production UI baseline or change the M1 block.

## Context

Upstream `dioxus-desktop` 0.7.9 does not expose Wry's incognito option and
opens `http`, `https`, and `mailto` URLs through `webbrowser` before invoking
its configurable navigation handler. Its intercepted-anchor IPC path also
opens a browser without applying that handler. The unpatched upstream package
therefore remains failed for M0-DIOXUS-009 and M0-DIOXUS-010.

No upstream issue or pull request specifically covering this exact 0.7.9
navigation-and-incognito boundary was identified when this ADR was written.
This ADR deliberately does not invent a reference.

## Decision

Vendor pristine `dioxus-desktop` 0.7.9 under `vendor/` and select it through a
same-version `[patch.crates-io]` override. Wry is not patched. The local fork:

- adds `Config::with_incognito(bool)` and passes its value to
  `WebViewBuilder::with_incognito(bool)`;
- makes navigation a pure ordered decision: Dioxus internal one-shot handling,
  configured application handler, then upstream-compatible external-browser
  fallback;
- shares only the navigation handler with the application so the intercepted
  anchor IPC route cannot launch an external browser after a denial.

The diagnostic spike opts into incognito and deny-all navigation. Its denial
handler emits `TERSA-DIOXUS-NAV-DENIED`. The vendor tree is reproducible from
the crates.io 0.7.9 archive, the registry checksum captured from the unpatched
`Cargo.lock` in `patches/dioxus-desktop-0.7.9.lock-checksum`, and the reviewable
patch file. Cargo removes a patched package's registry checksum from the active
lock entry, so the immutable companion record preserves the source checksum.
The verifier fails if archive verification, patch application, or byte-for-byte
vendor comparison does not succeed.

The vendor fork is a maintained-drift risk. Any Dioxus version bump, patch or
checksum-record change, or Wry behavior change invalidates this diagnostic and
requires a new review.

The verifier uses an existing Cargo cache entry when available. On a clean
runner, where the path override gives Cargo no reason to cache the registry
archive, it downloads the versioned archive from `static.crates.io` and rejects
it before extraction unless the captured SHA-256 checksum matches. Offline runs
can provide the same archive explicitly with `--archive`.

## Consequences

M0-DIOXUS-009 and M0-DIOXUS-010 may be recorded as `diagnostic` with
source/host evidence for this locally patched fork only. Their required tier
remains `device-signed`. Non-persistent WebKit storage does not mean zero
in-memory state. The `dioxus://` custom scheme does not expose a usable cookie
API in the host probe, so cookie persistence is not exercised. No production
navigation, storage, sandbox, signed-device, or distribution claim follows.

M1-UI-001 remains blocked, `ui_baseline_approved` remains false, and every
other blocker in ADR-0005 remains untouched.
