# ADR 0010: Dioxus sandboxed navigation classification

## Status

Accepted as the design for a host-only diagnostic classifier. This ADR records
the classifier design only; it records no observed probe result and changes no
gate status.

## Context

The existing unsigned diagnostic verifies denied navigation callbacks, but an
exploratory sandboxed host launch previously suggested that a denied navigation
could blank the WebView. A diagnostic must distinguish a control or rendering
failure from a rendered page that becomes blank after the denied action without
changing Dioxus, Wry, or WebKit vendor behavior.

## Decision

When `TERSA_DIOXUS_EVIDENCE` is set, the optional
`TERSA_DIOXUS_SANDBOX_PROBE` accepts exactly `anchor`, `ipc`, or `location`.
The application rejects a probe without evidence and rejects every other value
before its event loop starts. Each value executes exactly one corresponding
denied URL in its own ad-hoc-signed sandboxed process:

- `anchor` uses `https://example.invalid/anchor`.
- `ipc` uses `https://example.invalid/ipc-browser-open`.
- `location` uses `https://example.invalid/location`.

The page announces `SANDBOX PROBE <NAME> ARMED` before the action. The harness
captures that screen and OCR before waiting for the single action. A zero-delay
post-action callback announces `SANDBOX PROBE <NAME> FIRED` only if rendering
survives long enough to run it.

The static runtime verifier requires the evidence gate and each probe marker in
their expected order and exactly once. Its existing prohibition on declarative
external-navigation elements remains active for the diagnostic UI.

Before every probe, the harness derives the diagnostic bundle identifier and
removes that bundle's actual App Sandbox container. It captures the process
log, listener state, ARMED and final screenshots/OCR, and the presence of
directories named `WebKit` or `WebsiteData` below container `Data`.
The harness refuses to remove a container unless the embedded bundle identifier
is exactly the diagnostic macOS identifier.

## Outcome taxonomy and CI semantics

The classifier writes exactly one of these outcomes for each probe:

- `RENDERED_PRESERVED`: the final OCR contains `FIRED` and both stable core UI
  markers.
- `BLANK_AFTER_DENIAL`: the exact denial log is present and final OCR contains
  neither stable core UI marker.

Either enumerated outcome exits successfully so CI can retain evidence. Missing
ARMED, a missing exact denial log, premature process exit, a non-loopback
listener, or ambiguous final OCR exits nonzero. A blank result is evidence, not
a success claim. The final screenshot and OCR are captured only after the exact
native denial log has been observed.

## Stop conditions and nonclaims

This classifier is host-only and diagnostic. It does not establish device
signing, production sandbox compatibility, storage persistence, zero residue,
or behavior on every operating-system WebKit surface. It records only selected
directory names under the fresh diagnostic container; it does not claim that
all WebKit surfaces were enumerated. M0-DIOXUS-009, M0-DIOXUS-010, and
M0-DIOXUS-011 remain host-only diagnostics, `ui_baseline_approved` remains
false, and M1 remains blocked.

The investigation stops and records an architecture decision instead of adding
more harness patches when any probe deterministically produces
`BLANK_AFTER_DENIAL`. A failure of the no-probe sandbox baseline requires a
smaller Wry-only reproduction. Flaky outcomes across repeated runs of the same
commit require redesigning the probe handshake. Any need to change the existing
unsigned probes or vendor navigation behavior also stops this work and reports
the blocker instead of patching vendor code.
