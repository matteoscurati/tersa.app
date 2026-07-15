# ADR 0009: Dioxus sandboxed transport diagnostic

## Status

Accepted as the design for collecting host-only M0 diagnostic evidence. The
gate remains open until an immutable exact-head artifact is recorded. M1
remains blocked and `ui_baseline_approved` remains false.

## Decision

The checksum-bound `dioxus-desktop` 0.7.9 fork keeps its synchronous loopback
transport but bounds unauthenticated handshakes to eight slots. The accept loop
only accepts a TCP stream and either assigns a slot to a worker or closes the
excess stream immediately. The worker applies one monotonic absolute deadline
across the complete WebSocket upgrade and server-key write. RAII releases every
slot on success, rejection, parse failure, timeout, peer close, or unwind.

Each listener/key rotation has a monotonic generation. A worker authenticates
and changes connection state only while its captured generation remains active.
Connection teardown changes `Connected` to `Pending` only when its generation
still owns that map entry. This prevents an old or rejected connection from
clobbering a newer live connection. While holding the connection-map write
lock, teardown restores the unacknowledged edit first and drains every queued
edit in FIFO order before publishing `Pending`; cancellation is never accepted
as a WebView acknowledgement. No graceful-shutdown machinery is added.

The macOS evidence path leaves the Xcode archive unsigned. It copies the app,
ad-hoc signs only the copy with an exact three-key entitlement allowlist, checks
the effective entitlement plist, and runs the same minimal write canary with and
without that entitlement allowlist. The sandboxed canary must be denied outside
its container and the unsandboxed negative control must succeed. The stable UI
markers and loopback-only listener proof then run against the sandboxed app PID.
The existing navigation and isolated-HOME WebKit residue probes remain on the
unsigned archive. A local exploratory sandbox run left the WebView blank after
the synthetic denied anchor; that observation is not promoted to repeatable
evidence here. This decision therefore makes no sandboxed-navigation or
sandboxed-storage claim.

## Consequences

M0-DIOXUS-011 remains `open` at the `none` tier until CI produces an immutable,
exact-head host artifact and that artifact is independently reviewed and
recorded. Its required tier stays `device-signed`. The fork change re-runs the
existing unsigned host evidence for M0-DIOXUS-008, M0-DIOXUS-009, and
M0-DIOXUS-010 without changing their scope. It makes no physical-device,
signed-device, UI-baseline, distribution, or production claim.

## Risks and nonclaims

App Sandbox compatibility on an ad-hoc-signed host copy does not establish
provisioned signing, notarization, TestFlight, App Review, physical-device
network behavior, or production transport suitability. The diagnostic retains
a loopback server entitlement and detached worker threads; a production
candidate still requires independent security and Apple-platform review. The
exploratory blank WebView after a denied synthetic anchor is an unresolved
sandboxed-runtime risk, not accepted behavior or a repeatable gate result.
