# OAuth Authorization Code and PKCE feasibility

## Decision

The M0 callback transport is feasible for both Apple targets. The macOS path
has also completed a development-signed live run against the owner's Google
account; the authoritative gate remains open because that run was not captured
as the commit-bound, retained, independently attested evidence the gate
requires.

- Rust generates independent 256-bit verifier and state values from the OS
  CSPRNG and always derives an RFC 7636 S256 challenge.
- The authorization request uses `gmail.readonly` for Gmail access and
  `openid` only to obtain the immutable OIDC subject used by the account-
  identity gate. It contains no client secret.
- macOS binds `127.0.0.1` on an ephemeral port before returning the browser
  URL. Its HTTP receiver discards malformed or speculative connections, then
  consumes the first syntactically valid callback on the exact provider-
  documented root path. It accepts only GET from a loopback peer, applies an
  8 KiB request bound and absolute read deadline, and returns fixed non-
  reflecting success or error responses.
- iOS uses `ASWebAuthenticationSession`, an exact build-injected callback
  scheme, and `prefersEphemeralWebBrowserSession = true`.
- Every syntactically valid callback, provider error, malformed OAuth outcome,
  cancellation, or expiry atomically consumes the pending session. Malformed
  transport connections do not prevent the browser callback that follows.

## Evidence boundary

CI uses a public non-functional client identifier, a public test callback
scheme, and deterministic fake callbacks. It builds the macOS, iOS device, and
iOS simulator targets, verifies exported bridge symbols and Info.plist values,
and executes an ad-hoc-signed macOS sandbox probe that needs both inbound and
outbound loopback networking.

On 2026-08-01, Step 3f exercised a Release/arm64 build signed with an Apple
Development identity and the full committed production entitlements. The
owner completed consent in the browser; Tersa exchanged the loopback code,
stored the refresh token in the group-scoped Keychain, fetched read-only Gmail
data into the encrypted mailbox, rendered messages, and then disconnected with
a confirmed provider revoke, local token deletion, and mailbox purge. The
concrete Google Desktop client required its issued `client_secret` at the token
endpoint even with PKCE. [PR #76](https://github.com/matteoscurati/tersa.app/pull/76)
landed optional build-time support for that non-confidential native-app
configuration; the value stayed in ignored local configuration and was neither
committed nor logged.

This is not evidence of:

- the `M0-OAUTH-001` device-signed gate, because no immutable retained evidence
  artifact and independent evidence attestation were registered;
- authorization against a Google Workspace account;
- physical-device browser lifecycle behavior;
- Google restricted-scope verification or CASA;
- Developer ID, notarized, or distributable release behavior.

## Security invariants

Authorization state, verifier, and returned code have redacted debug output and
zeroizing storage. Callback state comparison is constant-time. Redirect
identity is exact, duplicate query parameters are rejected, and replay is
terminal. Pending iOS sessions are removed automatically at their deadline. No
sensitive value is written to logs or evidence artifacts.

The literal loopback bind and peer check reduce exposure but do not authenticate
the browser. Another local process can reach the port. Unpredictable state
prevents callback injection, while PKCE prevents an intercepted code from being
redeemed without its verifier.

## Remaining work

The live implementation keeps access tokens in memory, persists only the
refresh token in a device-only Keychain item, and serializes refresh per
account. Remaining hardening is tracked separately: the
[distinct token Keychain access group](https://github.com/matteoscurati/tersa.app/issues/51),
[durable revoke-unconfirmed state](https://github.com/matteoscurati/tersa.app/issues/80),
[client-side operation deadlines](https://github.com/matteoscurati/tersa.app/issues/81),
[complete Swift FFI call inventory](https://github.com/matteoscurati/tersa.app/issues/82),
and [offline freshness UI](https://github.com/matteoscurati/tersa.app/issues/83).
None weakens the invariants above or reopens the completed Step 3 delivery
slice; gate closure still requires the separately governed evidence tier.
