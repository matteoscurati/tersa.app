# OAuth Authorization Code and PKCE feasibility

## Decision

The M0 callback transport is feasible for both Apple targets, subject to real
Google authorization and physical-device validation in a later gate.

- Rust generates independent 256-bit verifier and state values from the OS
  CSPRNG and always derives an RFC 7636 S256 challenge.
- The authorization request uses only `gmail.modify` and contains no client
  secret.
- macOS binds `127.0.0.1` on an ephemeral port before returning the browser
  URL. Its one-shot HTTP receiver accepts only an exact GET callback path from
  a loopback peer, accepts only the provider-documented root redirect, applies
  an 8 KiB request bound and deadline, and returns a fixed non-reflecting
  response.
- iOS uses `ASWebAuthenticationSession`, an exact build-injected callback
  scheme, and `prefersEphemeralWebBrowserSession = true`.
- Every success, provider error, malformed callback, cancellation, or expiry
  atomically consumes the pending session.

## Evidence boundary

CI uses a public non-functional client identifier, a public test callback
scheme, and deterministic fake callbacks. It builds the macOS, iOS device, and
iOS simulator targets, verifies exported bridge symbols and Info.plist values,
and executes an ad-hoc-signed macOS sandbox probe that needs both inbound and
outbound loopback networking.

This is not evidence of:

- authorization against a real Google consumer or Workspace account;
- token endpoint compatibility;
- refresh-token persistence or Keychain behavior;
- Gmail API access;
- physical-device browser lifecycle behavior;
- Google restricted-scope verification.

## Security invariants

Authorization state, verifier, and returned code have redacted debug output and
zeroizing storage. Callback state comparison is constant-time. Redirect
identity is exact, duplicate query parameters are rejected, and replay is
terminal. No sensitive value is written to logs or evidence artifacts.

The literal loopback bind and peer check reduce exposure but do not authenticate
the browser. Another local process can reach the port. Unpredictable state
prevents callback injection, while PKCE prevents an intercepted code from being
redeemed without its verifier.

## Deferred work

The next OAuth slice must exchange the validated code without a client secret,
keep the access token in memory, store only the refresh token in a device-only
Keychain item, serialize refresh per account, and exercise real Google test
accounts. It must not weaken any invariant established here.
