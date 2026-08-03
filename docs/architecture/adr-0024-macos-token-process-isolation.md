<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0024: macOS token/root isolation across signed processes

- Status: Accepted
- Date: 2026-08-02

## Context

ADR 0023 stores the OAuth refresh token and the installation root key as
different Keychain items. Source guards confine refresh-token mutation to the
reviewed adapter and keep the root item add-only. Issue #51 proposed strengthening
that separation by giving the two items different Keychain access groups while
keeping both adapters in `TersaMac`.

That proposal cannot create the claimed runtime barrier. Keychain access-group
authorization is granted to a signed executable through its entitlements; code
linked into that process does not receive a narrower entitlement set. If
`TersaMac` carries both groups, every code path in `TersaMac` runs with both
capabilities. A token adapter linked into that executable therefore cannot be
made to receive `errSecMissingEntitlement` for the root group merely by naming a
different group in its normal queries.

Apple's documentation describes Keychain sharing as access granted to apps by
their signed access-group entitlements and describes an XPC service as a
separately executable, sandboxed helper embedded in an app:

- [Sharing access to Keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- [TN3137: On Mac Keychains](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [Embedding a helper tool in a sandboxed app](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app)

The existing lexical guards remain valuable review controls, but repository
source inspection cannot turn two libraries in one process into mutually
untrusted principals.

## Decision

The release architecture will isolate refresh-token authority in a separately
signed embedded XPC service. The process capabilities are disjoint:

| Process | Keychain group | Other required capabilities | Required signing posture |
| --- | --- | --- | --- |
| `TersaMac` | installation root/store group only | App Sandbox, network client/server, App Group | Hardened Runtime; library validation enabled |
| token broker XPC service | refresh-token group only | App Sandbox and network client | Hardened Runtime; library validation enabled |

The main app will not carry the token access-group entitlement. The broker will
not carry the installation root/store Keychain group or App Group entitlement.
The broker owns OAuth code exchange, refresh, refresh-token persistence,
rotation, deletion, and provider revoke. It exposes a closed, versioned XPC
protocol for those operations and never returns a refresh token. A successful
exchange or refresh may return only the bounded short-lived access token and the
already validated subject required by the account-identity gate. Gmail mailbox
fetch and SQLCipher ownership remain in the main process.

The main app owns the IPv4 loopback listener and passes its ephemeral redirect
URI to the broker before authorization begins. The broker generates and retains
the PKCE verifier and state, returns the authorization URL plus an opaque session
handle, validates the forwarded callback for that session, and redeems the code.
The verifier and refresh token never cross IPC. Seeing the callback code in the
main process is insufficient to redeem it without the broker-held verifier. This
choice keeps `network.server` out of the broker and pins it to `TersaMac`.

Both release processes must omit `get-task-allow`,
`com.apple.security.cs.debugger`,
`com.apple.security.cs.disable-library-validation`, and
`com.apple.security.cs.allow-dyld-environment-variables`. The target and
entitlement inventories treat presence or enablement of any of those exceptions
as a release-blocking violation. Without this posture, debugger attachment or
library injection could collapse the process boundary while leaving the
Keychain-group table apparently disjoint.

The broker must accept connections only from the embedded Tersa app by applying
`NSXPCConnection.setCodeSigningRequirement(_:)` with the reviewed team and
designated requirement. PID-based identity checks are forbidden because PID
reuse is not a signing identity. The broker validates every bounded request
again at the service boundary, serializes token mutation per account, rejects
unknown protocol versions and operations, and fails closed if the service is
unavailable. There is no in-process Keychain fallback, environment/file
credential channel, or generic Keychain-operation RPC.

Disconnect retains the ordering `outer intent → SQLCipher marker → broker
revoke → broker token delete → main-app purge → marker clear`. If the broker is
unavailable, the app preserves `IncompleteTeardown` and reports an unconfirmed
failure; it never reports a clean disconnect or purges away the recovery
evidence. Short-lived access tokens returned to the main process remain
memory-only, cycle-scoped, zeroized on drop, and are never persisted or logged.

The current app has not been distributed. Before the entitlement split, a build
that still carries only the legacy group must best-effort revoke and then delete
the development refresh-token item. An explicit absence query must confirm the
item is gone; absence is not assumed. The split build then introduces the new
broker group and requires owner-driven re-consent. No migration build may give
one executable both the new token group and the root/store group.

## Required implementation and evidence

Issue #51 remains open until all of the following are complete:

1. Register the dedicated token Keychain group under the production Apple team.
2. Add the embedded XPC service target and the closed IPC protocol; move token
   exchange, refresh, persistence, rotation, deletion, and revoke behind it.
3. Remove token-group authority and direct refresh-token Keychain reachability
   from `TersaMac`; keep root/store authority out of the broker.
4. Extend dependency, source, target, entitlement, Hardened Runtime, library
   validation, and forbidden-debug-capability inventories so drift in either
   process fails CI.
5. In a development-signed build, prove normal token operations succeed, a
   broker root-targeted probe receives `errSecMissingEntitlement`, and a main-app
   token-targeted probe receives `errSecMissingEntitlement`.
6. Repeat entitlement inspection and both negative controls on the exact
   Developer ID signed and notarized release candidate. Prove debugger attach
   and `task_for_pid` from the main app to the broker fail under the exact
   release signing posture.

Items 2 through 4 are implemented in source and fail-closed in CI as of the
point-4 cutover (see *Current packaging status*). Items 1, 5, and 6 remain
unproved: they require external registration and signed-runtime evidence
that this repository cannot produce or attest by inspection.

The probes must be fixed-purpose test entries, set
`kSecUseDataProtectionKeychain`, and must not expose a generic Keychain mutation
capability. Only `errSecMissingEntitlement` passes a wrong-group negative
control; `errSecItemNotFound` is a failed probe. Evidence must be redacted,
commit-bound, and independently reviewed under the existing distribution
protocol.

## Consequences

This decision replaces issue #51's same-process access-group design; it does not
weaken the requested operating-system boundary. It also amends ADR 0023's
current-process token ownership for the release architecture. The extra process
and IPC protocol increase implementation and packaging cost, but produce a real
principal boundary that code changes inside either process cannot bypass without
also changing the signed entitlement topology.

## Current packaging status

The repository now includes the embedded `TersaMacTokenBroker` XPC packaging
target: an XcodeGen target, a closed version-1 NSXPC protocol surface extended
with the reviewed operational status set, a fail-closed service entry point
bound to the dedicated Rust broker composition, disjoint broker entitlement
declarations, and xtask inventory guards for those shapes.

The portable token-broker lifecycle core exists as the
`tersa-token-broker-core` workspace crate (`adapters/token-broker-core`). It
implements the broker's process-agnostic OAuth/token logic over generic ports:
authorization begin/complete with a bounded TTL'd PKCE session registry, code
exchange, refresh, rotation, per-subject serialized token mutation, a
refresh-token store port, revoke/delete separation, zeroizing public token
results, and a closed error surface. It deliberately contains no
Security.framework/Keychain code, no C ABI, and no IPC.

Point 3 binds that core into the XPC service through the dedicated
`tersa-token-broker-ffi-macos` static archive (`adapters/token-broker-ffi-macos`):
production Google token transport, the broker-only Data Protection Keychain
store fixed to the dedicated token access group and token service, a narrow
redacted C ABI, the closed operational `TersaTokenBrokerStatusV1` wire set,
the main-app `TokenBrokerClient` / status mapping / authorization-session
surface, and deterministic unit tests for those mappings. The main app still
links only its mailbox-sync FFI archive; point 4 (below) has since completed
the production cutover that moves token authority off the legacy in-process
path.

Three operational properties of that core remain binding for the service.
First, Google's revocation endpoint is grant-wide:
revoking any one token of a grant revokes every token minted for the same
Google user and OAuth client. The core therefore runs its stranded-grant
cleanup revoke only against a definitively empty local store snapshot. That
snapshot is per-install local state, not global grant knowledge: a second
install or device holding credentials for the same user/client grant is
invisible to it, so an empty-snapshot cleanup revoke can still invalidate
that other install's grant. This residual risk is accepted for the
best-effort cleanup; an unconditional revoke on every failed completion was
rejected precisely because it would multiply such cross-install damage.
Second, an explicitly under-scoped first-connect completion
(`InsufficientScope`) is deliberately non-destructive: the broker persists
nothing and revokes nothing, because the under-scoped outcome carries no
validated identity and no subject-keyed snapshot exists to gate a
grant-wide revoke. The accepted cost is that this path can leave a live
under-scoped grant at Google, and the app CANNOT revoke it in-app — the
minted tokens were dropped and there is no validated subject or stored
credential to revoke against. The only remedies are the point-3 UI recovery
below (retain-or-retry, or external manual revocation). Third, the core
enforces a hard 1,024-byte bound on provider-minted refresh
tokens, and Google documents no maximum length. A rotation exceeding the
bound is rejected as `MalformedResponse` before any persistence or revoke
input, so the failure mode is a visible terminal error, never a truncation
or a partial write. Monitoring should read a sustained rise in refresh-path
`MalformedResponse` terminals as a possible provider-side change outgrowing
the bound — a signal to review the constant — not only as response
corruption.

A deliberate identity asymmetry behind these properties is recorded once so
point 3 and reviewers do not normalize it away: a granted refresh
re-validates the exact stored subject FIRST and refuses to persist anything
— including a valid rotation — when the provider answer belongs to a
different subject, while an explicitly under-scoped refresh CANNOT validate
identity at all (the scope verdict is decided before claims validation) and
persists a valid rotation solely as a local revocation handle for the grant
before reporting the scope failure. The two paths intentionally treat a
rotation differently.

Point 3 has extended `TersaTokenBrokerStatusV1` from the five skeleton cases
to the reviewed closed operational set (stable integers only; no open-ended
strings, codes, or error payloads). The XPC operation-to-status mapping and
the main app's status-to-UI mapping preserve the four distinct recovery
semantics end to end: unconfirmed provider revocation
(`RevokeUnconfirmed` / operation-aware `PersistenceFailed` during revoke)
stays visibly distinct from a clean teardown; an explicitly under-scoped
grant (`InsufficientScope`) keeps Gmail-specific recovery and a safe link
to Google Account permissions for external manual revocation; revoked
consent and missing refresh token (`ConsentRevoked`, `MissingRefreshToken`)
route to re-connect; and exchange-time authorization-code rejection
(`AuthorizationCodeRejected`) maps to the existing
`ConnectionFailure.signInExpired` UI recovery and never folds into ordinary
provider rejection or consent revoked. `PersistenceFailed` from
`delete_stored_tokens` maps to incomplete local teardown and never looks
clean.

Operational binding and the closed client/mapping surface are implemented,
and point 4 has completed the production cutover described in the next
subsection. What remains open is strictly the signed-runtime evidence: the
dedicated token Keychain group is declared for the broker only and, unless
externally completed, is not yet registered or provisioned under the
production team — the repository cannot prove external registration;
development-signed runtime success and both wrong-group
`errSecMissingEntitlement` fixed-purpose probes are not yet run; and the
exact Developer ID signed and notarized release-candidate entitlement
inspection, negative controls, and debugger/`task_for_pid` evidence are not
yet produced. Builds remain unsigned unless an operator configures signing
locally; the local unsigned Debug arm64 `TersaMac` build with the embedded
broker succeeds, but an unsigned build proves no process-isolation property.
This ADR still implements no signed runtime proof, notarization, or
distribution evidence. Until the remaining required-evidence items land,
final distribution remains blocked by issue #51.

### Point-4 production cutover and legacy credential disposition

Point 4 has moved the main macOS production flow onto the broker.
`TokenBrokerAuthorizationSession` / `TokenBrokerClient` now drive consent,
exchange completion, stored-token refresh, revoke, and delete through the
embedded XPC service over the closed version-1 protocol. The main process
keeps Gmail access-token sync and SQLCipher ownership: a successful exchange
or refresh returns only the bounded short-lived access token and the
validated subject. The subject is stored in the encrypted mailbox database
through `tersa_mailbox_macos_broker_subject_store`; the access token is
memory-only, handed to `tersa_mailbox_macos_broker_sync_begin`, and wiped
in place immediately after that FFI call returns (and on box deinit if a
queued begin never runs). It is never persisted or logged.

Disconnect runs the decided ordering: outer intent journal, then the Rust
prepare marker/fence, then broker revoke, then the mandatory broker token
delete, then the Rust finalize purge and marker clear. Revoke-unconfirmed
stays visibly distinct from a clean teardown, and a failed delete gates the
local purge — the finalize never runs on a delete failure, so the marker
and the recovery evidence survive for the retry path.

The production dependency and ABI contract now matches that flow. The
mailbox-sync FFI's production edge to `tersa-apple-bridge` sets
`default-features = false`, disabling the bridge's `legacy-oauth` feature,
and the main app's graph never enables the Keychain `oauth-token` feature;
the mailbox-sync FFI declares no legacy feature and exports no legacy C
symbols in production. Its shipped static archive surface is exactly the
seven reviewed broker mailbox exports plus the bridge's five reviewed safe
reexports — twelve symbols total. `tersa-apple-bridge`'s `legacy-oauth`
remains available for the direct/iOS bridge composition and dev tests;
`tersa-oauth-sync-macos`'s `legacy-token-lifecycle` remains opt-in only
for legacy/test compositions and is not enabled by the production main-app
graph. xtask source
guards and the CI archive symbol/string checks fail closed on any
`_tersa_oauth_macos_*` global symbol, on the three retired mailbox begins
(`_tersa_mailbox_macos_sync_begin`, `_tersa_mailbox_macos_connect_begin`,
`_tersa_mailbox_macos_disconnect_begin`), and on the embedded strings
`oauth_token` and `DataProtectionRefreshTokenStore`. `cargo xtask
architecture` passes with these fail-closed source, dependency, ABI,
header, Swift-call, handoff, and deinit guards in place.

The legacy development credential is disposed. Before the cutover the owner
completed a live legacy disconnect and observed the confirmed
disconnected / local-mail-purged outcome. On 2026-08-03 the non-secret query
`security find-generic-password -s app.tersa.mac.oauth-refresh-token.v1 -a primary-gmail`
returned exit 44 (item not found), which is explicit evidence that the
legacy development refresh-token item is absent. This is
development-item absence evidence only; it is not signed process-isolation
proof and does not discharge any pending required-evidence item above.
