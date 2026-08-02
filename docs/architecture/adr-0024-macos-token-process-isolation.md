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

| Process | Keychain group | Other required capabilities |
| --- | --- | --- |
| `TersaMac` | installation root/store group only | App Sandbox, network client/server, App Group |
| token broker XPC service | refresh-token group only | App Sandbox and network client |

The main app will not carry the token access-group entitlement. The broker will
not carry the installation root/store Keychain group or App Group entitlement.
The broker owns OAuth code exchange, refresh, refresh-token persistence,
rotation, deletion, and provider revoke. It exposes a closed, versioned XPC
protocol for those operations and never returns a refresh token. A successful
exchange or refresh may return only the bounded short-lived access token and the
already validated subject required by the account-identity gate. Gmail mailbox
fetch and SQLCipher ownership remain in the main process.

The broker must accept connections only from the embedded, same-team Tersa app,
validate every bounded request again at the service boundary, serialize token
mutation per account, reject unknown protocol versions and operations, and fail
closed if the service is unavailable. There is no in-process Keychain fallback,
environment/file credential channel, or generic Keychain-operation RPC.

The current app has not been distributed. Migration therefore deliberately
discards the development refresh-token item and requires owner-driven
re-consent. No migration build may temporarily give one executable both the new
token group and the root/store group. The legacy development credential must be
removed before release-candidate evidence is captured.

## Required implementation and evidence

Issue #51 remains open until all of the following are complete:

1. Register the dedicated token Keychain group under the production Apple team.
2. Add the embedded XPC service target and the closed IPC protocol; move token
   exchange, refresh, persistence, rotation, deletion, and revoke behind it.
3. Remove token-group authority and direct refresh-token Keychain reachability
   from `TersaMac`; keep root/store authority out of the broker.
4. Extend dependency, source, target, and entitlement inventories so drift in
   either process fails CI.
5. In a development-signed build, prove normal token operations succeed, a
   broker root-targeted probe receives `errSecMissingEntitlement`, and a main-app
   token-targeted probe receives `errSecMissingEntitlement`.
6. Repeat entitlement inspection and both negative controls on the exact
   Developer ID signed and notarized release candidate.

The probes must be fixed-purpose test entries and must not expose a generic
Keychain mutation capability. Evidence must be redacted, commit-bound, and
independently reviewed under the existing distribution protocol.

## Consequences

This decision replaces issue #51's same-process access-group design; it does not
weaken the requested operating-system boundary. It also amends ADR 0023's
current-process token ownership for the release architecture. The extra process
and IPC protocol increase implementation and packaging cost, but produce a real
principal boundary that code changes inside either process cannot bypass without
also changing the signed entitlement topology.

This ADR implements no XPC target, entitlement, Keychain migration, signed
runtime proof, notarization, or distribution evidence. Until those items land,
the source guard is defense in depth and final distribution remains blocked by
issue #51.
