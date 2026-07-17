<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0019: macOS key provisioning and read-only CLI

- Status: Accepted
- Date: 2026-07-16
- Amended: 2026-07-17

## Context

Phase 1 roadmap item 7 needs a read-only macOS CLI over the encrypted account
store. Giving that executable a database path or key on its command line would
create a second, unsafe provisioning channel. Reusing the existing read-write
store opening path could create, claim, migrate, configure, or otherwise mutate
a profile merely because a user asked to read it. A live WAL database also
cannot be opened with SQLite's `immutable=1` promise because the file is not
immutable and committed WAL content must remain visible.

The direct local reader is an interim composition boundary. The planned
`maild` owner remains outside the MVP, but a later IPC client must be able to
replace the direct reader without changing the CLI's public JSON contract.

## Decision

The CLI work is divided into independently reviewed pull requests. The final
slice was split after the repository preflight found no usable Developer ID
Application identity or configured notarization authority. Ad-hoc signing and
unsigned builds cannot substitute for that evidence:

1. **PR 30 — policy:** this ADR, dependency documentation, and fail-closed
   reservations only. It adds no crate, dependency, key access, store opening,
   command, or gate evidence.
2. **PR 31 — strict read-only SQLCipher open:** the existing macOS store adapter
   now owns persistent WAL coordination, the separately named
   `SqlCipherMailboxReader::open_read_only` constructor, and deterministic
   standalone/coexistence and fail-closed tests.
3. **PR 32 — macOS Keychain and private HKDF boundary:** add
   `tersa-keychain-macos`, the inward platform contract it implements, and the
   reviewed provisioning/retrieval internals and application-group locator.
   It exposes no raw root or derived key and no database opener. This pull
   request replaces and activates the Keychain reservation.
4. **PR 33a — deterministic metadata-only JSON CLI source:** add
   `tersa-cli-macos` with exactly the `inbox` and `thread` commands, activate
   its dependency policy, and compose private Keychain retrieval and derivation
   directly with strict read-only SQLCipher opening. This slice adds no Apple
   distribution target and makes no signed interoperability claim.
5. **PR 33a.5 — credentialless product-application bootstrap source:** add the
   source-only composition that lets the product application provision the
   fixed installation root and establish or open the fixed account profile
   through the existing validated read-write SQLCipher path. It adds no new
   executable, Xcode target, signing configuration, entitlement, package, or
   distribution surface.
6. **PR 33b — signed CLI distribution evidence:** add the bundled `mailctl`
   target and its closed signing, entitlement, packaging, and symlink policy;
   then capture the real same-team Developer ID, notarization, sandbox, App
   Group, and cross-target Data Protection Keychain evidence.

Each later pull request requires exact-head independent review and must replace
its reservation with an explicitly activated policy. Merely adding a reserved
crate makes the architecture check fail. Phase 1 roadmap item 7 remains open
after PR 33a and PR 33a.5 and closes only when PR 33b satisfies its external
evidence gate. This governance amendment authorizes PR 33a.5 but implements no
bootstrap, edits no gate register, and passes no gate.

### Root-key lifecycle and derivation

The product application, never the CLI, provisions exactly one installation
root key when the fixed Keychain item is absent. It generates 32 bytes with
Apple's CSPRNG and stores them as a generic-password item with service
`app.tersa.mac.storage-root.v1`, account `default`,
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, synchronization disabled,
and the shared application-group identifier as `kSecAttrAccessGroup`. Every
add and copy query omits `kSecAttrSynchronizable` and sets
`kSecUseDataProtectionKeychain` to true; an attribute-returning copy accepts
the synchronization attribute only when it is absent or false. Update and
delete operations are not implemented. There is no legacy-keychain fallback.
Missing entitlement, unexpected item attributes, or a query that cannot use
the Data Protection Keychain fails closed. Existing items are retrieved but
never replaced implicitly. The PR 33a CLI has retrieval-only access: an
absent item is an error and cannot cause key generation, import, repair,
rotation, or a second Keychain write.

For the PR 33a.5 product bootstrap, an absent root does not by itself authorize
provisioning. While holding the global bootstrap lock and before generating any
key, the trusted composition inspects the fixed profile tree
descriptor-relatively with no-follow semantics. New-state provisioning is
allowed only when `profiles` is absent or the entire existing tree is an empty
fixed skeleton: `profiles` contains no entry other than an optional `default`;
`default` contains no entry other than an optional `accounts`; and `accounts`
contains no entries. The global lock file at the App Group root is not profile
state. Any account-digest directory, database, rollback journal, WAL,
shared-memory file, or other child under `profiles` is conservatively existing
profile state. A fixed
component that exists as a symlink, non-directory, or otherwise unexpected
object also counts as existing profile state. An inspection error fails closed
without mutation.

Only a validated Keychain item-not-found result enters this profile preflight.
An entitlement, attribute, access-group, decoding, or other retrieval failure
fails closed before the profile tree is inspected and cannot authorize
provisioning.

If the root is absent and existing profile state is present, the composition
must not generate or store a key, mutate the profile tree, or open, migrate,
repair, or otherwise mutate the store. The already validated permanent global
lock file may have been created before this determination; it is the only
permitted filesystem effect. The composition returns the distinct closed
redacted product-bootstrap status `root_missing_with_existing_profile`, not
corruption.
There is no automatic delete, replacement, import, or recovery. Migration
Assistant, backup restore, and re-signing into a different Keychain access group
are recorded causes; recovery belongs to a later separately reviewed path owned
by the product application. The CLI continues to report its fixed key-access
failure and remains retrieval-only; it cannot recover this state. Deterministic
tests must cover absent-root empty/new state, absent-root existing fixed or
unexpected profile state, and concurrent calls where the first valid bootstrap
provisions and the serialized follower retrieves the winner.

Provisioning uses an add-only `SecItemAdd` operation, never an add-or-update
password helper. On `errSecDuplicateItem`, the generated losing key is
zeroized, the process retrieves and validates the single winning item, and no
update occurs. Other add failures are terminal. PR 32 must test simultaneous
provisioners and prove they converge on the stored winner without exposing or
replacing either candidate.

PR 33b must make the macOS application and `mailctl` two targets of one
distribution. Both will be signed by the same Apple Developer team, carry the
registered `${TeamIdentifierPrefix}app.tersa.shared` application-group
entitlement, and use that group as their shared Keychain access group.
`mailctl` will have the stable bundle identifier `app.tersa.mailctl`, an
embedded Info.plist section, Hardened Runtime, and its own
`com.apple.security.app-sandbox = true` entitlement. It is
launched directly by the shell and therefore must not use
`com.apple.security.inherit`. After PR 33b, the official CLI will be the signed
executable shipped inside the app bundle; a package manager may then install
only a symlink to that exact executable, not rebuild or re-sign it
independently. Community distributions must register and inject their own
group under their own signing team. Unsigned, differently signed,
missing-entitlement, or mismatched-group builds receive no production fallback
and cannot claim Keychain/profile interoperability.

The root key is never exported or accepted through arguments, environment,
stdin, files, IPC, logs, diagnostics, or JSON. PR 32 keeps retrieval and
HKDF-SHA256 derivation private to the trusted Keychain adapter; there is no
public callback, borrowed-key API, or other raw-key capability. The salt is
the literal byte string
`tersa.app/macos/root-key/v1`. The `info` input is unambiguous framing of the
literal prefix `tersa.app/macos/hkdf-sha256/v1`, followed by a two-byte
big-endian validated account-identifier length and its UTF-8 bytes, then a
two-byte big-endian purpose length and its ASCII bytes. Purposes are a closed,
versioned enum; the initial value is `sqlcipher/account-database/v1`. Unknown
versions or purposes fail closed. Root and derived key buffers use best-effort
zeroization through one private `SecretKey` newtype whose `Drop` implementation
clears its bytes and whose only `Debug` representation is redacted. Root,
candidate, retrieved, and derived keys never use a raw byte-array value across
adapter operations and never implement serialization.
This guarantee covers explicit buffers owned by the adapter; the internal
state and temporary storage of the `hkdf`, `hmac`, and digest implementations
are outside `zeroize`'s guarantee and may leave transient copies in process
memory.
PR 33a owns the trusted composition that passes a privately derived key
directly into strict database opening without returning key bytes to the CLI.
The composition lives inside `tersa-keychain-macos`, because the crate that
owns the private `SecretKey` must consume it into the database opener without a
public accessor, callback, borrowed-key API, or cross-crate key capability.
`tersa-keychain-macos` may therefore depend inward on
`tersa-store-sqlcipher-macos` for this one composition. The store edge is
macOS-gated and its transitive SQLCipher reachability is explicitly allowed;
the Keychain adapter must not declare `rusqlite` or `libsqlite3-sys` directly.
Replacing the direct reader with `maild` requires a new reviewed boundary and
must not expose the derived bytes during that replacement.

The add-only Keychain boundary constructs its no-copy `CFData`, attribute
dictionary, and synchronous `SecItemAdd` call in one private scope. Neither the
dictionary nor any object containing the candidate pointer can escape that
scope.

PR 32 uses direct `security-framework-sys =2.17.0` with default features
disabled and only `OSX_10_15`,
`core-foundation =0.10.1`, `objc2-foundation =0.3.2` with default features
disabled and only `std`, `NSFileManager`, `NSString`, and `NSURL` enabled,
`hkdf =0.12.4`, `sha2 =0.10.9`, and `zeroize =1.9.0`. They are declared only
for the exact macOS target where applicable. The explicit Security/Core
Foundation surface exists so PR 32 can build add-only and attribute-returning
Keychain dictionaries; the high-level `security-framework` generic-password
setter is forbidden because its duplicate-item path can update existing data.
`OSX_10_15` is required for the
Data Protection Keychain API on macOS. The Foundation surface resolves and
validates the application-group container through the inward platform port.

PR 33a.5 keeps the workspace `objc2-foundation` declaration on its current four
features and adds only `NSThread` through the Keychain member's workspace
inheritance. Its effective requested feature set is therefore exactly `std`,
`NSFileManager`, `NSString`, `NSThread`, and `NSURL`. The synchronous Rust C ABI
boundary uses `NSThread::isMainThread` solely to reject direct main-thread
bootstrap calls before Keychain or filesystem access. The implementation must
update the exact Foundation feature policy and its positive and negative
fixtures; no other Foundation type or feature is authorized.

PR 33a.5 authorizes `rustix =1.1.4` as the sole new external package, with exact
direct macOS declarations in both `tersa-keychain-macos` and
`tersa-store-sqlcipher-macos`. Both use the canonical atomic target structure
`cfg(target_os = "macos")` and disable default features. The workspace
declaration remains exact-pinned with `fs` and `std`; the Keychain member adds
directly only `process`, solely for `geteuid`-based same-user validation. The
store member inherits only workspace `fs` and `std` and must not directly
request `process`. Rustix supplies safe descriptor-relative filesystem,
advisory-lock, `statat`, and `unlinkat` operations. No direct `libc` dependency,
handwritten syscall binding, or new unsafe POSIX FFI is authorized.

The exact direct-owner set is the existing portable `tersa-blob-spike`
diagnostic plus the future macOS-gated Keychain and SQLCipher-store declarations.
The blob keeps its existing member declaration and inherited `fs`/`std` request
unchanged. Policy tests must reject a direct `process` request from the blob or
store. Cargo may unify `process` into a resolved macOS rustix package shared
with the Keychain member; that graph-level unification does not mean the blob or
store directly selected the feature. Direct-declaration and resolved-feature
assertions remain separate.

On `aarch64-apple-darwin`, `tersa-cli-macos` and `tersa-apple-bridge` may reach
the protected package only through their exact edge to
`tersa-keychain-macos`, followed by either the Keychain direct rustix edge or
`tersa-keychain-macos -> tersa-store-sqlcipher-macos -> rustix`. They gain no
direct ownership. Alternate workspace parents or paths, direct CLI/bridge
declarations, iOS, and every non-macOS target fail. The policy remains scoped
to exact workspace declarations and these protected paths; unrelated
third-party rustix reachability must not trigger a false global ban.

The implementation pull request must update both closed direct-dependency sets
and enforce exact versions, canonical targets, default-feature states,
member-requested features, allowed resolved paths, and target-specific resolved
features in `xtask`. Positive fixtures cover blob, Keychain, store, and both
CLI/bridge transitive paths. Negative fixtures cover wrong owners, direct
`process` on blob/store, direct CLI/bridge declarations, alternate parents,
ungated or broadened targets, iOS, and non-macOS graphs. This governance
amendment changes no manifest, active graph, or gate.

The current HKDF release, 0.13.0, resolves HMAC 0.13; 0.12.4 is
deliberately selected because it uses the already reviewed `hmac =0.12.1`.
PR 32 narrowly expands the HMAC owner set to `tersa-blob-spike` and
`tersa-keychain-macos` after checking the exact resolved graph. ChaCha20-
Poly1305 remains exclusive to `tersa-blob-spike`.

Before PR 33a, `tersa-keychain-macos` depends inward only on `tersa-platform`.
PR 33a activates the exact additional edge to
`tersa-store-sqlcipher-macos` described above and no other edge. The platform
port in turn uses the canonical domain `AccountId` so raw account strings
cannot reach hashing or derivation. Apple Security types do not cross the port.
Additional inward edges require a new ADR rather than an incidental manifest
edit.

PR 32 proves simultaneous-provisioner convergence only against its fake
backend. Real signed cross-target Data Protection Keychain interoperability is
a PR 33b acceptance condition; this is a Fable approval condition and is not
claimed by unsigned builds or by PR 33a. PR 32 also does not claim a usable
database opener: PR 33a is responsible for connecting private derivation to the
strict reader without adding a key-export surface.

### Fixed profile layout

Production resolution accepts no database path, profile-root, Keychain
service, access group, or derivation-purpose override from command-line flags,
environment, configuration, or test hooks. The only Phase 1 production profile
is `default` under the shared application-group container returned by
`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`:

```text
<shared-group-container>/profiles/default/
  accounts/<sha256-account-id>/mail.sqlite3
```

The expanded application-group identifier is a required signing-time setting
shared by the app and CLI entitlements. Resolution must verify access to the
returned container because macOS may return an expected-form URL even for an
invalid group. It never falls back to a normal Application Support path or
either target's private sandbox container.

Every product-application bootstrap uses one non-configurable global lock file
at `<shared-group-container>/.tersa-profile-bootstrap-v1.lock`. After opening
and validating the existing App Group container and acquiring the process-local
mutex under the deadline below, `tersa-keychain-macos` opens the file
descriptor-relatively with no-follow and `O_CLOEXEC` semantics. Initial
creation uses `O_EXCL`, requests mode `0600`, retains the returned descriptor,
applies `fchmod(0600)`, and requires `fstat` to report the expected same-user
regular file at exact `0600`.

When create-new reports an existing name, the adapter first uses no-follow
`statat` beneath the validated App Group descriptor and records the expected
same-user regular-file identity and mode. A mode with no bits outside `0600` --
exactly `0000`, `0200`, `0400`, or `0600` -- is recoverable. If owner read or
write is missing, descriptor-relative no-follow `chmodat(0600)` normalizes the
fixed name. The adapter then opens the fixed name no-follow, requires `fstat` to
match the recorded identity and exact `0600`, and only then takes the advisory
lock. This bounded path handles restrictive umasks and a prior creator crashing
after create but before `fchmod`, including a `0000` file that cannot itself be
opened before owner permissions are restored. Any execute, group, or other bit,
wrong type or owner, identity change, symlink, or other attribute drift fails
closed. Creation, convergence, normalization, revalidation, and lock acquisition
all consume the same deadline. Open and normalization errors fail closed. The
lock file is never deleted, renamed, or made configurable; this missing-owner-bit
normalization is its only authorized repair.

`chmodat` still names a mutable directory entry. A same-user malicious process
can replace that entry between `statat`, `chmodat`, open, and final `fstat`; the
identity check detects an observable replacement but cannot prevent chmod from
affecting the replacement. This is an explicit unlocked-device/local-malware
residual. Deterministic hooks exercise both gaps and record the non-prevention
case without claiming atomicity.

The synchronous bootstrap C ABI runs only on the dedicated bounded `TersaMac`
bootstrap worker, never on the AppKit/main thread. The worker has concurrency
one and at most one pending operation; overflow returns the fixed redacted
`bootstrap_busy_or_unavailable` status. A direct main-thread C ABI call returns
the fixed redacted `bootstrap_invalid_execution_context` status before touching
Keychain or filesystem state. Completion may be delivered to the main thread
only after the worker call returns.

A fixed non-configurable 30-second monotonic deadline begins before the first
process-local mutex attempt and covers mutex, lock-file open/validation, and
advisory-lock acquisition. Mutex acquisition and the exclusive advisory lock use
nonblocking attempts with a fixed 10-millisecond backoff capped by the remaining
deadline. `EINTR` retries within the same remaining budget; would-block retries
after the backoff; poisoning, any other error, or deadline expiry returns
`bootstrap_busy_or_unavailable` without entering bootstrap state and releases
every guard or descriptor acquired by that attempt. After both guards are
acquired, they remain held through Keychain root retrieval, the absent-root
profile preflight, any authorized root provisioning, fixed-directory work,
store claim and migration, all pre- and post-open identity checks, every
authorized failure-cleanup attempt, and construction of the final closed
status.

Every cooperative `TersaMac` bootstrap must enter through this worker and lock
protocol; the CLI never bootstraps and receives no lock or repair authority.
PR 33a.5 proves the concurrency-one, one-pending worker contract through exact
review of `apple/macos/BootstrapWorker.swift` and its sole application call site
in `apple/macos/AppDelegate.swift`, `xtask` source-policy fixtures that pin those
bounds and paths, and only a credentialless build of the existing
`TersaMac` Xcode target. It adds no Xcode test target, scheme test action,
entitlement or signing-policy exception, and this source evidence passes no
runtime or device-signed gate. Runtime worker dispatch and overflow evidence
belongs to PR 33b. Rust deterministic tests in PR 33a.5 cover the C ABI's
`NSThread`-based main-thread rejection, timeout, injected `EINTR`, restrictive
umasks, a crash after lock-file creation but before `fchmod`, concurrent
normalization, rejection of any execute/group/other permission bit, crash
release of the advisory lock, and adversarial two-thread and two-process
interleavings around directory creation and
main/rollback-journal/WAL/shared-memory cleanup. The
interleaving tests must prove cooperative serialization through final status
rather than deletion or replacement of another bootstrap's state.

PR 33a.5 makes the product application the logical profile owner and assigns
the directory-establishment operation exclusively to the trusted composition
inside `tersa-keychain-macos`. Starting from an opened and validated existing
App Group container, that composition may walk or create only the literal
`profiles`, `default`, and `accounts` components and the lowercase digest
derived from the canonical `AccountId`. Every step is descriptor-relative and
no-follow. A newly created directory must have verified owner-only `0700`
permissions. An existing component is accepted only when it is the expected
same-user directory with no group or other permission bits. A symlink,
non-directory, wrong owner, permissive mode, changed identity, or any other
unexpected existing object fails closed; replacement and fallback are
forbidden. These descriptor-relative guarantees apply to fixed-directory
establishment and validation only. They do not replace the existing store
opener's pathname and parent-canonicalization behavior.

Concurrent creators converge without replacement: an already-existing result
from a create attempt is accepted only after the same no-follow identity,
ownership, type, and permission validation. The composition records the
identity of each directory created by its invocation. On failure it attempts
cleanup in reverse order, removing only an empty directory whose identity still
matches beneath the validated parent. It never recursively removes content or
removes a pre-existing directory. Cleanup failure preserves the original
redacted failure and may leave only validated owner-only directories; it cannot
continue into database opening. This reverse directory cleanup is authorized
only for a failure before `SqlCipherMailboxStore::open` is invoked. Once that
call begins, the composition must not remove any profile directory. Deterministic
tests must inject failure after each directory-creation boundary, verify reverse
cleanup and safe residuals, cover symlink/non-directory/permission/identity
rejection, and prove concurrent convergence.

After the fixed account directory is validated, the trusted composition passes
only the fixed `mail.sqlite3` leaf path and private derived key into the existing
validated, pathname-based `SqlCipherMailboxStore::open` path. The composition
snapshots the identity, ownership, type, and permissions of every fixed
directory component. Immediately before invoking the store, and immediately
after it returns on either success or failure, it reopens every component
descriptor-relatively with no-follow semantics and requires it to match the
snapshot. An ordinary observable parent replacement or mutation fails closed.
On a nominal store success, the composition performs this post-check before it
returns the closed bootstrap status; a failed post-check closes the store and
returns a redacted failure without directory cleanup.
The store retains its existing parent canonicalization; no validated directory
descriptor is transferred into SQLite, and this amendment does not claim an
end-to-end descriptor-bound opener. A same-user swap-in/open/swap-back between
the immediate checks remains an explicit unlocked-device/local-malware residual.

The store remains the sole owner of database-leaf creation, claiming, schema
migration, validation, and leaf cleanup. PR 33a.5 must harden the same existing
`SqlCipherMailboxStore::open` API and path for a freshly created leaf. While the
bootstrap lock is held and immediately before SQLite open, the store opens and
retains a validated account-directory descriptor solely for descriptor-relative
snapshot, `statat`, and cleanup. Through its direct rustix dependency it records
a no-follow absence/presence snapshot for exactly `mail.sqlite3`,
`mail.sqlite3-journal`, `mail.sqlite3-wal`, and `mail.sqlite3-shm`. The snapshot
classifies cleanup authorization; it does not reject an existing main database
merely because any sidecar is absent.

| Main | Rollback journal / WAL / SHM | Required behavior |
|---|---|---|
| Absent | All three absent | Fresh leaf: invoke the existing opener and permit bounded fresh-failure cleanup. |
| Present | Any combination, including all absent | Existing leaf: invoke the existing opener and migration path; never permit fresh-failure cleanup. The opener may still reject it. |
| Absent | Any one or more present | Fail closed before store open; perform no cleanup. |

This four-entry pre-open classification augments and must not weaken the
existing `database_sidecar_exists` invariant over the three suffixes
`-journal`, `-wal`, and `-shm`. In particular, the existing
`absent_with_sidecar` and `empty_with_sidecar` rollback-journal fixtures retain
their behavior: an orphan journal with no main file is preserved and fails
before open, while an empty present main plus journal enters the existing-leaf
opener and preserves the journal when that opener rejects it.

On any fresh-leaf failure before successful claim and migration, the store
first closes all SQLite handles while retaining the validated parent descriptor.
For each fixed name that was absent in the pre-open snapshot and is newly
present after close, the store may treat it as a cleanup candidate under the
cooperative-writer assumption. It uses descriptor-relative no-follow `statat`,
records identity, type, owner, and permissions after close, and revalidates
immediately before descriptor-relative `unlinkat` beneath that same retained
parent. Cleanup may remove only a same-user restrictive regular file whose
post-close identity still matches. It must never call `std::fs::remove_file`,
re-resolve the account path, remove an entry present in the pre-open snapshot,
remove an entry with changed identity, or remove a profile directory. Cleanup
failure preserves the original redacted failure and may leave restrictive
residual store files. A retry never reclassifies a nonempty residual as fresh:
it re-enters the same state matrix. A main-present residual is handled only by
the existing opener and migration path and may converge only if every existing
key, identity, sidecar, schema, and integrity invariant passes; otherwise it
fails closed. Any journal/WAL/shared-memory residual without the main file fails
closed before open. No retry gains repair or fresh-cleanup authority; unresolved
states require a later reviewed owning-product recovery path, and the CLI gains
no repair authority.

The retained parent descriptor removes parent-path re-resolution from this leaf
cleanup. The global lock serializes cooperative bootstraps only. A same-user
malicious process that ignores it can insert a fixed-name entry after the absent
snapshot but before post-close recording; the store cannot prove whether SQLite
or that process created the candidate. It can also replace the mutable fixed
final name after final identity revalidation and before `unlinkat`. macOS
provides neither creation provenance for the first gap nor an unlink-if-inode
primitive for the second. These two mutable-final-name gaps are the stated
store-cleanup residuals; no parent-path cleanup race is claimed. Deterministic
hooks must exercise insertion between snapshot and post-close recording,
replacement between recording and revalidation, and replacement in the exact
revalidation-to-`unlinkat` gap for the main file, rollback journal, WAL, and
shared-memory file. The insertion and final replacement hooks record
non-prevention rather than claiming safety; the middle hook proves that an
observable identity mismatch is preserved. The retained parent descriptor is
released on every return after the snapshot, open, and any authorized cleanup
sequence.

Deterministic tests must inject failures before and after each fresh-leaf claim
or migration boundary; cover the all-absent fresh state, every main-present
combination of the three sidecars, and every main-absent orphan-sidecar
combination; preserve the existing `absent_with_sidecar` and
`empty_with_sidecar` journal behavior; and replace each recorded entry before
cleanup to prove an identity mismatch is preserved rather than removed. Tests
must also retry every nonempty cleanup-residual subset and prove the matrix above:
main-present subsets may converge only through all existing-opener invariants,
while sidecar-only subsets fail before open. Pre-existing entries and profile
directories survive every failure, and cleanup uses only the retained
descriptor plus fixed names.
This is a hardening of the existing pathname-based SQLite opener, not a new
descriptor-bound SQLite API, opener, composition crate, or
workspace-to-workspace dependency edge. The only new external-package edges are
the exact rustix declarations authorized above. The directory composition must
not itself create, delete, replace, or repair any of the four fixed entries and
must not return the opened store or another storage capability across the bridge
boundary.

The architecture check accepts the PR 32 signing configuration only at the
exact `TersaMac` target paths. It rejects project or per-configuration
overrides, includes, target templates, setting groups, configuration files,
conditional sensitive keys, protected entitlement-path reuse, and protected
groups in every other source entitlement file. The `options` mapping is closed
to the current three entries, which rejects XcodeGen's nested `preGenCommand`
and `postGenCommand` hooks. `TersaMac` is fixed to an application target, one
exact Rust build phase, no post-build or compile phases, no build rules or
build-tool plugins, and a scheme without executable actions. Signing controls,
conditional variants, identifier expansion roots, and the bundle identifier
are exact allowlists. The project root and `TersaMac` target also have closed
top-level key sets, so project attributes, target attributes, dependencies,
and legacy target forms cannot add an alternate signing or execution surface.
Both the source entitlement and XcodeGen entitlement properties contain exactly
the same five reviewed keys; their three capability flags are boolean `true`.

All repository project generation uses the checked
`apple/scripts/generate-project.sh` wrapper with XcodeGen `--no-env`. This keeps
`${TeamIdentifierPrefix}` literal in the generated project until Xcode resolves
it. The entitlement source inventory excludes only the ignored generated
`apple/build/` tree, including local DerivedData copies and internal symlinks;
the excluded root itself must be a real directory. A separate Git-index
inventory rejects every tracked entry below `apple/build/` and every tracked
entitlement symlink, then independently enumerates all tracked entitlement
files. Every other entitlement file under `apple/` is parsed and rejected if it
claims either protected group entitlement, and any source-tree symlink fails
closed. A repository-wide tracked-file inventory permits the XcodeGen generation
command only in the byte-exact wrapper.
These surfaces require a reviewed policy change rather than attempted partial
XcodeGen resolution.

PR 33b has a CLI-specific acceptance condition independent of the later macOS
UI gate: a same-team Developer ID package must be notarized, contain the
embedded signed `mailctl`, expose only a symlink to that exact binary, and prove
a direct shell launch under its own non-inherited sandbox. Captured evidence
must verify the app and CLI code-signing identifiers and entitlements, App
Group container access, cross-target add/read of the non-synchronizable Data
Protection Keychain item, and denial after a group or signature mismatch. This
condition passes no UI, mobile, M0, or Phase 1 release gate.

PR 33b does not begin until a real Developer ID Application identity, registered
application group, and notarization authority are available to the release
operator. The product application must also have a reviewed production path
that provisions the fixed root and establishes the account profile used by the
cross-target fixture. Credentialless CI may verify policy and package structure
but cannot close any of these runtime conditions.

PR 33a.5 supplies that reviewed production source path without credentials.
It must reuse the single existing add-only Keychain provisioning channel in
`tersa-keychain-macos`; a second provisioning mechanism or key import path is
forbidden. The private derived account-database key is consumed directly by the
existing validated read-write SQLCipher opening path and is never returned to
the application, CLI, or another adapter. The `TersaMac` product application is
the sole logical profile owner and the only production authority allowed to
request profile establishment or migration. `tersa-keychain-macos` is its sole
trusted composition executor, while the existing SQLCipher writer remains the
only database-leaf creation and migration implementation. The CLI remains
retrieval-only and non-owning and must never provision, establish, claim,
migrate, or repair a profile.

The only new workspace dependency edge authorized for PR 33a.5 is a
macOS-target-gated edge from the existing `tersa-apple-bridge` composition root
to `tersa-keychain-macos`. The existing `TersaMac` product-application target is
the sole production invoker. PR 33a.5 may add exactly one macOS-gated C ABI
invocation to the existing bridge and the corresponding call from the existing
`TersaMac` application source. The call accepts only opaque account-identifier
bytes and returns only a closed success or redacted failure status. The bridge
performs only C ABI pointer/length safety, copies at most 256 opaque bytes, and
forwards them to exactly one validating bootstrap entry in
`tersa-keychain-macos`. That trusted entry performs UTF-8 and canonical domain
`AccountId::new` validation before any Apple Keychain or filesystem operation.
Empty, oversized, malformed UTF-8, or domain-invalid input returns the fixed
redacted `invalid_account_identifier` status. The bridge must not import or
construct `AccountId`, call a domain-validation helper, or gain a domain edge.
It receives narrow one-shot bootstrap command authority, not a reusable storage
capability: no raw key, store object, database handle, database path, profile,
group, derivation input, configuration, or test override crosses the bridge
boundary or is returned to it. The bridge may not depend directly on the
SQLCipher store or add another platform, application, domain, or executable
edge. The implementation PR must activate this exact edge in the dependency
policy; no other manifest edge is implied by this amendment. Name-only
allowance in `dependency_policy` is insufficient. The implementation
must also add `tersa-apple-bridge -> tersa-keychain-macos` to the exact
`protected_edge` match enforced by
`future_macos_store_dependency_violation`, so only the canonical atomic target
structure `cfg(target_os = "macos")` is accepted. `cargo_metadata` canonicalizes
equivalent whitespace and quote spelling, so source-text spelling is not a
policy boundary. Tests must prove that the canonical atomic macOS target passes
and that an untargeted edge, iOS, combined platforms, nested `all`/`any`/`not`,
feature-conditioned targets, and other semantically different or broadened
target expressions fail. This governance pull request does not add the edge or
change `xtask`; PR 33a.5 must activate the manifest and both policy layers
atomically.

PR 33a.5 must also make this validation boundary source-verifiable. The bridge
tracked-source policy accepts only pointer/length checks, the 256-byte bound,
and one call to the Keychain adapter's single validating entry. It rejects
`tersa-domain`, `AccountId`, domain-validation helpers, alternate bootstrap
entries, aliases, and reexports in bridge production sources. Deterministic
fixtures cover null/nonzero pointer combinations, lengths above 256, empty and
malformed UTF-8, canonical-domain failures, and valid identifiers. They prove
that invalid bytes produce only `invalid_account_identifier` before Apple
Keychain or filesystem access.

PR 33a.5 must also add narrow resolved-graph exceptions for
`tersa-apple-bridge` on `aarch64-apple-darwin` only. HMAC reachability is
allowed solely through the immediate workspace chain
`tersa-apple-bridge -> tersa-keychain-macos -> hkdf -> hmac`; SQLCipher
reachability is allowed solely from `tersa-apple-bridge` through
`tersa-keychain-macos`, `tersa-store-sqlcipher-macos`, `rusqlite`, and
`libsqlite3-sys` in that order. The bridge must not be added to the general
`HMAC_OWNERS` or `SQLCIPHER_OWNERS` sets and receives no direct HMAC, HKDF,
rusqlite, libsqlite3-sys, SQLCipher-store, or other crypto dependency.

The current enforcement points are `check_blob_dependency_graph` and
`blob_dependency_graph_violations` for HKDF/HMAC, and
`check_sqlcipher_dependency_graph` and
`sqlcipher_dependency_graph_violations` for SQLCipher. The implementation may
refactor those helpers only if exact semantic path tests remain. Positive tests
must prove both approved bridge paths on `aarch64-apple-darwin`; negative tests
must reject direct declarations, alternate workspace intermediaries, additional
workspace path parents, any extra crypto or SQLCipher path, iOS, and every
non-macOS target. Existing owner rules remain unchanged for all other members.

Only the canonical domain `AccountId` may select an account. Production uses
only the fixed `default` profile and the fixed paths, Keychain attributes, and
derivation purpose already defined by this ADR; command-line, environment,
configuration, or test-hook overrides remain forbidden. PR 33a.5 adds no new
executable, Xcode target, signing setting, entitlement, package, or distribution
surface. Its fake or deterministic tests are source evidence only: they are not
runtime, signing, App Group container, Data Protection Keychain interoperability,
notarization, or distribution evidence. The slice adds no OAuth, token, network,
or real-account behavior or implication. PR 33a.5 requires independent review
with zero unresolved actionable findings on its exact head. Phase 1 roadmap
item 7 remains open until PR 33b supplies the unchanged credential-dependent
evidence.

`<sha256-account-id>` is the 64-character lowercase hexadecimal SHA-256 digest
of the validated opaque `AccountId` UTF-8 bytes. Tests may construct isolated
adapter paths directly, but the production CLI composition exposes no override.

### Strict read-only store contract

PR 31 opens an existing regular database only and fails when the file is
absent. The read path must preserve the current canonical parent, no-follow
leaf, path identity, account ownership, exact schema, SQLCipher version,
SQLite/SQLCipher integrity, bounded decode, and opaque error validation. It
must not create or claim a database, migrate schema, begin a write transaction,
fall back to read-write, or repair any state. Opening the CLI is never an
ownership or migration event.

Every validated read-write store connection sets and verifies
`SQLITE_FCNTL_PERSIST_WAL = 1` after ownership is established, so a clean final
checkpoint retains both `-wal` and `-shm` for a later reader. The read-only path
requires the main database and both sidecars to exist with the expected file
identities before it opens. It exposes no create, replace, delete, or repair
operation. If a legacy profile lacks the pair, a crash requires recovery, or a
sidecar replacement remains observable during the post-open identity check,
the reader fails closed until the owning read-write application opens and
establishes a valid persistent-WAL state.

The live connection uses SQLite read-only/no-mutex/no-follow mode without
`immutable=1` and without a private copy. It disables and verifies
checkpoint-on-close. SQLite may update lock and WAL-index coordination in the
existing `-shm` file; that is not mailbox persistence authority. In uncontended
operation, main and WAL content remain unchanged and no entry is created.
Deterministic tests prove both supported states: a standalone reader after a
clean writer close, and a reader while a writer holds WAL mode and commits data
that remains in the WAL. Missing sidecars at preflight and ordinary replacements
that remain observable at the post-open check fail without database/WAL
mutation. The bundled VFS opens WAL/SHM with create-capable internal flags, so
same-user deletion after preflight can recreate an entry before the post-read
identity check fails closed. Fixtures record that deletion/recreation residual
and the swap-in/open/swap-back non-detection instead of asserting prevention.
The reader verifies connection-local persistent-WAL state and requires
`journal_size_limit = -1`. Busy, moved-path, wrong-key, foreign-owner,
unknown-schema, and integrity failures remain fail closed and redacted.

The current bundled Unix VFS does not expose a supported handle that binds its
internally opened `-shm` inode to the caller's preflight identity. Pre-open and
post-open pathname identity checks detect ordinary replacement but cannot prove
defense against same-user regular-file swap-in/open/swap-back or
deletion/recreation races. PR 31 includes deterministic fixtures for both
limitations and does not claim that sidecar handles are descriptor-bound or
non-create-capable. A process able to race files inside the signed App Group
container is treated as the existing unlocked-device/local-malware residual
threat. If review expands that attacker into scope, direct SQLite access stops
and the design moves to an owning host or a reviewed VFS rather than overstating
the check.

### CLI and JSON contract

PR 33a exposes only these operations, both with a validated `StoreLimit`
(`1..=10_000`) and a default of 50:

```text
mailctl inbox --account <opaque-account-id> [--limit <count>]
mailctl thread --account <opaque-account-id> --thread <opaque-thread-id> [--limit <count>]
```

There is no `message`, body, raw, HTML, MIME, export, mutation, sync, key, path,
or human-rendering command. Version-1 JSON is one document on stdout with
`schema_version`, `command`, `account_id`, `limit`, and `messages`. Each message
contains only `message_id`, `thread_id`, `from`, `subject`,
`received_at_millis`, and `unread`; the body-derived preview and cached content
are excluded. Arrays preserve the store contract's deterministic order.

Before any string reaches stdout, PR 33a must encode every C0 control
(`U+0000..U+001F`), DEL (`U+007F`), and C1 control (`U+0080..U+009F`) as a
JSON `\uXXXX` escape, even if current domain validation would reject it. This
is a terminal-safety boundary, not a substitute for JSON serialization.
Successful stdout is an explicit user-directed declassification from encrypted
storage; redirected files, pipes, terminal history, and downstream consumers
are outside the encrypted cache boundary.

The CLI writes no user or provider data to stderr. Its complete stable exit and
stderr contract is:

| Exit | Fixed stderr line |
|---:|---|
| 0 | no stderr |
| 2 | `mailctl: invalid invocation` |
| 3 | `mailctl: key access failed` |
| 4 | `mailctl: local profile is unavailable` |
| 5 | `mailctl: mailbox item was not found` |
| 6 | `mailctl: local mailbox is corrupted` |
| 7 | `mailctl: operation failed` |

Serialization is completed before the first stdout write. A broken pipe or
partial stdout write returns 7 without retrying and emits the same fixed
`mailctl: operation failed` stderr line. The process does not attempt another
stdout write, but bytes already accepted by the operating system cannot be
retracted and may contain a prefix of the serialized document.

The mapping is closed: invocation and domain validation failures use exit 2;
Keychain retrieval or validation failures use exit 3; profile location and
`MailboxStoreError::Storage` use exit 4; an empty `thread` result uses exit 5,
while an empty inbox is successful; `MailboxStoreError::Corrupted` uses exit 6;
and serialization or process-I/O failures use exit 7. New error variants require
a reviewed contract amendment rather than a catch-all content-bearing message.

`tersa-cli-macos` may depend inward only on `tersa-application`,
`tersa-domain`, and `tersa-keychain-macos`. It owns only fixed composition and
stable rendering; it does not depend directly on the platform or SQLCipher
adapters. The metadata-listing use cases and JSON DTO shape live in
`tersa-application` against `MailboxReader` and remain independent of concrete
Apple, SQLCipher, serialization, and future IPC types. The CLI adapter owns
argument parsing, the fixed JSON serializer, terminal-safe escaping, process
I/O, and stable exit mapping; serde is not added to the application boundary.
Replacing the direct adapters with `maild` IPC must preserve commands, limits,
ordering, JSON, exit codes, and declassification semantics.

The production CLI composition is reviewed and source-policy-checked to invoke
only `open_default_read_only_mailbox` and inspect
`ReadOnlyMailboxOpenError`. Its behavior and authority remain retrieval-only.
This is not a Rust visibility sandbox: because the CLI depends on
`tersa-keychain-macos`, the public provisioner is compile-reachable in the crate
graph today. No semantic or compiler-level non-reachability claim is made.

As defense in depth, PR 33a.5 must add a narrow Git-index tracked-source
inventory for `apps/cli-macos`. Every Keychain-adapter item reference is closed
to the two retrieval items above. The inventory rejects direct references,
imports, reexports, wildcard imports, crate aliases, and item aliases involving
any provisioning or bootstrap API, and the same implementation pull request
must register every new public bootstrap symbol in the rejected inventory.
Positive and negative fixtures must cover fully qualified calls, `use`,
`pub use`, `as`, wildcard, and crate-alias forms. This textual tracked-source
guard is defense in depth, not proof against all Rust syntax or generated code.
If true compile-time non-reachability becomes required, a separately reviewed
facade/crate boundary and ADR must replace this composition.

## Non-claims

PR 32 adds root provisioning, validated retrieval, private derivation, and
fixed profile discovery, but no CLI, public raw-key provider, database-opening
composition, IPC, or `maild`. PR 33a adds source composition and deterministic
CLI behavior but passes no signed runtime or distribution gate and is not the
official CLI. PR 33a.5 adds only the credentialless product-application
bootstrap and profile-establishment source described above. It does not change
the gate register or pass signed runtime, App Group, Keychain interoperability,
distribution, M0, M1, UI, or release evidence. Phase 1 roadmap item 7 remains
open until PR 33b. None of these slices adds real Google
authorization, token persistence, sync, background work, mailbox mutation,
search, UI, or release evidence.

All iPhone and iPad product implementation, mobile Keychain and protected-data
behavior, mobile UI selection, device evidence, background behavior,
TestFlight, and App Store work remain deferred to Phase 2. No macOS source or
evidence closes a mobile or mobile-inclusive gate.

## Consequences

The first CLI is intentionally narrow and locally replaceable. Key generation
has one owner, the Data Protection Keychain and application-group boundaries
are shared only by same-team signed targets, direct database reads cannot
mutate or silently ignore live WAL, and JSON output has a defined privacy
boundary. Future commands, renderers, profiles, key rotation, path overrides,
and IPC require separately reviewed contracts rather than compatibility
assumptions.
