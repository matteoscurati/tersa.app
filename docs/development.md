# Development

## Prerequisites

- macOS 15 or later, or a current Linux distribution, for shared-core work
- Rust 1.91.1, installed automatically through `rust-toolchain.toml`
- Xcode 26 for Apple application work

The supported release targets are arm64 macOS 15 or later and iOS/iPadOS 18 or
later. Linux is a continuous-integration target for the platform-independent
core, not a product distribution target.

## Baseline verification

Run the complete local Rust suite with:

```sh
cargo xtask verify
```

This command checks dependency boundaries, formatting, compilation, Clippy,
tests, and documentation. CI additionally runs dependency licensing and
advisory checks, feature-powerset checks, DCO validation, and spelling checks.
The xtask architecture check enforces active product dependency boundaries on
every supported Apple target.

Coding agents should classify work and run **scoped** loops from the
[agent playbook](development/agent-playbook.md) during implementation. Full
`cargo xtask verify` remains the merge-quality gate and is not required after
every single-file edit. The playbook also links ADR entry points and the
unsigned macOS UI test command for Swift-only changes.

For physical-device or signed-distribution evidence, follow the
[Apple physical-device and distribution protocol](release/apple-distribution.md),
including its commit-bound locator and review-retention rules. macOS UI and
release acceptance are defined by the
[macOS acceptance protocol](quality/macos-acceptance.md) and the
[macOS performance harness](quality/macos-performance.md).

Development-signed (non-gate) accessibility and App Sandbox capture for the
macOS UI vertical slice follows
[macOS UI development evidence](quality/macos-ui-dev-evidence.md):

```sh
sh apple/scripts/capture-macos-ui-dev-evidence.sh
```

That runner requires a clean worktree, exactly one Apple Development identity,
and a matching Mac Development profile. It cannot satisfy
`P1-MACOS-001`/`002`/`003`.

### CI execution modes

Open implementation pull requests as drafts. Draft creation and synchronization
schedule no CI runners; changing the pull request to ready-for-review triggers
the required path-scoped product CI. Subsequent ready pull-request commits
supersede an older in-progress run through the per-PR concurrency group. Every
ready pull request runs the lightweight classifier job (deterministic
control-script tests, DCO validation, and change scope), then only the
path-scoped active lanes that apply, and finally the required `CI gate`.
Documentation and non-executable GitHub templates (issue/PR templates and
`CODEOWNERS`) stay lightweight and stop at the classifier and gate, so those
required runs normally finish in seconds. Workflow YAML, `xtask/**`, and other
executable CI-control inputs intentionally fail closed to full fanout so a
control-plane change cannot skip the lanes it alters.

The four path-scoped build and policy lanes are:

- Rust (Linux)
- Policy and supply chain
- Apple product
- macOS quality

Portable shared-crate changes add Linux Rust verification and supply-chain
policy. Host macOS Rust verification (`rust_macos`) is reserved for platform,
adapter, Apple bridge, and macOS CLI paths and runs inside `macOS quality`.
Notice regeneration (`notices`) also runs conditionally inside that same job
whenever the selected scope requires it. Apple product paths add the real macOS
test and iOS-simulator build; that build also covers the Rust linked into the
application. Root manifests, shared build inputs, unknown paths, workflow YAML,
`xtask/**`, and executable CI-control scripts still fail closed to the full
active baseline.

Merge-group runs fan out conservatively across every active product lane for the
combined state. There is no `main` push workflow and no manual evidence-suite
dispatch path. GitHub Actions cache restore and save are disabled for every job
and event, so each run starts without a repository cache. CI uploads no
diagnostic artifacts.

The repository is public and uses only standard GitHub-hosted runners, so runner
execution has no billable minute charge. The policy above still minimizes queue
time, redundant macOS capacity, and artifact growth.

The classifier in `scripts/ci-change-scope.py` is fail closed: unknown or shared
build paths fan out conservatively. Documentation and non-executable GitHub
templates avoid build jobs; workflow YAML, `xtask/**`, and the executable
CI-control allowlist (scope/DCO/performance scripts and their tests) enable
every active product scope. The classifier and its own tests are that exact
control-path allowlist, exercised inside the scope job; every other unknown
`scripts/` path still fans out. Its table-driven tests must change with every
new scope rule.

## Dependency changes

Use intentional dependency declarations in the workspace manifest. Do not use
wildcard versions or add a dependency speculatively. A pull request that
changes `Cargo.lock` must explain why the dependency is needed, its license,
and any relevant security or binary-size impact.

See [Dependency rules](architecture/dependency-rules.md) before adding a new
crate or changing an internal edge.

## OAuth PKCE

Official builds inject public OAuth client identifiers and the registered iOS
callback scheme as Xcode build settings; they are not secrets. Some Google
Desktop clients also require their issued client secret at the token endpoint
even with PKCE. For an installed native app this is non-confidential client
configuration, not an authentication boundary; inject it only through ignored
local or release configuration and never commit or log it. An unconfigured build
fails closed.

```sh
xcodebuild ... \
  TERSA_OAUTH_CLIENT_ID=public-ci-client.apps.googleusercontent.com \
  TERSA_OAUTH_REDIRECT_SCHEME=app.tersa.oauth.ci
```

The product macOS path is governed by
[ADR 0023](architecture/adr-0023-step3-oauth-and-bounded-sync.md) and
[ADR 0024](architecture/adr-0024-macos-token-process-isolation.md). The bridge
`legacy-oauth` feature remains required for the active iOS begin/finish/cancel
exports and still carries the legacy macOS begin/poll surface for source
completeness; the product macOS archive rejects that legacy surface through its
closed contract. Ad-hoc signing is not production proof and does not substitute
for Developer ID, notarization, or independently reviewed distribution evidence.

Rust tests exercise the deterministic callback, negative state machine, bounded
HTTP parser, static responses, speculative-connection recovery, absolute read
deadline, and one-shot valid callback. No evidence file contains state,
verifier, authorization code, token, or authorization URL.

The loopback peer check is not browser authentication. Any local process can
connect to a loopback port; unpredictable OAuth state and PKCE are the defenses
against redirect injection and intercepted authorization codes.

## macOS Keychain isolation probe

ADR 0024 isolates refresh-token Keychain authority in the separately signed
`TersaMacTokenBroker` XPC service. Its Item 5 negative controls need a
fixed-purpose, read-only probe compiled into the real executables. That probe
(`KeychainIsolationProbe`) is an internal, version-pinned diagnostic, not a
public interface: it runs only when a host process is launched with the exact
single argument `--tersa-keychain-isolation-probe-v1`, then reads its own
signed `keychain-access-groups` entitlement, derives the other principal's
Keychain group, and issues one query-only `SecItemCopyMatching` against it. It
mutates nothing and returns no item data. See
[ADR 0024](architecture/adr-0024-macos-token-process-isolation.md) for the full
contract; this section covers only the safe deterministic checks.

These checks prove the probe is fixed-purpose, read-only, and correctly shaped.
They do not prove signed runtime isolation. The xtask architecture gate holds
the probe source inventory, capability, query, entry-point, and
signing-settings guards:

```sh
cargo xtask architecture
```

Generate the Xcode project and run the `TersaMacTests` bundle unsigned. The
probe's pure derivation, entitlement parsing, query construction, status
classification, and evidence mapping are unit-tested there without invoking
live `SecItem*` or any real signing entitlement:

```sh
sh apple/scripts/generate-project.sh
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac \
  -configuration Debug -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath apple/build/DerivedData CODE_SIGNING_ALLOWED=NO test
```

Unsigned and ad-hoc output is not isolation evidence. An unsigned build has
no signed entitlement context, and an ad-hoc build may embed an entitlement
plist but is not Apple Development provisioned evidence for these team-scoped
groups. Unsigned/ad-hoc outcomes are therefore non-authoritative and
normally configuration-invalid in the documented deterministic path,
regardless of which status a scratch build happens to report; only the Apple
Development signed Point-6 procedure can prove Item 5 runtime isolation.
Never weaken, broaden, or ad-hoc-substitute the committed entitlements to
make a local run appear to pass. The signed-runtime procedure — normal token operations plus both
wrong-group probes in an Apple Development build, then the Developer ID signed
and notarized release candidate — is a separate evidence step tracked by
ADR 0024 Items 5 and 6.

## Retired M0 diagnostics

The M0 diagnostic program is retired. A short
[historical summary](history/m0-summary.md) consolidates what the spikes
learned. Active product SQLCipher remains the production store adapter. Product
mailbox search remains the bounded application/store search path. No production
blob implementation, Tantivy replacement, MIME renderer, `SafeHtml`
implementation, restricted WKWebView, parser, or fuzz harness is claimed by that
retirement. Hostile-content handling remains a product security requirement.

Preserved architectural decisions include
[ADR 0011](architecture/adr-0011-sqlcipher-schema-and-migration-ownership.md),
[ADR 0012](architecture/adr-0012-chunked-blob-format.md), and the OAuth path in
[ADR 0023](architecture/adr-0023-step3-oauth-and-bounded-sync.md) and
[ADR 0024](architecture/adr-0024-macos-token-process-isolation.md).

## Apple bootstrap

The Apple bootstrap requires Xcode 26 and XcodeGen 2.45.4. It supports only
arm64 macOS 15 and iOS/iPadOS 18. `TersaMac` and `TersaIOS` are the product
bridge targets. Historical M0 diagnostic schemes and helpers were removed under
ADR-0025; see the [M0 historical summary](history/m0-summary.md).

Install the Rust targets once, generate the Xcode project, and build unsigned
product artifacts:

The checked wrapper is the only supported XcodeGen entry point. It passes
`--no-env`, so signing placeholders such as `${TeamIdentifierPrefix}` remain
literal until Xcode resolves them; CI uses the same path.
The architecture gate inventories every tracked file and rejects a direct
XcodeGen generation command anywhere outside the byte-exact wrapper.

```sh
rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim
sh apple/scripts/generate-project.sh

xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac \
  -configuration Debug -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath apple/build/DerivedData CODE_SIGNING_ALLOWED=NO build
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaIOS \
  -configuration Debug -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath apple/build/DerivedData CODE_SIGNING_ALLOWED=NO build
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaIOS \
  -configuration Debug -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath apple/build/DerivedData CODE_SIGNING_ALLOWED=NO build
```

The generated `apple/Tersa.xcodeproj` is intentionally ignored. The project
build phase creates the Rust static library in `apple/build/rust`; it is also
ignored with all local Apple build products.

The Rust bridge is a root workspace member and is therefore covered by
`cargo xtask verify` and the repository supply-chain checks. Only the Apple
application targets disable Xcode user-script sandboxing: Cargo and rustup must
read the compiler sysroot outside `SRCROOT`, while locked build
scripts write intermediates exclusively below the ignored `apple/build`
directory.
The base macOS target declares both sandbox network client and server
entitlements: future Google token/API traffic needs outbound networking, while
the desktop OAuth redirect requires the narrowly bound loopback listener.
Regenerate or verify the complete Rust and native dependency license
inventories for active product targets with:

```sh
sh apple/scripts/generate-third-party-notices.sh --write
sh apple/scripts/generate-third-party-notices.sh --check
```

Notice comparison stays on macOS because `cargo-about` 0.9.1 is not byte-stable
for Apple target selection across host operating systems.

Create unsigned archives with:

```sh
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac \
  -configuration Debug -destination 'generic/platform=macOS' \
  -derivedDataPath apple/build/DerivedData CODE_SIGNING_ALLOWED=NO archive \
  -archivePath apple/build/TersaMac.xcarchive
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaIOS \
  -configuration Debug -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath apple/build/DerivedData CODE_SIGNING_ALLOWED=NO archive \
  -archivePath apple/build/TersaIOS.xcarchive
```
