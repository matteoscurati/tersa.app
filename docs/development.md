# Development

## Prerequisites

- macOS 15 or later, or a current Linux distribution, for shared-core work
- Rust 1.91.1, installed automatically through `rust-toolchain.toml`
- Xcode 26 for Apple application work beginning in M0 PR3

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
The xtask architecture check is the enforcement point for direct and transitive
diagnostic-only Slint and Dioxus dependency isolation on every supported Apple
target; `cargo deny` alone cannot establish that runtime boundary.

While the frozen M0 gate register remains tracked, keep the product-gate
validator and its self-test available:

```sh
python3 scripts/verify-m0-gates.py
python3 scripts/verify-m0-gates.py --self-test
```

CI runs `python3 scripts/verify-m0-gates.py --self-test` in the lightweight
change-scope job. That mode performs full register validation plus negative
mutation self-tests; the policy job does not own it. Contributors should run
the same `--self-test` command locally before `cargo xtask verify`. The
validator is not an active product lane; it stays only while the register is
still in tree and retires with that register in the documentation PR. Adding a
gate, changing a minimum evidence tier, or changing the attestation schema
still requires a matching validator update and independent exact-head review;
editing the JSON alone fails closed. For physical-device or signed-distribution
evidence, follow the
[physical-device and distribution protocol](m0/physical-device-and-distribution-protocol.md),
including its commit-bound locator and review-retention rules.

### CI execution modes

Open implementation pull requests as drafts. Draft creation and synchronization
schedule no CI runners; changing the pull request to ready-for-review triggers
the required path-scoped product CI. Subsequent ready pull-request commits
supersede an older in-progress run through the per-PR concurrency group. Every
ready pull request runs the lightweight classifier job (deterministic
control-script tests, retained-helper self-tests, DCO validation, and change
scope), then only the path-scoped active lanes that apply, and finally the
required `CI gate`. Documentation, workflow, and exact self-tested CI-control
changes stop at the classifier and gate, so their required run normally
finishes in seconds.

The five path-scoped active lanes are:

- Rust (Linux)
- Rust (macOS)
- Policy and supply chain
- Apple product
- Third-party notices

Portable Rust or xtask changes add Linux Rust verification and supply-chain
policy. macOS Rust verification is reserved for platform, adapter, Apple bridge,
and macOS CLI paths. Apple product paths add the real macOS test and
iOS-simulator build; that build also covers the Rust linked into the
application. Root manifests, shared build inputs, and unknown paths still fail
closed to the full active baseline.

Merge-group runs fan out conservatively across every active product lane for the
combined state. There is no `main` push workflow and no manual evidence-suite
dispatch path. GitHub Actions cache restore and save are disabled for every job
and event, so each run starts without a repository cache. CI uploads no
diagnostic artifacts.

The repository is public and uses only standard GitHub-hosted runners, so runner
execution has no billable minute charge. The policy above still minimizes queue
time, redundant macOS capacity, and artifact growth.

The classifier in `scripts/ci-change-scope.py` is fail closed: unknown or shared
build paths fan out conservatively, while documentation, workflow, and exact
self-tested control paths avoid build jobs. xtask-only changes run the portable
Linux and policy baseline but avoid Apple product work. The classifier and its
own tests are an exact control-path allowlist exercised inside the scope job;
every other unknown `scripts/` path still fans out. Its table-driven tests must
change with every new scope rule. A dedicated macOS lane owns the single
target-specific notice regeneration whenever the selected scope requires it.

## Dependency changes

Use intentional dependency declarations in the workspace manifest. Do not use
wildcard versions or add a dependency speculatively. A pull request that
changes `Cargo.lock` must explain why the dependency is needed, its license,
and any relevant security or binary-size impact.

See [Dependency rules](architecture/dependency-rules.md) before adding a new
crate or changing an internal edge.

## OAuth PKCE feasibility

The M0 adapter proves authorization request generation and native callback
transport without real Google credentials. Official builds inject public OAuth
client identifiers and the registered iOS callback scheme as Xcode build
settings; they are not secrets. Some Google Desktop clients also require their
issued client secret at the token endpoint even with PKCE. For an installed
native app this is non-confidential client configuration, not an authentication
boundary; inject it only through ignored local or release configuration and
never commit or log it. An unconfigured build fails closed.

```sh
xcodebuild ... \
  TERSA_OAUTH_CLIENT_ID=public-ci-client.apps.googleusercontent.com \
  TERSA_OAUTH_REDIRECT_SCHEME=app.tersa.oauth.ci
```

The combined local verifier `sh apple/scripts/verify-oauth-feasibility.sh` is
obsolete after the ADR-0024 token-broker cutover: it still expects
`TersaOAuthClientID` and `_tersa_oauth_macos_begin` in TersaMac plus retired
archive inputs that product CI no longer produces. Do not use it as a current
local route; PR5 will remove it. Its historical scope covered archived symbols
and injected Info.plist values, ad-hoc signing of a macOS archive copy with the
exact five-key production entitlement shape for static signing evidence, and a
separately signed runnable loopback probe limited to App Sandbox plus network
client and server entitlements: an ad-hoc identity cannot authorize the
production team-bound Keychain access group, so that probe proved only the
OAuth sandbox networking subset. Signed same-team Keychain interoperability
remains a later distribution gate. Neither current product CI nor local
verification covers that obsolete combined macOS OAuth surface.

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

## SQLCipher feasibility

The M0 encrypted-storage diagnostic is isolated from the shared application
layers. It uses synthetic data to verify CommonCrypto-backed SQLCipher, WAL
crash recovery, key rejection, integrity checks, in-memory temporary storage,
and known-marker absence in controlled files.

```sh
rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim
sh apple/scripts/verify-sqlcipher-feasibility.sh
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked \
  --package tersa-sqlcipher-spike --target aarch64-apple-ios
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked \
  --package tersa-sqlcipher-spike --target aarch64-apple-ios-sim
```

The committed result contains no key, sentinel, SQL, path, or raw database.
Read [the SQLCipher feasibility record](m0/sqlcipher-feasibility.md) before
changing the dependency, keying boundary, temporary-store policy, or evidence
claims.

## Crash-safe blob feasibility

The portable M0 blob diagnostic proves a bounded candidate XChaCha20-Poly1305
chunk format, authenticated random access, per-account HMAC content identifiers,
exact-size validation, atomic same-directory no-replace hard-link publication,
descriptor-bound no-follow collision validation, narrow staging cleanup, and
deterministic process-crash publication using only synthetic data.

```sh
rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim
cargo test --locked --package tersa-blob-spike
sh apple/scripts/verify-blob-feasibility.sh
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked --release \
  --package tersa-blob-spike --target aarch64-apple-ios
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked --release \
  --package tersa-blob-spike --target aarch64-apple-ios-sim
```

The verifier builds and runs the macOS arm64 release executable and accepts
only its exact three-line aggregate result. The iOS device and simulator builds
are compile evidence only. Read [the blob feasibility record](m0/blob-feasibility.md)
and [ADR 0012](architecture/adr-0012-chunked-blob-format.md) before changing the
format, publication protocol, cryptographic dependencies, or evidence claims.

## Encrypted search feasibility

The M0 search diagnostic is Apple-only and remains explicitly non-production.
It compares exact message-ID match sets from SQLCipher FTS5 and Tantivy 0.26.1;
it does not claim ranking-order parity. Tantivy uses a custom fixed-size-chunk
SQLCipher `Directory`, not memory mapping or temporary index files.

```sh
rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim
sh apple/scripts/verify-search-feasibility.sh
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked \
  --release --package tersa-search-spike --target aarch64-apple-ios
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked \
  --release --package tersa-search-spike --target aarch64-apple-ios-sim
cargo run --locked --release --package tersa-search-spike \
  --target aarch64-apple-darwin -- --profile manual
```

The default host profile uses 10,000 synthetic messages and at least 128 MiB of
normalized text. The optional manual host profile uses 100,000 messages and at
least 2 GiB of normalized text; it can consume substantial time and disk. Every
host result is labeled `NOT A DEVICE-GATE RESULT`. The iOS commands prove only
that the locked Rust 1.91.1 graph builds; they do not prove runtime behavior or
production performance. Only the physical-device M0 run can close the iPhone
gate.

## MIME and hostile HTML feasibility

The portable M0 diagnostic owns the exact-pinned `mail-parser` and `ammonia`
dependencies. It accepts only synthetic fixtures, applies deterministic byte,
header, tree, part, charset, transfer-decoding, and display limits, and exposes
sanitized markup only through `SafeHtml`. The native Apple diagnostic is a
separate Swift target and does not use Dioxus or Wry.

```sh
rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim
cargo test --locked --package tersa-mime-spike
cargo build --locked --release --package tersa-mime-spike \
  --target aarch64-apple-darwin
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked --release \
  --package tersa-mime-spike --target aarch64-apple-ios
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --locked --release \
  --package tersa-mime-spike --target aarch64-apple-ios-sim
```

The deterministic host fuzz regression is a standalone Cargo project with its
own lockfile. It pins nightly `2026-07-14`, `cargo-fuzz` 0.13.2, and
`libfuzzer-sys` 0.4.13. Install the exact toolchain and driver, then run its
finite verifier:

```sh
rustup toolchain install nightly-2026-07-14 --profile minimal \
  --component clippy --component rust-src --component rustfmt
cargo install cargo-fuzz --version 0.13.2 --locked
sh scripts/verify-mime-fuzz.sh
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cargo deny --locked --manifest-path fuzz/Cargo.toml \
  --config fuzz/deny.toml check
cargo audit --file fuzz/Cargo.lock --deny warnings
```

The verifier first replays every committed seed, then requests 10,000 total
libFuzzer target executions, including corpus initialization, in one process
with a fixed seed, a 512 KiB maximum input, and fixed per-input timeout and RSS
limits. Each input runs the public parser twice and checks typed-result
equality, conservative HTML expansion, and deterministic CID placeholder
invariants. Its aggregate evidence is written below the ignored `fuzz/target`
directory and contains no input, content, or path.

The fuzz project is excluded from the root workspace and application notice
generation. Its isolated supply-chain policy permits NCSA only because
`libfuzzer-sys` requires it; neither dependency nor that license enters a
shipping application graph.

After generating the Apple project and creating the `TersaMimeMac` archive,
run:

```sh
sh apple/scripts/verify-mime-feasibility.sh
```

The verifier replaces the bundled synthetic fixture with current Rust
sanitizer output, ad-hoc signs the macOS archive with App Sandbox and network
client entitlements, proves literal-loopback transport with an unblocked in-app
WKWebView control, resets the canary, and then requires zero protected
WKWebView canary hits, zero TCP listeners, zero website data records, disabled
content JavaScript, attached block rules, and denied action, response, and
new-window paths. Evidence contains only aggregate counts and hashes. Every result is
labeled `NOT A DEVICE-GATE RESULT`: macOS is the only runtime exercised, while
iOS device and simulator commands are locked cross-build evidence.

Read [the MIME and hostile HTML feasibility record](m0/mime-html-feasibility.md)
before changing parser limits, sanitizer output, WebKit configuration,
entitlements, or evidence claims.

## Apple bootstrap

The Apple bootstrap requires Xcode 26 and XcodeGen 2.45.4. It supports only
arm64 macOS 15 and iOS/iPadOS 18. The existing bridge targets intentionally
contain no product UI. The separate `TersaSlintMac` and `TersaSlintIOS` schemes
package the M0 diagnostic Slint executable. `TersaDioxusMac` and
`TersaDioxusIOS` package the fallback WebView diagnostic directly with Cargo.
`TersaMimeMac` and `TersaMimeIOS` compile the native hostile-content policy.
None of the six diagnostic schemes is a production target.

Install the Rust targets once, generate the Xcode project, and build unsigned
diagnostic artifacts:

The checked wrapper is the only supported XcodeGen entry point. It passes
`--no-env`, so signing placeholders such as `${TeamIdentifierPrefix}` remain
literal until Xcode resolves them; CI and evidence scripts use the same path.
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

xcodebuild -project apple/Tersa.xcodeproj -scheme TersaSlintMac \
  -configuration Debug -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath apple/build/DerivedData CODE_SIGNING_ALLOWED=NO build
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaSlintIOS \
  -configuration Debug -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath apple/build/DerivedData CODE_SIGNING_ALLOWED=NO build

xcodebuild -project apple/Tersa.xcodeproj -scheme TersaDioxusMac \
  -configuration Release -destination 'generic/platform=macOS' \
  -derivedDataPath apple/build/DerivedDataDioxus CODE_SIGNING_ALLOWED=NO archive \
  -archivePath apple/build/TersaDioxusMac.xcarchive
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaDioxusIOS \
  -configuration Release -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath apple/build/DerivedDataDioxus CODE_SIGNING_ALLOWED=NO build
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaDioxusIOS \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath apple/build/DerivedDataDioxus CODE_SIGNING_ALLOWED=NO archive \
  -archivePath apple/build/TersaDioxusIOS.xcarchive

xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMimeMac \
  -configuration Release -destination 'generic/platform=macOS' \
  -derivedDataPath apple/build/DerivedDataMime CODE_SIGNING_ALLOWED=NO archive \
  -archivePath apple/build/TersaMimeMac.xcarchive
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMimeIOS \
  -configuration Release -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath apple/build/DerivedDataMime CODE_SIGNING_ALLOWED=NO build
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMimeIOS \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath apple/build/DerivedDataMime CODE_SIGNING_ALLOWED=NO archive \
  -archivePath apple/build/TersaMimeIOS.xcarchive
```

The generated `apple/Tersa.xcodeproj` is intentionally ignored. The project
build phase creates the Rust static library in `apple/build/rust`; it is also
ignored with all local Apple build products.

The Rust bridge, both UI spikes, and the MIME diagnostic are root workspace
members and are therefore covered by `cargo xtask verify` and the repository
supply-chain checks. The standalone fuzz project is deliberately excluded.
Local `sh scripts/verify-mime-fuzz.sh` covers only the finite fuzz path; its
formatting, Clippy/lint, license, source, and advisory policies are not
automated after diagnostic CI retirement and remain unchecked pending PR4
removal. Root workspace policy still rejects fuzz dependencies entering the
workspace graph. Only the Apple
application targets disable Xcode user-script sandboxing: Cargo and rustup must
read the compiler sysroot outside `SRCROOT`, while locked build
scripts write intermediates exclusively below the ignored `apple/build`
directory.
The base macOS target declares both sandbox network client and server
entitlements: future Google token/API traffic needs outbound networking, while
the desktop OAuth redirect requires the narrowly bound loopback listener.
The shared Slint archive helper verifies the target's pinned Skia archive
before making it available to `skia-bindings`. Both Xcode builds and the
workspace-wide macOS CI check use this helper. The Xcode build then copies the
executable only into the requested application bundle. XcodeGen installs the
target-specific Slint notice or matching `THIRD_PARTY_NOTICES-dioxus-*.txt`
resource; each evidence script compares its bundled copy byte-for-byte with
the source. The Slint supplemental
inventory includes every native third-party component in the pinned Skia
archive, with source revision, license path, and license SHA-256. Regenerate or
verify the complete Rust and native dependency license inventories with:

```sh
sh apple/scripts/generate-third-party-notices.sh --write
sh apple/scripts/generate-third-party-notices.sh --check
python3 apple/scripts/verify-dioxus-runtime.py
```

The Dioxus verifier pins the exact 0.7.9 graph, rejects Manganis and devtools,
allows only the required `tokio_runtime` feature, and checks the private
WebSocket's loopback bind and mutual-key invariants in the resolved source. The
shared macOS notice gate regenerates the Apple-target notices. The live-listener
check with `lsof` is local-only through
`sh apple/scripts/capture-dioxus-evidence.sh`; no CI job performs it. Notice
comparison stays on macOS because
`cargo-about` 0.9.1 is not byte-stable for Apple target selection across host
operating systems. This is diagnostic evidence, not a product backend or App
Sandbox claim. See
[Dioxus UI feasibility](m0/dioxus-ui-feasibility.md) before changing this path.

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
