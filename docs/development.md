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
settings; they are not secrets. An unconfigured build fails closed.

```sh
xcodebuild ... \
  TERSA_OAUTH_CLIENT_ID=public-ci-client.apps.googleusercontent.com \
  TERSA_OAUTH_REDIRECT_SCHEME=app.tersa.oauth.ci
```

After creating the unsigned base archives, run:

```sh
sh apple/scripts/verify-oauth-feasibility.sh
```

The verifier checks archived symbols and injected Info.plist values, ad-hoc
signs the macOS archive with its production sandbox entitlements, then runs a
fixed in-process loopback client/server probe. Rust tests exercise the
deterministic callback, negative state machine, bounded HTTP parser, static
responses, speculative-connection recovery, absolute read deadline, and
one-shot valid callback. No evidence file contains state, verifier,
authorization code, token, or authorization URL.

The loopback peer check is not browser authentication. Any local process can
connect to a loopback port; unpredictable OAuth state and PKCE are the defenses
against redirect injection and intercepted authorization codes.

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

The CI profile uses 10,000 synthetic messages and at least 128 MiB of normalized
text. The optional manual host profile uses 100,000 messages and at least 2 GiB
of normalized text; it can consume substantial time and disk. Every host result
is labeled `NOT A DEVICE-GATE RESULT`. The iOS commands prove only that the
locked Rust 1.91.1 graph builds; they do not prove runtime behavior or
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

After generating the Apple project and creating the `TersaMimeMac` archive,
run:

```sh
sh apple/scripts/verify-mime-feasibility.sh
```

The verifier replaces the bundled synthetic fixture with current Rust
sanitizer output, ad-hoc signs the macOS archive with App Sandbox and network
client entitlements, proves the request canary with a positive control,
and then requires zero WKWebView canary hits, zero TCP listeners, zero website
data records, disabled content JavaScript, attached block rules, and denied
navigation. Evidence contains only aggregate counts and hashes. Every result is
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
debug artifacts:

```sh
rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim
xcodegen generate --spec apple/project.yml --project apple

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
  -configuration Debug -destination 'generic/platform=macOS' \
  -derivedDataPath apple/build/DerivedDataDioxus CODE_SIGNING_ALLOWED=NO archive \
  -archivePath apple/build/TersaDioxusMac.xcarchive
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaDioxusIOS \
  -configuration Debug -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath apple/build/DerivedDataDioxus CODE_SIGNING_ALLOWED=NO build
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaDioxusIOS \
  -configuration Debug -sdk iphoneos -destination 'generic/platform=iOS' \
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
supply-chain checks. Only the Apple application targets disable Xcode
user-script sandboxing: Cargo and rustup must read the compiler sysroot outside
`SRCROOT`, while locked build
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
separate Apple evidence job also regenerates the Apple-target notices and
checks live listeners with `lsof`. Notice comparison stays on macOS because
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
