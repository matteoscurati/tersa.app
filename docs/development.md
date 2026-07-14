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

## Apple bootstrap

The Apple bootstrap requires Xcode 26 and XcodeGen 2.45.4. It supports only
arm64 macOS 15 and iOS/iPadOS 18. It intentionally contains no product UI or
Slint integration yet.

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
```

The generated `apple/Tersa.xcodeproj` is intentionally ignored. The project
build phase creates the Rust static library in `apple/build/rust`; it is also
ignored with all local Apple build products.

The Rust bridge is a root workspace member and is therefore covered by
`cargo xtask verify` and the repository supply-chain checks. Only the Apple
application targets disable Xcode user-script sandboxing: Cargo and rustup must
read the compiler sysroot outside `SRCROOT`, while the locked build script
writes exclusively below the ignored `apple/build` directory.

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
