// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Repository automation for tersa.app.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use cargo_metadata::{
    CrateType, Dependency, DependencyKind, Metadata, MetadataCommand, Package, PackageId,
    TargetKind,
};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

// Rust guideline compliant 1.0.

type TaskResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
type RuntimeBoundary = (&'static str, fn(&str) -> bool, &'static str);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedDependencyIdentity {
    package_id: PackageId,
}

const SQLCIPHER_OWNERS: [&str; 8] = [
    "tersa-search-spike",
    "tersa-sqlcipher-spike",
    "tersa-store-sqlcipher-macos",
    "tersa-keychain-macos",
    "tersa-cli-macos",
    // 3d: the trusted composition reconciles sync into the encrypted store.
    "tersa-oauth-sync-macos",
    // 3d: the mailbox-sync FFI reaches the store only through the composition; its
    // closed direct-dependency set forbids declaring rusqlite directly.
    "tersa-mailbox-sync-ffi-macos",
    // ADR-0024 point 3: the token-broker FFI reaches Keychain (and thus the
    // store graph) only through the broker-only token store composition.
    "tersa-token-broker-ffi-macos",
];
const BLOB_DIAGNOSTIC_OWNERS: [&str; 1] = ["tersa-blob-spike"];
const HMAC_OWNERS: [&str; 5] = [
    "tersa-blob-spike",
    "tersa-keychain-macos",
    // 3d: reaches HMAC transitively through the Keychain HKDF key derivation.
    "tersa-oauth-sync-macos",
    // 3d: the mailbox-sync FFI reaches HMAC only through the composition's Keychain
    // HKDF; its closed direct-dependency set forbids declaring hmac directly.
    "tersa-mailbox-sync-ffi-macos",
    // ADR-0024 point 3: broker FFI reaches HMAC only transitively via Keychain.
    "tersa-token-broker-ffi-macos",
];
const RESERVED_FUTURE_POLICY: [(&str, &[&str]); 0] = [];
const MACOS_STORE_TARGET: &str = r#"cfg(target_os = "macos")"#;
const MACOS_GMAIL_TARGET: &str = r#"cfg(target_os = "macos")"#;
const MACOS_KEYCHAIN_TARGET: &str = r#"cfg(target_os = "macos")"#;
const REQWEST_DIRECT_FEATURES: [&str; 1] = ["native-tls"];
const REQWEST_RESOLVED_FEATURES: [&str; 4] =
    ["__native-tls", "__native-tls-alpn", "__tls", "native-tls"];
const RUSQLITE_RESOLVED_FEATURES: [&str; 3] = ["bundled", "bundled-sqlcipher", "modern_sqlite"];
const RUSTIX_RESOLVED_FEATURES: [&str; 12] = [
    "alloc", "default", "event", "fs", "mm", "net", "pipe", "process", "shm", "std", "system",
    "time",
];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> TaskResult {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("architecture") => {
            reject_extra_arguments(arguments)?;
            check_architecture()
        }
        Some("dco") => {
            let base = required_argument(&mut arguments, "base commit")?;
            let head = required_argument(&mut arguments, "head commit")?;
            reject_extra_arguments(arguments)?;
            check_dco(&base, &head)
        }
        Some("verify") => {
            reject_extra_arguments(arguments)?;
            verify()
        }
        Some("help") | None => {
            print_help();
            Ok(())
        }
        Some(command) => Err(io::Error::other(format!(
            "unknown command `{command}`; run `cargo xtask help`"
        ))
        .into()),
    }
}

fn required_argument(
    arguments: &mut impl Iterator<Item = String>,
    description: &str,
) -> TaskResult<String> {
    arguments.next().ok_or_else(|| {
        io::Error::other(format!("missing {description}; run `cargo xtask help`")).into()
    })
}

fn reject_extra_arguments(mut arguments: impl Iterator<Item = String>) -> TaskResult {
    if let Some(argument) = arguments.next() {
        return Err(io::Error::other(format!("unexpected argument `{argument}`")).into());
    }
    Ok(())
}

fn print_help() {
    println!(
        "\
Repository automation for tersa.app

Usage:
  cargo xtask architecture       Check workspace dependency boundaries
  cargo xtask dco <base> <head>  Check DCO sign-offs in a commit range
  cargo xtask verify             Run the baseline Rust verification suite
  cargo xtask help               Show this help"
    );
}

fn verify() -> TaskResult {
    check_architecture()?;
    run_command("format", cargo(["fmt", "--all", "--check"]))?;
    run_command(
        "check",
        cargo([
            "check",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
        ]),
    )?;
    run_command(
        "Clippy",
        cargo([
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "--deny",
            "warnings",
        ]),
    )?;
    run_command(
        "tests",
        cargo([
            "test",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
        ]),
    )?;
    run_command(
        "documentation tests",
        cargo(["test", "--locked", "--workspace", "--doc", "--all-features"]),
    )?;

    let mut documentation = cargo([
        "doc",
        "--locked",
        "--workspace",
        "--no-deps",
        "--all-features",
    ]);
    documentation.env("RUSTDOCFLAGS", "--deny warnings");
    run_command("documentation", documentation)?;

    println!("Baseline verification passed.");
    Ok(())
}

fn cargo<const N: usize>(arguments: [&str; N]) -> Command {
    let mut command = Command::new("cargo");
    command.args(arguments);
    command
}

fn run_command(label: &str, mut command: Command) -> TaskResult {
    println!("Running {label} check...");
    let status = command.status()?;
    if status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!("{label} check exited with status {status}")).into())
}

fn check_architecture() -> TaskResult {
    let metadata = MetadataCommand::new()
        .other_options(vec!["--locked".to_owned(), "--all-features".to_owned()])
        .exec()?;
    let workspace_packages = metadata.workspace_packages();
    let policy = dependency_policy();
    let mut violations = Vec::new();
    let workspace_resolved_dependencies = workspace_resolved_dependencies(&metadata)?;
    violations.extend(reserved_future_policy_violations(
        &workspace_resolved_dependencies,
    ));
    for package in workspace_packages {
        let package_name = package.name.to_string();
        if package_name == "xtask" {
            continue;
        }
        let allowed = policy.get(package_name.as_str()).ok_or_else(|| {
            io::Error::other(format!(
                "workspace crate `{package_name}` is missing from the dependency policy"
            ))
        })?;
        let workspace_dependencies = workspace_resolved_dependencies
            .get(&package_name)
            .ok_or_else(|| {
                io::Error::other(format!(
                    "workspace crate `{package_name}` is missing from resolved metadata"
                ))
            })?;

        for dependency_name in workspace_dependencies {
            if !allowed.contains(&dependency_name.as_str()) {
                violations.push(format!("{package_name} -> {dependency_name}"));
            }
        }

        violations.extend(protected_package_shape_violations(package, &metadata));

        for dependency in &package.dependencies {
            check_slint_dependency(&package_name, dependency, &mut violations);
            check_dioxus_dependency(&package_name, dependency, &mut violations);
            check_sqlcipher_dependency(&package_name, dependency, &mut violations);
            check_search_dependency(&package_name, dependency, &mut violations);
            check_mime_dependency(&package_name, dependency, &mut violations);
            check_blob_dependency(&package_name, dependency, &mut violations);
            check_gmail_dependency(&package_name, dependency, &mut violations);
            check_keychain_dependency(&package_name, dependency, &mut violations);
            violations.extend(protected_keychain_dependency_rename_violations(
                &package_name,
                dependency.name.as_str(),
                dependency.rename.as_deref(),
            ));
            check_rustix_dependency(&package_name, dependency, &mut violations);
            check_tokio_dependency(&package_name, dependency, &mut violations);
            if let Some(violation) = future_macos_store_dependency_violation(
                &package_name,
                dependency.name.as_str(),
                dependency
                    .target
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
            ) {
                violations.push(violation);
            }
        }
    }

    check_macos_keychain_signing_configuration(&mut violations)?;
    check_resolved_architecture(&mut violations)?;

    finish_architecture_check(&violations)
}

/// Collects the names of a package's SHIPPED direct dependencies.
///
/// The closed-composition and required-dependency invariants govern the shipped
/// production graph, so only normal dependencies count. Dev-dependencies (test
/// fixtures) and build-dependencies never enter the shipped binary and cannot
/// grant it a capability, so they are excluded.
fn shipped_direct_dependency_names(dependencies: &[Dependency]) -> BTreeSet<&str> {
    dependencies
        .iter()
        .filter(|dependency| dependency.kind == DependencyKind::Normal)
        .map(|dependency| dependency.name.as_str())
        .collect()
}

fn protected_package_shape_violations(package: &Package, metadata: &Metadata) -> Vec<String> {
    let package_name = package.name.as_str();
    let direct_dependencies = shipped_direct_dependency_names(&package.dependencies);
    let mut violations = Vec::new();
    if package_name == "tersa-blob-spike" && !direct_dependencies.contains("rustix") {
        violations.push("tersa-blob-spike must depend directly on exact-pinned rustix".to_owned());
    }
    if package_name == "tersa-keychain-macos" {
        violations.extend(keychain_direct_dependency_set_violations(
            &direct_dependencies,
        ));
        violations.extend(custom_build_target_violations(package));
        violations.extend(authority_package_target_violations(package, metadata));
    }
    if package_name == "tersa-apple-bridge" {
        violations.extend(apple_bridge_package_violations(
            package,
            metadata
                .workspace_root
                .join("apple/rust-bridge/src/lib.rs")
                .as_str(),
        ));
    }
    if package_name == "tersa-cli-macos" {
        violations.extend(cli_direct_dependency_set_violations(&direct_dependencies));
        violations.extend(custom_build_target_violations(package));
        violations.extend(authority_package_target_violations(package, metadata));
    }
    if package_name == "tersa-oauth-sync-macos" {
        violations.extend(oauth_sync_direct_dependency_set_violations(
            &direct_dependencies,
        ));
        violations.extend(custom_build_target_violations(package));
    }
    if package_name == "tersa-mailbox-sync-ffi-macos" {
        violations.extend(mailbox_sync_ffi_direct_dependency_set_violations(
            &direct_dependencies,
        ));
        violations.extend(mailbox_sync_ffi_package_violations(
            package,
            metadata
                .workspace_root
                .join("adapters/mailbox-sync-ffi-macos/src/lib.rs")
                .as_str(),
        ));
        violations.extend(custom_build_target_violations(package));
    }
    if package_name == "tersa-token-broker-ffi-macos" {
        violations.extend(token_broker_ffi_direct_dependency_set_violations(
            &direct_dependencies,
        ));
        violations.extend(token_broker_ffi_package_violations(
            package,
            metadata
                .workspace_root
                .join("adapters/token-broker-ffi-macos/src/lib.rs")
                .as_str(),
        ));
        violations.extend(custom_build_target_violations(package));
    }
    violations
}

/// The token-broker FFI's direct dependency set is closed: broker core, Google
/// transport, broker Keychain store, portable clocks, and a pinned tokio runtime
/// — and NOTHING else. It must never depend on the main app's mailbox-sync FFI
/// or the Apple bootstrap bridge.
fn token_broker_ffi_direct_dependency_set_violations(dependencies: &BTreeSet<&str>) -> Vec<String> {
    const REQUIRED: [&str; 7] = [
        "tersa-application",
        "tersa-domain",
        "tersa-gmail-rest-macos",
        "tersa-keychain-macos",
        "tersa-token-broker-core",
        "tokio",
        "zeroize",
    ];
    let required = REQUIRED.into_iter().collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    for dependency in dependencies.difference(&required) {
        violations.push(format!(
            "tersa-token-broker-ffi-macos -> {dependency} (dependency is outside the closed token-broker FFI set)"
        ));
    }
    for dependency in required.difference(dependencies) {
        violations.push(format!(
            "tersa-token-broker-ffi-macos is missing required direct dependency {dependency}"
        ));
    }
    violations
}

/// The token-broker FFI must expose exactly one reviewed library target.
fn token_broker_ffi_package_violations(package: &Package, canonical_library: &str) -> Vec<String> {
    let has_exact_library = package.targets.iter().any(|target| {
        target.name == "tersa_token_broker_ffi_macos"
            && target.src_path.as_str() == canonical_library
            && target.kind == [TargetKind::RLib, TargetKind::StaticLib]
            && target.crate_types == [CrateType::RLib, CrateType::StaticLib]
    });
    if package.targets.len() != 1 || !has_exact_library {
        return vec![
            "tersa-token-broker-ffi-macos must expose only the reviewed rlib/staticlib library target from its canonical source"
                .to_owned(),
        ];
    }
    Vec::new()
}

/// The trusted composition's direct dependency set is closed: it may compose the
/// Keychain token store, the Gmail network adapter, the `SQLCipher` store, the
/// portable application/domain, and its pinned tokio runtime — and NOTHING else.
/// Because it is (necessarily) in the `SQLCipher` and `HMAC` reachability
/// owner-sets, this closed set is what stops it from DIRECTLY declaring
/// `rusqlite`, `hmac`, or any other capability crate and bypassing the store or
/// key-derivation abstractions.
fn oauth_sync_direct_dependency_set_violations(dependencies: &BTreeSet<&str>) -> Vec<String> {
    const REQUIRED: [&str; 7] = [
        "tersa-application",
        "tersa-domain",
        "tersa-gmail-rest-macos",
        "tersa-keychain-macos",
        "tersa-store-sqlcipher-macos",
        "tokio",
        "zeroize",
    ];
    let required = REQUIRED.into_iter().collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    for dependency in dependencies.difference(&required) {
        violations.push(format!(
            "tersa-oauth-sync-macos -> {dependency} (dependency is outside the closed composition set)"
        ));
    }
    for dependency in required.difference(dependencies) {
        violations.push(format!(
            "tersa-oauth-sync-macos is missing required direct dependency {dependency}"
        ));
    }
    violations
}

/// The mailbox-sync FFI's direct dependency set is closed: it forwards two public
/// strings to the trusted composition, claims finished grants through the Apple
/// bridge's session registry seams, and builds a token-client configuration from
/// the portable application types — and NOTHING else. Because it is (necessarily)
/// in the `SQLCipher` and `HMAC` reachability owner-sets, this closed set is what
/// stops it from DIRECTLY declaring `rusqlite`, `hmac`, or any other capability
/// crate and bypassing the composition it exists only to expose. The bridge edge
/// is a network-free tersa-* crate, not a capability crate: it adds no new
/// network, `SQLCipher`, or `HMAC` reachability, and it is what lets the
/// application link only the FFI archive while still seeing the bridge's symbols.
/// ADR-0024: `zeroize` is an intentional direct dependency — the broker-fed
/// entry points copy the short-lived access-token and routing-subject buffers
/// under zeroizing wrappers immediately, and no other crate in this set can
/// provide that wrapper.
fn mailbox_sync_ffi_direct_dependency_set_violations(dependencies: &BTreeSet<&str>) -> Vec<String> {
    const REQUIRED: [&str; 5] = [
        "tersa-application",
        "tersa-apple-bridge",
        "tersa-oauth-sync-macos",
        "url",
        "zeroize",
    ];
    let required = REQUIRED.into_iter().collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    for dependency in dependencies.difference(&required) {
        violations.push(format!(
            "tersa-mailbox-sync-ffi-macos -> {dependency} (dependency is outside the closed FFI set)"
        ));
    }
    for dependency in required.difference(dependencies) {
        violations.push(format!(
            "tersa-mailbox-sync-ffi-macos is missing required direct dependency {dependency}"
        ));
    }
    violations
}

/// The mailbox-sync FFI must expose exactly one reviewed library target, an
/// `rlib`+`staticlib` from the canonical `src/lib.rs`, and nothing else — no example,
/// binary, or custom-build target that could smuggle an unreviewed exported symbol.
fn mailbox_sync_ffi_package_violations(package: &Package, canonical_library: &str) -> Vec<String> {
    let has_exact_library = package.targets.iter().any(|target| {
        target.name == "tersa_mailbox_sync_ffi_macos"
            && target.src_path.as_str() == canonical_library
            && target.kind == [TargetKind::RLib, TargetKind::StaticLib]
            && target.crate_types == [CrateType::RLib, CrateType::StaticLib]
    });
    if package.targets.len() != 1 || !has_exact_library {
        return vec![
            "tersa-mailbox-sync-ffi-macos must expose only the reviewed rlib/staticlib library target from its canonical source"
                .to_owned(),
        ];
    }
    Vec::new()
}

fn authority_package_target_violations(package: &Package, metadata: &Metadata) -> Vec<String> {
    let expected = match package.name.as_str() {
        "tersa-keychain-macos" => vec![(
            "tersa_keychain_macos",
            TargetKind::Lib,
            CrateType::Lib,
            "adapters/keychain-macos/src/lib.rs",
        )],
        "tersa-cli-macos" => vec![
            (
                "tersa_cli_macos",
                TargetKind::Lib,
                CrateType::Lib,
                "apps/cli-macos/src/lib.rs",
            ),
            (
                "tersa-cli-macos",
                TargetKind::Bin,
                CrateType::Bin,
                "apps/cli-macos/src/main.rs",
            ),
        ],
        _ => return Vec::new(),
    };
    let exact = package.targets.len() == expected.len()
        && expected.into_iter().all(|(name, kind, crate_type, path)| {
            let canonical = metadata.workspace_root.join(path);
            package.targets.iter().any(|target| {
                target.name == name
                    && target.kind == [kind.clone()]
                    && target.crate_types == [crate_type.clone()]
                    && target.src_path == canonical
            })
        });
    (!exact)
        .then(|| {
            format!(
                "{} target sources must match the exact reviewed authority inventory",
                package.name
            )
        })
        .into_iter()
        .collect()
}

fn custom_build_target_violations(package: &Package) -> Vec<String> {
    package
        .targets
        .iter()
        .any(cargo_metadata::Target::is_custom_build)
        .then(|| {
            format!(
                "{} must not expose a Cargo custom-build target",
                package.name
            )
        })
        .into_iter()
        .collect()
}

fn apple_bridge_package_violations(package: &Package, canonical_library: &str) -> Vec<String> {
    let direct_dependencies = shipped_direct_dependency_names(&package.dependencies);
    let mut violations = apple_bridge_direct_dependency_set_violations(&direct_dependencies);
    if package
        .targets
        .iter()
        .any(cargo_metadata::Target::is_custom_build)
    {
        violations
            .push("tersa-apple-bridge must not expose a Cargo custom-build target".to_owned());
    }
    let canonical_example = Path::new(canonical_library)
        .parent()
        .and_then(Path::parent)
        .map(|package_root| package_root.join("examples/oauth_entitlement_probe.rs"))
        .and_then(|path| path.to_str().map(str::to_owned));
    let has_exact_library = package.targets.iter().any(|target| {
        target.name == "tersa_apple_bridge"
            && target.src_path.as_str() == canonical_library
            && target.kind == [TargetKind::RLib, TargetKind::StaticLib]
            && target.crate_types == [CrateType::RLib, CrateType::StaticLib]
    });
    let has_exact_example = canonical_example
        .as_deref()
        .is_some_and(|canonical_example| {
            package.targets.iter().any(|target| {
                target.name == "oauth_entitlement_probe"
                    && target.src_path.as_str() == canonical_example
                    && target.kind == [TargetKind::Example]
                    && target.crate_types == [CrateType::Bin]
            })
        });
    if package.targets.len() != 2 || !has_exact_library || !has_exact_example {
        violations.push(
            "tersa-apple-bridge must expose only the reviewed rlib/staticlib and oauth_entitlement_probe example targets from their canonical sources"
                .to_owned(),
        );
    }
    violations
}

fn finish_architecture_check(violations: &[String]) -> TaskResult {
    if violations.is_empty() {
        println!("Architecture dependency boundaries passed.");
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "architecture dependency violations: {}",
            violations.join(", ")
        ))
        .into())
    }
}

fn check_macos_keychain_signing_configuration(violations: &mut Vec<String>) -> TaskResult {
    let entitlements = fs::read_to_string("apple/macos/TersaMac.entitlements")?;
    let broker_entitlements =
        fs::read_to_string("apple/macos-token-broker/TersaMacTokenBroker.entitlements")?;
    let project = fs::read_to_string("apple/project.yml")?;
    violations.extend(signing_configuration_violations(
        &entitlements,
        &broker_entitlements,
        &project,
    ));
    let mut entitlement_paths = Vec::new();
    collect_entitlement_paths(
        Path::new("apple"),
        Path::new("apple"),
        &mut entitlement_paths,
    )?;
    let tracked_entitlements = tracked_apple_signing_inventory(Path::new("."))?;
    violations.extend(tracked_entitlements.violations);
    entitlement_paths.extend(tracked_entitlements.entitlement_paths);
    entitlement_paths.sort();
    entitlement_paths.dedup();
    for path in entitlement_paths {
        if path == Path::new("apple/macos/TersaMac.entitlements") {
            continue;
        }
        let document = fs::read_to_string(&path)?;
        if path == Path::new("apple/macos-token-broker/TersaMacTokenBroker.entitlements") {
            violations.extend(source_token_broker_entitlement_violations(&document));
            continue;
        }
        violations.extend(non_owner_entitlement_violations(
            &path.to_string_lossy(),
            &document,
        ));
    }

    let keychain_owner_sources =
        tracked_source_documents(Path::new("."), "adapters/keychain-macos/src")?;
    let mut keychain_authority_sources = Vec::new();
    for product_root in ["adapters", "apple/rust-bridge", "apps", "crates"] {
        keychain_authority_sources.extend(tracked_source_documents(Path::new("."), product_root)?);
    }
    keychain_authority_sources.extend(tracked_source_documents(Path::new("."), "apple/macos")?);
    keychain_authority_sources.extend(tracked_source_documents(
        Path::new("."),
        "apple/macos-token-broker",
    )?);
    violations.extend(keychain_mutation_boundary_violations(
        &keychain_owner_sources,
        &keychain_authority_sources,
    ));
    let macos_sources = tracked_source_documents(Path::new("."), "apple/macos")?;
    violations.extend(macos_client_xpc_wiring_violations(&macos_sources));
    let broker_sources = tracked_source_documents(Path::new("."), "apple/macos-token-broker")?;
    violations.extend(token_broker_source_surface_violations(&broker_sources));
    let service_protocol = fs::read_to_string(REVIEWED_TOKEN_BROKER_PROTOCOL_PATH)?;
    let client_protocol = fs::read_to_string(REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH)?;
    violations.extend(token_broker_protocol_mirror_violations(
        &service_protocol,
        &client_protocol,
    ));
    let project_generation_wrapper = fs::read_to_string("apple/scripts/generate-project.sh")?;
    let ci = fs::read_to_string(".github/workflows/ci.yml")?;
    let development = fs::read_to_string("docs/development.md")?;
    let evidence = fs::read_to_string("apple/scripts/capture-dioxus-device-evidence.sh")?;
    violations.extend(project_generation_surface_violations(
        &project_generation_wrapper,
        &ci,
        &development,
        &evidence,
    ));
    violations.extend(tracked_project_generation_violations(Path::new("."))?);
    violations.extend(bootstrap_source_surface_violations(Path::new("."))?);
    Ok(())
}

fn bootstrap_source_surface_violations(repository_root: &Path) -> io::Result<Vec<String>> {
    let mut violations = Vec::new();
    for (path, document) in tracked_source_documents(repository_root, "apps/cli-macos")? {
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            violations.extend(rust_authority_source_surface_violations(&path, &document));
            violations.extend(cli_keychain_source_violations(
                &path.to_string_lossy(),
                &document,
            ));
        }
    }

    let cli_sources = tracked_source_documents(repository_root, "apps/cli-macos/src")?;
    let cli_paths = cli_sources
        .iter()
        .map(|(path, _document)| path.clone())
        .collect::<BTreeSet<_>>();
    violations.extend(canonical_cli_source_anchor_violations(&cli_paths));

    let bridge_package_sources = tracked_source_documents(repository_root, "apple/rust-bridge")?;
    let bridge_sources = tracked_source_documents(repository_root, "apple/rust-bridge/src")?;
    let bridge_paths = bridge_sources
        .iter()
        .map(|(path, _document)| path.clone())
        .collect::<BTreeSet<_>>();
    let canonical_bridge = PathBuf::from("apple/rust-bridge/src/lib.rs");
    let canonical_mailbox_bridge = PathBuf::from("apple/rust-bridge/src/mailbox.rs");
    violations.extend(bridge_package_source_surface_violations(
        &bridge_package_sources,
        &bridge_paths,
    ));
    violations.extend(rust_exported_c_abi_violations(
        &bridge_package_sources,
        &expected_apple_c_abi_exports(),
        APPLE_BRIDGE_C_ABI_COUNT_MESSAGE,
    ));

    // The mailbox-sync FFI is a sibling static library with its own seven-symbol C ABI;
    // pin its reviewed sources and export inventory exactly as the bridge's, so a new
    // source file or exported symbol cannot land without review.
    let ffi_package_sources =
        tracked_source_documents(repository_root, "adapters/mailbox-sync-ffi-macos")?;
    violations.extend(mailbox_sync_ffi_source_surface_violations(
        &ffi_package_sources,
    ));
    violations.extend(rust_exported_c_abi_violations(
        &ffi_package_sources,
        &expected_mailbox_sync_ffi_c_abi_exports(),
        MAILBOX_SYNC_FFI_C_ABI_COUNT_MESSAGE,
    ));

    violations.extend(token_broker_bootstrap_source_surface_violations(
        repository_root,
    )?);

    for (path, document) in tracked_source_documents(repository_root, "adapters/keychain-macos")? {
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            violations.extend(rust_authority_source_surface_violations(&path, &document));
        }
    }
    let mut boundary_document = String::new();
    for canonical_source in [&canonical_bridge, &canonical_mailbox_bridge] {
        if !bridge_paths.contains(canonical_source) {
            violations.push(format!(
                "the Apple bridge canonical source `{}` must be tracked",
                canonical_source.display()
            ));
            continue;
        }
        if let Some((_path, document)) = bridge_sources
            .iter()
            .find(|(path, _document)| path == canonical_source)
        {
            boundary_document.push_str(document);
            boundary_document.push('\n');
        }
    }
    violations.extend(bridge_bootstrap_source_violations(&boundary_document));

    let worker_path = repository_root.join("apple/macos/BootstrapWorker.swift");
    let app_delegate_path = repository_root.join("apple/macos/AppDelegate.swift");
    let macos_sources = tracked_source_documents(repository_root, "apple/macos")?;
    let tracked_macos_sources = macos_sources
        .iter()
        .map(|(path, _document)| path.clone())
        .collect::<BTreeSet<_>>();
    for required in [
        PathBuf::from("apple/macos/BootstrapWorker.swift"),
        PathBuf::from("apple/macos/AppDelegate.swift"),
    ] {
        if !tracked_macos_sources.contains(&required) {
            violations.push(format!(
                "reviewed macOS bootstrap source `{}` must be tracked",
                required.display()
            ));
        }
    }
    if !worker_path.is_file() || !app_delegate_path.is_file() {
        violations.push("the reviewed macOS bootstrap worker sources are missing".to_owned());
    } else {
        let worker = fs::read_to_string(worker_path)?;
        let app_delegate = fs::read_to_string(app_delegate_path)?;
        violations.extend(swift_bootstrap_source_violations(&worker, &app_delegate));
        violations.extend(swift_bootstrap_inventory_violations(&macos_sources));
    }
    violations.extend(swift_ffi_symbol_inventory_violations(&macos_sources));
    violations.extend(swift_oauth_foreground_handoff_violations(&macos_sources));
    Ok(violations)
}

/// The token-broker FFI is a dedicated static library with its own five-symbol
/// C ABI. This source-level guard pins this crate's own five exports, bridge
/// header, and wire-status inventory exactly, so a sixth local export (for
/// example refresh-token export) or status renumber cannot land without review.
/// The built-archive CI assertion closes transitive linked `_tersa_` text
/// exports in the final static archive.
fn token_broker_bootstrap_source_surface_violations(
    repository_root: &Path,
) -> io::Result<Vec<String>> {
    let mut violations = Vec::new();
    let token_broker_ffi_sources =
        tracked_source_documents(repository_root, REVIEWED_TOKEN_BROKER_FFI_PACKAGE_ROOT)?;
    violations.extend(token_broker_ffi_source_surface_violations(
        &token_broker_ffi_sources,
    ));
    violations.extend(rust_exported_c_abi_violations(
        &token_broker_ffi_sources,
        &expected_token_broker_ffi_c_abi_exports(),
        TOKEN_BROKER_FFI_C_ABI_COUNT_MESSAGE,
    ));
    let token_broker_bridge_header =
        fs::read_to_string(repository_root.join(REVIEWED_TOKEN_BROKER_BRIDGE_HEADER_PATH))?;
    violations.extend(token_broker_bridge_header_c_abi_violations(
        &token_broker_bridge_header,
    ));
    if let Some((_path, rust_ffi_source)) = token_broker_ffi_sources
        .iter()
        .find(|(path, _)| path == Path::new("adapters/token-broker-ffi-macos/src/lib.rs"))
    {
        let service_protocol =
            fs::read_to_string(repository_root.join(REVIEWED_TOKEN_BROKER_PROTOCOL_PATH))?;
        let client_protocol =
            fs::read_to_string(repository_root.join(REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH))?;
        violations.extend(token_broker_wire_status_coherence_violations(
            rust_ffi_source,
            &service_protocol,
            &client_protocol,
        ));
    } else {
        violations.push(
            "the token-broker FFI canonical source adapters/token-broker-ffi-macos/src/lib.rs must be tracked"
                .to_owned(),
        );
    }
    Ok(violations)
}

fn canonical_cli_source_anchor_violations(paths: &BTreeSet<PathBuf>) -> Vec<String> {
    ["apps/cli-macos/src/lib.rs", "apps/cli-macos/src/main.rs"]
        .into_iter()
        .filter(|required| !paths.contains(&PathBuf::from(required)))
        .map(|required| format!("the CLI canonical source `{required}` must be tracked"))
        .collect()
}

fn tracked_source_documents(
    repository_root: &Path,
    prefix: &str,
) -> io::Result<Vec<(PathBuf, String)>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(["ls-files", "--stage", "-z", "--", prefix])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git ls-files failed while inventorying `{prefix}` sources"
        )));
    }
    let entries = String::from_utf8(output.stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut documents = Vec::new();
    for entry in entries.split('\0').filter(|entry| !entry.is_empty()) {
        let Some((metadata, path)) = entry.split_once('\t') else {
            return Err(io::Error::other("malformed tracked source index entry"));
        };
        let mode = metadata
            .split_whitespace()
            .next()
            .ok_or_else(|| io::Error::other("tracked source index entry has no mode"))?;
        if !matches!(mode, "100644" | "100755") {
            return Err(io::Error::other(format!(
                "tracked source `{path}` has forbidden git mode `{mode}`"
            )));
        }
        let path = PathBuf::from(path);
        let document = fs::read_to_string(repository_root.join(&path))?;
        documents.push((path, document));
    }
    Ok(documents)
}

fn cli_keychain_source_violations(path: &str, document: &str) -> Vec<String> {
    const ALLOWED: [&str; 2] = ["ReadOnlyMailboxOpenError", "open_default_read_only_mailbox"];
    const FORBIDDEN_COMPOSITION: [&str; 8] = [
        "DataProtectionRootKeyProvisioner",
        "InstallationRootKeyProvisioner",
        "MailboxReadStatus",
        "ProductBootstrapStatus",
        "bootstrap_default_account_bytes",
        "read_default_inbox",
        "read_default_thread",
        "search_default_mailbox",
    ];
    let mut violations = Vec::new();
    let code = strip_rust_non_code(document);
    let policy_code = strip_rust_test_modules(&code);
    for reference in rust_qualified_item_uses(&policy_code, "tersa_keychain_macos") {
        if !ALLOWED.contains(&reference.item.as_str())
            || (reference.item == "open_default_read_only_mailbox" && !reference.is_call)
        {
            violations.push(format!(
                "{path} references forbidden Keychain adapter item `{}`",
                reference.item
            ));
        }
    }
    if rust_keychain_imported(&policy_code) {
        violations.push(format!(
            "{path} must use only fully qualified, non-aliased Keychain retrieval items"
        ));
    }
    for symbol in FORBIDDEN_COMPOSITION {
        if contains_identifier(&policy_code, symbol) {
            violations.push(format!(
                "{path} contains forbidden Keychain composition symbol `{symbol}`"
            ));
        }
    }
    violations
}

fn keychain_mutation_boundary_violations(
    owner_sources: &[(PathBuf, String)],
    authority_sources: &[(PathBuf, String)],
) -> Vec<String> {
    const REQUIRED: [&str; 5] = [
        "SecItemAdd",
        "SecItemCopyMatching",
        "SecRandomCopyBytes",
        "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        "kSecUseDataProtectionKeychain",
    ];
    const FORBIDDEN: [&str; 3] = ["SecItemUpdate", "SecItemDelete", "set_generic_password"];
    let mut violations = Vec::new();
    let mut production_owner_sources = Vec::new();
    let owner_paths = owner_sources
        .iter()
        .map(|(path, _document)| path)
        .collect::<BTreeSet<_>>();
    for (path, document) in owner_sources {
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let code = strip_rust_non_code(document);
        let production = strip_rust_test_modules(&code);
        production_owner_sources.push(production);
    }
    for (path, document) in authority_sources {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("rs") => {
                let is_owner = owner_paths.contains(path);
                let code = strip_rust_non_code(document);
                let production = strip_rust_test_modules(&code);
                // Owner adapter files are governed by the owner partition below,
                // which permits the single token file (and only it) to mutate the
                // token item while keeping every other owner file add-only. Callers
                // may never mutate at all, so the full ban still applies to them.
                if !is_owner {
                    for forbidden in FORBIDDEN {
                        if contains_identifier(&production, forbidden) {
                            violations.push(format!(
                                "{} contains forbidden Keychain mutation boundary `{forbidden}`",
                                path.display()
                            ));
                        }
                    }
                }
                if !is_owner && contains_identifier(&production, "SecItemAdd") {
                    violations.push(format!(
                        "{} contains Keychain insertion authority outside the owning adapter",
                        path.display()
                    ));
                }
                if contains_identifier_with_prefix(&production, "SecKeychain") {
                    violations.push(format!(
                        "{} contains forbidden legacy Keychain authority",
                        path.display()
                    ));
                }
                if !is_owner {
                    violations.extend(rust_authority_dynamic_alias_violations(path, document));
                }
            }
            Some("swift") => {
                violations.extend(swift_keychain_authority_violations(path, document));
                violations.extend(swift_source_lexical_violations(path, document));
            }
            _ => {}
        }
    }
    violations.extend(keychain_owner_partition_violations(owner_sources));
    let aggregate = production_owner_sources.join("\n");
    for required in REQUIRED {
        if !contains_identifier(&aggregate, required) {
            violations.push(format!(
                "the macOS Keychain adapter is missing required production boundary `{required}`"
            ));
        }
    }
    violations
}

/// The one owner file permitted to mutate (rotate/delete) the token item.
const TOKEN_MUTATION_FILE: &str = "adapters/keychain-macos/src/oauth_token.rs";

/// Partitions the Keychain adapter's own sources so that exactly one file — the
/// OAuth token store — may call `SecItemUpdate` / `SecItemDelete`, and only ever
/// against the token service, while every other owner file stays add-only.
///
/// Because the Phase-1 token and root items share account and access group, the
/// service string is their only discriminator, so the token file is held
/// lexically fixed to its own service: it may not name the root service, use a
/// string escape, byte literal, external include, or assembly intrinsic, and any
/// service-prefixed literal it carries must be exactly the token service value.
/// This is defense in depth plus reviewability, NOT a runtime guarantee: a
/// lexical guard provably cannot stop runtime construction of the root service
/// value — string concatenation (`"a" + "b"`), a `[u8]` array with `from_utf8`
/// (un-bannable, the decode path needs it), char-by-char assembly, or a helper in
/// another owner module all evade any denylist. Only a distinct Keychain access
/// group (out of ADR-0023 scope, tracked as a follow-up) closes those at runtime.
/// What this guard DOES enforce is that no root service can be reached by a
/// direct, literal, escaped, raw/byte-string, or listed-intrinsic path — i.e. it
/// fails closed on every accidental or plainly review-visible retarget, and any
/// remaining route is a deliberate runtime computation a reviewer would see.
///
/// This lexical set is intentionally FINAL: further bans chase an unwinnable
/// in-repo arms race (a malicious committer edits the guard in the same commit as
/// the bypass, so it can never be in scope). The runtime barrier is the tracked
/// access-group follow-up, not another denylist entry.
fn keychain_owner_partition_violations(owner_sources: &[(PathBuf, String)]) -> Vec<String> {
    const OWNER_FORBIDDEN: [&str; 3] = ["SecItemUpdate", "SecItemDelete", "set_generic_password"];
    const LINK_MECHANISMS: [&str; 8] = [
        "asm",
        "dlopen",
        "dlsym",
        "export_name",
        "global_asm",
        "link_name",
        "llvm_asm",
        "naked_asm",
    ];
    let token_path = Path::new(TOKEN_MUTATION_FILE);
    let mut violations = Vec::new();
    for (path, document) in owner_sources {
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let comments_masked = strip_rust_comments(document);
        let production = strip_rust_non_code(&strip_rust_test_modules(&comments_masked));
        // Legacy Keychain APIs and dynamic-linkage mechanisms are forbidden in
        // every owner file, including the token file (it uses only the audited
        // `security_framework_sys` bindings).
        if contains_identifier_with_prefix(&production, "SecKeychain") {
            violations.push(format!(
                "{} contains forbidden legacy Keychain authority",
                path.display()
            ));
        }
        for mechanism in LINK_MECHANISMS {
            if contains_identifier(&production, mechanism) {
                violations.push(format!(
                    "{} declares forbidden dynamic linkage `{mechanism}` in the Keychain adapter",
                    path.display()
                ));
            }
        }

        if path == token_path {
            violations.extend(token_mutation_boundary_violations(
                path,
                &production,
                document,
            ));
        } else {
            // Every other owner file stays add-only: the root key can never be
            // rotated or deleted.
            for forbidden in OWNER_FORBIDDEN {
                if contains_identifier(&production, forbidden) {
                    violations.push(format!(
                        "{} contains forbidden Keychain mutation boundary `{forbidden}` outside the token file",
                        path.display()
                    ));
                }
            }
        }
    }
    violations
}

/// The lexical checks that keep the single token-mutation file fixed to the
/// token service. See [`keychain_owner_partition_violations`] for the threat
/// model: the token file may `SecItemUpdate` / `SecItemDelete`, but must stay
/// unable to plainly name or construct the root service value. Every dynamic or
/// external string-construction path is banned, and any service-prefixed literal
/// it carries must be exactly the token service value.
fn token_mutation_boundary_violations(
    path: &Path,
    production: &str,
    document: &str,
) -> Vec<String> {
    const CONSTRUCTION_INTRINSICS: [&str; 8] = [
        "format!",
        "concat!",
        "concat_bytes!",
        ".join(",
        "push_str",
        "include_str!",
        "include_bytes!",
        "env!",
    ];
    const BYTE_LITERALS: [&str; 4] = ["b\"", "br\"", "br#", "b'"];
    const ESCAPES: [&str; 2] = ["\\u{", "\\x"];
    const ROOT_LITERALS: [&str; 2] = ["storage-root", "AfterFirstUnlock"];
    const TOKEN_REQUIRED: [&str; 2] = [
        "TOKEN_SERVICE",
        "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    ];
    const SERVICE_PREFIX: &str = "app.tersa.mac.";
    const TOKEN_SERVICE_VALUE: &str = "app.tersa.mac.oauth-refresh-token.v1";

    let mut violations = Vec::new();
    if contains_identifier(production, "set_generic_password") {
        violations.push(format!(
            "{} contains forbidden Keychain mutation boundary `set_generic_password`",
            path.display()
        ));
    }
    for required in TOKEN_REQUIRED {
        if !contains_identifier(production, required) {
            violations.push(format!(
                "{} must positively scope the token mutation boundary to `{required}`",
                path.display()
            ));
        }
    }
    if contains_identifier(production, "SERVICE") {
        violations.push(format!(
            "{} must not name the root key service identifier `SERVICE`",
            path.display()
        ));
    }
    for intrinsic in CONSTRUCTION_INTRINSICS {
        if production.contains(intrinsic) {
            violations.push(format!(
                "{} must not build or import a string (`{intrinsic}`) in the token mutation boundary",
                path.display()
            ));
        }
    }
    // The literal / escape / byte / service-prefix checks scan comment-stripped
    // source (string literals intact, so an escaped or byte-built service is
    // caught; comments cannot construct anything and would only false-positive).
    let literals = strip_rust_comments(document);
    for literal in ROOT_LITERALS {
        if literals.contains(literal) {
            violations.push(format!(
                "{} must not name the root key literal `{literal}`",
                path.display()
            ));
        }
    }
    for byte_literal in BYTE_LITERALS {
        if literals.contains(byte_literal) {
            violations.push(format!(
                "{} must not use byte literals (`{byte_literal}`) in the token mutation boundary",
                path.display()
            ));
        }
    }
    for escape in ESCAPES {
        if literals.contains(escape) {
            violations.push(format!(
                "{} must not use string escapes (`{escape}`) in the token mutation boundary",
                path.display()
            ));
        }
    }
    // Raw string literals let a `"` inside the value defeat the closing-quote
    // allowlist below; the token file has no raw string. Matched at an identifier
    // boundary so a word ending in `r` before a closing quote (`behavior"`) is not
    // a false positive.
    for prefix in ["r\"", "r#"] {
        if literals.match_indices(prefix).any(|(index, _matched)| {
            literals[..index]
                .bytes()
                .next_back()
                .is_none_or(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
        }) {
            violations.push(format!(
                "{} must not use raw string literals in the token mutation boundary",
                path.display()
            ));
        }
    }
    // Positive allowlist: every service-prefixed literal must be EXACTLY the
    // token service value, immediately closed by `"`. Any suffix — `.v1.evil`,
    // `.v1/evil`, an escaped separator, or the root service — fails closed.
    let mut rest = literals.as_str();
    while let Some(index) = rest.find(SERVICE_PREFIX) {
        let tail = &rest[index..];
        let exact = tail.starts_with(TOKEN_SERVICE_VALUE)
            && tail[TOKEN_SERVICE_VALUE.len()..].starts_with('"');
        if !exact {
            violations.push(format!(
                "{} may only carry the token service literal `{TOKEN_SERVICE_VALUE}`, not another `{SERVICE_PREFIX}` value",
                path.display()
            ));
        }
        rest = &rest[index + SERVICE_PREFIX.len()..];
    }
    violations
}

fn swift_keychain_authority_violations(path: &Path, document: &str) -> Vec<String> {
    const FORBIDDEN_MUTATIONS: [&str; 3] = ["SecItemAdd", "SecItemUpdate", "SecItemDelete"];
    let code = strip_swift_non_code(document);

    let mut violations = FORBIDDEN_MUTATIONS
        .into_iter()
        .filter(|mutation| contains_identifier(&code, mutation))
        .map(|mutation| {
            format!(
                "{} contains forbidden Swift Keychain mutation boundary `{mutation}`",
                path.display()
            )
        })
        .collect::<Vec<_>>();
    if contains_identifier_with_prefix(&code, "SecKeychain") {
        violations.push(format!(
            "{} contains forbidden legacy Swift Keychain authority",
            path.display()
        ));
    }
    violations
}

fn rust_authority_source_surface_violations(path: &Path, document: &str) -> Vec<String> {
    let mut violations = rust_external_source_expansion_violations(path, document);
    if path.file_name().and_then(|name| name.to_str()) == Some("build.rs") {
        violations.push(format!(
            "{} must not introduce a generated authority source graph",
            path.display()
        ));
    }
    violations
}

/// Scans one production Rust document for dynamic or link-time mechanisms that
/// alias or export a symbol outside the reviewed `no_mangle` inventory — an
/// `export_name`/`link_name`/`link_section` attribute or inline assembly adds a
/// linkable symbol the export scanner never counts. Comments, string literals,
/// and test modules stay inert.
fn forbidden_export_mechanism_violations(path: &Path, document: &str) -> Vec<String> {
    const FORBIDDEN_MECHANISMS: [&str; 9] = [
        "asm",
        "dlopen",
        "dlsym",
        "export_name",
        "global_asm",
        "link_name",
        "link_section",
        "llvm_asm",
        "naked_asm",
    ];
    let comments_masked = strip_rust_comments(document);
    let production_document = strip_rust_test_modules(&comments_masked);
    let production_code = strip_rust_non_code(&production_document);
    let mut violations = Vec::new();
    for mechanism in FORBIDDEN_MECHANISMS {
        if contains_identifier(&production_code, mechanism) {
            violations.push(format!(
                "{} must not use dynamic or link-time authority alias mechanism `{mechanism}`",
                path.display()
            ));
        }
    }
    violations
}

fn rust_authority_dynamic_alias_violations(path: &Path, document: &str) -> Vec<String> {
    const FORBIDDEN_SYMBOLS: [&str; 4] = [
        "SecItemUpdate",
        "SecItemDelete",
        "SecKeychain",
        "set_generic_password",
    ];
    let comments_masked = strip_rust_comments(document);
    let production_document = strip_rust_test_modules(&comments_masked);
    let mut violations = forbidden_export_mechanism_violations(path, document);
    for symbol in FORBIDDEN_SYMBOLS {
        if rust_literal_contains(&production_document, symbol) {
            violations.push(format!(
                "{} must not name forbidden Keychain mutation symbol `{symbol}` in a production literal",
                path.display()
            ));
        }
    }
    violations
}

fn bridge_package_source_surface_violations(
    package_documents: &[(PathBuf, String)],
    inventoried_sources: &BTreeSet<PathBuf>,
) -> Vec<String> {
    let manifest_path = Path::new("apple/rust-bridge/Cargo.toml");
    let build_script_path = Path::new("apple/rust-bridge/build.rs");
    let mut violations = Vec::new();
    let Some((_path, manifest)) = package_documents
        .iter()
        .find(|(path, _document)| path == manifest_path)
    else {
        return vec!["the Apple bridge Cargo.toml must be tracked".to_owned()];
    };
    if toml_table_has_key(manifest, "package", "build") {
        violations
            .push("the Apple bridge package must not declare a Cargo build script".to_owned());
    }
    if toml_table_has_key(manifest, "lib", "path") {
        violations.push(
            "the Apple bridge library must use the canonical inventoried src/lib.rs entry"
                .to_owned(),
        );
    }
    if package_documents
        .iter()
        .any(|(path, _document)| path == build_script_path)
    {
        violations.push("the Apple bridge must not track a conventional build.rs".to_owned());
    }
    let reviewed_rust_sources = BTreeSet::from([
        PathBuf::from("apple/rust-bridge/examples/oauth_entitlement_probe.rs"),
        PathBuf::from("apple/rust-bridge/src/lib.rs"),
        PathBuf::from("apple/rust-bridge/src/mailbox.rs"),
        PathBuf::from("apple/rust-bridge/src/oauth.rs"),
    ]);
    let tracked_rust_sources = package_documents
        .iter()
        .filter(|(path, _document)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("rs")
        })
        .map(|(path, _document)| path.clone())
        .collect::<BTreeSet<_>>();
    if tracked_rust_sources != reviewed_rust_sources {
        violations.push(
            "the Apple bridge tracked Rust source inventory must match the reviewed library, mailbox read module, OAuth module, and entitlement probe"
                .to_owned(),
        );
    }
    if !inventoried_sources.is_subset(&reviewed_rust_sources) {
        violations.push(
            "the Apple bridge module inventory contains an unreviewed Rust source".to_owned(),
        );
    }
    for (path, document) in package_documents {
        if !reviewed_rust_sources.contains(path) {
            continue;
        }
        violations.extend(rust_external_source_expansion_violations(path, document));
        violations.extend(forbidden_export_mechanism_violations(path, document));
        if path != Path::new("apple/rust-bridge/src/lib.rs")
            && path != Path::new("apple/rust-bridge/src/mailbox.rs")
        {
            let code = strip_rust_test_modules(&strip_rust_non_code(document));
            if contains_identifier(&code, "tersa_keychain_macos") {
                violations.push(format!(
                    "{} must not reference the Keychain bootstrap adapter outside the canonical bridge sources",
                    path.display()
                ));
            }
        }
    }
    violations
}

/// The exact count message for the Apple bridge's reviewed C ABI symbol set.
const APPLE_BRIDGE_C_ABI_COUNT_MESSAGE: &str = "the Apple bridge production exported C ABI set must match the eleven reviewed symbols, including the unexposed entitlement probe";
/// The exact count message for the mailbox-sync FFI's reviewed C ABI symbol
/// set. It pins THIS crate's own seven declared `#[no_mangle]` exports — the
/// ADR-0024 broker-fed entry points plus the shared lifecycle-query and poll;
/// the legacy in-process begins are ordinary unsafe Rust functions under
/// `#[cfg(test)]` only and never exported. The archive the application links
/// carries those seven plus the Apple bridge's five reviewed safe reexports
/// (twelve symbols total; see [`APPLE_BRIDGE_C_ABI_COUNT_MESSAGE`]).
const MAILBOX_SYNC_FFI_C_ABI_COUNT_MESSAGE: &str = "the mailbox-sync FFI production exported C ABI set must match this crate's own seven reviewed broker sync begin, disconnect prepare/finalize, subject store/get, lifecycle-query, and poll no_mangle exports (the shipped archive surface is these seven plus the Apple bridge's five reviewed safe reexports, twelve symbols total)";
/// The exact count message for the token-broker FFI's reviewed C ABI symbol set.
/// Pins exactly five operations: begin, complete, refresh, revoke, and delete.
const TOKEN_BROKER_FFI_C_ABI_COUNT_MESSAGE: &str = "the token-broker FFI production exported C ABI set must match the five reviewed begin, complete, refresh, revoke, and delete no_mangle exports";
/// Reviewed path of the token-broker C ABI header mirrored into the XPC service.
const REVIEWED_TOKEN_BROKER_BRIDGE_HEADER_PATH: &str =
    "apple/macos-token-broker/TersaTokenBrokerBridge.h";
/// Reviewed Rust package root for the token-broker FFI static archive.
const REVIEWED_TOKEN_BROKER_FFI_PACKAGE_ROOT: &str = "adapters/token-broker-ffi-macos";
/// Reviewed closed wire-status name/integer pairs shared by Rust and Swift.
const REVIEWED_TOKEN_BROKER_WIRE_STATUSES: [(&str, i64); 20] = [
    ("success", 0),
    ("notImplemented", 1),
    ("notProvisioned", 2),
    ("invalidRequest", 3),
    ("rejectedClient", 4),
    ("authorizationCodeRejected", 5),
    ("providerRejected", 6),
    ("insufficientScope", 7),
    ("missingRefreshToken", 8),
    ("consentRevoked", 9),
    ("revokeUnconfirmed", 10),
    ("persistenceFailed", 11),
    ("invalidConfiguration", 12),
    ("unavailable", 13),
    ("busy", 14),
    ("sessionUnknown", 15),
    ("transport", 16),
    ("malformedResponse", 17),
    ("identityUnverified", 18),
    ("identityMismatch", 19),
];

/// Pins a static-library package's exported C ABI to an exact reviewed set: every
/// production `no_mangle` symbol must be one of `expected`, carry its exact reviewed
/// whitespace-normalized signature, and the total count must match `expected` — so
/// adding, removing, or reshaping an exported symbol cannot pass review silently.
/// `count_message` names the reviewed set in the mismatch diagnostic.
fn rust_exported_c_abi_violations(
    package_documents: &[(PathBuf, String)],
    expected: &BTreeMap<&str, &str>,
    count_message: &str,
) -> Vec<String> {
    let mut actual = BTreeMap::<String, Vec<String>>::new();
    let mut no_mangle_attributes = 0_usize;
    let mut violations = Vec::new();
    for (path, document) in package_documents {
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let comments_masked = strip_rust_comments(document);
        let production_document = strip_rust_test_modules(&comments_masked);
        let code = strip_rust_non_code(&production_document);
        let signature_ranges = rust_no_mangle_signature_ranges(&code);
        let parsed_no_mangle_attributes = signature_ranges.len();
        let no_mangle_occurrences = identifier_occurrence_count(&code, "no_mangle");
        if no_mangle_occurrences != parsed_no_mangle_attributes {
            violations.push(format!(
                "{} contains a production no_mangle occurrence outside an exact reviewed direct attribute",
                path.display()
            ));
        }
        for signature_range in signature_ranges {
            no_mangle_attributes += 1;
            let Some((signature_start, signature_end)) = signature_range else {
                violations.push(format!(
                    "{} has a no_mangle attribute without an exported function body",
                    path.display()
                ));
                continue;
            };
            let signature = &code[signature_start..signature_end];
            let source_signature = &production_document[signature_start..signature_end];
            let Some(name) = rust_function_name(signature) else {
                violations.push(format!(
                    "{} has a no_mangle attribute without an exact exported Rust function",
                    path.display()
                ));
                continue;
            };
            let compact = source_signature
                .bytes()
                .filter(|byte| !is_rust_ascii_whitespace(*byte))
                .map(char::from)
                .collect::<String>();
            actual.entry(name.to_owned()).or_default().push(compact);
        }
    }
    if no_mangle_attributes != expected.len() || actual.len() != expected.len() {
        violations.push(count_message.to_owned());
    }
    for (name, expected_signature) in expected {
        if actual
            .get(*name)
            .is_none_or(|signatures| signatures != &[*expected_signature])
        {
            violations.push(format!(
                "exported C ABI symbol `{name}` must retain its exact reviewed Rust signature"
            ));
        }
    }
    violations
}

/// Pins the mailbox-sync FFI's tracked sources to exactly the reviewed manifest and
/// single library module, and forbids a Cargo build script — so no unreviewed source
/// file (which could add an exported symbol or bypass the closed dependency set) can
/// enter the crate without review. Each tracked Rust source is also scanned for
/// source-graph expansion (`include!`, `#[path]`) and for non-`no_mangle` export
/// mechanisms, either of which could smuggle a linkable symbol past the
/// `.rs`-only export inventory.
fn mailbox_sync_ffi_source_surface_violations(
    package_documents: &[(PathBuf, String)],
) -> Vec<String> {
    let manifest_path = Path::new("adapters/mailbox-sync-ffi-macos/Cargo.toml");
    let build_script_path = Path::new("adapters/mailbox-sync-ffi-macos/build.rs");
    let mut violations = Vec::new();
    let Some((_path, manifest)) = package_documents
        .iter()
        .find(|(path, _document)| path == manifest_path)
    else {
        return vec!["the mailbox-sync FFI Cargo.toml must be tracked".to_owned()];
    };
    if toml_table_has_key(manifest, "package", "build") {
        violations
            .push("the mailbox-sync FFI package must not declare a Cargo build script".to_owned());
    }
    if toml_table_has_key(manifest, "lib", "path") {
        violations.push(
            "the mailbox-sync FFI library must use the canonical inventoried src/lib.rs entry"
                .to_owned(),
        );
    }
    if package_documents
        .iter()
        .any(|(path, _document)| path == build_script_path)
    {
        violations.push("the mailbox-sync FFI must not track a conventional build.rs".to_owned());
    }
    let reviewed_rust_sources =
        BTreeSet::from([PathBuf::from("adapters/mailbox-sync-ffi-macos/src/lib.rs")]);
    let tracked_rust_sources = package_documents
        .iter()
        .filter(|(path, _document)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("rs")
        })
        .map(|(path, _document)| path.clone())
        .collect::<BTreeSet<_>>();
    if tracked_rust_sources != reviewed_rust_sources {
        violations.push(
            "the mailbox-sync FFI tracked Rust source inventory must be exactly the reviewed src/lib.rs"
                .to_owned(),
        );
    }
    for (path, document) in package_documents {
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        violations.extend(rust_external_source_expansion_violations(path, document));
        violations.extend(forbidden_export_mechanism_violations(path, document));
    }
    violations
}

/// Exact reviewed Rust export inventory for the seven broker-fed mailbox-sync
/// C ABI operations (ADR-0024). Signatures are whitespace-normalized. The three
/// legacy in-process begins are `#[cfg(test)]`-only ordinary unsafe Rust
/// functions — never `no_mangle` — so they must not appear here.
fn expected_mailbox_sync_ffi_c_abi_exports() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "tersa_mailbox_macos_broker_disconnect_finalize",
            "pubunsafeextern\"C\"fntersa_mailbox_macos_broker_disconnect_finalize(account_id:*constu8,account_id_len:usize,revoke_unconfirmed:i32,output_session_id:*mutu64,)->i32",
        ),
        (
            "tersa_mailbox_macos_broker_disconnect_prepare",
            "pubunsafeextern\"C\"fntersa_mailbox_macos_broker_disconnect_prepare(account_id:*constu8,account_id_len:usize,)->i32",
        ),
        (
            "tersa_mailbox_macos_broker_subject_get",
            "pubunsafeextern\"C\"fntersa_mailbox_macos_broker_subject_get(account_id:*constu8,account_id_len:usize,output_subject:*mutu8,output_subject_capacity:usize,output_subject_len:*mutusize,)->i32",
        ),
        (
            "tersa_mailbox_macos_broker_subject_store",
            "pubunsafeextern\"C\"fntersa_mailbox_macos_broker_subject_store(account_id:*constu8,account_id_len:usize,subject:*constu8,subject_len:usize,)->i32",
        ),
        (
            "tersa_mailbox_macos_broker_sync_begin",
            "pubunsafeextern\"C\"fntersa_mailbox_macos_broker_sync_begin(account_id:*constu8,account_id_len:usize,access_token:*constu8,access_token_len:usize,subject:*constu8,subject_len:usize,output_session_id:*mutu64,)->i32",
        ),
        (
            "tersa_mailbox_macos_lifecycle_get",
            concat!(
                "pubunsafeextern\"C\"fntersa_mailbox_macos_lifecycle_get(account_id:*constu8,account_id_len:usize,output_recovery:*mut",
                "i32,output_last_successful_sync_unix_millis:*mut",
                "i64,)->i32"
            ),
        ),
        (
            "tersa_mailbox_macos_sync_poll",
            "pubextern\"C\"fntersa_mailbox_macos_sync_poll(session_id:u64)->i32",
        ),
    ])
}

/// Closed Rust source inventory for the token-broker FFI package: exactly the
/// reviewed `Cargo.toml` + `src/lib.rs`, no build script, no extra sources.
fn token_broker_ffi_source_surface_violations(
    package_documents: &[(PathBuf, String)],
) -> Vec<String> {
    let manifest_path = Path::new("adapters/token-broker-ffi-macos/Cargo.toml");
    let build_script_path = Path::new("adapters/token-broker-ffi-macos/build.rs");
    let mut violations = Vec::new();
    let Some((_path, manifest)) = package_documents
        .iter()
        .find(|(path, _document)| path == manifest_path)
    else {
        return vec!["the token-broker FFI Cargo.toml must be tracked".to_owned()];
    };
    if toml_table_has_key(manifest, "package", "build") {
        violations
            .push("the token-broker FFI package must not declare a Cargo build script".to_owned());
    }
    if toml_table_has_key(manifest, "lib", "path") {
        violations.push(
            "the token-broker FFI library must use the canonical inventoried src/lib.rs entry"
                .to_owned(),
        );
    }
    if package_documents
        .iter()
        .any(|(path, _document)| path == build_script_path)
    {
        violations.push("the token-broker FFI must not track a conventional build.rs".to_owned());
    }
    let reviewed_rust_sources =
        BTreeSet::from([PathBuf::from("adapters/token-broker-ffi-macos/src/lib.rs")]);
    let tracked_rust_sources = package_documents
        .iter()
        .filter(|(path, _document)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("rs")
        })
        .map(|(path, _document)| path.clone())
        .collect::<BTreeSet<_>>();
    if tracked_rust_sources != reviewed_rust_sources {
        violations.push(
            "the token-broker FFI tracked Rust source inventory must be exactly the reviewed src/lib.rs"
                .to_owned(),
        );
    }
    for (path, document) in package_documents {
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        violations.extend(rust_external_source_expansion_violations(path, document));
        violations.extend(forbidden_export_mechanism_violations(path, document));
    }
    violations
}

/// Exact reviewed Rust export inventory for the five token-broker C ABI
/// operations. Signatures are whitespace-normalized.
fn expected_token_broker_ffi_c_abi_exports() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "tersa_token_broker_begin_authorization",
            concat!(
                "pubunsafeextern\"C\"fntersa_token_broker_begin_authorization(",
                "redirect_uri:*constu8,redirect_uri_len:usize,",
                "authorization_url_out:*mutu8,authorization_url_capacity:usize,authorization_url_len:*mutusize,",
                "session_handle_out:*mutu8,session_handle_capacity:usize,session_handle_len:*mutusize,",
                ")->i32"
            ),
        ),
        (
            "tersa_token_broker_complete_authorization",
            concat!(
                "pubunsafeextern\"C\"fntersa_token_broker_complete_authorization(",
                "session_handle:*constu8,session_handle_len:usize,",
                "callback_url:*constu8,callback_url_len:usize,",
                "access_token_out:*mutu8,access_token_capacity:usize,access_token_len:*mutusize,",
                "subject_out:*mutu8,subject_capacity:usize,subject_len:*mutusize,",
                "expires_out:*mut",
                "i64,)->i32"
            ),
        ),
        (
            "tersa_token_broker_refresh_access_token",
            concat!(
                "pubunsafeextern\"C\"fntersa_token_broker_refresh_access_token(",
                "account_subject:*constu8,account_subject_len:usize,",
                "access_token_out:*mutu8,access_token_capacity:usize,access_token_len:*mutusize,",
                "subject_out:*mutu8,subject_capacity:usize,subject_len:*mutusize,",
                "expires_out:*mut",
                "i64,)->i32"
            ),
        ),
        (
            "tersa_token_broker_revoke_provider_grant",
            concat!(
                "pubunsafeextern\"C\"fntersa_token_broker_revoke_provider_grant(",
                "account_subject:*constu8,account_subject_len:usize,)->i32"
            ),
        ),
        (
            "tersa_token_broker_delete_stored_tokens",
            concat!(
                "pubunsafeextern\"C\"fntersa_token_broker_delete_stored_tokens(",
                "account_subject:*constu8,account_subject_len:usize,)->i32"
            ),
        ),
    ])
}

/// Pins `TersaTokenBrokerBridge.h` to exactly the five reviewed C ABI symbols.
/// A sixth declaration (for example `tersa_token_broker_export_refresh_token`)
/// or a missing/renamed symbol fails closed.
fn token_broker_bridge_header_c_abi_violations(header: &str) -> Vec<String> {
    let expected = expected_token_broker_ffi_c_abi_exports()
        .into_keys()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let actual = c_header_tersa_token_broker_function_symbols(header);
    let mut violations = Vec::new();
    if actual != expected {
        violations.push(format!(
            "{REVIEWED_TOKEN_BROKER_BRIDGE_HEADER_PATH} must declare exactly the five reviewed token-broker C ABI symbols"
        ));
        for missing in expected.difference(&actual) {
            violations.push(format!(
                "{REVIEWED_TOKEN_BROKER_BRIDGE_HEADER_PATH} is missing reviewed C ABI symbol `{missing}`"
            ));
        }
        for extra in actual.difference(&expected) {
            violations.push(format!(
                "{REVIEWED_TOKEN_BROKER_BRIDGE_HEADER_PATH} declares unreviewed C ABI symbol `{extra}`"
            ));
        }
    }
    violations
}

/// Collects `tersa_token_broker_*` function declarators from a C header.
fn c_header_tersa_token_broker_function_symbols(header: &str) -> BTreeSet<String> {
    let mut symbols = BTreeSet::new();
    let mut search_from = 0;
    while let Some(relative) = header[search_from..].find("tersa_token_broker_") {
        let start = search_from + relative;
        if start > 0 {
            let before = header.as_bytes()[start - 1];
            if before.is_ascii_alphanumeric() || before == b'_' {
                search_from = start + 1;
                continue;
            }
        }
        let name_length = header[start..]
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        let name = &header[start..start + name_length];
        let after_name = skip_ascii_whitespace(header, start + name_length);
        if header.as_bytes().get(after_name) == Some(&b'(') {
            symbols.insert(name.to_owned());
        }
        search_from = start + name_length;
    }
    symbols
}

/// Pins Rust `STATUS_*` constants to the exact reviewed 0..=19 integers and
/// requires service/client Swift status enums to declare the same closed set.
/// Renumbering either side fails; self-comparison is not used.
fn token_broker_wire_status_coherence_violations(
    rust_source: &str,
    service_protocol: &str,
    client_protocol: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    let expected = REVIEWED_TOKEN_BROKER_WIRE_STATUSES
        .iter()
        .map(|(name, value)| ((*name).to_owned(), *value))
        .collect::<BTreeMap<_, _>>();

    match rust_token_broker_status_constants(rust_source) {
        Some(rust_cases) => {
            if rust_cases != expected {
                violations.push(
                    "token-broker Rust STATUS_* constants must pin exactly the reviewed 0..=19 wire status set"
                        .to_owned(),
                );
            }
        }
        None => violations.push(
            "adapters/token-broker-ffi-macos/src/lib.rs must declare parseable STATUS_* wire constants"
                .to_owned(),
        ),
    }

    let service_status = swift_closed_int_enum_cases(service_protocol, "TersaTokenBrokerStatusV1");
    let client_status = swift_closed_int_enum_cases(client_protocol, "TokenBrokerStatus");
    match (service_status, client_status) {
        (Some(service_cases), Some(client_cases)) => {
            if service_cases != expected {
                violations.push(
                    "service TersaTokenBrokerStatusV1 must declare exactly the reviewed 0..=19 wire status set"
                        .to_owned(),
                );
            }
            if client_cases != expected {
                violations.push(
                    "client TokenBrokerStatus must declare exactly the reviewed 0..=19 wire status set"
                        .to_owned(),
                );
            }
        }
        (None, _) => violations.push(
            "apple/macos-token-broker/TokenBrokerProtocol.swift must declare closed enum TersaTokenBrokerStatusV1"
                .to_owned(),
        ),
        (_, None) => violations.push(
            "apple/macos/TokenBrokerProtocol.swift must declare closed enum TokenBrokerStatus"
                .to_owned(),
        ),
    }
    violations
}

/// Parses production `const STATUS_*: i32 = N;` bindings into Swift-case names.
fn rust_token_broker_status_constants(source: &str) -> Option<BTreeMap<String, i64>> {
    // Comment-mask only: keep whitespace so `: i32 = N` stays parseable without
    // depending on a full non-code strip.
    let code = strip_rust_comments(source);
    let mut cases = BTreeMap::new();
    let mut search_from = 0;
    while let Some(relative) = code[search_from..].find("const STATUS_") {
        let start = search_from + relative;
        if !is_identifier_at(&code, start, "const") {
            search_from = start + 1;
            continue;
        }
        let name_start = skip_ascii_whitespace(&code, start + "const".len());
        if !code[name_start..].starts_with("STATUS_") {
            search_from = name_start + 1;
            continue;
        }
        let name_length = code[name_start..]
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        let const_name = &code[name_start..name_start + name_length];
        let after_name = skip_ascii_whitespace(&code, name_start + name_length);
        if code.as_bytes().get(after_name) != Some(&b':') {
            search_from = name_start + name_length;
            continue;
        }
        let type_start = skip_ascii_whitespace(&code, after_name + 1);
        if !code[type_start..].starts_with("i32") || !is_identifier_at(&code, type_start, "i32") {
            search_from = name_start + name_length;
            continue;
        }
        let after_type = skip_ascii_whitespace(&code, type_start + "i32".len());
        if code.as_bytes().get(after_type) != Some(&b'=') {
            search_from = name_start + name_length;
            continue;
        }
        let value_start = skip_ascii_whitespace(&code, after_type + 1);
        let value_length = code[value_start..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if value_length == 0 {
            return None;
        }
        let value: i64 = code[value_start..value_start + value_length].parse().ok()?;
        let swift_name = rust_status_const_to_swift_case(const_name)?;
        if cases.insert(swift_name, value).is_some() {
            return None;
        }
        search_from = value_start + value_length;
    }
    if cases.is_empty() {
        return None;
    }
    Some(cases)
}

/// `STATUS_AUTHORIZATION_CODE_REJECTED` → `authorizationCodeRejected`.
fn rust_status_const_to_swift_case(const_name: &str) -> Option<String> {
    let rest = const_name.strip_prefix("STATUS_")?;
    let mut result = String::new();
    for (index, part) in rest.split('_').enumerate() {
        if part.is_empty() {
            return None;
        }
        if index == 0 {
            result.push_str(&part.to_ascii_lowercase());
        } else {
            let mut chars = part.chars();
            let first = chars.next()?;
            result.push(first.to_ascii_uppercase());
            result.push_str(&chars.as_str().to_ascii_lowercase());
        }
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn expected_apple_c_abi_exports() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "tersa_apple_bridge_version",
            "pubextern\"C\"fntersa_apple_bridge_version()->u32",
        ),
        (
            "tersa_macos_bootstrap_default_account",
            "pubunsafeextern\"C\"fntersa_macos_bootstrap_default_account(account_id:*constu8,account_id_len:usize,)->i32",
        ),
        (
            "tersa_macos_mailbox_read_inbox",
            "pubunsafeextern\"C\"fntersa_macos_mailbox_read_inbox(account_id:*constu8,account_id_len:usize,limit:u16,output:*mutu8,output_capacity:usize,output_len:*mutusize,)->i32",
        ),
        (
            "tersa_macos_mailbox_read_thread",
            "pubunsafeextern\"C\"fntersa_macos_mailbox_read_thread(account_id:*constu8,account_id_len:usize,thread_id:*constu8,thread_id_len:usize,limit:u16,output:*mutu8,output_capacity:usize,output_len:*mutusize,)->i32",
        ),
        (
            "tersa_macos_mailbox_search",
            "pubunsafeextern\"C\"fntersa_macos_mailbox_search(account_id:*constu8,account_id_len:usize,query:*constu8,query_len:usize,limit:u16,output:*mutu8,output_capacity:usize,output_len:*mutusize,)->i32",
        ),
        (
            "tersa_oauth_cancel",
            "pubextern\"C\"fntersa_oauth_cancel(session_id:u64)->i32",
        ),
        (
            "tersa_oauth_ios_begin",
            "pubunsafeextern\"C\"fntersa_oauth_ios_begin(client_id:*constu8,client_id_len:usize,redirect_scheme:*constu8,redirect_scheme_len:usize,output_session_id:*mutu64,output_url:*mutu8,output_url_capacity:usize,output_url_len:*mutusize,)->i32",
        ),
        (
            "tersa_oauth_ios_finish",
            "pubunsafeextern\"C\"fntersa_oauth_ios_finish(session_id:u64,callback_url:*constu8,callback_url_len:usize,)->i32",
        ),
        (
            "tersa_oauth_macos_begin",
            "pubunsafeextern\"C\"fntersa_oauth_macos_begin(client_id:*constu8,client_id_len:usize,output_session_id:*mutu64,output_url:*mutu8,output_url_capacity:usize,output_url_len:*mutusize,)->i32",
        ),
        (
            "tersa_oauth_macos_entitlement_probe",
            "pubextern\"C\"fntersa_oauth_macos_entitlement_probe()->i32",
        ),
        (
            "tersa_oauth_macos_poll",
            "pubextern\"C\"fntersa_oauth_macos_poll(session_id:u64)->i32",
        ),
    ])
}

fn rust_no_mangle_signature_ranges(document: &str) -> Vec<Option<(usize, usize)>> {
    let mut signatures = Vec::new();
    let mut index = 0;
    while index < document.len() {
        let Some(relative) = document[index..].find('#') else {
            break;
        };
        let attribute_start = index + relative;
        let opening = skip_ascii_whitespace(document, attribute_start + 1);
        if document.as_bytes().get(opening) != Some(&b'[') {
            index = attribute_start + 1;
            continue;
        }
        let Some(attribute) = balanced_delimited_body(document, opening, b'[', b']') else {
            break;
        };
        let attribute_end = opening + attribute.len();
        let compact = attribute
            .bytes()
            .filter(|byte| !is_rust_ascii_whitespace(*byte))
            .collect::<Vec<_>>();
        if compact == b"[unsafe(no_mangle)]" {
            let signature_start = skip_ascii_whitespace(document, attribute_end);
            if let Some(opening_relative) = document[signature_start..].find('{') {
                let function_opening = signature_start + opening_relative;
                signatures.push(Some((signature_start, function_opening)));
                index = function_opening + 1;
                continue;
            }
            signatures.push(None);
        }
        index = attribute_end;
    }
    signatures
}

fn rust_function_name(signature: &str) -> Option<&str> {
    for (start, _) in signature.match_indices("fn") {
        if !is_identifier_at(signature, start, "fn") {
            continue;
        }
        let name_start = skip_ascii_whitespace(signature, start + 2);
        let name_length = signature[name_start..]
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if name_length != 0 {
            return Some(&signature[name_start..name_start + name_length]);
        }
    }
    None
}

fn toml_table_has_key(document: &str, expected_table: &str, expected_key: &str) -> bool {
    let mut table = None;
    for line in document.lines() {
        let line = toml_without_comment(line);
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            table = toml_table_name(trimmed);
            continue;
        }
        if table != Some(expected_table) {
            continue;
        }
        let Some((key, _value)) = trimmed.split_once('=') else {
            continue;
        };
        if toml_bare_or_quoted_key(key.trim()) == Some(expected_key) {
            return true;
        }
    }
    false
}

fn toml_without_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some(current) if character == current => quote = None,
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character == '#' => return &line[..index],
            Some(_) | None => {}
        }
    }
    line
}

fn toml_table_name(header: &str) -> Option<&str> {
    if header.starts_with("[[") || header.ends_with("]]") {
        return None;
    }
    toml_bare_or_quoted_key(header.strip_prefix('[')?.strip_suffix(']')?.trim())
}

fn toml_bare_or_quoted_key(key: &str) -> Option<&str> {
    if let Some(key) = key.strip_prefix('"').and_then(|key| key.strip_suffix('"')) {
        return Some(key);
    }
    if let Some(key) = key
        .strip_prefix('\'')
        .and_then(|key| key.strip_suffix('\''))
    {
        return Some(key);
    }
    (!key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then_some(key)
}

/// Rejects the textual ways a tracked production source can expand its own source
/// graph — `#[path]` (directly, via `cfg_attr`, or as a raw-identifier attribute)
/// and `include!` (directly or renamed by a `use` alias) — so a non-`.rs` file
/// cannot smuggle unreviewed items past the tracked-`.rs` inventory and the C-ABI
/// export scanner. This is a textual lint, not a Rust parser: expansion reached only
/// through a `macro_rules!` metavariable (`#[$attr]`, `$m!(...)`) or a proc-macro
/// attribute is OUT OF SCOPE here and is instead backstopped by human review of the
/// visible source plus, for a proc-macro, its required `Cargo.toml`/notices diff.
/// See the deferred AST-aware guard follow-up.
fn rust_external_source_expansion_violations(path: &Path, document: &str) -> Vec<String> {
    let code = strip_rust_non_code(document);
    let policy_code = strip_rust_test_modules(&code);
    let mut violations = Vec::new();
    if !policy_code.is_ascii() {
        violations.push(format!(
            "{} must not contain non-ASCII production authority code",
            path.display()
        ));
    }
    if rust_has_path_attribute(&policy_code) {
        violations.push(format!(
            "{} must not expand the production Rust source graph with #[path] (including via cfg_attr or a raw-identifier attribute)",
            path.display()
        ));
    }
    if rust_has_macro_invocation(&policy_code, "include") {
        violations.push(format!(
            "{} must not expand the production Rust source graph with include!",
            path.display()
        ));
    }
    for name in ["include", "include_str", "include_bytes"] {
        if rust_has_aliased_include_macro(&policy_code, name) {
            violations.push(format!(
                "{} must not alias the include macro `{name}`",
                path.display()
            ));
        }
    }
    violations
}

fn rust_has_path_attribute(document: &str) -> bool {
    let bytes = document.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'#' {
            index += 1;
            continue;
        }
        let opening = skip_ascii_whitespace(document, index + 1);
        if bytes.get(opening) != Some(&b'[') {
            index += 1;
            continue;
        }
        let Some(attribute) = balanced_delimited_body(document, opening, b'[', b']') else {
            return true;
        };
        let inner = &attribute[1..attribute.len() - 1];
        let name = inner.trim_start();
        let name_length = name
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if &name[..name_length] == "path" || rust_attribute_body_applies_path(inner) {
            return true;
        }
        index = opening + attribute.len();
    }
    false
}

/// Flags a `path` attribute reached inside an attribute body that the leading-
/// identifier check misses: a `path` nested at any `cfg_attr` depth, or a direct
/// `#[r#path = ...]` whose raw `r#` prefix defeats the leading-identifier scan.
/// A boundary-checked `path` (so `is_identifier_at` treats the `r#`/`,`/`(`
/// neighbour as a boundary) directly applied with `=` or `(` anywhere in the body
/// trips it. The tiny inventoried sources never apply `path` conditionally, so
/// failing closed on a predicate-shaped `path` is intentional.
fn rust_attribute_body_applies_path(body: &str) -> bool {
    body.match_indices("path").any(|(index, _)| {
        is_identifier_at(body, index, "path")
            && matches!(
                body.as_bytes()
                    .get(skip_ascii_whitespace(body, index + "path".len())),
                Some(b'=' | b'(')
            )
    })
}

fn rust_has_macro_invocation(document: &str, name: &str) -> bool {
    document.match_indices(name).any(|(index, _)| {
        is_identifier_at(document, index, name)
            && document
                .as_bytes()
                .get(skip_ascii_whitespace(document, index + name.len()))
                == Some(&b'!')
    })
}

/// An include macro renamed by a production `use` declaration
/// (`use ... <name> as <alias>;`) hides its invocations from the direct
/// `include!` scan, and aliasing one is never legitimate in the tiny
/// inventoried sources, so the alias itself fails closed.
fn rust_has_aliased_include_macro(document: &str, name: &str) -> bool {
    let mut search_from = 0;
    while let Some(relative) = document[search_from..].find("use") {
        let use_start = search_from + relative;
        if !is_identifier_at(document, use_start, "use") {
            search_from = use_start + "use".len();
            continue;
        }
        let declaration_end = document[use_start..]
            .find(';')
            .map_or(document.len(), |relative| use_start + relative);
        if rust_use_declaration_aliases(&document[use_start..declaration_end], name) {
            return true;
        }
        search_from = declaration_end;
    }
    false
}

fn rust_use_declaration_aliases(declaration: &str, name: &str) -> bool {
    declaration.match_indices(name).any(|(index, _)| {
        if !is_identifier_at(declaration, index, name) {
            return false;
        }
        let alias_keyword = skip_ascii_whitespace(declaration, index + name.len());
        if !declaration[alias_keyword..].starts_with("as")
            || !is_identifier_at(declaration, alias_keyword, "as")
        {
            return false;
        }
        let alias = skip_ascii_whitespace(declaration, alias_keyword + "as".len());
        declaration
            .as_bytes()
            .get(alias)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    })
}

/// The closed per-function Keychain reference policy for one bridge C ABI
/// boundary function.
struct BridgeBoundaryPolicy {
    /// The single reviewed Keychain status item the function may reference,
    /// with its exact reviewed reference count.
    status: &'static str,
    status_references: usize,
    /// The reviewed Keychain status variants the function must reference
    /// individually, in the qualified form the source uses.
    status_variants: &'static [&'static str],
    /// The single validating Keychain entry the function must call exactly once.
    entry: &'static str,
    /// The single reviewed encoder call the function must make exactly once,
    /// or empty when the function returns validated bytes without encoding.
    encoder: &'static str,
    /// The single reviewed bounded-output call the function must make exactly
    /// once, or empty when the function writes no caller output.
    bounded_write: &'static str,
    /// Required bounded-copy and boundary-check source fragments. Each
    /// `slice::from_raw_parts` site is pinned to its own `.to_vec()` copy so
    /// one bounded copy cannot satisfy another site's requirement.
    required: &'static [&'static str],
}

const BRIDGE_BOUNDARY_POLICIES: [(&str, BridgeBoundaryPolicy); 4] = [
    (
        "tersa_macos_bootstrap_default_account",
        BridgeBoundaryPolicy {
            status: "ProductBootstrapStatus",
            status_references: 1,
            status_variants: &[],
            entry: "bootstrap_default_account_bytes",
            encoder: "",
            bounded_write: "",
            required: &[
                "account_id.is_null()",
                "account_id_len == 0",
                "account_id_len > 256",
                "slice::from_raw_parts(account_id, account_id_len) }.to_vec()",
            ],
        },
    ),
    (
        "tersa_macos_mailbox_read_inbox",
        BridgeBoundaryPolicy {
            status: "mailbox_read::MailboxReadStatus",
            status_references: 3,
            status_variants: &[
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput",
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok",
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall",
            ],
            entry: "mailbox_read::read_default_inbox",
            encoder: "encode_inbox(&model)",
            bounded_write: "write_bounded_output(&encoded, output, output_capacity, output_len)",
            required: &[
                "account_id.is_null()",
                "account_id_len == 0",
                "account_id_len > 256",
                "slice::from_raw_parts(account_id, account_id_len) }.to_vec()",
                "output.is_null()",
                "output_len.is_null()",
            ],
        },
    ),
    (
        "tersa_macos_mailbox_read_thread",
        BridgeBoundaryPolicy {
            status: "mailbox_read::MailboxReadStatus",
            status_references: 3,
            status_variants: &[
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput",
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok",
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall",
            ],
            entry: "mailbox_read::read_default_thread",
            encoder: "encode_thread(&model)",
            bounded_write: "write_bounded_output(&encoded, output, output_capacity, output_len)",
            required: &[
                "account_id.is_null()",
                "account_id_len == 0",
                "account_id_len > 256",
                "slice::from_raw_parts(account_id, account_id_len) }.to_vec()",
                "thread_id.is_null()",
                "thread_id_len == 0",
                "thread_id_len > 256",
                "slice::from_raw_parts(thread_id, thread_id_len) }.to_vec()",
                "output.is_null()",
                "output_len.is_null()",
            ],
        },
    ),
    (
        "tersa_macos_mailbox_search",
        BridgeBoundaryPolicy {
            status: "mailbox_read::MailboxReadStatus",
            status_references: 3,
            status_variants: &[
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput",
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok",
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall",
            ],
            entry: "mailbox_read::search_default_mailbox",
            encoder: "encode_search(&model)",
            bounded_write: "write_bounded_output(&encoded, output, output_capacity, output_len)",
            required: &[
                "account_id.is_null()",
                "account_id_len == 0",
                "account_id_len > 256",
                "slice::from_raw_parts(account_id, account_id_len) }.to_vec()",
                "query.is_null()",
                "query_len == 0",
                "query_len > 256",
                "slice::from_raw_parts(query, query_len) }.to_vec()",
                "output.is_null()",
                "output_len.is_null()",
            ],
        },
    ),
];

fn bridge_bootstrap_source_violations(document: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let code = strip_rust_non_code(document);
    let policy_code = strip_rust_test_modules(&code);
    for forbidden in ["tersa_domain"] {
        if contains_identifier(&policy_code, forbidden) {
            violations.push(format!(
                "the Apple bridge contains forbidden bootstrap boundary `{forbidden}`"
            ));
        }
    }
    if rust_keychain_imported(&policy_code) {
        violations.push(
            "the Apple bridge must not import or alias the Keychain bootstrap adapter".to_owned(),
        );
    }
    if contains_identifier(&policy_code, "AccountId") {
        violations
            .push("the Apple bridge contains forbidden bootstrap boundary `AccountId`".to_owned());
    }
    let references = rust_qualified_item_uses(&policy_code, "tersa_keychain_macos");
    let mut function_reference_count = 0_usize;
    for (function_name, policy) in &BRIDGE_BOUNDARY_POLICIES {
        let Some(function) = rust_function_body(&policy_code, function_name) else {
            violations.push(format!(
                "the Apple bridge must define the canonical macOS C ABI function `{function_name}`"
            ));
            continue;
        };
        let function_references = rust_qualified_item_uses(function, "tersa_keychain_macos");
        function_reference_count += function_references.len();
        for reference in &function_references {
            if reference.item != policy.status && reference.item != policy.entry {
                violations.push(format!(
                    "the Apple bridge references forbidden Keychain adapter item `{}`",
                    reference.item
                ));
            }
        }
        if function_references
            .iter()
            .filter(|reference| reference.item == policy.status)
            .count()
            != policy.status_references
        {
            violations.push(format!(
                "the Apple bridge `{function_name}` must reference its reviewed Keychain status vocabulary exactly {} times",
                policy.status_references
            ));
        }
        let entry_call_count = function_references
            .iter()
            .filter(|reference| reference.item == policy.entry && reference.is_call)
            .count();
        let entry_reference_count = function_references
            .iter()
            .filter(|reference| reference.item == policy.entry)
            .count();
        if entry_call_count != 1 || entry_reference_count != 1 {
            violations.push(format!(
                "the Apple bridge `{function_name}` must call exactly one validating Keychain entry"
            ));
        }
        violations.extend(bridge_boundary_pin_violations(
            function_name,
            policy,
            function,
        ));
    }
    if references.len() != function_reference_count {
        violations.push(
            "the Apple bridge must not reference the Keychain adapter outside the canonical boundary functions"
                .to_owned(),
        );
    }
    violations
}

/// Enforces the reviewed per-function source pins for one bridge boundary
/// function: each status variant referenced individually, the command
/// encoder and bounded write called exactly once each, and every required
/// bounded-copy fragment present. Fragment matching canonicalizes whitespace
/// so token-equivalent formatting cannot raise spurious violations.
fn bridge_boundary_pin_violations(
    function_name: &str,
    policy: &BridgeBoundaryPolicy,
    function: &str,
) -> Vec<String> {
    let canonical_function = rust_token_canonical(function);
    let mut violations = Vec::new();
    for variant in policy.status_variants {
        if !canonical_function.contains(&rust_token_canonical(variant)) {
            violations.push(format!(
                "the Apple bridge `{function_name}` must reference its reviewed Keychain status variant `{variant}`"
            ));
        }
    }
    if !policy.encoder.is_empty() {
        let encoder = rust_token_canonical(policy.encoder);
        if canonical_function.matches(&encoder).count() != 1 {
            violations.push(format!(
                "the Apple bridge `{function_name}` must call its reviewed encoder `{}` exactly once",
                policy.encoder
            ));
        }
    }
    if !policy.bounded_write.is_empty() {
        let bounded_write = rust_token_canonical(policy.bounded_write);
        if canonical_function.matches(&bounded_write).count() != 1 {
            violations.push(format!(
                "the Apple bridge `{function_name}` must write caller output through `{}` exactly once",
                policy.bounded_write
            ));
        }
    }
    for required in policy.required {
        if !canonical_function.contains(&rust_token_canonical(required)) {
            violations.push(format!(
                "the Apple bridge `{function_name}` is missing required bounded-copy source `{required}`"
            ));
        }
    }
    violations
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustQualifiedItemUse {
    item: String,
    is_call: bool,
}

/// Finds qualified Rust path uses while treating whitespace as non-semantic.
///
/// A lowercase first segment followed by another segment names a module, so
/// the reported item spans both segments (for example
/// `mailbox_read::read_default_inbox`). Type-like first segments keep the
/// single-segment item form, including enum variant references.
fn rust_qualified_item_uses(document: &str, module: &str) -> Vec<RustQualifiedItemUse> {
    let mut uses = Vec::new();
    for (start, _) in document.match_indices(module) {
        if !is_identifier_at(document, start, module) {
            continue;
        }
        let mut index = skip_ascii_whitespace(document, start + module.len());
        if !document[index..].starts_with("::") {
            continue;
        }
        index = skip_ascii_whitespace(document, index + 2);
        let Some((first, first_end)) = rust_path_segment(document, index) else {
            continue;
        };
        let mut item = first.to_owned();
        let mut item_end = first_end;
        let after_first = skip_ascii_whitespace(document, first_end);
        if first
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
            && document[after_first..].starts_with("::")
        {
            let second_start = skip_ascii_whitespace(document, after_first + 2);
            if let Some((second, second_end)) = rust_path_segment(document, second_start) {
                item.push_str("::");
                item.push_str(second);
                item_end = second_end;
            }
        }
        let is_call = document[skip_ascii_whitespace(document, item_end)..].starts_with('(');
        uses.push(RustQualifiedItemUse { item, is_call });
    }
    uses
}

/// Reads one Rust path segment starting at `start`.
fn rust_path_segment(document: &str, start: usize) -> Option<(&str, usize)> {
    let mut index = start;
    while document
        .as_bytes()
        .get(index)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        index += 1;
    }
    (index != start).then_some((&document[start..index], index))
}

/// Masks test-only Rust modules before enforcing production source boundaries.
fn strip_rust_test_modules(document: &str) -> String {
    // Discover attributes and module braces from code-only bytes, then apply
    // the resulting ranges to the original document. This preserves literals
    // for later alias inspection without allowing literal text to invent a
    // cfg(test) module that masks following production code.
    let syntax = strip_rust_non_code(document);
    let mut output = document.to_owned();
    let mut search_from = 0;
    while let Some(relative) = syntax[search_from..].find("#[cfg") {
        let attribute_start = search_from + relative;
        let Some(attribute_end) = syntax[attribute_start..].find(']') else {
            break;
        };
        let attribute_end = attribute_start + attribute_end + 1;
        let compact_attribute = syntax[attribute_start..attribute_end]
            .bytes()
            .filter(|byte| !is_rust_ascii_whitespace(*byte))
            .collect::<Vec<_>>();
        if compact_attribute != b"#[cfg(test)]" {
            search_from = attribute_end;
            continue;
        }
        let Some(opening) = rust_directly_attributed_module(&syntax, attribute_end) else {
            search_from = attribute_end;
            continue;
        };
        let Some(module) = balanced_brace_body(&syntax, opening) else {
            search_from = attribute_end;
            continue;
        };
        let end = opening + module.len();
        let masked = String::from_utf8(
            document.as_bytes()[attribute_start..end]
                .iter()
                .map(|byte| if *byte == b'\n' { b'\n' } else { b' ' })
                .collect(),
        )
        .expect("the test-module mask contains only ASCII bytes");
        output.replace_range(attribute_start..end, &masked);
        search_from = end;
    }
    output
}

fn rust_directly_attributed_module(document: &str, mut index: usize) -> Option<usize> {
    loop {
        index = skip_ascii_whitespace(document, index);
        if document.as_bytes().get(index) != Some(&b'#') {
            break;
        }
        let opening = skip_ascii_whitespace(document, index + 1);
        if document.as_bytes().get(opening) != Some(&b'[') {
            return None;
        }
        let attribute = balanced_delimited_body(document, opening, b'[', b']')?;
        index = opening + attribute.len();
    }
    if document[index..].starts_with("pub") && is_identifier_at(document, index, "pub") {
        index = skip_ascii_whitespace(document, index + "pub".len());
        if document.as_bytes().get(index) == Some(&b'(') {
            let visibility = balanced_delimited_body(document, index, b'(', b')')?;
            index = skip_ascii_whitespace(document, index + visibility.len());
        }
    }
    if !document[index..].starts_with("mod") || !is_identifier_at(document, index, "mod") {
        return None;
    }
    index = skip_ascii_whitespace(document, index + "mod".len());
    let name_length = document[index..]
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if name_length == 0 {
        return None;
    }
    index = skip_ascii_whitespace(document, index + name_length);
    (document.as_bytes().get(index) == Some(&b'{')).then_some(index)
}

fn skip_ascii_whitespace(document: &str, mut index: usize) -> usize {
    while document
        .as_bytes()
        .get(index)
        .is_some_and(|byte| is_rust_ascii_whitespace(*byte))
    {
        index += 1;
    }
    index
}

fn is_rust_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Canonicalizes a source fragment for token comparison by dropping every
/// Rust ASCII whitespace byte, mirroring the whitespace-insensitive qualified
/// path matching so formatting drift cannot raise spurious violations while
/// token content stays exactly as strict.
fn rust_token_canonical(document: &str) -> String {
    document
        .bytes()
        .filter(|byte| !is_rust_ascii_whitespace(*byte))
        .map(char::from)
        .collect()
}

fn is_identifier_at(document: &str, index: usize, identifier: &str) -> bool {
    let before = document[..index].bytes().next_back();
    let after = document[index + identifier.len()..].bytes().next();
    let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    before.is_none_or(|byte| !is_identifier(byte)) && after.is_none_or(|byte| !is_identifier(byte))
}

/// Replaces Rust comments with spaces while preserving literals and byte offsets.
fn strip_rust_comments(document: &str) -> String {
    let mut output = Vec::with_capacity(document.len());
    let bytes = document.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            for byte in &bytes[start..index] {
                output.push(if *byte == b'\n' { b'\n' } else { b' ' });
            }
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1_u32;
            while index < bytes.len() && depth != 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            for byte in &bytes[start..index] {
                output.push(if *byte == b'\n' { b'\n' } else { b' ' });
            }
        } else if let Some(end) = rust_raw_literal_end(bytes, index) {
            output.extend_from_slice(&bytes[index..end]);
            index = end;
        } else if let Some(end) = rust_char_literal_end(bytes, index) {
            output.extend_from_slice(&bytes[index..end]);
            index = end;
        } else if bytes[index] == b'"' || bytes[index..].starts_with(b"b\"") {
            if bytes[index..].starts_with(b"b\"") {
                index += 1;
            }
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else {
                    let done = bytes[index] == b'"';
                    index += 1;
                    if done {
                        break;
                    }
                }
            }
            output.extend_from_slice(&bytes[start..index]);
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).expect("masking Rust comments preserves UTF-8")
}

/// Replaces comments and literals with spaces (while retaining newlines).  This is
/// intentionally a small lexical scanner, not a Rust parser: architecture gates
/// must never treat examples or strings as executable authority.
fn strip_rust_non_code(document: &str) -> String {
    let mut output = Vec::with_capacity(document.len());
    let bytes = document.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        let end = if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            index
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1;
            while index < bytes.len() && depth != 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            index
        } else if let Some(end) = rust_raw_literal_end(bytes, index) {
            index = end;
            end
        } else if let Some(end) = rust_char_literal_end(bytes, index) {
            index = end;
            end
        } else if bytes[index] == b'"' || bytes[index..].starts_with(b"b\"") {
            if bytes[index..].starts_with(b"b\"") {
                index += 1;
            }
            let quote = bytes[index];
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index += 2;
                } else {
                    let done = bytes[index] == quote;
                    index += 1;
                    if done {
                        break;
                    }
                }
            }
            index.min(bytes.len())
        } else {
            output.push(bytes[index]);
            index += 1;
            continue;
        };
        for byte in &bytes[start..end] {
            output.push(if *byte == b'\n' { b'\n' } else { b' ' });
        }
    }
    String::from_utf8(output).expect("masking valid Rust source preserves UTF-8")
}

fn rust_literal_contains(document: &str, needle: &str) -> bool {
    let bytes = document.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1_u32;
            while index < bytes.len() && depth != 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            continue;
        }
        let start = index;
        let end = if let Some(end) = rust_raw_literal_end(bytes, index) {
            Some(end)
        } else if bytes[index] == b'"' || bytes[index..].starts_with(b"b\"") {
            if bytes[index..].starts_with(b"b\"") {
                index += 1;
            }
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else {
                    let done = bytes[index] == b'"';
                    index += 1;
                    if done {
                        break;
                    }
                }
            }
            Some(index)
        } else {
            None
        };
        if let Some(end) = end {
            if document[start..end].contains(needle) {
                return true;
            }
            index = end;
        } else {
            index += 1;
        }
    }
    false
}

fn rust_char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    if bytes.get(index) == Some(&b'b') {
        index += 1;
    }
    if bytes.get(index) != Some(&b'\'') {
        return None;
    }
    index += 1;
    let first = *bytes.get(index)?;
    if first == b'\\' {
        index += 1;
        match *bytes.get(index)? {
            b'x' => index += 3,
            b'u' if bytes.get(index + 1) == Some(&b'{') => {
                index += 2;
                index += bytes[index..].iter().position(|byte| *byte == b'}')? + 1;
            }
            _ => index += 1,
        }
    } else {
        let width = match first {
            0x00..=0x7f => 1,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => return None,
        };
        index += width;
    }
    (bytes.get(index) == Some(&b'\'')).then_some(index + 1)
}

fn rust_raw_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    if bytes.get(index) == Some(&b'b') {
        index += 1;
    }
    if bytes.get(index) != Some(&b'r') {
        return None;
    }
    index += 1;
    let hashes = bytes[index..]
        .iter()
        .take_while(|byte| **byte == b'#')
        .count();
    index += hashes;
    if bytes.get(index) != Some(&b'"') {
        return None;
    }
    index += 1;
    loop {
        let Some(relative) = bytes[index..].iter().position(|byte| *byte == b'"') else {
            return Some(bytes.len());
        };
        let quote = index + relative;
        if bytes[quote + 1..].starts_with(&vec![b'#'; hashes]) {
            return Some(quote + 1 + hashes);
        }
        index = quote + 1;
    }
}

fn rust_keychain_imported(code: &str) -> bool {
    for (index, _) in code.match_indices("tersa_keychain_macos") {
        let statement = &code[code[..index].rfind(';').map_or(0, |end| end + 1)..index];
        let statement = statement.trim_start();
        if contains_identifier(statement, "use")
            || (contains_identifier(statement, "extern") && contains_identifier(statement, "crate"))
        {
            return true;
        }
    }
    false
}

fn rust_function_body<'a>(document: &'a str, function_name: &str) -> Option<&'a str> {
    for (start, _) in document.match_indices("fn") {
        if !is_identifier_at(document, start, "fn") {
            continue;
        }
        let name_start = skip_ascii_whitespace(document, start + 2);
        if !document[name_start..].starts_with(function_name)
            || !is_identifier_at(document, name_start, function_name)
        {
            continue;
        }
        let signature_end = name_start + function_name.len();
        let opening = document[signature_end..].find('{')? + signature_end;
        return balanced_brace_body(document, opening);
    }
    None
}

fn balanced_brace_body(document: &str, opening: usize) -> Option<&str> {
    balanced_delimited_body(document, opening, b'{', b'}')
}

fn balanced_delimited_body(
    document: &str,
    opening: usize,
    opening_delimiter: u8,
    closing_delimiter: u8,
) -> Option<&str> {
    if document.as_bytes().get(opening) != Some(&opening_delimiter) {
        return None;
    }
    let mut depth = 0usize;
    for (offset, byte) in document.as_bytes()[opening..].iter().enumerate() {
        match *byte {
            byte if byte == opening_delimiter => depth += 1,
            byte if byte == closing_delimiter => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&document[opening..=opening + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

fn contains_identifier(document: &str, identifier: &str) -> bool {
    document.match_indices(identifier).any(|(index, _matched)| {
        let before = document[..index].bytes().next_back();
        let after = document[index + identifier.len()..].bytes().next();
        let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
        before.is_none_or(|byte| !is_identifier(byte))
            && after.is_none_or(|byte| !is_identifier(byte))
    })
}

fn contains_identifier_with_prefix(document: &str, prefix: &str) -> bool {
    document.match_indices(prefix).any(|(index, _matched)| {
        let before = document[..index].bytes().next_back();
        before.is_none_or(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
    })
}

fn swift_bootstrap_source_violations(worker: &str, app_delegate: &str) -> Vec<String> {
    let worker = strip_swift_non_code(worker);
    let app_delegate = strip_swift_non_code(app_delegate);
    let mut violations = Vec::new();
    for required in [
        "private var running = false",
        "private var pending: (() -> Void)?",
        "else if pending == nil",
        "tersa_macos_bootstrap_default_account(",
    ] {
        if !worker.contains(required) {
            violations.push(format!(
                "BootstrapWorker.swift is missing bounded-worker source `{required}`"
            ));
        }
    }
    if worker.contains("[() -> Void]") || worker.contains("append(") {
        violations.push("BootstrapWorker.swift must not implement an unbounded queue".to_owned());
    }
    if swift_call_count(&app_delegate, "bootstrapWorker.submit") != 1
        || swift_member_call_count(&app_delegate, "submit") != 1
    {
        violations.push(
            "AppDelegate.swift must contain exactly one product bootstrap worker call site"
                .to_owned(),
        );
    }
    if app_delegate.contains("local-profile-owner") {
        violations.push("AppDelegate.swift must not bootstrap a placeholder account".to_owned());
    }
    if !swift_owner_flow_forwards_completion(&app_delegate) {
        violations.push(
            "AppDelegate.swift must forward ProductBootstrapStatus through the owner completion"
                .to_owned(),
        );
    }
    for required in [
        "@main\n@MainActor\nprivate enum TersaApplication",
        "private static let delegate = AppDelegate()",
    ] {
        if !app_delegate.contains(required) {
            violations.push(format!(
                "AppDelegate.swift is missing explicit application entrypoint source `{required}`"
            ));
        }
    }
    if app_delegate.matches("@main").count() != 1 {
        violations.push(
            "AppDelegate.swift must contain exactly one explicit application entrypoint".to_owned(),
        );
    }
    if !swift_has_canonical_application_main(&app_delegate) {
        violations.push(
            "AppDelegate.swift must create NSApplication, install the retained delegate, and run the event loop exactly once in that order inside the sole main() body"
                .to_owned(),
        );
    }
    violations
}

fn swift_has_canonical_application_main(document: &str) -> bool {
    let bodies = swift_function_bodies(document, "main");
    let [body] = bodies.as_slice() else {
        return false;
    };
    let required = [
        "let application = NSApplication.shared",
        "application.delegate = delegate",
        "application.run()",
    ];
    if required
        .iter()
        .any(|source| document.matches(source).count() != 1 || body.matches(source).count() != 1)
    {
        return false;
    }
    let compact = body
        .bytes()
        .filter(|byte| !is_rust_ascii_whitespace(*byte))
        .collect::<Vec<_>>();
    compact
        == b"{letapplication=NSApplication.sharedapplication.delegate=delegateapplication.run()}"
}

fn swift_bootstrap_inventory_violations(sources: &[(PathBuf, String)]) -> Vec<String> {
    let (mut violations, bridge_calls, worker_constructions, submissions, owner_entries) =
        swift_bootstrap_source_inventory(sources);
    if bridge_calls != 1 {
        violations.push(
            "the macOS source inventory must contain exactly one bootstrap C ABI call".to_owned(),
        );
    }
    if submissions != 1 {
        violations.push(
            "the macOS source inventory must contain exactly one bootstrap worker submission"
                .to_owned(),
        );
    }
    if worker_constructions != 1 {
        violations.push(
            "the macOS source inventory must contain exactly one canonical BootstrapWorker construction"
                .to_owned(),
        );
    }
    violations.extend(swift_bootstrap_launch_entry_violations(
        sources,
        &owner_entries,
    ));
    violations
}

/// Keeps the browser-to-Keychain handoff foreground-gated. A successful OAuth
/// callback commonly arrives while the browser is still active; starting the
/// connect worker there can make the `WhenUnlockedThisDeviceOnly` token store
/// fail with `errSecInteractionNotAllowed` on macOS. This structural check makes
/// the reviewed activation boundary part of the Apple product surface.
fn swift_oauth_foreground_handoff_violations(sources: &[(PathBuf, String)]) -> Vec<String> {
    let path = Path::new(ACCOUNT_CONNECTION_VIEW_MODEL_PATH);
    let Some((_path, document)) = sources.iter().find(|(candidate, _)| candidate == path) else {
        return vec![format!(
            "the OAuth foreground handoff source `{}` must be tracked",
            path.display()
        )];
    };
    let code = strip_swift_non_code(document);
    let mut violations = Vec::new();

    let authorize = swift_function_bodies(&code, "authorizeAndConnect");
    let [authorize] = authorize.as_slice() else {
        return vec![
            "AccountConnectionViewModel must contain exactly one authorizeAndConnect function"
                .to_owned(),
        ];
    };
    if !authorize.contains("connectBrokerGrantAfterApplicationActivation(")
        || [
            "finishBrokerGrantApplicationActivation(",
            "connectWithBrokerGrant(",
            "syncWorker.storeBrokerSubject",
            "syncWorker.beginBrokerSync",
        ]
        .iter()
        .any(|forbidden| authorize.contains(forbidden))
    {
        violations.push(
            "a successful OAuth outcome must enter the application-activation handoff, never connect directly"
                .to_owned(),
        );
    }

    let activation = swift_function_bodies(&code, "connectBrokerGrantAfterApplicationActivation");
    let [activation] = activation.as_slice() else {
        violations.push(
            "AccountConnectionViewModel must contain exactly one connectBrokerGrantAfterApplicationActivation function"
                .to_owned(),
        );
        return violations;
    };
    for required in [
        "NSApplication.didBecomeActiveNotification",
        "NSApp.activate()",
        "Timer.scheduledTimer",
        "cleanupFreshBrokerGrant(",
        "finishBrokerGrantApplicationActivation(",
    ] {
        if !activation.contains(required) {
            violations.push(format!(
                "the OAuth activation handoff must contain `{required}`"
            ));
        }
    }
    if ["connectWithBrokerGrant(", "syncWorker.storeBrokerSubject"]
        .iter()
        .any(|forbidden| activation.contains(forbidden))
    {
        violations.push(
            "the OAuth activation handoff must deliver only through finishBrokerGrantApplicationActivation"
                .to_owned(),
        );
    }
    let observer_position = activation.find("activationObserver =");
    let activate_position = activation.find("NSApp.activate()");
    if !matches!(
        (observer_position, activate_position),
        (Some(observer), Some(activate)) if observer < activate
    ) {
        violations.push(
            "the OAuth activation observer must be installed before NSApp.activate()".to_owned(),
        );
    }

    let finish = swift_function_bodies(&code, "finishBrokerGrantApplicationActivation");
    let [finish] = finish.as_slice() else {
        violations.push(
            "AccountConnectionViewModel must contain exactly one finishBrokerGrantApplicationActivation function"
                .to_owned(),
        );
        return violations;
    };
    let clear_position = finish.find("clearApplicationActivation()");
    let store_position = finish.find("syncWorker.storeBrokerSubject(");
    let connect_position = finish.find("connectWithBrokerGrant(");
    if !finish.contains("guard activationPending")
        || !matches!(
            (clear_position, store_position, connect_position),
            (Some(clear), Some(store), Some(connect)) if clear < store && store < connect
        )
    {
        violations.push(
            "the activation completion must clear its one-shot state before persisting the broker subject and connect only from the subject-store completion"
                .to_owned(),
        );
    }

    let connect_callers = swift_function_names_with(&code, "connectWithBrokerGrant(");
    if connect_callers != ["finishBrokerGrantApplicationActivation".to_owned()] {
        violations.push(
            "finishBrokerGrantApplicationActivation must be the sole caller of connectWithBrokerGrant"
                .to_owned(),
        );
    }
    violations
}

fn swift_bootstrap_source_inventory(
    sources: &[(PathBuf, String)],
) -> (Vec<String>, usize, usize, usize, BTreeSet<String>) {
    let worker_path = Path::new("apple/macos/BootstrapWorker.swift");
    let app_delegate_path = Path::new("apple/macos/AppDelegate.swift");
    let mut violations = Vec::new();
    let mut bridge_calls = 0;
    let mut worker_constructions = 0;
    let mut submissions = 0;
    let mut owner_entries = BTreeSet::new();

    for (path, document) in sources {
        let extension = path.extension().and_then(|extension| extension.to_str());
        if !is_allowed_macos_target_source(path, extension) {
            violations.push(format!(
                "{} is outside the closed TersaMac source and resource allowlist",
                path.display(),
            ));
            continue;
        }
        if !matches!(extension, Some("swift" | "h")) {
            continue;
        }
        violations.extend(swift_source_lexical_violations(path, document));
        let is_header = extension == Some("h");
        let code = if is_header {
            strip_c_comments(document)
        } else {
            strip_swift_non_code(document)
        };
        // The exact reviewed-header comparison pins the raw document, including
        // its reviewed comments; only the lexical/call analysis below uses the
        // comment-stripped form.
        let bridge_document = if is_header {
            document.as_str()
        } else {
            code.as_str()
        };
        let (bridge_violations, bridge_count) =
            swift_bridge_call_inventory(path, is_header, bridge_document);
        violations.extend(bridge_violations);
        bridge_calls += bridge_count;
        if bridge_count > 0 && path != worker_path {
            violations.push(format!(
                "{} must not call the bootstrap C ABI",
                path.display()
            ));
        }
        let constructor_count = swift_call_count(&code, "BootstrapWorker");
        let canonical_constructor_count = code
            .matches("private let bootstrapWorker = BootstrapWorker()")
            .count();
        worker_constructions += constructor_count;
        if constructor_count != canonical_constructor_count
            || (constructor_count > 0 && path != app_delegate_path)
        {
            violations.push(format!(
                "{} must not construct or alias BootstrapWorker outside its canonical AppDelegate property",
                path.display()
            ));
        }
        let submit_count = swift_member_call_count(&code, "submit");
        let submit_reference_count = swift_member_reference_count(&code, "submit");
        let canonical_submit_count = swift_call_count(&code, "bootstrapWorker.submit");
        let has_unqualified_submit = swift_has_unqualified_call_in_executable_body(&code, "submit");
        submissions += submit_count;
        if submit_count != submit_reference_count
            || submit_count != canonical_submit_count
            || has_unqualified_submit
            || (submit_count > 0 && path != app_delegate_path)
        {
            violations.push(format!(
                "{} must not submit product bootstrap work",
                path.display()
            ));
        }
        if path == app_delegate_path {
            for name in swift_function_names_with(&code, "bootstrapWorker.submit") {
                owner_entries.insert(name);
            }
        }
    }
    let worker_name_occurrences = sources
        .iter()
        .filter(|(path, _document)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("swift")
        })
        .map(|(_path, document)| {
            identifier_occurrence_count(&strip_swift_non_code(document), "BootstrapWorker")
        })
        .sum::<usize>();
    if worker_name_occurrences != 2 {
        violations.push(
            "the macOS source inventory must contain only the BootstrapWorker declaration and canonical construction"
                .to_owned(),
        );
    }
    (
        violations,
        bridge_calls,
        worker_constructions,
        submissions,
        owner_entries,
    )
}

fn swift_bridge_call_inventory(path: &Path, is_header: bool, code: &str) -> (Vec<String>, usize) {
    let mut violations = Vec::new();
    if is_header {
        let normalized = normalized_source_lines(code);
        let is_reviewed_header = match path.to_str() {
            Some("apple/macos/TersaRustBridge.h") => {
                normalized == CANONICAL_TERSA_RUST_BRIDGE_HEADER
            }
            Some("apple/macos/TersaMac-Bridging-Header.h") => {
                normalized == CANONICAL_TERSA_MAC_BRIDGING_HEADER
            }
            _ => false,
        };
        if !is_reviewed_header {
            violations.push(format!(
                "{} must match an exact reviewed TersaMac header",
                path.display()
            ));
        }
        if ["__asm", "__asm__", "asm"]
            .iter()
            .any(|alias| contains_identifier(code, alias))
        {
            violations.push(format!(
                "{} must not declare source-level C symbol aliases",
                path.display()
            ));
        }
        return (violations, 0);
    }
    if contains_identifier(code, "_silgen_name") || contains_identifier(code, "_cdecl") {
        violations.push(format!(
            "{} must not declare source-level Swift symbol aliases",
            path.display()
        ));
    }
    let occurrences = identifier_occurrence_count(code, "tersa_macos_bootstrap_default_account");
    let calls = swift_call_count(code, "tersa_macos_bootstrap_default_account");
    if occurrences != calls {
        violations.push(format!(
            "{} must not alias or reference the bootstrap C ABI outside its exact call site",
            path.display()
        ));
    }
    (violations, calls)
}

fn is_allowed_macos_target_source(path: &Path, extension: Option<&str>) -> bool {
    matches!(extension, Some("swift" | "h"))
        || matches!(
            path.to_str(),
            Some("apple/macos/Info.plist" | "apple/macos/TersaMac.entitlements")
        )
}

const CANONICAL_TERSA_RUST_BRIDGE_HEADER: &str = r"// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
#ifndef TERSA_RUST_BRIDGE_H
#define TERSA_RUST_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
uint32_t tersa_apple_bridge_version(void);
int32_t tersa_macos_bootstrap_default_account(const uint8_t *account_id, size_t account_id_len);
int32_t tersa_macos_mailbox_read_inbox(
const uint8_t *account_id,
size_t account_id_len,
uint16_t limit,
uint8_t *output,
size_t output_capacity,
size_t *output_len
);
int32_t tersa_macos_mailbox_read_thread(
const uint8_t *account_id,
size_t account_id_len,
const uint8_t *thread_id,
size_t thread_id_len,
uint16_t limit,
uint8_t *output,
size_t output_capacity,
size_t *output_len
);
int32_t tersa_macos_mailbox_search(
const uint8_t *account_id,
size_t account_id_len,
const uint8_t *query,
size_t query_len,
uint16_t limit,
uint8_t *output,
size_t output_capacity,
size_t *output_len
);
// Mailbox sync FFI (adapters/mailbox-sync-ffi-macos). The macOS app links only
// that crate's archive, which also re-exports the bridge symbols above.
// Begins a broker-driven sync. The access token and subject both come from
// the same token broker reply and are scoped to this sync cycle; the caller
// must wipe/discard its own buffers after this call returns. The output
// session id is written only when the return value is STATUS_STARTED.
int32_t tersa_mailbox_macos_broker_sync_begin(
const uint8_t *account_id,
size_t account_id_len,
const uint8_t *access_token,
size_t access_token_len,
const uint8_t *subject,
size_t subject_len,
uint64_t *output_session_id
);
// Broker-driven disconnect, two-phase. prepare follows the durable outer
// disconnect intent and writes the SQLCipher pre-marker/fence for the account.
int32_t tersa_mailbox_macos_broker_disconnect_prepare(
const uint8_t *account_id,
size_t account_id_len
);
// finalize is allowed only after broker token deletion; revoke_unconfirmed
// accepts only 0/1 as the revoke disposition, and output_session_id is
// published only when the return value is STATUS_STARTED.
int32_t tersa_mailbox_macos_broker_disconnect_finalize(
const uint8_t *account_id,
size_t account_id_len,
int32_t revoke_unconfirmed,
uint64_t *output_session_id
);
// Broker subject routing value, two-phase access. The subject is an
// account-identifying broker routing value stored only in the encrypted
// mailbox DB; it is not an OAuth credential. store persists the value for
// the account.
int32_t tersa_mailbox_macos_broker_subject_store(
const uint8_t *account_id,
size_t account_id_len,
const uint8_t *subject,
size_t subject_len
);
// get publishes output_subject bytes and output_subject_len only on status
// 0, and returns -6 when no subject is stored for the account. The caller
// must wipe or discard its output buffer after use.
int32_t tersa_mailbox_macos_broker_subject_get(
const uint8_t *account_id,
size_t account_id_len,
uint8_t *output_subject,
size_t output_subject_capacity,
size_t *output_subject_len
);
int32_t tersa_mailbox_macos_lifecycle_get(
const uint8_t *account_id,
size_t account_id_len,
int32_t *output_recovery,
int64_t *output_last_successful_sync_unix_millis
);
int32_t tersa_mailbox_macos_sync_poll(uint64_t session_id);
#endif";

const CANONICAL_TERSA_MAC_BRIDGING_HEADER: &str = r#"// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
#include "TersaRustBridge.h""#;

struct SwiftFfiSymbolSpec {
    symbol: &'static str,
    allowed_calls: &'static [(&'static str, usize)],
}

/// The closed production Swift call surface for every C symbol declared in the
/// reviewed bridge header. This detects review drift; it is not an ABI or OS
/// security boundary.
const SWIFT_FFI_SYMBOL_SPECS: &[SwiftFfiSymbolSpec] = &[
    SwiftFfiSymbolSpec {
        symbol: "tersa_apple_bridge_version",
        allowed_calls: &[("apple/macos/AppDelegate.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_macos_bootstrap_default_account",
        allowed_calls: &[("apple/macos/BootstrapWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_macos_mailbox_read_inbox",
        allowed_calls: &[("apple/macos/MailboxReadWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_macos_mailbox_read_thread",
        allowed_calls: &[("apple/macos/MailboxReadWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_macos_mailbox_search",
        allowed_calls: &[("apple/macos/MailboxReadWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_mailbox_macos_broker_sync_begin",
        allowed_calls: &[("apple/macos/MailboxSyncWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_mailbox_macos_broker_disconnect_prepare",
        allowed_calls: &[("apple/macos/MailboxSyncWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_mailbox_macos_broker_disconnect_finalize",
        allowed_calls: &[("apple/macos/MailboxSyncWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_mailbox_macos_broker_subject_store",
        allowed_calls: &[("apple/macos/MailboxSyncWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_mailbox_macos_broker_subject_get",
        allowed_calls: &[("apple/macos/MailboxSyncWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_mailbox_macos_lifecycle_get",
        allowed_calls: &[("apple/macos/MailboxSyncWorker.swift", 1)],
    },
    SwiftFfiSymbolSpec {
        symbol: "tersa_mailbox_macos_sync_poll",
        allowed_calls: &[("apple/macos/MailboxSyncWorker.swift", 1)],
    },
];

fn swift_ffi_symbol_inventory_violations(sources: &[(PathBuf, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for spec in SWIFT_FFI_SYMBOL_SPECS {
        for (allowed_path, allowed_count) in spec.allowed_calls {
            let actual_count = sources
                .iter()
                .find(|(path, _)| path == Path::new(allowed_path))
                .filter(|(path, _)| {
                    path.extension().and_then(|extension| extension.to_str()) == Some("swift")
                })
                .map(|(_, document)| swift_call_count(&strip_swift_non_code(document), spec.symbol))
                .unwrap_or_default();
            if actual_count != *allowed_count {
                violations.push(format!(
                    "{allowed_path} must call `{}` exactly {allowed_count} time(s), found {actual_count}",
                    spec.symbol
                ));
            }
        }

        for (path, document) in sources.iter().filter(|(path, _)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("swift")
        }) {
            let code = strip_swift_non_code(document);
            let occurrences = identifier_occurrence_count(&code, spec.symbol);
            let calls = swift_call_count(&code, spec.symbol);
            if occurrences != calls {
                violations.push(format!(
                    "{} must not alias or reference the `{}` C ABI outside an exact call site",
                    path.display(),
                    spec.symbol
                ));
            }
            let allowed_count = spec
                .allowed_calls
                .iter()
                .find_map(|(allowed_path, count)| {
                    (path == Path::new(allowed_path)).then_some(*count)
                })
                .unwrap_or_default();
            if calls != allowed_count {
                violations.push(format!(
                    "{} must call `{}` exactly {allowed_count} time(s), found {calls}",
                    path.display(),
                    spec.symbol
                ));
            }
        }
    }
    violations
}

fn normalized_source_lines(document: &str) -> String {
    document
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn strip_c_comments(document: &str) -> String {
    let mut output = Vec::with_capacity(document.len());
    let bytes = document.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        let end = if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            index
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            while index < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            index
        } else {
            output.push(bytes[index]);
            index += 1;
            continue;
        };
        for byte in &bytes[start..end] {
            output.push(if *byte == b'\n' { b'\n' } else { b' ' });
        }
    }
    String::from_utf8(output).expect("masking valid C header comments preserves UTF-8")
}

fn identifier_occurrence_count(document: &str, identifier: &str) -> usize {
    document
        .match_indices(identifier)
        .filter(|(index, _)| is_identifier_at(document, *index, identifier))
        .count()
}

/// The single reviewed macOS view-model that may drive the product bootstrap
/// owner from a user-intent action (ADR 0021 slice 2c).
const ACCOUNT_CONNECTION_VIEW_MODEL_PATH: &str = "apple/macos/AccountConnectionViewModel.swift";
/// The reviewed `AppKit` owner method that forwards to the bootstrap worker.
const PRODUCT_BOOTSTRAP_OWNER: &str = "establishOwnedAccountProfile";

/// Confines every reference to the reviewed bootstrap owner and collects the at
/// most one user-intent entry that `AccountConnectionViewModel.swift` may use to
/// drive it. The owner may appear only as its single `AppDelegate` declaration
/// and as at most one call inside a single view-model function body; any
/// reference elsewhere, a second view-model reference, or an `AppDelegate` call
/// (rather than the declaration alone) fails closed.
fn swift_bootstrap_intent_entries(
    sources: &[(PathBuf, String)],
    violations: &mut Vec<String>,
) -> BTreeSet<String> {
    let app_delegate_path = Path::new("apple/macos/AppDelegate.swift");
    let intent_path = Path::new(ACCOUNT_CONNECTION_VIEW_MODEL_PATH);
    let mut owner_total = 0;
    let mut owner_in_app_delegate = 0;
    let mut owner_in_view_model = 0;
    let mut intent_entries = BTreeSet::new();
    for (path, document) in sources {
        if path.extension().and_then(|extension| extension.to_str()) != Some("swift") {
            continue;
        }
        let code = strip_swift_non_code(document);
        let references = identifier_occurrence_count(&code, PRODUCT_BOOTSTRAP_OWNER);
        owner_total += references;
        if path == app_delegate_path {
            owner_in_app_delegate += references;
        } else if path == intent_path {
            owner_in_view_model += references;
            let mut body_references = 0;
            for (name, body, is_initializer) in swift_function_declarations_with_kind(&code) {
                let count = identifier_occurrence_count(body, PRODUCT_BOOTSTRAP_OWNER);
                body_references += count;
                if count == 0 {
                    continue;
                }
                if is_initializer {
                    // An initializer runs at construction, never on user intent;
                    // it may not be the reviewed entry into product bootstrap.
                    violations.push(format!(
                        "{} must not reference the reviewed product bootstrap owner from an initializer",
                        path.display()
                    ));
                } else {
                    intent_entries.insert(name);
                }
            }
            if body_references != references {
                violations.push(format!(
                    "{} may reference the reviewed product bootstrap owner only inside a single intent-entry function body",
                    path.display()
                ));
            }
        } else if references != 0 {
            violations.push(format!(
                "{} must not reference the reviewed product bootstrap owner",
                path.display()
            ));
        }
    }
    if owner_total != owner_in_app_delegate + owner_in_view_model {
        violations.push(
            "the reviewed product bootstrap owner may be referenced only in AppDelegate and the reviewed view-model"
                .to_owned(),
        );
    }
    if owner_in_app_delegate != 1 {
        violations.push(
            "AppDelegate.swift must declare the reviewed product bootstrap owner exactly once and never call it"
                .to_owned(),
        );
    }
    if owner_in_view_model > 1 || intent_entries.len() > 1 {
        violations.push(
            "the reviewed view-model must contain at most one product bootstrap intent entry"
                .to_owned(),
        );
        // Fail closed: never treat an over-referenced view-model as reviewed.
        intent_entries.clear();
    }
    intent_entries
}

fn swift_bootstrap_launch_entry_violations(
    sources: &[(PathBuf, String)],
    owner_entries: &BTreeSet<String>,
) -> Vec<String> {
    let mut violations = Vec::new();
    let intent_entries = swift_bootstrap_intent_entries(sources, &mut violations);
    let stripped = sources
        .iter()
        .filter(|(path, _document)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("swift")
        })
        .map(|(path, document)| (path.clone(), strip_swift_non_code(document)))
        .collect::<Vec<_>>();
    // Two reachability closures over the same call graph:
    // - `terminal_reachable` stops propagation at the reviewed intent entry, so
    //   only functions reaching bootstrap through a NON-intent path appear here;
    // - `strict_reachable` ignores the exemption, so it contains every function
    //   that transitively reaches bootstrap, including callers of the intent.
    let reachability = BootstrapReachability {
        owner_entries,
        intent_entries: &intent_entries,
        terminal_reachable: &swift_bootstrap_reachable_entries(
            &stripped,
            owner_entries,
            &intent_entries,
        ),
        strict_reachable: &swift_bootstrap_reachable_entries(
            &stripped,
            owner_entries,
            &BTreeSet::new(),
        ),
    };
    for (path, code) in &stripped {
        for (name, body, is_initializer) in swift_function_declarations_with_kind(code) {
            if swift_function_enters_bootstrap_unreviewed(
                path,
                &name,
                body,
                is_initializer,
                &reachability,
            ) {
                violations.push(format!(
                    "{} must not enter bootstrap from unreviewed function `{name}`",
                    path.display()
                ));
            }
        }
        for (property, bodies) in swift_named_property_bodies(code) {
            if bodies.iter().any(|body| {
                swift_member_call_count(body, "submit") != 0
                    || swift_unqualified_call_count(body, "submit") != 0
                    || reachability
                        .terminal_reachable
                        .iter()
                        .any(|(_node_path, node_name)| contains_identifier(body, node_name))
            }) {
                violations.push(format!(
                    "{} property `{property}` must not enter product bootstrap during initialization",
                    path.display()
                ));
            }
        }
    }
    violations
}

/// The reviewed owner/intent sets and the two reachability closures used to
/// classify each function's relationship to product bootstrap.
struct BootstrapReachability<'a> {
    owner_entries: &'a BTreeSet<String>,
    intent_entries: &'a BTreeSet<String>,
    terminal_reachable: &'a BTreeSet<BootstrapNode>,
    strict_reachable: &'a BTreeSet<BootstrapNode>,
}

/// One call-graph node: a named declaration in ONE macOS source file.
type BootstrapNode = (PathBuf, String);

fn bootstrap_node_reachable(set: &BTreeSet<BootstrapNode>, path: &Path, name: &str) -> bool {
    set.iter()
        .any(|(node_path, node_name)| node_path == path && node_name == name)
}

/// Whether a function declaration reaches product bootstrap through an
/// unreviewed path. The reviewed `AppDelegate` owner and the single reviewed
/// view-model intent entry are allowed; anything else that reaches bootstrap is
/// allowed only as a user-action caller — it reaches bootstrap solely through the
/// intent entry and is neither an initializer nor an `AppDelegate` member (both of
/// which run automatically at construction or launch, never on user intent).
fn swift_function_enters_bootstrap_unreviewed(
    path: &Path,
    name: &str,
    body: &str,
    is_initializer: bool,
    reachability: &BootstrapReachability,
) -> bool {
    let calls_submit = swift_member_call_count(body, "submit") != 0
        || swift_unqualified_call_count(body, "submit") != 0;
    if !calls_submit && !bootstrap_node_reachable(reachability.strict_reachable, path, name) {
        return false;
    }
    let app_delegate_path = Path::new("apple/macos/AppDelegate.swift");
    let intent_path = Path::new(ACCOUNT_CONNECTION_VIEW_MODEL_PATH);
    let is_reviewed_owner = path == app_delegate_path
        && reachability.owner_entries.contains(name)
        && swift_call_count(body, "bootstrapWorker.submit") == 1;
    let is_reviewed_intent = path == intent_path
        && !is_initializer
        && reachability.intent_entries.contains(name)
        && identifier_occurrence_count(body, PRODUCT_BOOTSTRAP_OWNER) == 1
        && !calls_submit;
    if is_reviewed_owner || is_reviewed_intent {
        return false;
    }
    let reaches_only_through_intent =
        !calls_submit && !bootstrap_node_reachable(reachability.terminal_reachable, path, name);
    let is_automatic_entry = is_initializer || path == app_delegate_path;
    !reaches_only_through_intent || is_automatic_entry
}

fn swift_bootstrap_reachable_entries(
    stripped: &[(PathBuf, String)],
    owner_entries: &BTreeSet<String>,
    intent_entries: &BTreeSet<String>,
) -> BTreeSet<BootstrapNode> {
    let entries = stripped
        .iter()
        .flat_map(|(path, code)| {
            swift_named_entry_bodies(code)
                .into_iter()
                .map(move |(name, bodies)| ((path.clone(), name), bodies))
        })
        .collect::<Vec<_>>();
    let mut reachable = entries
        .iter()
        .filter(|((_path, name), _bodies)| owner_entries.contains(name))
        .map(|(node, _bodies)| node.clone())
        .collect::<BTreeSet<_>>();
    loop {
        // Reviewed intent entries are reachable sinks: they are validated on
        // their own, but callers reaching only through them do not enter
        // bootstrap, so they never seed further propagation.
        let seeds = reachable
            .iter()
            .map(|(_path, name)| name.clone())
            .filter(|name| !intent_entries.contains(name.as_str()))
            .collect::<BTreeSet<_>>();
        let mut changed = false;
        for (node, bodies) in &entries {
            if reachable.contains(node) {
                continue;
            }
            if bodies
                .iter()
                .any(|body| seeds.iter().any(|seed| contains_identifier(body, seed)))
            {
                reachable.insert(node.clone());
                changed = true;
            }
        }
        if !changed {
            return reachable;
        }
    }
}

fn swift_named_entry_bodies(document: &str) -> BTreeMap<String, Vec<&str>> {
    let mut entries = swift_named_function_bodies(document);
    for (name, bodies) in swift_named_property_bodies(document) {
        entries.entry(name).or_default().extend(bodies);
    }
    entries
}

fn swift_named_function_bodies(document: &str) -> BTreeMap<String, Vec<&str>> {
    let mut functions = BTreeMap::new();
    for (name, body) in swift_function_declarations(document) {
        functions.entry(name).or_insert_with(Vec::new).push(body);
    }
    functions
}

fn swift_named_property_bodies(document: &str) -> BTreeMap<String, Vec<&str>> {
    // A `let`/`var` nested inside a function body is a LOCAL binding, not a
    // declaration another function could name: it is not a call-graph node, and
    // its enclosing function body is already inventoried on its own.
    let function_bodies = swift_function_declaration_sites(document)
        .into_iter()
        .map(|(_name, body, _is_initializer, offset)| offset..offset + body.len())
        .collect::<Vec<_>>();
    let mut properties = BTreeMap::<String, Vec<&str>>::new();
    for declaration in ["let", "var"] {
        for (start, _) in document.match_indices(declaration) {
            if !is_identifier_at(document, start, declaration) {
                continue;
            }
            if function_bodies.iter().any(|range| range.contains(&start)) {
                continue;
            }
            let name_start = skip_ascii_whitespace(document, start + declaration.len());
            let name_length = document[name_start..]
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                .count();
            if name_length == 0 {
                continue;
            }
            let name = &document[name_start..name_start + name_length];
            let Some(body) = swift_property_body(document, name_start + name_length) else {
                continue;
            };
            properties.entry(name.to_owned()).or_default().push(body);
        }
    }
    properties
}

fn swift_property_body(document: &str, mut index: usize) -> Option<&str> {
    const NEXT_DECLARATIONS: [&str; 8] = [
        "class",
        "enum",
        "extension",
        "func",
        "init",
        "let",
        "struct",
        "var",
    ];
    let mut parenthesis_depth = 0_u32;
    let mut bracket_depth = 0_u32;
    let mut initializer_start = None;
    while index < document.len() {
        index = skip_ascii_whitespace(document, index);
        if index >= document.len() {
            return initializer_start.map(|start| &document[start..index]);
        }
        if parenthesis_depth == 0 && bracket_depth == 0 {
            if document.as_bytes()[index] == b'{' {
                return balanced_brace_body(document, index);
            }
            if matches!(document.as_bytes()[index], b';' | b'}')
                || NEXT_DECLARATIONS.iter().any(|keyword| {
                    document[index..].starts_with(keyword)
                        && is_identifier_at(document, index, keyword)
                })
            {
                return initializer_start.map(|start| &document[start..index]);
            }
            if document.as_bytes()[index] == b'=' {
                initializer_start.get_or_insert(index + 1);
            }
        }
        match document.as_bytes()[index] {
            b'(' => parenthesis_depth = parenthesis_depth.saturating_add(1),
            b')' => parenthesis_depth = parenthesis_depth.saturating_sub(1),
            b'[' => bracket_depth = bracket_depth.saturating_add(1),
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    initializer_start.map(|start| &document[start..])
}

fn swift_call_count(document: &str, name: &str) -> usize {
    document
        .match_indices(name)
        .filter(|(index, _)| {
            is_identifier_at(document, *index, name)
                && document[skip_ascii_whitespace(document, *index + name.len())..].starts_with('(')
        })
        .count()
}

fn swift_member_call_count(document: &str, method: &str) -> usize {
    document
        .match_indices(method)
        .filter(|(index, _)| {
            swift_member_reference_at(document, *index, method)
                && swift_identifier_token_bounds(document, *index, method).is_some_and(
                    |(_token_start, token_end)| {
                        document[skip_ascii_whitespace(document, token_end)..].starts_with('(')
                    },
                )
        })
        .count()
}

fn swift_member_reference_count(document: &str, method: &str) -> usize {
    document
        .match_indices(method)
        .filter(|(index, _)| swift_member_reference_at(document, *index, method))
        .count()
}

fn swift_member_reference_at(document: &str, index: usize, method: &str) -> bool {
    let Some((token_start, _token_end)) = swift_identifier_token_bounds(document, index, method)
    else {
        return false;
    };
    document[..token_start]
        .bytes()
        .rev()
        .find(|byte| !is_rust_ascii_whitespace(*byte))
        == Some(b'.')
}

fn swift_identifier_token_bounds(
    document: &str,
    index: usize,
    identifier: &str,
) -> Option<(usize, usize)> {
    if !is_identifier_at(document, index, identifier) {
        return None;
    }
    let escaped =
        document[..index].ends_with('`') && document[index + identifier.len()..].starts_with('`');
    Some((
        index.saturating_sub(usize::from(escaped)),
        index + identifier.len() + usize::from(escaped),
    ))
}

fn swift_has_unqualified_call_in_executable_body(document: &str, name: &str) -> bool {
    swift_function_declarations(document)
        .into_iter()
        .any(|(_function, body)| swift_unqualified_call_count(body, name) != 0)
        || swift_named_property_bodies(document)
            .into_values()
            .flatten()
            .any(|body| swift_unqualified_call_count(body, name) != 0)
}

fn swift_unqualified_call_count(document: &str, name: &str) -> usize {
    document
        .match_indices(name)
        .filter(|(index, _matched)| {
            if !is_identifier_at(document, *index, name) {
                return false;
            }
            let Some((token_start, token_end)) =
                swift_identifier_token_bounds(document, *index, name)
            else {
                return false;
            };
            let opening = skip_ascii_whitespace(document, token_end);
            if document.as_bytes().get(opening) != Some(&b'(') {
                return false;
            }
            if document[..token_start]
                .bytes()
                .rev()
                .find(|byte| !is_rust_ascii_whitespace(*byte))
                == Some(b'.')
            {
                return false;
            }
            if matches!(
                swift_preceding_identifier(document, token_start),
                Some("func" | "macro")
            ) {
                return false;
            }
            !swift_selector_reference_at(document, token_start)
        })
        .count()
}

fn swift_preceding_identifier(document: &str, index: usize) -> Option<&str> {
    let prefix = document.get(..index)?;
    let end = prefix
        .bytes()
        .rposition(|byte| !is_rust_ascii_whitespace(byte))?
        + 1;
    let start = prefix[..end]
        .bytes()
        .rposition(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
        .map_or(0, |delimiter| delimiter + 1);
    (start != end).then_some(&prefix[start..end])
}

fn swift_selector_reference_at(document: &str, index: usize) -> bool {
    let prefix = &document[..index];
    let mut closed_depth = 0_usize;
    let Some(opening) = prefix
        .bytes()
        .enumerate()
        .rev()
        .find_map(|(position, byte)| {
            match byte {
                b')' => closed_depth += 1,
                b'(' if closed_depth != 0 => closed_depth -= 1,
                b'(' => return Some(position),
                _ => {}
            }
            None
        })
    else {
        return false;
    };
    prefix[..opening].trim_end().ends_with("#selector")
}

fn swift_owner_flow_forwards_completion(document: &str) -> bool {
    swift_function_bodies(document, "establishOwnedAccountProfile")
        .into_iter()
        .any(|body| {
            swift_call_argument_is_identifier(
                body,
                "bootstrapWorker.submit",
                "completion",
                "completion",
            )
        })
}

fn swift_call_argument_is_identifier(
    document: &str,
    call: &str,
    label: &str,
    identifier: &str,
) -> bool {
    document.match_indices(call).any(|(start, _)| {
        if !is_identifier_at(document, start, call) {
            return false;
        }
        let opening = skip_ascii_whitespace(document, start + call.len());
        if document.as_bytes().get(opening) != Some(&b'(') {
            return false;
        }
        let Some(arguments) = balanced_delimited_body(document, opening, b'(', b')') else {
            return false;
        };
        let compact = arguments
            .bytes()
            .filter(|byte| !is_rust_ascii_whitespace(*byte))
            .collect::<Vec<_>>();
        compact
            .windows(label.len() + identifier.len() + 1)
            .any(|window| window == format!("{label}:{identifier}").as_bytes())
    })
}

/// Exact path of the reviewed closed NSXPC token-broker protocol declaration.
/// No directory-wide, filename-suffix, or generic `protocol` exemption exists.
const REVIEWED_TOKEN_BROKER_PROTOCOL_PATH: &str =
    "apple/macos-token-broker/TokenBrokerProtocol.swift";
/// Exact path of the reviewed main-app client mirror of the closed NSXPC
/// protocol. Required so the main process can configure `NSXPCInterface`
/// against the same Objective-C selector surface without inventing a second
/// wire protocol.
const REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH: &str = "apple/macos/TokenBrokerProtocol.swift";
/// Exact path of the reviewed NSXPC listener delegate that pins the peer
/// code-signing requirement.
const REVIEWED_TOKEN_BROKER_LISTENER_PATH: &str =
    "apple/macos-token-broker/TokenBrokerListenerDelegate.swift";
/// Reviewed dedicated Rust archive linked only into the token-broker XPC target.
const TERSA_MAC_TOKEN_BROKER_OTHER_LDFLAGS: &str =
    "$(SRCROOT)/build/rust/$(PLATFORM_NAME)/$(CONFIGURATION)/libtersa_token_broker_ffi_macos.a";
/// Reviewed build script that produces the token-broker archive.
const TERSA_MAC_TOKEN_BROKER_BUILD_SCRIPT: &str =
    "sh \"${SRCROOT}/scripts/build-rust-staticlib.sh\" macos-token-broker \"${CONFIGURATION}\"";
/// Reviewed bridging header for the token-broker C ABI.
const TERSA_MAC_TOKEN_BROKER_BRIDGING_HEADER: &str =
    "macos-token-broker/TersaMacTokenBroker-Bridging-Header.h";
/// Reviewed token-group build setting value for the broker process.
const TOKEN_BUILD_SETTING_GROUP: &str = "$(TeamIdentifierPrefix)app.tersa.token";
/// Objective-C runtime name and Swift protocol identifier for the closed v1
/// NSXPC interface. Both must match exactly for the lexical exemption.
const REVIEWED_TOKEN_BROKER_PROTOCOL_NAME: &str = "TersaMacTokenBrokerProtocolV1";
/// Exact `@objc(...)` attribute that must immediately precede the reviewed
/// protocol declaration (modulo ASCII whitespace).
const REVIEWED_TOKEN_BROKER_PROTOCOL_OBJC_ATTR: &str = "@objc(TersaMacTokenBrokerProtocolV1)";
/// Explicit bounded wire-version constant name required on the protocol surface.
const REVIEWED_TOKEN_BROKER_PROTOCOL_VERSION_NAME: &str = "TersaMacTokenBrokerProtocolVersion";
/// Exact assignment for the bounded protocol wire version (`1` only).
const REVIEWED_TOKEN_BROKER_PROTOCOL_VERSION_ASSIGNMENT: &str = "static let value: Int = 1";
/// Reviewed peer code-signing requirement literal (unescaped). The raw Swift
/// source must carry this exact string value; empty or anchor-only values fail.
const REVIEWED_TOKEN_BROKER_CODE_SIGNING_REQUIREMENT_LITERAL: &str =
    "identifier \"app.tersa.mac\" and anchor apple generic";
/// Reviewed constant that must hold the code-signing requirement literal.
const REVIEWED_TOKEN_BROKER_CODE_SIGNING_REQUIREMENT_CONSTANT: &str =
    "embeddingAppCodeSigningRequirement";
/// Exact call that must apply the reviewed constant (whitespace-normalized).
const REVIEWED_TOKEN_BROKER_CODE_SIGNING_REQUIREMENT_CALL: &str =
    "newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)";
/// Reviewed main-app constant that must hold the embedded token-broker service
/// bundle identifier for `NSXPCConnection(serviceName:)`.
const REVIEWED_TOKEN_BROKER_CLIENT_SERVICE_BUNDLE_CONSTANT: &str = "serviceBundleIdentifier";
/// Exact executable constructor that must open the embedded token-broker XPC
/// connection (whitespace-normalized). Alternate initializers fail closed.
const REVIEWED_TOKEN_BROKER_CLIENT_CONNECTION_CONSTRUCTION: &str =
    "NSXPCConnection(serviceName: Self.serviceBundleIdentifier)";
/// Whitespace-normalized exact signatures for the five closed v1 broker
/// protocol operations. Parameter labels and reply value types are part of the
/// wire contract; top-level returns and additional methods fail closed.
const REVIEWED_TOKEN_BROKER_PROTOCOL_OPERATION_SIGNATURES: [&str; 5] = [
    "funcbeginAuthorizationSession(redirectURI:String,withReplyreply:@escaping@Sendable(_authorizationURL:String?,_sessionHandle:String?,_status:Int)->Void)",
    "funccompleteAuthorizationSession(sessionHandle:String,callbackURL:String,withReplyreply:@escaping@Sendable(_accessToken:String?,_subject:String?,_expiresInSeconds:Int,_status:Int)->Void)",
    "funcrefreshAccessToken(accountSubject:String,withReplyreply:@escaping@Sendable(_accessToken:String?,_subject:String?,_expiresInSeconds:Int,_status:Int)->Void)",
    "funcrevokeProviderGrant(accountSubject:String,withReplyreply:@escaping@Sendable(_status:Int)->Void)",
    "funcdeleteStoredTokens(accountSubject:String,withReplyreply:@escaping@Sendable(_status:Int)->Void)",
];
/// Exact closed allowlist of reviewed main-app `TokenBroker` client Swift paths.
/// No `TokenBroker*` filename-prefix or directory wildcard exemption exists:
/// any other `apple/macos/TokenBroker*.swift` fails closed.
const REVIEWED_TOKEN_BROKER_CLIENT_SWIFT_PATHS: [&str; 4] = [
    "apple/macos/TokenBrokerAuthorizationSession.swift",
    "apple/macos/TokenBrokerClient.swift",
    "apple/macos/TokenBrokerProtocol.swift",
    "apple/macos/TokenBrokerStatusMapping.swift",
];
/// Exact path of the sole reviewed abandoned-session `deinit` cleanup. No
/// directory-wide, filename-prefix, or generic `deinit` exemption exists.
const REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_DEINIT_PATH: &str =
    "apple/macos/TokenBrokerAuthorizationSession.swift";
/// Exact owner class of the sole reviewed abandoned-session `deinit` cleanup.
const REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_CLASS: &str = "TokenBrokerSessionResourceBag";
/// Whitespace-normalized form of the sole reviewed abandoned-session `deinit`.
const REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_DEINIT: &str = "deinit{release()}";
/// Exact path of the sole reviewed abandoned-request `deinit` cleanup. No
/// directory-wide, filename-prefix, or generic `deinit` exemption exists.
const REVIEWED_BROKER_SYNC_SECRETS_DEINIT_PATH: &str = "apple/macos/MailboxSyncWorker.swift";
/// Exact direct owner class of the sole reviewed abandoned-request `deinit`
/// cleanup: the secrets box zeroizing queued access-token and subject buffers
/// when a request is abandoned before begin.
const REVIEWED_BROKER_SYNC_SECRETS_CLASS: &str = "BrokerSyncSecrets";
/// Exact file-scope class that directly owns `BrokerSyncSecrets`; a file-scope
/// or differently nested `BrokerSyncSecrets` decoy fails closed.
const REVIEWED_BROKER_SYNC_SECRETS_OUTER_CLASS: &str = "MailboxSyncWorker";
/// Whitespace-normalized form of the sole reviewed abandoned-request `deinit`.
const REVIEWED_BROKER_SYNC_SECRETS_DEINIT: &str = "deinit{wipe()}";
/// Closed `TersaMacTokenBroker` source inventory. Missing or extra paths fail closed.
const TOKEN_BROKER_ALLOWED_SOURCE_PATHS: [&str; 9] = [
    "apple/macos-token-broker/Info.plist",
    "apple/macos-token-broker/TersaMacTokenBroker-Bridging-Header.h",
    "apple/macos-token-broker/TersaMacTokenBroker.entitlements",
    "apple/macos-token-broker/TersaTokenBrokerBridge.h",
    "apple/macos-token-broker/TokenBrokerCallbackBuffer.swift",
    REVIEWED_TOKEN_BROKER_LISTENER_PATH,
    REVIEWED_TOKEN_BROKER_PROTOCOL_PATH,
    "apple/macos-token-broker/TokenBrokerService.swift",
    "apple/macos-token-broker/main.swift",
];

/// Declarations forbidden in inventoried macOS sources because they run code the
/// func/init body inventory cannot safely parse (`deinit`, `protocol`,
/// `subscript`) or would place an app-lifecycle entry point outside
/// `AppDelegate.swift` (a cross-file `extension AppDelegate`). Returns the first
/// violation, if any.
///
/// The sole reviewed `protocol` exception is the closed NSXPC interface
/// `@objc(TersaMacTokenBrokerProtocolV1) protocol TersaMacTokenBrokerProtocolV1`
/// in `apple/macos-token-broker/TokenBrokerProtocol.swift`. Every other protocol
/// declaration in inventoried product or broker sources fails closed.
///
/// The reviewed `deinit` exceptions are exactly two, each pinned to an exact
/// path, exact direct owner class, exact body form, and exactly one
/// occurrence:
///
/// 1. The abandoned-session cleanup `deinit { release() }` as a direct member
///    of file-scope class `TokenBrokerSessionResourceBag` in
///    `apple/macos/TokenBrokerAuthorizationSession.swift`.
/// 2. The abandoned-request cleanup `deinit { wipe() }` as a direct member of
///    class `BrokerSyncSecrets`, itself a direct member of file-scope class
///    `MailboxSyncWorker`, in `apple/macos/MailboxSyncWorker.swift`.
///
/// Any second `deinit`, any other path or owner class, attributes/parameters,
/// extra statements, alternate calls, nested placement, or comment/string
/// decoys fail closed. `subscript` remains unconditionally forbidden.
fn swift_forbidden_declaration_violation(path: &Path, code: &str) -> Option<String> {
    if let Some(violation) = swift_deinit_declaration_violation(path, code) {
        return Some(violation);
    }
    if contains_identifier(code, "subscript") {
        return Some(format!(
            "{} must not declare `subscript` in inventoried macOS sources",
            path.display()
        ));
    }
    if let Some(violation) = swift_protocol_declaration_violation(path, code) {
        return Some(violation);
    }
    if path != Path::new("apple/macos/AppDelegate.swift") {
        for (start, _) in code.match_indices("AppDelegate") {
            if is_identifier_at(code, start, "AppDelegate")
                && swift_preceding_identifier(code, start) == Some("extension")
            {
                return Some(format!(
                    "{} must not extend AppDelegate; app-lifecycle members belong in AppDelegate.swift",
                    path.display()
                ));
            }
        }
    }
    None
}

/// Rejects every `deinit` declaration except the two pinned reviewed cleanups:
/// the abandoned-session cleanup on `TokenBrokerSessionResourceBag` at
/// `REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_DEINIT_PATH` and the
/// abandoned-request cleanup on `BrokerSyncSecrets` at
/// `REVIEWED_BROKER_SYNC_SECRETS_DEINIT_PATH`. Each exception accepts exactly
/// one occurrence; a second `deinit` fails closed.
fn swift_deinit_declaration_violation(path: &Path, code: &str) -> Option<String> {
    let mut saw_reviewed = false;
    for (start, _) in code.match_indices("deinit") {
        if !is_identifier_at(code, start, "deinit") {
            continue;
        }
        if is_exact_reviewed_token_broker_session_resource_bag_deinit(path, code, start)
            || is_exact_reviewed_broker_sync_secrets_deinit(path, code, start)
        {
            if saw_reviewed {
                return Some(format!(
                    "{} must not declare `deinit` in inventoried macOS sources",
                    path.display()
                ));
            }
            saw_reviewed = true;
            continue;
        }
        return Some(format!(
            "{} must not declare `deinit` in inventoried macOS sources",
            path.display()
        ));
    }
    None
}

/// True only for the exact reviewed form `deinit { release() }` as a direct
/// member of file-scope `class TokenBrokerSessionResourceBag` in
/// `REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_DEINIT_PATH`. Leading attributes
/// or modifiers, parameters, body mutations, nested placement, and any other
/// path or owner fail closed. Comment/string regions are already masked by the
/// caller, so decoys cannot satisfy the match.
fn is_exact_reviewed_token_broker_session_resource_bag_deinit(
    path: &Path,
    code: &str,
    deinit_start: usize,
) -> bool {
    if path != Path::new(REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_DEINIT_PATH) {
        return false;
    }
    if swift_declaration_has_attached_prefix(code, deinit_start) {
        return false;
    }
    let after_keyword = skip_ascii_whitespace(code, deinit_start + "deinit".len());
    if code.as_bytes().get(after_keyword) != Some(&b'{') {
        return false;
    }
    let Some(body) = balanced_brace_body(code, after_keyword) else {
        return false;
    };
    let declaration = &code[deinit_start..after_keyword + body.len()];
    if rust_token_canonical(declaration) != REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_DEINIT {
        return false;
    }
    swift_is_direct_member_of_file_scope_class(
        code,
        deinit_start,
        REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_CLASS,
    )
}

/// True only for the exact reviewed form `deinit { wipe() }` as a direct
/// member of class `BrokerSyncSecrets`, itself a direct member of file-scope
/// `class MailboxSyncWorker`, in `REVIEWED_BROKER_SYNC_SECRETS_DEINIT_PATH`.
/// Leading attributes or modifiers, parameters, body mutations, a file-scope
/// or differently nested `BrokerSyncSecrets` decoy, deeper member nesting, and
/// any other path or owner fail closed. Comment/string regions are already
/// masked by the caller, so decoys cannot satisfy the match.
fn is_exact_reviewed_broker_sync_secrets_deinit(
    path: &Path,
    code: &str,
    deinit_start: usize,
) -> bool {
    if path != Path::new(REVIEWED_BROKER_SYNC_SECRETS_DEINIT_PATH) {
        return false;
    }
    if swift_declaration_has_attached_prefix(code, deinit_start) {
        return false;
    }
    let after_keyword = skip_ascii_whitespace(code, deinit_start + "deinit".len());
    if code.as_bytes().get(after_keyword) != Some(&b'{') {
        return false;
    }
    let Some(body) = balanced_brace_body(code, after_keyword) else {
        return false;
    };
    let declaration = &code[deinit_start..after_keyword + body.len()];
    if rust_token_canonical(declaration) != REVIEWED_BROKER_SYNC_SECRETS_DEINIT {
        return false;
    }
    swift_is_direct_member_of_nested_class(
        code,
        deinit_start,
        REVIEWED_BROKER_SYNC_SECRETS_CLASS,
        REVIEWED_BROKER_SYNC_SECRETS_OUTER_CLASS,
    )
}

/// True when `member_start` is a direct member (brace depth 1 inside the inner
/// class body) of a `class <inner_name>` that is itself a direct member of
/// file-scope `class <outer_name>`. Deeper member nesting (a type, function,
/// or closure inside the inner class), a file-scope or differently nested
/// `class <inner_name>` decoy, and non-class owners fail closed.
fn swift_is_direct_member_of_nested_class(
    code: &str,
    member_start: usize,
    inner_name: &str,
    outer_name: &str,
) -> bool {
    for (start, _) in code.match_indices("class") {
        if !is_identifier_at(code, start, "class") {
            continue;
        }
        let name_start = skip_ascii_whitespace(code, start + "class".len());
        let Some(name) = swift_type_declaration_name_at(code, name_start) else {
            continue;
        };
        if name != inner_name {
            continue;
        }
        // Inheritance, generics, and where-clauses may appear between the name
        // and the body brace; comments/strings are already masked to spaces.
        let Some(brace_relative) = code[name_start..].find('{') else {
            continue;
        };
        let brace = name_start + brace_relative;
        let Some(body) = balanced_brace_body(code, brace) else {
            continue;
        };
        let body_end = brace + body.len();
        if member_start <= brace || member_start >= body_end - 1 {
            continue;
        }
        // Direct member only: depth 1 means inside this class body and not
        // nested inside any further `{ ... }` (method, nested type, closure).
        if swift_brace_depth_between(code, brace, member_start) != 1 {
            continue;
        }
        // The inner class must itself be a direct member of the reviewed
        // file-scope outer class; file-scope or differently nested decoys of
        // the inner class name fail closed.
        return swift_is_direct_member_of_file_scope_class(code, start, outer_name);
    }
    false
}

/// True when a non-whitespace token other than a declaration boundary (`{`,
/// `}`, or `;`) immediately precedes `start`. Rejects attributes and modifiers
/// attached to a declaration while still accepting a type-member after `{` or
/// a prior member's `}`/`;`.
fn swift_declaration_has_attached_prefix(code: &str, start: usize) -> bool {
    let mut index = start;
    while index > 0 && is_rust_ascii_whitespace(code.as_bytes()[index - 1]) {
        index -= 1;
    }
    if index == 0 {
        return false;
    }
    !matches!(code.as_bytes()[index - 1], b'{' | b'}' | b';')
}

/// True when `member_start` is a direct member (brace depth 1) of a file-scope
/// `class <class_name> { ... }` whose balanced body contains it. Nested types,
/// function/property/closure bodies, and non-class owners fail closed.
fn swift_is_direct_member_of_file_scope_class(
    code: &str,
    member_start: usize,
    class_name: &str,
) -> bool {
    for (start, _) in code.match_indices("class") {
        if !is_identifier_at(code, start, "class") {
            continue;
        }
        // Nested `class` declarations are not the reviewed file-scope owner.
        if swift_brace_depth_until(code, start) != 0 {
            continue;
        }
        let name_start = skip_ascii_whitespace(code, start + "class".len());
        let Some(name) = swift_type_declaration_name_at(code, name_start) else {
            continue;
        };
        if name != class_name {
            continue;
        }
        // Inheritance, generics, and where-clauses may appear between the name
        // and the body brace; comments/strings are already masked to spaces.
        let Some(brace_relative) = code[name_start..].find('{') else {
            continue;
        };
        let brace = name_start + brace_relative;
        let Some(body) = balanced_brace_body(code, brace) else {
            continue;
        };
        let body_end = brace + body.len();
        if member_start <= brace || member_start >= body_end - 1 {
            continue;
        }
        // Direct member only: depth 1 means inside this class body and not
        // nested inside any further `{ ... }` (method, nested type, closure).
        if swift_brace_depth_between(code, brace, member_start) == 1 {
            return true;
        }
    }
    false
}

/// Brace nesting depth immediately before `until`, scanning from the start of
/// `code`. Comment/string regions must already be masked.
fn swift_brace_depth_until(code: &str, until: usize) -> usize {
    swift_brace_depth_between(code, 0, until)
}

/// Brace nesting depth immediately before `until` after scanning `[from, until)`.
/// `from` may point at an opening `{` (counted) so a type body's first member
/// is depth 1.
fn swift_brace_depth_between(code: &str, from: usize, until: usize) -> usize {
    let until = until.min(code.len());
    let from = from.min(until);
    let mut depth = 0usize;
    for byte in &code.as_bytes()[from..until] {
        match *byte {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

/// Rejects every `protocol` declaration except the single reviewed closed NSXPC
/// interface at `REVIEWED_TOKEN_BROKER_PROTOCOL_PATH`.
fn swift_protocol_declaration_violation(path: &Path, code: &str) -> Option<String> {
    let mut saw_reviewed = false;
    for (start, _) in code.match_indices("protocol") {
        if !is_identifier_at(code, start, "protocol") {
            continue;
        }
        if is_exact_reviewed_token_broker_protocol_declaration(path, code, start) {
            if saw_reviewed {
                return Some(format!(
                    "{} must not declare `protocol` in inventoried macOS sources",
                    path.display()
                ));
            }
            saw_reviewed = true;
            continue;
        }
        return Some(format!(
            "{} must not declare `protocol` in inventoried macOS sources",
            path.display()
        ));
    }
    None
}

/// True only for the exact reviewed form
/// `@objc(TersaMacTokenBrokerProtocolV1) protocol TersaMacTokenBrokerProtocolV1 {`
/// in the service protocol file or the main-app client mirror. Inheritance,
/// `where` clauses, attributes, and any other token between the protocol name
/// and the opening brace are rejected so inherited selectors cannot bypass the
/// five-operation allowlist.
fn is_exact_reviewed_token_broker_protocol_declaration(
    path: &Path,
    code: &str,
    protocol_start: usize,
) -> bool {
    if path != Path::new(REVIEWED_TOKEN_BROKER_PROTOCOL_PATH)
        && path != Path::new(REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH)
    {
        return false;
    }
    let name_start = skip_ascii_whitespace(code, protocol_start + "protocol".len());
    if !code[name_start..].starts_with(REVIEWED_TOKEN_BROKER_PROTOCOL_NAME)
        || !is_identifier_at(code, name_start, REVIEWED_TOKEN_BROKER_PROTOCOL_NAME)
    {
        return false;
    }
    let after_name =
        skip_ascii_whitespace(code, name_start + REVIEWED_TOKEN_BROKER_PROTOCOL_NAME.len());
    if code.as_bytes().get(after_name) != Some(&b'{') {
        return false;
    }
    let mut attr_end = protocol_start;
    while attr_end > 0 && is_rust_ascii_whitespace(code.as_bytes()[attr_end - 1]) {
        attr_end -= 1;
    }
    let attr = REVIEWED_TOKEN_BROKER_PROTOCOL_OBJC_ATTR;
    if attr_end < attr.len() {
        return false;
    }
    let attr_start = attr_end - attr.len();
    // Byte-offset pin: Swift source may be non-ASCII, so use a boundary-aware
    // lookup instead of slicing (which panics on a mid-character offset).
    code.get(attr_start..attr_end) == Some(attr)
}

/// True when exactly one `enum TersaMacTokenBrokerProtocolVersion { ... }`
/// exists and its balanced body pins the bounded wire version with exactly one
/// terminated `static let value: Int = 1`. File-wide decoy assignments, a
/// second version enum, inheritance/generic/`where` drift after the enum name,
/// or an unbalanced body all fail closed.
fn has_exact_token_broker_protocol_version_assignment(code: &str) -> bool {
    let enum_name = REVIEWED_TOKEN_BROKER_PROTOCOL_VERSION_NAME;
    let mut version_body: Option<&str> = None;
    for (start, _) in code.match_indices("enum") {
        if !is_identifier_at(code, start, "enum") {
            continue;
        }
        let name_start = skip_ascii_whitespace(code, start + "enum".len());
        if !code[name_start..].starts_with(enum_name)
            || !is_identifier_at(code, name_start, enum_name)
        {
            continue;
        }
        let after_name = skip_ascii_whitespace(code, name_start + enum_name.len());
        if code.as_bytes().get(after_name) != Some(&b'{') {
            return false;
        }
        if version_body.is_some() {
            return false;
        }
        let Some(body) = balanced_brace_body(code, after_name) else {
            return false;
        };
        version_body = Some(body);
    }
    let Some(body) = version_body else {
        return false;
    };
    let assignment = REVIEWED_TOKEN_BROKER_PROTOCOL_VERSION_ASSIGNMENT;
    let mut matches = body.match_indices(assignment);
    let Some((index, _)) = matches.next() else {
        return false;
    };
    if matches.next().is_some() {
        return false;
    }
    // Masked comments are whitespace; only the enum's closing `}` may follow.
    swift_expression_terminates_before_boundary(
        body,
        index + assignment.len(),
        is_swift_closing_brace_boundary,
    )
}

/// After an exact reviewed expression value at `index`, skip every ASCII
/// whitespace byte (including newlines). Comment/string-masked regions are
/// already spaces, so optional trailing comments remain accepted. The next
/// executable token must satisfy `is_boundary`; next-line operators, calls,
/// members, second literals, and other expression continuations fail closed.
fn swift_expression_terminates_before_boundary(
    code: &str,
    index: usize,
    is_boundary: fn(&str, usize) -> bool,
) -> bool {
    is_boundary(code, skip_ascii_whitespace(code, index))
}

/// True only at a closing `}` — the sole valid boundary after the reviewed
/// protocol-version assignment inside its balanced enum body.
fn is_swift_closing_brace_boundary(code: &str, index: usize) -> bool {
    code.as_bytes().get(index) == Some(&b'}')
}

fn swift_source_lexical_violations(path: &Path, document: &str) -> Vec<String> {
    let code = strip_swift_non_code(document);
    if swift_has_underscored_attribute(&code) {
        return vec![format!(
            "{} must not use underscored Swift attributes in inventoried macOS sources",
            path.display()
        )];
    }
    for forbidden in [
        "CFBundleGetFunctionPointerForName",
        "NSAddressOfSymbol",
        "NSLookupSymbolInImage",
        "_cdecl",
        "_silgen_name",
        "convention",
        "dlopen",
        "dlsym",
        "unsafeBitCast",
    ] {
        if contains_identifier(&code, forbidden) {
            return vec![format!(
                "{} must not use dynamic symbol or unsafe function-pointer alias boundary `{forbidden}`",
                path.display()
            )];
        }
    }
    if let Some(violation) = swift_forbidden_declaration_violation(path, &code) {
        return vec![violation];
    }
    let bytes = document.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1;
            while index < bytes.len() && depth != 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
        } else if swift_raw_string_starts_at(bytes, index) {
            return vec![format!(
                "{} must not use raw Swift string literals in inventoried macOS sources",
                path.display()
            )];
        } else if bytes[index..].starts_with(b"\"\"\"") || bytes[index] == b'\"' {
            let literal_start = index;
            let multiline = bytes[index..].starts_with(b"\"\"\"");
            index += if multiline { 3 } else { 1 };
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    if bytes.get(index + 1) == Some(&b'(') {
                        return vec![format!(
                            "{} must not use Swift string interpolation in inventoried macOS sources",
                            path.display()
                        )];
                    }
                    index = (index + 2).min(bytes.len());
                } else if multiline && bytes[index..].starts_with(b"\"\"\"") {
                    index += 3;
                    break;
                } else if !multiline && bytes[index] == b'\"' {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
            if document[literal_start..index].contains("tersa_macos_bootstrap_default_account") {
                return vec![format!(
                    "{} must not hide the protected bootstrap C ABI in a Swift string literal",
                    path.display()
                )];
            }
        } else {
            index += 1;
        }
    }
    Vec::new()
}

fn swift_raw_string_starts_at(bytes: &[u8], start: usize) -> bool {
    if bytes.get(start) != Some(&b'#') {
        return false;
    }
    let hashes = bytes[start..]
        .iter()
        .take_while(|byte| **byte == b'#')
        .count();
    matches!(bytes.get(start + hashes), Some(b'\"'))
}

/// Swift has the same comment forms as Rust, plus ordinary, multiline, and raw
/// string literals. Masks comments and string literals with spaces while
/// preserving newlines and byte offsets, so executable-declaration pins can map
/// back into the original document without accepting string or comment decoys.
fn strip_swift_non_code(document: &str) -> String {
    let mut output = Vec::with_capacity(document.len());
    let bytes = document.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        let end = if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            index
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1;
            while index < bytes.len() && depth != 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            index
        } else if swift_raw_string_starts_at(bytes, index) {
            consume_swift_raw_string_end(bytes, index)
        } else if bytes[index..].starts_with(b"\"\"\"") {
            index += 3;
            while index < bytes.len() && !bytes[index..].starts_with(b"\"\"\"") {
                index += 1;
            }
            index = (index + 3).min(bytes.len());
            index
        } else if bytes[index] == b'"' {
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index += 2;
                } else {
                    let done = bytes[index] == b'"';
                    index += 1;
                    if done {
                        break;
                    }
                }
            }
            index.min(bytes.len())
        } else {
            output.push(bytes[index]);
            index += 1;
            continue;
        };
        index = end;
        for byte in &bytes[start..end] {
            output.push(if *byte == b'\n' { b'\n' } else { b' ' });
        }
    }
    String::from_utf8(output).expect("masking valid Swift source preserves UTF-8")
}

/// Advance past a Swift raw string literal starting at `start` (`#"..."#`,
/// `#"""..."""#`, or with more hash delimiters). Unclosed literals consume
/// through end-of-input so their body cannot be treated as executable code.
fn consume_swift_raw_string_end(bytes: &[u8], start: usize) -> usize {
    let hashes = bytes[start..]
        .iter()
        .take_while(|byte| **byte == b'#')
        .count();
    let after_hashes = start + hashes;
    let multiline = bytes[after_hashes..].starts_with(b"\"\"\"");
    let mut index = after_hashes + if multiline { 3 } else { 1 };
    while index < bytes.len() {
        if multiline {
            if bytes[index..].starts_with(b"\"\"\"")
                && bytes[index + 3..].len() >= hashes
                && bytes[index + 3..index + 3 + hashes]
                    .iter()
                    .all(|byte| *byte == b'#')
            {
                return index + 3 + hashes;
            }
        } else if bytes[index] == b'"'
            && bytes[index + 1..].len() >= hashes
            && bytes[index + 1..index + 1 + hashes]
                .iter()
                .all(|byte| *byte == b'#')
        {
            return index + 1 + hashes;
        }
        index += 1;
    }
    bytes.len()
}

fn swift_function_names_with(document: &str, needle: &str) -> Vec<String> {
    swift_function_declarations(document)
        .into_iter()
        .filter_map(|(name, body)| body.contains(needle).then_some(name))
        .collect()
}

fn swift_function_bodies<'a>(document: &'a str, name: &str) -> Vec<&'a str> {
    swift_function_declarations(document)
        .into_iter()
        .filter_map(|(candidate, body)| (candidate == name).then_some(body))
        .collect()
}

fn swift_function_declarations(document: &str) -> Vec<(String, &str)> {
    swift_function_declarations_with_kind(document)
        .into_iter()
        .map(|(name, body, _is_initializer)| (name, body))
        .collect()
}

/// Like [`swift_function_declarations`] but also reports whether each declaration
/// is a constructor (`init`), so callers can forbid bootstrap during
/// construction independently of ordinary methods.
fn swift_function_declarations_with_kind(document: &str) -> Vec<(String, &str, bool)> {
    swift_function_declaration_sites(document)
        .into_iter()
        .map(|(name, body, is_initializer, _offset)| (name, body, is_initializer))
        .collect()
}

/// Every parsed `func`/`init` declaration with the byte offset of its body, so
/// callers can tell a type-scope declaration from a binding nested inside a
/// function body.
fn swift_function_declaration_sites(document: &str) -> Vec<(String, &str, bool, usize)> {
    let mut declarations = Vec::new();
    for keyword in ["func", "init"] {
        let is_initializer = keyword == "init";
        for (start, _) in document.match_indices(keyword) {
            if !is_identifier_at(document, start, keyword) {
                continue;
            }
            // `.init(...)` / `Type.init(...)` is a call expression, not a
            // declaration; skip it so its body is not wrongly attributed.
            if is_initializer
                && document[..start]
                    .bytes()
                    .rev()
                    .find(|byte| !is_rust_ascii_whitespace(*byte))
                    == Some(b'.')
            {
                continue;
            }
            let mut index = skip_ascii_whitespace(document, start + keyword.len());
            let name = if keyword == "func" {
                let name_length = document[index..]
                    .bytes()
                    .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                    .count();
                if name_length == 0 {
                    continue;
                }
                let name = document[index..index + name_length].to_owned();
                index += name_length;
                name
            } else {
                if matches!(document.as_bytes().get(index), Some(b'?' | b'!')) {
                    index += 1;
                    index = skip_ascii_whitespace(document, index);
                }
                "init".to_owned()
            };
            // Skip the balanced parameter list before locating the body brace, so
            // a default-closure parameter (`= {}`) inside the signature cannot be
            // mistaken for the body. The parameter list is the first `(` at or
            // after the name (a leading generic `<...>` clause carries no `(`).
            let Some(paren_relative) = document[index..].find('(') else {
                continue;
            };
            let paren = index + paren_relative;
            let Some(parameters) = balanced_delimited_body(document, paren, b'(', b')') else {
                continue;
            };
            index = paren + parameters.len();
            let Some(opening_relative) = document[index..].find('{') else {
                continue;
            };
            let opening = index + opening_relative;
            if let Some(body) = balanced_brace_body(document, opening) {
                declarations.push((name, body, is_initializer, opening));
            }
        }
    }
    declarations
}

fn collect_entitlement_paths(
    source_root: &Path,
    directory: &Path,
    output: &mut Vec<PathBuf>,
) -> io::Result<()> {
    if directory == source_root {
        let metadata = fs::symlink_metadata(source_root)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::other(format!(
                "Apple signing inventory root `{}` must not be a symbolic link",
                source_root.display()
            )));
        }
        if !metadata.is_dir() {
            return Err(io::Error::other(format!(
                "Apple signing inventory root `{}` must be a directory",
                source_root.display()
            )));
        }
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if path == source_root.join("build") {
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(io::Error::other(format!(
                    "excluded Apple build root `{}` must be a real directory",
                    path.display()
                )));
            }
            continue;
        }
        if file_type.is_dir() {
            collect_entitlement_paths(source_root, &path, output)?;
        } else if file_type.is_symlink() {
            return Err(io::Error::other(format!(
                "Apple signing inventory path `{}` must not be a symbolic link",
                path.display()
            )));
        } else if file_type.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("entitlements")
        {
            output.push(path);
        }
    }
    Ok(())
}

#[derive(Debug, Default, Eq, PartialEq)]
struct TrackedAppleSigningInventory {
    entitlement_paths: Vec<PathBuf>,
    violations: Vec<String>,
}

fn tracked_apple_signing_inventory(
    repository_root: &Path,
) -> io::Result<TrackedAppleSigningInventory> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(["ls-files", "--stage", "-z", "--", "apple"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "git ls-files failed while inventorying Apple signing inputs",
        ));
    }
    let entries = String::from_utf8(output.stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut inventory = TrackedAppleSigningInventory::default();
    for entry in entries.split('\0').filter(|entry| !entry.is_empty()) {
        let Some((metadata, path)) = entry.split_once('\t') else {
            return Err(io::Error::other("malformed git index entry"));
        };
        let Some(mode) = metadata.split_whitespace().next() else {
            return Err(io::Error::other("git index entry is missing its mode"));
        };
        if path.starts_with("apple/build/") || path == "apple/build" {
            inventory.violations.push(format!(
                "tracked generated Apple build entry `{path}` is forbidden"
            ));
        }
        if !path.ends_with(".entitlements") {
            continue;
        }
        match mode {
            "100644" | "100755" => inventory.entitlement_paths.push(PathBuf::from(path)),
            "120000" => inventory.violations.push(format!(
                "tracked entitlement `{path}` must not be a symbolic link"
            )),
            _ => inventory.violations.push(format!(
                "tracked entitlement `{path}` has unsupported git mode `{mode}`"
            )),
        }
    }
    Ok(inventory)
}

fn project_generation_wrapper() -> String {
    concat!(
        r#"#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -eu

if [ "$#" -ne 0 ]; then
  echo 'Usage: sh apple/scripts/generate-project.sh' >&2
  exit 2
fi

workspace_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$workspace_dir"

command -v xcodegen >/dev/null 2>&1 || {
  echo 'xcodegen is required.' >&2
  exit 2
}

exec xcodegen"#,
        " generate --no-env --spec apple/project.yml --project apple\n"
    )
    .to_owned()
}

fn project_generation_surface_violations(
    wrapper: &str,
    ci: &str,
    development: &str,
    evidence: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    if wrapper != project_generation_wrapper() {
        violations.push(
            "apple/scripts/generate-project.sh must remain the exact reviewed --no-env wrapper"
                .to_owned(),
        );
    }
    for (path, document, minimum_wrapper_calls) in [
        (".github/workflows/ci.yml", ci, 3),
        ("docs/development.md", development, 1),
        (
            "apple/scripts/capture-dioxus-device-evidence.sh",
            evidence,
            1,
        ),
    ] {
        if contains_xcodegen_generation_invocation(document) {
            violations.push(format!(
                "{path} must not bypass apple/scripts/generate-project.sh"
            ));
        }
        if document
            .matches("sh apple/scripts/generate-project.sh")
            .count()
            < minimum_wrapper_calls
        {
            violations.push(format!(
                "{path} must invoke the reviewed project-generation wrapper"
            ));
        }
    }
    violations
}

fn swift_has_underscored_attribute(document: &str) -> bool {
    document.match_indices('@').any(|(at, _)| {
        let mut identifier = skip_ascii_whitespace(document, at + 1);
        if document.as_bytes().get(identifier) == Some(&b'`') {
            identifier += 1;
        }
        document.as_bytes().get(identifier) == Some(&b'_')
    })
}

fn tracked_project_generation_violations(repository_root: &Path) -> io::Result<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(["ls-files", "-z"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "git ls-files failed while inventorying project-generation commands",
        ));
    }
    let paths = String::from_utf8(output.stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let expected_wrapper = project_generation_wrapper();
    let mut violations = Vec::new();
    for path in paths.split('\0').filter(|path| !path.is_empty()) {
        let filesystem_path = repository_root.join(path);
        let metadata = fs::symlink_metadata(&filesystem_path)?;
        let contents = if metadata.file_type().is_symlink() {
            fs::read_link(&filesystem_path)?
                .to_string_lossy()
                .into_owned()
        } else if metadata.is_file() {
            String::from_utf8_lossy(&fs::read(&filesystem_path)?).into_owned()
        } else {
            continue;
        };
        if !contains_xcodegen_generation_invocation(&contents) {
            continue;
        }
        if path != "apple/scripts/generate-project.sh" || contents != expected_wrapper {
            violations.push(format!(
                "tracked file `{path}` contains a forbidden executable XcodeGen generation invocation"
            ));
        }
    }
    Ok(violations)
}

fn contains_xcodegen_generation_invocation(document: &str) -> bool {
    let logical_lines = document.replace("\\\r\n", " ").replace("\\\n", " ");
    let mut bindings = StaticXcodegenBindings::default();
    logical_lines
        .lines()
        .any(|line| shell_line_generates_xcode_project(line, &mut bindings))
}

#[derive(Default)]
struct StaticXcodegenBindings {
    aliases: BTreeSet<String>,
    variables: BTreeSet<String>,
}

fn shell_line_generates_xcode_project(line: &str, bindings: &mut StaticXcodegenBindings) -> bool {
    let tokens = shell_tokens(line);
    let mut segment = Vec::new();
    for token in tokens {
        if matches!(token.as_str(), ";" | "&&" | "||" | "|") {
            if shell_segment_generates_xcode_project(&segment, bindings) {
                return true;
            }
            segment.clear();
        } else {
            segment.push(token);
        }
    }
    shell_segment_generates_xcode_project(&segment, bindings)
}

fn shell_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else if character == '\\' && delimiter == '"' {
                if let Some(escaped) = characters.next() {
                    token.push(escaped);
                }
            } else {
                token.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '\\' => {
                if let Some(escaped) = characters.next() {
                    token.push(escaped);
                }
            }
            '#' if token.is_empty() => break,
            character if character.is_whitespace() => push_shell_token(&mut tokens, &mut token),
            ';' | '|' | '&' => {
                push_shell_token(&mut tokens, &mut token);
                let mut operator = character.to_string();
                if characters.peek() == Some(&character) {
                    operator.push(character);
                    characters.next();
                }
                tokens.push(operator);
            }
            _ => token.push(character),
        }
    }
    push_shell_token(&mut tokens, &mut token);
    tokens
}

fn push_shell_token(tokens: &mut Vec<String>, token: &mut String) {
    if !token.is_empty() {
        tokens.push(std::mem::take(token));
    }
}

fn shell_segment_generates_xcode_project(
    tokens: &[String],
    bindings: &mut StaticXcodegenBindings,
) -> bool {
    record_static_xcodegen_bindings(tokens, bindings);
    let mut index = 0;
    let mut yaml_run_scalar = false;
    if tokens.first().is_some_and(|token| token == "-")
        && tokens.get(1).is_some_and(|token| token == "run:")
    {
        index = 2;
        yaml_run_scalar = true;
    } else if tokens.first().is_some_and(|token| token == "run:") {
        index = 1;
        yaml_run_scalar = true;
    }
    if yaml_run_scalar
        && tokens.len() == index + 1
        && tokens[index].chars().any(char::is_whitespace)
        && contains_xcodegen_generation_invocation(&tokens[index])
    {
        return true;
    }
    while tokens.get(index).is_some_and(|token| {
        matches!(
            token.as_str(),
            "if" | "then" | "elif" | "while" | "until" | "do" | "!"
        )
    }) {
        index += 1;
    }
    while tokens
        .get(index)
        .is_some_and(|token| shell_assignment(token))
    {
        index += 1;
    }
    shell_wrapped_command_generates(tokens, index, bindings)
}

fn shell_wrapped_command_generates(
    tokens: &[String],
    mut index: usize,
    bindings: &StaticXcodegenBindings,
) -> bool {
    loop {
        let Some(command) = tokens.get(index).map(|token| shell_command_name(token)) else {
            return false;
        };
        match command {
            "env" | "sudo" => {
                index += 1;
                while tokens
                    .get(index)
                    .is_some_and(|token| token.starts_with('-') || shell_assignment(token))
                {
                    index += 1;
                }
            }
            "exec" => {
                index += 1;
                while tokens
                    .get(index)
                    .is_some_and(|token| token.starts_with('-'))
                {
                    index += 1;
                }
            }
            "command" => {
                index += 1;
                if tokens
                    .get(index)
                    .is_some_and(|token| matches!(token.as_str(), "-v" | "-V"))
                {
                    return false;
                }
                while tokens
                    .get(index)
                    .is_some_and(|token| token.starts_with('-'))
                {
                    index += 1;
                }
            }
            "sh" | "bash" | "zsh" => {
                return tokens
                    .iter()
                    .skip(index + 1)
                    .position(|token| shell_command_string_flag(token))
                    .and_then(|offset| tokens.get(index + offset + 2))
                    .is_some_and(|script| contains_xcodegen_generation_invocation(script));
            }
            "eval" => {
                return contains_xcodegen_generation_invocation(&tokens[index + 1..].join(" "));
            }
            "nice" | "nohup" | "timeout" | "xargs" => {
                return wrapped_tokens_generate_xcode_project(tokens, index + 1, bindings);
            }
            "xcodegen" => return xcodegen_arguments_generate(&tokens[index + 1..]),
            _ if static_binding_is_xcodegen(&tokens[index], bindings) => {
                return xcodegen_arguments_generate(&tokens[index + 1..]);
            }
            "cat" | "const" | "curl" | "echo" | "fn" | "grep" | "let" | "printf" => {
                return false;
            }
            _ if plausible_shell_command_token(&tokens[index]) => {
                return wrapped_tokens_generate_xcode_project(tokens, index + 1, bindings);
            }
            _ => return false,
        }
    }
}

fn plausible_shell_command_token(token: &str) -> bool {
    shell_variable_reference(token).is_some()
        || (!token.is_empty()
            && token.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/')
            }))
}

fn wrapped_tokens_generate_xcode_project(
    tokens: &[String],
    start: usize,
    bindings: &StaticXcodegenBindings,
) -> bool {
    (start..tokens.len()).any(|index| {
        let token = &tokens[index];
        if token.chars().any(char::is_whitespace) && contains_xcodegen_generation_invocation(token)
        {
            return true;
        }
        let command = shell_command_name(token);
        (command == "xcodegen" || static_binding_is_xcodegen(token, bindings))
            && xcodegen_arguments_generate(&tokens[index + 1..])
    })
}

fn record_static_xcodegen_bindings(tokens: &[String], bindings: &mut StaticXcodegenBindings) {
    let alias_declaration = tokens
        .first()
        .is_some_and(|token| shell_command_name(token) == "alias");
    let candidates = if alias_declaration {
        &tokens[1..]
    } else {
        tokens
    };
    for token in candidates {
        let Some((name, value)) = token.split_once('=') else {
            if !alias_declaration {
                break;
            }
            continue;
        };
        if !shell_identifier(name) {
            continue;
        }
        let is_xcodegen = static_value_is_xcodegen(value, bindings);
        let target = if alias_declaration {
            &mut bindings.aliases
        } else {
            &mut bindings.variables
        };
        if is_xcodegen {
            target.insert(name.to_owned());
        } else {
            target.remove(name);
        }
    }
}

fn static_value_is_xcodegen(value: &str, bindings: &StaticXcodegenBindings) -> bool {
    let command = value.split_whitespace().next().unwrap_or(value);
    shell_command_name(command) == "xcodegen" || static_binding_is_xcodegen(command, bindings)
}

fn static_binding_is_xcodegen(token: &str, bindings: &StaticXcodegenBindings) -> bool {
    if bindings.aliases.contains(token) {
        return true;
    }
    shell_variable_reference(token).is_some_and(|name| bindings.variables.contains(name))
}

fn shell_variable_reference(token: &str) -> Option<&str> {
    token
        .strip_prefix("${")
        .and_then(|name| name.strip_suffix('}'))
        .or_else(|| token.strip_prefix('$'))
        .filter(|name| shell_identifier(name))
}

fn shell_command_string_flag(token: &str) -> bool {
    token.starts_with('-') && !token.starts_with("--") && token[1..].chars().any(|flag| flag == 'c')
}

fn shell_command_name(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

fn shell_assignment(token: &str) -> bool {
    let Some((name, _value)) = token.split_once('=') else {
        return false;
    };
    shell_identifier(name)
}

fn shell_identifier(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|character: char| character.is_ascii_digit())
        && name
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn xcodegen_arguments_generate(arguments: &[String]) -> bool {
    let Some(first) = arguments.first().map(String::as_str) else {
        return true;
    };
    if matches!(first, "--version" | "version" | "--help" | "-h" | "help") {
        return false;
    }
    first == "generate" || first.starts_with('-')
}

fn non_owner_entitlement_violations(path: &str, document: &str) -> Vec<String> {
    let root: StrictYamlValue = match plist::from_bytes(document.as_bytes()) {
        Ok(root) => root,
        Err(error) => {
            return vec![format!("{path} plist parse failed: {error}")];
        }
    };
    let mut violations = Vec::new();
    for key in [
        "com.apple.security.application-groups",
        "keychain-access-groups",
    ] {
        if yaml_contains_key(&root, key) {
            violations.push(format!(
                "{path} must not contain protected entitlement `{key}`"
            ));
        }
    }
    violations
}

const SIGNING_GROUP: &str = "${TeamIdentifierPrefix}app.tersa.shared";
const BUILD_SETTING_GROUP: &str = "$(TeamIdentifierPrefix)app.tersa.shared";
const TOKEN_SIGNING_GROUP: &str = "${TeamIdentifierPrefix}app.tersa.token";
const TERSA_MAC_ENTITLEMENTS: &str = "macos/TersaMac.entitlements";
const TERSA_MAC_TOKEN_BROKER_ENTITLEMENTS: &str =
    "macos-token-broker/TersaMacTokenBroker.entitlements";
const TERSA_MAC_TOKEN_BROKER_TARGET: &str = "TersaMacTokenBroker";
const TERSA_MAC_TOKEN_BROKER_BUNDLE_ID: &str = "app.tersa.mac.token-broker";
const TERSA_MAC_BUILD_SCRIPT: &str =
    r#"sh "${SRCROOT}/scripts/build-rust-staticlib.sh" macos "${CONFIGURATION}""#;

#[derive(Clone, Debug, PartialEq)]
struct ProjectTarget {
    name: String,
    platform: String,
    body: StrictYamlValue,
}

#[derive(Clone, Debug, PartialEq)]
enum StrictYamlValue {
    Null,
    Bool(bool),
    OtherScalar,
    String(String),
    Sequence(Vec<Self>),
    Mapping(BTreeMap<String, Self>),
}

impl<'de> Deserialize<'de> for StrictYamlValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictYamlValueVisitor)
    }
}

struct StrictYamlValueVisitor;

impl<'de> Visitor<'de> for StrictYamlValueVisitor {
    type Value = StrictYamlValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an untagged YAML value with string-only mapping keys")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictYamlValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictYamlValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictYamlValue::Bool(value))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(StrictYamlValue::OtherScalar)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(StrictYamlValue::OtherScalar)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(StrictYamlValue::OtherScalar)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictYamlValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictYamlValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictYamlValue::Sequence(values))
    }

    fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(StrictYamlKey(key)) = mapping.next_key()? {
            if key == "<<" {
                return Err(de::Error::custom("YAML merge keys are forbidden"));
            }
            let value = mapping.next_value()?;
            if values.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format!("duplicate mapping key `{key}`")));
            }
        }
        Ok(StrictYamlValue::Mapping(values))
    }
}

struct StrictYamlKey(String);

impl<'de> Deserialize<'de> for StrictYamlKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictYamlKeyVisitor)
    }
}

struct StrictYamlKeyVisitor;

impl Visitor<'_> for StrictYamlKeyVisitor {
    type Value = StrictYamlKey;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a YAML string mapping key")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictYamlKey(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictYamlKey(value))
    }
}

fn signing_configuration_violations(
    entitlements: &str,
    broker_entitlements: &str,
    project: &str,
) -> Vec<String> {
    let mut violations = source_tersa_mac_entitlement_violations(entitlements);
    violations.extend(source_token_broker_entitlement_violations(
        broker_entitlements,
    ));
    let root = match parse_project_root(project) {
        Ok(root) => root,
        Err(error) => {
            violations.push(format!(
                "apple/project.yml target structure is invalid: {error}"
            ));
            return violations;
        }
    };
    let targets = match project_targets(&root) {
        Ok(targets) => targets,
        Err(error) => {
            violations.push(format!(
                "apple/project.yml target structure is invalid: {error}"
            ));
            return violations;
        }
    };
    violations.extend(effective_signing_configuration_violations(&root, &targets));
    violations.extend(signing_target_surface_violations(&targets));
    violations
}

fn signing_target_surface_violations(targets: &[ProjectTarget]) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(application) = targets.iter().find(|target| target.name == "TersaMac") else {
        violations.push("apple/project.yml is missing the TersaMac target".to_owned());
        return violations;
    };
    if application.platform != "macOS" {
        violations.push("the TersaMac target must declare platform macOS".to_owned());
    }
    violations.extend(tersa_mac_target_surface_violations(&application.body));
    match targets
        .iter()
        .find(|target| target.name == TERSA_MAC_TOKEN_BROKER_TARGET)
    {
        Some(broker_target) => {
            violations.extend(tersa_mac_token_broker_target_surface_violations(
                broker_target,
            ));
        }
        None => violations
            .push("apple/project.yml is missing the TersaMacTokenBroker target".to_owned()),
    }
    match targets.iter().find(|target| target.name == "TersaMacTests") {
        Some(test_target) => {
            violations.extend(tersa_mac_test_target_surface_violations(test_target));
        }
        None => violations.push("apple/project.yml is missing the TersaMacTests target".to_owned()),
    }
    violations.extend(tersa_mac_signing_property_violations(&application.body));
    violations
}

fn tersa_mac_signing_property_violations(body: &StrictYamlValue) -> Vec<String> {
    let mut violations = Vec::new();
    if !matches!(
        yaml_path(body, &["entitlements", "path"]),
        Some(StrictYamlValue::String(value)) if value == TERSA_MAC_ENTITLEMENTS
    ) {
        violations.push("the TersaMac target must use only macos/TersaMac.entitlements".to_owned());
    }

    for (path, label) in [
        (
            &[
                "entitlements",
                "properties",
                "com.apple.security.application-groups",
            ][..],
            "com.apple.security.application-groups",
        ),
        (
            &["entitlements", "properties", "keychain-access-groups"][..],
            "keychain-access-groups",
        ),
    ] {
        if !yaml_exact_string_array(yaml_path(body, path), SIGNING_GROUP) {
            violations.push(format!(
                "the TersaMac target `{label}` must contain exactly the registered macOS group"
            ));
        }
    }
    match yaml_path(body, &["entitlements", "properties"]) {
        Some(properties) => violations.extend(exact_tersa_mac_entitlement_violations(
            properties,
            "the TersaMac XcodeGen entitlement properties",
        )),
        None => violations.push(
            "the TersaMac XcodeGen entitlement properties must contain the exact five-key dictionary"
                .to_owned(),
        ),
    }
    if !matches!(
        yaml_path(body, &["settings", "base", "TERSA_MACOS_APP_GROUP"]),
        Some(StrictYamlValue::String(value)) if value == BUILD_SETTING_GROUP
    ) {
        violations.push(
            "the TersaMac target TERSA_MACOS_APP_GROUP setting must exactly match its entitlement group"
                .to_owned(),
        );
    }
    if !matches!(
        yaml_path(body, &["settings", "base", "CODE_SIGN_ENTITLEMENTS"]),
        Some(StrictYamlValue::String(value)) if value == TERSA_MAC_ENTITLEMENTS
    ) {
        violations.push(
            "the TersaMac target CODE_SIGN_ENTITLEMENTS setting must exactly match macos/TersaMac.entitlements"
                .to_owned(),
        );
    }
    violations
}

fn source_tersa_mac_entitlement_violations(entitlements: &str) -> Vec<String> {
    let mut violations = Vec::new();
    match plist::from_bytes::<StrictYamlValue>(entitlements.as_bytes()) {
        Ok(entitlements) => violations.extend(exact_tersa_mac_entitlement_violations(
            &entitlements,
            "apple/macos/TersaMac.entitlements",
        )),
        Err(error) => violations.push(format!(
            "apple/macos/TersaMac.entitlements plist parse failed: {error}"
        )),
    }
    for key in [
        "com.apple.security.application-groups",
        "keychain-access-groups",
    ] {
        match parse_plist_string_array(entitlements, key) {
            Ok(values) if values == [SIGNING_GROUP] => {}
            Ok(_) => violations.push(format!(
                "apple/macos/TersaMac.entitlements `{key}` must contain exactly the registered macOS group"
            )),
            Err(error) => violations.push(format!(
                "apple/macos/TersaMac.entitlements has invalid `{key}` structure: {error}"
            )),
        }
    }

    violations
}

fn exact_tersa_mac_entitlement_violations(
    entitlements: &StrictYamlValue,
    context: &str,
) -> Vec<String> {
    let Ok(entitlements) = yaml_mapping(entitlements, context) else {
        return vec![format!("{context} must be a dictionary")];
    };
    let expected_keys = BTreeSet::from([
        "com.apple.security.app-sandbox",
        "com.apple.security.application-groups",
        "com.apple.security.network.client",
        "com.apple.security.network.server",
        "keychain-access-groups",
    ]);
    let actual_keys = entitlements
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    if actual_keys != expected_keys {
        violations.push(format!(
            "{context} must contain exactly the five reviewed entitlement keys"
        ));
    }
    for key in [
        "com.apple.security.app-sandbox",
        "com.apple.security.network.client",
        "com.apple.security.network.server",
    ] {
        if !matches!(entitlements.get(key), Some(StrictYamlValue::Bool(true))) {
            violations.push(format!("{context} `{key}` must be boolean true"));
        }
    }
    for key in [
        "com.apple.security.application-groups",
        "keychain-access-groups",
    ] {
        if !yaml_exact_string_array(entitlements.get(key), SIGNING_GROUP) {
            violations.push(format!(
                "{context} `{key}` must contain exactly the registered macOS group"
            ));
        }
    }
    violations
}

fn validate_project_options(options: Option<&StrictYamlValue>, violations: &mut Vec<String>) {
    let Some(options) = options else {
        violations.push("apple/project.yml must declare the exact reviewed options".to_owned());
        return;
    };
    let Ok(options) = yaml_mapping(options, "project options") else {
        violations.push("apple/project.yml options must be a direct mapping".to_owned());
        return;
    };
    let expected_keys = BTreeSet::from(["bundleIdPrefix", "deploymentTarget", "xcodeVersion"]);
    let actual_keys = options.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        violations.push(
            "apple/project.yml options must contain only bundleIdPrefix, deploymentTarget, and xcodeVersion"
                .to_owned(),
        );
    }
    if !matches!(
        options.get("bundleIdPrefix"),
        Some(StrictYamlValue::String(value)) if value == "app.tersa"
    ) {
        violations.push("apple/project.yml options.bundleIdPrefix must be app.tersa".to_owned());
    }
    if !matches!(
        options.get("xcodeVersion"),
        Some(StrictYamlValue::String(value)) if value == "26.0"
    ) {
        violations.push("apple/project.yml options.xcodeVersion must be 26.0".to_owned());
    }
    let Some(deployment_target) = options.get("deploymentTarget") else {
        violations.push("apple/project.yml options.deploymentTarget is required".to_owned());
        return;
    };
    let Ok(deployment_target) = yaml_mapping(deployment_target, "deploymentTarget") else {
        violations.push("apple/project.yml options.deploymentTarget must be a mapping".to_owned());
        return;
    };
    let expected_targets = BTreeMap::from([("iOS", "18.0"), ("macOS", "15.0")]);
    let actual_targets = deployment_target
        .iter()
        .filter_map(|(key, value)| match value {
            StrictYamlValue::String(value) => Some((key.as_str(), value.as_str())),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    if actual_targets != expected_targets || actual_targets.len() != deployment_target.len() {
        violations.push(
            "apple/project.yml options.deploymentTarget must be exactly macOS 15.0 and iOS 18.0"
                .to_owned(),
        );
    }
}

/// The macOS app must link EXACTLY the mailbox-sync FFI archive and nothing else
/// Rust-side. That archive re-exports the bridge's C symbols, so linking
/// `libtersa_apple_bridge.a` alongside it would duplicate the bridge crate —
/// splitting its process-global grant/session statics (a grant stored via one
/// copy is unclaimable via the other). The linker only rejects one archive
/// ordering; this pin is the actual enforcement of the single-archive rule.
fn tersa_mac_links_only_ffi_archive(settings: Option<&StrictYamlValue>) -> bool {
    const TERSA_MAC_OTHER_LDFLAGS: &str =
        "$(SRCROOT)/build/rust/$(PLATFORM_NAME)/$(CONFIGURATION)/libtersa_mailbox_sync_ffi_macos.a";
    matches!(settings, Some(StrictYamlValue::Mapping(settings))
        if matches!(settings.get("OTHER_LDFLAGS"),
            Some(StrictYamlValue::Sequence(flags)) if flags.len() == 1
                && matches!(&flags[0], StrictYamlValue::String(value) if value == TERSA_MAC_OTHER_LDFLAGS))
            && !settings.keys().any(|key| key.starts_with("OTHER_LDFLAGS[")))
}

fn tersa_mac_target_surface_violations(target: &StrictYamlValue) -> Vec<String> {
    let mut violations = Vec::new();
    let Ok(target) = yaml_mapping(target, "TersaMac target") else {
        return vec!["the TersaMac target must be a direct mapping".to_owned()];
    };
    validate_tersa_mac_top_level_keys(target, &mut violations);
    validate_tersa_mac_type_settings_and_linkage(target, &mut violations);
    validate_tersa_mac_sources_dependencies_and_execution(target, &mut violations);
    violations
}

fn validate_tersa_mac_type_settings_and_linkage(
    target: &BTreeMap<String, StrictYamlValue>,
    violations: &mut Vec<String>,
) {
    if !matches!(
        target.get("type"),
        Some(StrictYamlValue::String(value)) if value == "application"
    ) {
        violations.push("the TersaMac target type must be exactly application".to_owned());
    }
    let settings = target.get("settings").and_then(|value| match value {
        StrictYamlValue::Mapping(settings) => settings.get("base"),
        _ => None,
    });
    let valid_bundle_identifier = matches!(settings, Some(StrictYamlValue::Mapping(settings))
        if matches!(settings.get("PRODUCT_BUNDLE_IDENTIFIER"), Some(StrictYamlValue::String(value)) if value == "app.tersa.mac")
            && !settings.keys().any(|key| key.starts_with("PRODUCT_BUNDLE_IDENTIFIER[")));
    if !valid_bundle_identifier {
        violations.push(
            "the TersaMac PRODUCT_BUNDLE_IDENTIFIER must be exactly app.tersa.mac without conditional overrides"
                .to_owned(),
        );
    }
    if !tersa_mac_links_only_ffi_archive(settings) {
        violations.push(
            "the TersaMac OTHER_LDFLAGS must link exactly the single mailbox-sync FFI archive (libtersa_mailbox_sync_ffi_macos.a) with no conditional overrides and no additional Rust archive — linking the bridge archive too would split the bridge's process-global grant/session state"
                .to_owned(),
        );
    }
}

fn validate_tersa_mac_sources_dependencies_and_execution(
    target: &BTreeMap<String, StrictYamlValue>,
    violations: &mut Vec<String>,
) {
    if !yaml_exact_tersa_mac_sources(target.get("sources")) {
        violations.push(
            "the TersaMac target sources must match the exact reviewed source and resource sequence"
                .to_owned(),
        );
    }
    if !yaml_exact_tersa_mac_token_broker_dependency(target.get("dependencies")) {
        violations.push(
            "the TersaMac target must embed exactly the TersaMacTokenBroker XPC dependency"
                .to_owned(),
        );
    }
    for key in [
        "postBuildScripts",
        "preCompileScripts",
        "postCompileScripts",
        "buildRules",
        "buildToolPlugins",
        "buildToolPath",
        "buildArgumentsString",
        "passSettings",
    ] {
        if target.contains_key(key) {
            violations.push(format!(
                "the TersaMac target forbidden execution surface `{key}` is present"
            ));
        }
    }
    if !yaml_exact_tersa_mac_pre_build_script(target.get("preBuildScripts")) {
        violations.push(
            "the TersaMac target must contain only the exact reviewed Rust pre-build script"
                .to_owned(),
        );
    }
    if !yaml_exact_tersa_mac_scheme(target.get("scheme")) {
        violations.push(
            "the TersaMac scheme must contain only the TersaMacTests test target and no executable actions"
                .to_owned(),
        );
    }
}

fn yaml_exact_tersa_mac_pre_build_script(value: Option<&StrictYamlValue>) -> bool {
    match value {
        Some(StrictYamlValue::Sequence(scripts)) if scripts.len() == 1 => match &scripts[0] {
            StrictYamlValue::Mapping(script) => {
                let expected_keys = BTreeSet::from(["basedOnDependencyAnalysis", "name", "script"]);
                script.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected_keys
                    && matches!(
                        script.get("name"),
                        Some(StrictYamlValue::String(value)) if value == "Build Rust static library"
                    )
                    && matches!(
                        script.get("basedOnDependencyAnalysis"),
                        Some(StrictYamlValue::Bool(false))
                    )
                    && matches!(
                        script.get("script"),
                        Some(StrictYamlValue::String(value)) if value == TERSA_MAC_BUILD_SCRIPT
                    )
            }
            _ => false,
        },
        _ => false,
    }
}

fn yaml_exact_tersa_mac_scheme(value: Option<&StrictYamlValue>) -> bool {
    match value {
        Some(StrictYamlValue::Mapping(scheme)) => {
            scheme.len() == 1
                && matches!(
                    scheme.get("testTargets"),
                    Some(StrictYamlValue::Sequence(targets))
                        if matches!(targets.as_slice(), [StrictYamlValue::String(target)] if target == "TersaMacTests")
                )
        }
        _ => false,
    }
}

fn tersa_mac_test_target_surface_violations(target: &ProjectTarget) -> Vec<String> {
    let mut violations = Vec::new();
    if target.platform != "macOS" {
        violations.push("the TersaMacTests target must declare platform macOS".to_owned());
    }
    let Ok(body) = yaml_mapping(&target.body, "TersaMacTests target") else {
        return vec!["the TersaMacTests target must be a direct mapping".to_owned()];
    };
    let expected_keys = BTreeSet::from(["platform", "settings", "sources", "type"]);
    if body.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys {
        violations.push(
            "the TersaMacTests target must contain only the exact reviewed top-level XcodeGen keys"
                .to_owned(),
        );
    }
    if !matches!(
        body.get("type"),
        Some(StrictYamlValue::String(value)) if value == "bundle.unit-test"
    ) {
        violations
            .push("the TersaMacTests target type must be exactly bundle.unit-test".to_owned());
    }
    // Exact ordered TersaMacTests sources: macos-tests, the pure client/model
    // surface under macos/, and the single reviewed shared callback-buffer
    // helper. No directory wildcard for macos-token-broker; only this path.
    let valid_sources = matches!(
        body.get("sources"),
        Some(StrictYamlValue::Sequence(sources))
            if matches!(sources.as_slice(), [
                StrictYamlValue::Mapping(test_sources),
                StrictYamlValue::Mapping(deadline_source),
                StrictYamlValue::Mapping(connection_state_source),
                StrictYamlValue::Mapping(disconnect_intent_source),
                StrictYamlValue::Mapping(lifecycle_source),
                StrictYamlValue::Mapping(broker_protocol_source),
                StrictYamlValue::Mapping(broker_client_source),
                StrictYamlValue::Mapping(broker_status_mapping_source),
                StrictYamlValue::Mapping(broker_authorization_session_source),
                StrictYamlValue::Mapping(broker_callback_buffer_source),
            ] if test_sources.len() == 1
                && matches!(test_sources.get("path"), Some(StrictYamlValue::String(path)) if path == "macos-tests")
                && deadline_source.len() == 1
                && matches!(deadline_source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos/ConnectionOperationDeadline.swift")
                && connection_state_source.len() == 1
                && matches!(connection_state_source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos/ConnectionState.swift")
                && disconnect_intent_source.len() == 1
                && matches!(disconnect_intent_source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos/DisconnectIntentStore.swift")
                && lifecycle_source.len() == 1
                && matches!(lifecycle_source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos/MailboxLifecyclePresentation.swift")
                && broker_protocol_source.len() == 1
                && matches!(broker_protocol_source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos/TokenBrokerProtocol.swift")
                && broker_client_source.len() == 1
                && matches!(broker_client_source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos/TokenBrokerClient.swift")
                && broker_status_mapping_source.len() == 1
                && matches!(broker_status_mapping_source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos/TokenBrokerStatusMapping.swift")
                && broker_authorization_session_source.len() == 1
                && matches!(broker_authorization_session_source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos/TokenBrokerAuthorizationSession.swift")
                && broker_callback_buffer_source.len() == 1
                && matches!(broker_callback_buffer_source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos-token-broker/TokenBrokerCallbackBuffer.swift"))
    );
    if !valid_sources {
        violations.push(
            "the TersaMacTests sources must be exactly macos-tests and the reviewed pure Swift client/model surface"
                .to_owned(),
        );
    }
    let valid_settings = matches!(
        body.get("settings"),
        Some(StrictYamlValue::Mapping(settings))
            if settings.len() == 1
                && matches!(settings.get("base"), Some(StrictYamlValue::Mapping(base))
                    if base.len() == 2
                        && matches!(base.get("PRODUCT_BUNDLE_IDENTIFIER"), Some(StrictYamlValue::String(value)) if value == "app.tersa.mac.tests")
                        && matches!(base.get("MACOSX_DEPLOYMENT_TARGET"), Some(StrictYamlValue::String(value)) if value == "15.0"))
    );
    if !valid_settings {
        violations.push(
            "the TersaMacTests settings must contain only its reviewed bundle identifier and macOS deployment target"
                .to_owned(),
        );
    }
    violations
}

fn yaml_exact_tersa_mac_sources(value: Option<&StrictYamlValue>) -> bool {
    let Some(StrictYamlValue::Sequence(sources)) = value else {
        return false;
    };
    matches!(
        sources.as_slice(),
        [StrictYamlValue::Mapping(source), StrictYamlValue::Mapping(resource)]
            if source.len() == 1
                && matches!(source.get("path"), Some(StrictYamlValue::String(path)) if path == "macos")
                && resource.len() == 2
                && matches!(resource.get("path"), Some(StrictYamlValue::String(path)) if path == "licenses/THIRD_PARTY_NOTICES-bridge-macos.txt")
                && matches!(resource.get("buildPhase"), Some(StrictYamlValue::String(phase)) if phase == "resources")
    )
}

fn yaml_exact_tersa_mac_token_broker_dependency(value: Option<&StrictYamlValue>) -> bool {
    let Some(StrictYamlValue::Sequence(dependencies)) = value else {
        return false;
    };
    matches!(
        dependencies.as_slice(),
        [StrictYamlValue::Mapping(dependency)]
            if dependency.len() == 2
                && matches!(
                    dependency.get("target"),
                    Some(StrictYamlValue::String(target)) if target == TERSA_MAC_TOKEN_BROKER_TARGET
                )
                && matches!(dependency.get("embed"), Some(StrictYamlValue::Bool(true)))
    )
}

fn source_token_broker_entitlement_violations(entitlements: &str) -> Vec<String> {
    let mut violations = Vec::new();
    match plist::from_bytes::<StrictYamlValue>(entitlements.as_bytes()) {
        Ok(entitlements) => violations.extend(exact_token_broker_entitlement_violations(
            &entitlements,
            "apple/macos-token-broker/TersaMacTokenBroker.entitlements",
        )),
        Err(error) => violations.push(format!(
            "apple/macos-token-broker/TersaMacTokenBroker.entitlements plist parse failed: {error}"
        )),
    }
    match parse_plist_string_array(entitlements, "keychain-access-groups") {
        Ok(values) if values == [TOKEN_SIGNING_GROUP] => {}
        Ok(_) => violations.push(
            "apple/macos-token-broker/TersaMacTokenBroker.entitlements `keychain-access-groups` must contain exactly the dedicated token group"
                .to_owned(),
        ),
        Err(error) => violations.push(format!(
            "apple/macos-token-broker/TersaMacTokenBroker.entitlements has invalid `keychain-access-groups` structure: {error}"
        )),
    }
    for forbidden in [
        "com.apple.security.application-groups",
        "com.apple.security.network.server",
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.debugger",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
    ] {
        if entitlements.contains(forbidden) {
            violations.push(format!(
                "apple/macos-token-broker/TersaMacTokenBroker.entitlements must not declare forbidden capability `{forbidden}`"
            ));
        }
    }
    violations
}

fn exact_token_broker_entitlement_violations(
    entitlements: &StrictYamlValue,
    context: &str,
) -> Vec<String> {
    let Ok(entitlements) = yaml_mapping(entitlements, context) else {
        return vec![format!("{context} must be a dictionary")];
    };
    let expected_keys = BTreeSet::from([
        "com.apple.security.app-sandbox",
        "com.apple.security.network.client",
        "keychain-access-groups",
    ]);
    let actual_keys = entitlements
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    if actual_keys != expected_keys {
        violations.push(format!(
            "{context} must contain exactly the three reviewed token-broker entitlement keys"
        ));
    }
    for key in [
        "com.apple.security.app-sandbox",
        "com.apple.security.network.client",
    ] {
        if !matches!(entitlements.get(key), Some(StrictYamlValue::Bool(true))) {
            violations.push(format!("{context} `{key}` must be boolean true"));
        }
    }
    if !yaml_exact_string_array(
        entitlements.get("keychain-access-groups"),
        TOKEN_SIGNING_GROUP,
    ) {
        violations.push(format!(
            "{context} `keychain-access-groups` must contain exactly the dedicated token group"
        ));
    }
    for forbidden in [
        "com.apple.security.application-groups",
        "com.apple.security.network.server",
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.debugger",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
    ] {
        if entitlements.contains_key(forbidden) {
            violations.push(format!(
                "{context} must not declare forbidden capability `{forbidden}`"
            ));
        }
    }
    violations
}

fn tersa_mac_token_broker_target_surface_violations(target: &ProjectTarget) -> Vec<String> {
    let mut violations = Vec::new();
    if target.platform != "macOS" {
        violations.push("the TersaMacTokenBroker target must declare platform macOS".to_owned());
    }
    let Ok(body) = yaml_mapping(&target.body, "TersaMacTokenBroker target") else {
        return vec!["the TersaMacTokenBroker target must be a direct mapping".to_owned()];
    };
    validate_token_broker_top_level_keys(body, &mut violations);
    validate_token_broker_type_and_sources(body, &mut violations);
    validate_token_broker_info_surface(&target.body, &mut violations);
    validate_token_broker_entitlements_surface(&target.body, &mut violations);
    validate_token_broker_settings_surface(body, &mut violations);
    validate_token_broker_forbidden_surfaces(body, &mut violations);
    violations
}

fn validate_token_broker_top_level_keys(
    body: &BTreeMap<String, StrictYamlValue>,
    violations: &mut Vec<String>,
) {
    let expected_keys = BTreeSet::from([
        "entitlements",
        "info",
        "platform",
        "preBuildScripts",
        "settings",
        "sources",
        "type",
    ]);
    if body.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys {
        violations.push(
            "the TersaMacTokenBroker target must contain only the exact reviewed top-level XcodeGen keys"
                .to_owned(),
        );
    }
    if !yaml_exact_token_broker_pre_build_script(body.get("preBuildScripts")) {
        violations.push(
            "the TersaMacTokenBroker preBuildScripts must be exactly the reviewed token-broker Rust archive build"
                .to_owned(),
        );
    }
}

fn yaml_exact_token_broker_pre_build_script(value: Option<&StrictYamlValue>) -> bool {
    match value {
        Some(StrictYamlValue::Sequence(scripts)) if scripts.len() == 1 => match &scripts[0] {
            StrictYamlValue::Mapping(script) => {
                let expected_keys = BTreeSet::from(["basedOnDependencyAnalysis", "name", "script"]);
                script.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected_keys
                    && matches!(
                        script.get("name"),
                        Some(StrictYamlValue::String(value))
                            if value == "Build Rust token-broker static library"
                    )
                    && matches!(
                        script.get("basedOnDependencyAnalysis"),
                        Some(StrictYamlValue::Bool(false))
                    )
                    && matches!(
                        script.get("script"),
                        Some(StrictYamlValue::String(value))
                            if value == TERSA_MAC_TOKEN_BROKER_BUILD_SCRIPT
                    )
            }
            _ => false,
        },
        _ => false,
    }
}

fn validate_token_broker_type_and_sources(
    body: &BTreeMap<String, StrictYamlValue>,
    violations: &mut Vec<String>,
) {
    if !matches!(
        body.get("type"),
        Some(StrictYamlValue::String(value)) if value == "xpc-service"
    ) {
        violations
            .push("the TersaMacTokenBroker target type must be exactly xpc-service".to_owned());
    }
    let valid_sources = matches!(
        body.get("sources"),
        Some(StrictYamlValue::Sequence(sources))
            if matches!(
                sources.as_slice(),
                [StrictYamlValue::Mapping(source)]
                    if source.len() == 1
                        && matches!(
                            source.get("path"),
                            Some(StrictYamlValue::String(path)) if path == "macos-token-broker"
                        )
            )
    );
    if !valid_sources {
        violations.push(
            "the TersaMacTokenBroker sources must be exactly the macos-token-broker root"
                .to_owned(),
        );
    }
}

fn validate_token_broker_info_surface(body: &StrictYamlValue, violations: &mut Vec<String>) {
    match yaml_path(body, &["info", "path"]) {
        Some(StrictYamlValue::String(path)) if path == "macos-token-broker/Info.plist" => {}
        _ => violations.push(
            "the TersaMacTokenBroker info path must be macos-token-broker/Info.plist".to_owned(),
        ),
    }
    let valid_info_properties = matches!(
        yaml_path(body, &["info", "properties"]),
        Some(StrictYamlValue::Mapping(properties))
            if properties.len() == 3
                && matches!(
                    properties.get("CFBundlePackageType"),
                    Some(StrictYamlValue::String(value)) if value == "XPC!"
                )
                && matches!(
                    properties.get("XPCService"),
                    Some(StrictYamlValue::Mapping(service))
                        if service.len() == 1
                            && matches!(
                                service.get("ServiceType"),
                                Some(StrictYamlValue::String(value)) if value == "Application"
                            )
                )
                && matches!(
                    properties.get("TersaOAuthClientID"),
                    Some(StrictYamlValue::String(value)) if value == "$(TERSA_OAUTH_CLIENT_ID)"
                )
    );
    if !valid_info_properties {
        violations.push(
            "the TersaMacTokenBroker info properties must declare only the reviewed XPC package type, Application service type, and OAuth client id build setting"
                .to_owned(),
        );
    }
}

fn validate_token_broker_entitlements_surface(
    body: &StrictYamlValue,
    violations: &mut Vec<String>,
) {
    if !matches!(
        yaml_path(body, &["entitlements", "path"]),
        Some(StrictYamlValue::String(value)) if value == TERSA_MAC_TOKEN_BROKER_ENTITLEMENTS
    ) {
        violations.push(
            "the TersaMacTokenBroker target must use only macos-token-broker/TersaMacTokenBroker.entitlements"
                .to_owned(),
        );
    }
    match yaml_path(body, &["entitlements", "properties"]) {
        Some(properties) => violations.extend(exact_token_broker_entitlement_violations(
            properties,
            "the TersaMacTokenBroker XcodeGen entitlement properties",
        )),
        None => violations.push(
            "the TersaMacTokenBroker XcodeGen entitlement properties must contain the exact three-key dictionary"
                .to_owned(),
        ),
    }
}

fn validate_token_broker_settings_surface(
    body: &BTreeMap<String, StrictYamlValue>,
    violations: &mut Vec<String>,
) {
    let settings = body.get("settings").and_then(|value| match value {
        StrictYamlValue::Mapping(settings) => settings.get("base"),
        _ => None,
    });
    if !yaml_exact_token_broker_base_settings(settings) {
        violations.push(
            "the TersaMacTokenBroker settings must contain only the reviewed operational identity, token group, bridging header, dedicated Rust archive, and SKIP_INSTALL"
                .to_owned(),
        );
    }
}

fn yaml_exact_token_broker_base_settings(settings: Option<&StrictYamlValue>) -> bool {
    matches!(
        settings,
        Some(StrictYamlValue::Mapping(settings))
            if settings.len() == 9
                && matches!(
                    settings.get("PRODUCT_BUNDLE_IDENTIFIER"),
                    Some(StrictYamlValue::String(value)) if value == TERSA_MAC_TOKEN_BROKER_BUNDLE_ID
                )
                && matches!(
                    settings.get("PRODUCT_NAME"),
                    Some(StrictYamlValue::String(value)) if value == TERSA_MAC_TOKEN_BROKER_TARGET
                )
                && matches!(
                    settings.get("MACOSX_DEPLOYMENT_TARGET"),
                    Some(StrictYamlValue::String(value)) if value == "15.0"
                )
                && matches!(
                    settings.get("CODE_SIGN_ENTITLEMENTS"),
                    Some(StrictYamlValue::String(value)) if value == TERSA_MAC_TOKEN_BROKER_ENTITLEMENTS
                )
                && matches!(
                    settings.get("SKIP_INSTALL"),
                    Some(StrictYamlValue::String(value)) if value == "YES"
                )
                && matches!(
                    settings.get("SWIFT_OBJC_BRIDGING_HEADER"),
                    Some(StrictYamlValue::String(value))
                        if value == TERSA_MAC_TOKEN_BROKER_BRIDGING_HEADER
                )
                && matches!(
                    settings.get("TERSA_MACOS_TOKEN_GROUP"),
                    Some(StrictYamlValue::String(value)) if value == TOKEN_BUILD_SETTING_GROUP
                )
                && matches!(
                    settings.get("ENABLE_USER_SCRIPT_SANDBOXING"),
                    Some(StrictYamlValue::String(value)) if value == "NO"
                )
                && matches!(
                    settings.get("OTHER_LDFLAGS"),
                    Some(StrictYamlValue::Sequence(flags))
                        if flags.len() == 1
                            && matches!(
                                &flags[0],
                                StrictYamlValue::String(value)
                                    if value == TERSA_MAC_TOKEN_BROKER_OTHER_LDFLAGS
                            )
                )
                && !settings.keys().any(|key| {
                    key.starts_with("PRODUCT_BUNDLE_IDENTIFIER[")
                        || key.starts_with("CODE_SIGN_ENTITLEMENTS[")
                        || key.starts_with("OTHER_LDFLAGS[")
                        || key.starts_with("TERSA_MACOS_TOKEN_GROUP[")
                        || key.starts_with("ENABLE_USER_SCRIPT_SANDBOXING[")
                })
    )
}

fn validate_token_broker_forbidden_surfaces(
    body: &BTreeMap<String, StrictYamlValue>,
    violations: &mut Vec<String>,
) {
    for key in [
        "postBuildScripts",
        "preCompileScripts",
        "postCompileScripts",
        "buildRules",
        "buildToolPlugins",
        "dependencies",
        "scheme",
        "legacy",
        "attributes",
        "configFiles",
        "templates",
    ] {
        if body.contains_key(key) {
            violations.push(format!(
                "the TersaMacTokenBroker target forbidden surface `{key}` is present"
            ));
        }
    }
}

fn macos_client_xpc_wiring_violations(sources: &[(PathBuf, String)]) -> Vec<String> {
    const FORBIDDEN_OUTSIDE_CLIENT: [&str; 5] = [
        "NSXPCConnection",
        "NSXPCInterface",
        "NSXPCListener",
        "setCodeSigningRequirement",
        REVIEWED_TOKEN_BROKER_PROTOCOL_NAME,
    ];
    let mut violations = Vec::new();
    for (path, document) in sources {
        let extension = path.extension().and_then(|extension| extension.to_str());
        if extension != Some("swift") {
            continue;
        }
        let Some(path_str) = path.to_str() else {
            continue;
        };
        let code = strip_swift_non_code(document);
        // Closed allowlist only — a decoy `TokenBroker*.swift` filename must
        // not inherit the reviewed client XPC exemption.
        if path_str.starts_with("apple/macos/TokenBroker")
            && !REVIEWED_TOKEN_BROKER_CLIENT_SWIFT_PATHS.contains(&path_str)
        {
            violations.push(format!(
                "{path_str} is outside the closed reviewed TokenBroker client allowlist"
            ));
        }
        let is_reviewed_client = REVIEWED_TOKEN_BROKER_CLIENT_SWIFT_PATHS.contains(&path_str);
        if is_reviewed_client {
            // Server-side listener wiring stays out of the main app.
            if contains_identifier(&code, "NSXPCListener")
                || contains_identifier(&code, "setCodeSigningRequirement")
            {
                violations.push(format!(
                    "{path_str} must not host token-broker server-side XPC listener wiring"
                ));
            }
            if contains_identifier(&code, "NSXPCConnection")
                && !reviewed_token_broker_client_xpc_connection_is_pinned(document, &code)
            {
                // String literals are masked in `code`, so a bare
                // `code.contains(bundle id)` check is both a false positive on
                // the reviewed client and a false negative for comment/string
                // decoys. Pin the executable constant assignment plus the exact
                // `NSXPCConnection(serviceName:)` construction instead.
                violations.push(format!(
                    "{path_str} must connect only to the embedded token-broker service bundle id"
                ));
            }
            continue;
        }
        for forbidden in FORBIDDEN_OUTSIDE_CLIENT {
            if contains_identifier(&code, forbidden) {
                violations.push(format!(
                    "{path_str} must not contain client-side XPC wiring `{forbidden}` outside the reviewed TokenBroker client allowlist"
                ));
            }
        }
    }
    violations
}

/// True when executable code pins the embedded broker service bundle id to
/// `static let serviceBundleIdentifier = "app.tersa.mac.token-broker"` and
/// constructs exactly one `NSXPCConnection(serviceName: Self.serviceBundleIdentifier)`.
/// Comment/string decoys, wrong service names, and alternate initializers fail.
fn reviewed_token_broker_client_xpc_connection_is_pinned(document: &str, code: &str) -> bool {
    let swift_string = format!("\"{TERSA_MAC_TOKEN_BROKER_BUNDLE_ID}\"");
    let constant = REVIEWED_TOKEN_BROKER_CLIENT_SERVICE_BUNDLE_CONSTANT;
    let declaration_starts = executable_static_let_assignment_starts(code, constant);
    let has_exact_assignment = declaration_starts.len() == 1
        && exact_token_broker_code_signing_requirement_assignment_at(
            document,
            code,
            declaration_starts[0],
            constant,
            &swift_string,
        );
    if !has_exact_assignment {
        return false;
    }
    // Exactly one executable constructor, and it must be the reviewed form.
    if swift_call_count(code, "NSXPCConnection") != 1 {
        return false;
    }
    let construction = rust_token_canonical(REVIEWED_TOKEN_BROKER_CLIENT_CONNECTION_CONSTRUCTION);
    rust_token_canonical(code).matches(&construction).count() == 1
}

fn token_broker_source_surface_violations(sources: &[(PathBuf, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    let scan = scan_token_broker_source_files(sources, &mut violations);
    collect_token_broker_inventory_violations(&scan.seen, &mut violations);
    collect_token_broker_required_surface_violations(
        &scan.aggregate,
        scan.protocol_file_has_version_assignment,
        &scan.seen,
        &mut violations,
    );
    violations
}

struct TokenBrokerSourceScan {
    seen: BTreeSet<String>,
    aggregate: String,
    protocol_file_has_version_assignment: bool,
}

fn scan_token_broker_source_files(
    sources: &[(PathBuf, String)],
    violations: &mut Vec<String>,
) -> TokenBrokerSourceScan {
    const FORBIDDEN_IDENTIFIERS: [&str; 13] = [
        "processIdentifier",
        "SecItemAdd",
        "SecItemCopyMatching",
        "SecItemUpdate",
        "SecItemDelete",
        "URLSession",
        "URLRequest",
        "_silgen_name",
        "refreshToken",
        "pkceVerifier",
        "codeVerifier",
        "genericRPC",
        "NSXPCListenerEndpoint",
    ];
    const FORBIDDEN_SUBSTRINGS: [&str; 3] = ["import Security", "@_cdecl", "NSXPCConnection("];
    // `tersa_` is allowed only as the reviewed `tersa_token_broker_*` C ABI.
    // Any other `tersa_` prefix (mailbox sync, bridge, generic helpers) fails.
    const FORBIDDEN_PREFIXES: [&str; 1] = ["SecKeychain"];
    const REVIEWED_C_ABI_PREFIX: &str = "tersa_token_broker_";

    let mut seen = BTreeSet::new();
    let mut aggregate = String::new();
    let mut protocol_file_has_version_assignment = false;
    for (path, document) in sources {
        let Some(path_str) = path.to_str() else {
            violations.push(format!(
                "{} is outside the closed TersaMacTokenBroker source allowlist",
                path.display()
            ));
            continue;
        };
        if !TOKEN_BROKER_ALLOWED_SOURCE_PATHS.contains(&path_str) {
            violations.push(format!(
                "{path_str} is outside the closed TersaMacTokenBroker source allowlist"
            ));
            continue;
        }
        seen.insert(path_str.to_owned());
        if path_str == REVIEWED_TOKEN_BROKER_LISTENER_PATH {
            violations.extend(token_broker_code_signing_requirement_violations(document));
        }
        let extension = path.extension().and_then(|extension| extension.to_str());
        if extension != Some("swift") {
            continue;
        }
        let code = strip_swift_non_code(document);
        aggregate.push_str(&code);
        aggregate.push('\n');
        violations.extend(token_broker_type_shadowing_violations(path_str, &code));
        if path_str == REVIEWED_TOKEN_BROKER_PROTOCOL_PATH {
            protocol_file_has_version_assignment =
                has_exact_token_broker_protocol_version_assignment(&code);
            violations.extend(closed_token_broker_protocol_operation_violations(&code));
        }
        collect_token_broker_file_capability_violations(
            path_str,
            &code,
            &FORBIDDEN_IDENTIFIERS,
            &FORBIDDEN_SUBSTRINGS,
            &FORBIDDEN_PREFIXES,
            REVIEWED_C_ABI_PREFIX,
            violations,
        );
    }
    TokenBrokerSourceScan {
        seen,
        aggregate,
        protocol_file_has_version_assignment,
    }
}

fn collect_token_broker_file_capability_violations(
    path_str: &str,
    code: &str,
    forbidden_identifiers: &[&str],
    forbidden_substrings: &[&str],
    forbidden_prefixes: &[&str],
    reviewed_c_abi_prefix: &str,
    violations: &mut Vec<String>,
) {
    for forbidden in forbidden_identifiers {
        if contains_identifier(code, forbidden) {
            violations.push(format!(
                "{path_str} must not exercise forbidden broker capability `{forbidden}`"
            ));
        }
    }
    for forbidden in forbidden_substrings {
        if code.contains(forbidden) {
            violations.push(format!(
                "{path_str} must not exercise forbidden broker capability `{forbidden}`"
            ));
        }
    }
    for forbidden in forbidden_prefixes {
        if contains_identifier_with_prefix(code, forbidden) {
            violations.push(format!(
                "{path_str} must not exercise forbidden broker capability `{forbidden}`"
            ));
        }
    }
    // Allow only the reviewed token-broker C ABI prefix; every other `tersa_`
    // symbol stays out of the XPC service sources.
    if code.match_indices("tersa_").any(|(index, _)| {
        let before = code[..index].bytes().next_back();
        let boundary_ok = before.is_none_or(|byte| !byte.is_ascii_alphanumeric() && byte != b'_');
        boundary_ok && !code[index..].starts_with(reviewed_c_abi_prefix)
    }) {
        violations.push(format!(
            "{path_str} must not exercise forbidden broker capability `tersa_` outside the reviewed token-broker C ABI"
        ));
    }
}

fn collect_token_broker_inventory_violations(
    seen: &BTreeSet<String>,
    violations: &mut Vec<String>,
) {
    for required in TOKEN_BROKER_ALLOWED_SOURCE_PATHS {
        if !seen.contains(required) {
            violations.push(format!(
                "the TersaMacTokenBroker source inventory is missing required path `{required}`"
            ));
        }
    }
}

fn collect_token_broker_required_surface_violations(
    aggregate: &str,
    protocol_file_has_version_assignment: bool,
    seen: &BTreeSet<String>,
    violations: &mut Vec<String>,
) {
    const REQUIRED_PROTOCOL_MARKERS: [&str; 7] = [
        REVIEWED_TOKEN_BROKER_PROTOCOL_NAME,
        REVIEWED_TOKEN_BROKER_PROTOCOL_VERSION_NAME,
        "beginAuthorizationSession",
        "completeAuthorizationSession",
        "refreshAccessToken",
        "revokeProviderGrant",
        "deleteStoredTokens",
    ];
    const REQUIRED_SERVICE_MARKERS: [&str; 7] = [
        "setCodeSigningRequirement",
        "tersa_token_broker_begin_authorization",
        "tersa_token_broker_complete_authorization",
        "tersa_token_broker_refresh_access_token",
        "tersa_token_broker_revoke_provider_grant",
        "tersa_token_broker_delete_stored_tokens",
        "authorizationCodeRejected",
    ];

    for required in REQUIRED_PROTOCOL_MARKERS {
        if !contains_identifier(aggregate, required) {
            violations.push(format!(
                "the TersaMacTokenBroker sources are missing required protocol surface `{required}`"
            ));
        }
    }
    if seen.contains(REVIEWED_TOKEN_BROKER_PROTOCOL_PATH) && !protocol_file_has_version_assignment {
        violations.push(format!(
            "{REVIEWED_TOKEN_BROKER_PROTOCOL_PATH} must declare the exact reviewed protocol version constant `{REVIEWED_TOKEN_BROKER_PROTOCOL_VERSION_ASSIGNMENT}`"
        ));
    }
    for required in REQUIRED_SERVICE_MARKERS {
        if !contains_identifier(aggregate, required) {
            violations.push(format!(
                "the TersaMacTokenBroker sources are missing required operational marker `{required}`"
            ));
        }
    }
    if contains_identifier(aggregate, "processIdentifier") {
        violations.push(
            "the TersaMacTokenBroker sources must not authenticate with processIdentifier"
                .to_owned(),
        );
    }
}

/// Fail closed unless the service protocol file declares exactly the five
/// reviewed operation signatures and hosts no additional `func` declarations
/// outside that protocol body (parameter types `String` and trailing
/// `@escaping (...) -> Void` reply values of `String`, `String?`, or `Int`).
/// Top-level non-Void returns, arrays, Data/NSData/UInt8, aliases, generics,
/// dictionaries, extra methods, and missing methods all fail.
fn closed_token_broker_protocol_operation_violations(code: &str) -> Vec<String> {
    let mut violations = closed_token_broker_protocol_operation_violations_for(
        code,
        REVIEWED_TOKEN_BROKER_PROTOCOL_PATH,
    );
    // The service protocol file is the inventory authority: no helper `func`
    // may appear beside the five closed operations.
    match swift_func_signature_compacts(code) {
        Some(actual) => {
            let expected = REVIEWED_TOKEN_BROKER_PROTOCOL_OPERATION_SIGNATURES
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            let actual_set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
            if actual.len() != REVIEWED_TOKEN_BROKER_PROTOCOL_OPERATION_SIGNATURES.len()
                || actual_set != expected
            {
                violations.push(format!(
                    "{REVIEWED_TOKEN_BROKER_PROTOCOL_PATH} must expose only the exact reviewed closed broker protocol operations"
                ));
            }
        }
        None => violations.push(format!(
            "{REVIEWED_TOKEN_BROKER_PROTOCOL_PATH} must expose only parseable closed broker protocol operations"
        )),
    }
    violations
}

/// Same closed five-operation pin as
/// [`closed_token_broker_protocol_operation_violations`], with a path-specific
/// violation context (service declaration or main-app client mirror).
fn closed_token_broker_protocol_operation_violations_for(
    code: &str,
    context_path: &str,
) -> Vec<String> {
    // Mask comments/strings so inter-method doc comments cannot be read as
    // unexpected trailing tokens after a parameter list, while decoy `func`
    // text inside comments still cannot satisfy the closed allowlist.
    let code = strip_swift_non_code(code);
    let Some(protocol_body) = reviewed_token_broker_protocol_body(&code) else {
        return vec![format!(
            "{context_path} must declare the exact reviewed closed broker protocol body"
        )];
    };
    let Some(actual) = swift_func_signature_compacts(protocol_body) else {
        return vec![format!(
            "{context_path} must expose only parseable closed broker protocol operations"
        )];
    };
    let expected = REVIEWED_TOKEN_BROKER_PROTOCOL_OPERATION_SIGNATURES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let actual_set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if actual.len() != REVIEWED_TOKEN_BROKER_PROTOCOL_OPERATION_SIGNATURES.len()
        || actual_set != expected
    {
        return vec![format!(
            "{context_path} must expose only the exact reviewed closed broker protocol operations"
        )];
    }
    Vec::new()
}

/// Body of the reviewed `@objc(TersaMacTokenBrokerProtocolV1) protocol
/// TersaMacTokenBrokerProtocolV1 { ... }` declaration, if present exactly once
/// with a balanced brace body and no inheritance/`where` drift.
fn reviewed_token_broker_protocol_body(code: &str) -> Option<&str> {
    let mut body: Option<&str> = None;
    for (start, _) in code.match_indices("protocol") {
        if !is_identifier_at(code, start, "protocol") {
            continue;
        }
        // Either reviewed path satisfies the path gate; form matching is what
        // selects the closed v1 declaration inside a document.
        if !is_exact_reviewed_token_broker_protocol_declaration(
            Path::new(REVIEWED_TOKEN_BROKER_PROTOCOL_PATH),
            code,
            start,
        ) {
            continue;
        }
        let name_start = skip_ascii_whitespace(code, start + "protocol".len());
        let after_name =
            skip_ascii_whitespace(code, name_start + REVIEWED_TOKEN_BROKER_PROTOCOL_NAME.len());
        if code.as_bytes().get(after_name) != Some(&b'{') {
            return None;
        }
        if body.is_some() {
            return None;
        }
        body = Some(balanced_brace_body(code, after_name)?);
    }
    body
}

/// Pins service and client v1 protocol/status declarations to the same closed
/// five operations and the same integer status set.
fn token_broker_protocol_mirror_violations(service: &str, client: &str) -> Vec<String> {
    let mut violations = Vec::new();
    violations.extend(closed_token_broker_protocol_operation_violations_for(
        service,
        REVIEWED_TOKEN_BROKER_PROTOCOL_PATH,
    ));
    violations.extend(closed_token_broker_protocol_operation_violations_for(
        client,
        REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH,
    ));

    let service_status = swift_closed_int_enum_cases(service, "TersaTokenBrokerStatusV1");
    let client_status = swift_closed_int_enum_cases(client, "TokenBrokerStatus");
    match (service_status, client_status) {
        (Some(service_cases), Some(client_cases)) => {
            if service_cases != client_cases {
                violations.push(
                    "service TersaTokenBrokerStatusV1 and client TokenBrokerStatus must declare the exact same closed raw-value case set"
                        .to_owned(),
                );
            }
            if service_cases.len() != 20 {
                violations.push(
                    "token-broker status enums must declare exactly the 20 reviewed closed cases"
                        .to_owned(),
                );
            }
        }
        (None, _) => violations.push(
            "apple/macos-token-broker/TokenBrokerProtocol.swift must declare closed enum TersaTokenBrokerStatusV1"
                .to_owned(),
        ),
        (_, None) => violations.push(
            "apple/macos/TokenBrokerProtocol.swift must declare closed enum TokenBrokerStatus"
                .to_owned(),
        ),
    }
    violations
}

/// Parses `case name = <int>` members from a Swift enum with the given name.
/// Inheritance, generics, `where` clauses, and unparsable bodies fail closed.
fn swift_closed_int_enum_cases(code: &str, enum_name: &str) -> Option<BTreeMap<String, i64>> {
    let mut enum_body: Option<&str> = None;
    for (start, _) in code.match_indices("enum") {
        if !is_identifier_at(code, start, "enum") {
            continue;
        }
        let name_start = skip_ascii_whitespace(code, start + "enum".len());
        if !code[name_start..].starts_with(enum_name)
            || !is_identifier_at(code, name_start, enum_name)
        {
            continue;
        }
        let after_name = skip_ascii_whitespace(code, name_start + enum_name.len());
        // Allow a single inheritance clause such as `: Int` / `: Int, Equatable`.
        let brace = if code.as_bytes().get(after_name) == Some(&b'{') {
            after_name
        } else if code.as_bytes().get(after_name) == Some(&b':') {
            let mut index = after_name + 1;
            while index < code.len() {
                let byte = code.as_bytes()[index];
                if byte == b'{' {
                    break;
                }
                if byte == b'<' || byte == b'(' {
                    return None;
                }
                index += 1;
            }
            if index >= code.len() || code.as_bytes()[index] != b'{' {
                return None;
            }
            index
        } else {
            return None;
        };
        if enum_body.is_some() {
            return None;
        }
        enum_body = Some(balanced_brace_body(code, brace)?);
    }
    let body = enum_body?;
    let mut cases = BTreeMap::new();
    let mut search_from = 0;
    while let Some(relative) = body[search_from..].find("case") {
        let start = search_from + relative;
        if !is_identifier_at(body, start, "case") {
            search_from = start + "case".len();
            continue;
        }
        let name_start = skip_ascii_whitespace(body, start + "case".len());
        let name_length = body[name_start..]
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if name_length == 0 {
            return None;
        }
        let name = body[name_start..name_start + name_length].to_owned();
        let after_name = skip_ascii_whitespace(body, name_start + name_length);
        if body.as_bytes().get(after_name) != Some(&b'=') {
            return None;
        }
        let value_start = skip_ascii_whitespace(body, after_name + 1);
        let value_length = body[value_start..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if value_length == 0 {
            return None;
        }
        let value: i64 = body[value_start..value_start + value_length].parse().ok()?;
        if cases.insert(name, value).is_some() {
            return None;
        }
        search_from = value_start + value_length;
    }
    if cases.is_empty() {
        return None;
    }
    Some(cases)
}

/// Compact every `func` signature in `code` by stripping ASCII whitespace.
/// Effect specifiers (`async`, `reasync`, `throws`, `rethrows`, typed throws)
/// and top-level return types are consumed into the compact form so they cannot
/// silently match the closed allowlist. Once an identifier-boundary `func`
/// keyword is found, a nonempty plain ASCII identifier and an immediately
/// following `(` are required; backtick-escaped names, operators, unicode,
/// missing parameter lists, unbalanced parameter lists, and unexpected
/// trailing tokens all fail closed with `None`. Non-keyword substring matches
/// of `func` still continue.
fn swift_func_signature_compacts(code: &str) -> Option<Vec<String>> {
    let mut signatures = Vec::new();
    let mut search_from = 0;
    while let Some(relative) = code[search_from..].find("func") {
        let start = search_from + relative;
        if !is_identifier_at(code, start, "func") {
            search_from = start + "func".len();
            continue;
        }
        let name_start = skip_ascii_whitespace(code, start + "func".len());
        let name_length = code[name_start..]
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        // Fail closed on backtick-escaped, operator, unicode, or missing names
        // so a sixth declaration cannot be skipped out of the closed set.
        if name_length == 0 {
            return None;
        }
        let after_name = skip_ascii_whitespace(code, name_start + name_length);
        // `(` must be the next meaningful token; generics and other gaps fail.
        if code.as_bytes().get(after_name) != Some(&b'(') {
            return None;
        }
        let paren = after_name;
        // `balanced_delimited_body` returns the full span including both the
        // opening `(` and the matching closing `)` (nested parameter types such
        // as `@escaping (...) -> Void` are depth-tracked). Advance to the index
        // one past that inclusive span so the closing `)` is not re-read as an
        // unexpected trailing token.
        let parameters = balanced_delimited_body(code, paren, b'(', b')')?;
        let after_params = paren.checked_add(parameters.len())?;
        let end = consume_swift_func_signature_tail(code, after_params)?;
        signatures.push(rust_token_canonical(&code[start..end]));
        search_from = end;
    }
    Some(signatures)
}

/// Consume effect specifiers and an optional top-level return type after a
/// parameter list. Returns the end index of the signature, or `None` when an
/// unexpected non-whitespace token remains before the next declaration boundary.
fn consume_swift_func_signature_tail(code: &str, after_params: usize) -> Option<usize> {
    let mut end = after_params;
    let mut index = skip_ascii_whitespace(code, after_params);
    while let Some(effect_end) = consume_swift_effect_specifier_end(code, index) {
        end = effect_end;
        index = skip_ascii_whitespace(code, effect_end);
    }
    if code[index..].starts_with("->") {
        end = consume_swift_type_end(code, index + "->".len());
        index = skip_ascii_whitespace(code, end);
    }
    if index < code.len() && !is_swift_func_signature_boundary(code, index) {
        return None;
    }
    Some(end)
}

/// Advance past one Swift effect specifier (`async`, `reasync`, `throws`,
/// `rethrows`, or typed `throws(...)`) starting at `index`.
fn consume_swift_effect_specifier_end(code: &str, index: usize) -> Option<usize> {
    // Longer keywords first so `rethrows`/`reasync` are not split.
    for keyword in ["rethrows", "reasync", "throws", "async"] {
        if !code[index..].starts_with(keyword) || !is_identifier_at(code, index, keyword) {
            continue;
        }
        let mut end = index + keyword.len();
        if keyword == "throws" {
            let after = skip_ascii_whitespace(code, end);
            if code.as_bytes().get(after) == Some(&b'(') {
                let body = balanced_delimited_body(code, after, b'(', b')')?;
                end = after + body.len();
            }
        }
        return Some(end);
    }
    None
}

/// True when `index` begins a construct that ends a function signature rather
/// than an unexpected trailing token on that signature.
fn is_swift_func_signature_boundary(code: &str, index: usize) -> bool {
    if index >= code.len() {
        return true;
    }
    match code.as_bytes()[index] {
        b'{' | b'}' | b'@' | b';' => true,
        _ => {
            for keyword in [
                "func",
                "var",
                "let",
                "init",
                "deinit",
                "subscript",
                "enum",
                "struct",
                "class",
                "actor",
                "protocol",
                "typealias",
                "associatedtype",
                "case",
                "static",
                "private",
                "fileprivate",
                "internal",
                "public",
                "open",
                "final",
                "override",
                "required",
                "convenience",
                "mutating",
                "nonmutating",
                "weak",
                "unowned",
                "lazy",
                "optional",
                "dynamic",
                "indirect",
                "isolated",
                "nonisolated",
            ] {
                if code[index..].starts_with(keyword) && is_identifier_at(code, index, keyword) {
                    return true;
                }
            }
            false
        }
    }
}

/// Advance past a simple Swift type expression used as a top-level return type.
fn consume_swift_type_end(code: &str, mut index: usize) -> usize {
    index = skip_ascii_whitespace(code, index);
    let bytes = code.as_bytes();
    while index < bytes.len() {
        match bytes[index] {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'?' | b'!' => {
                index += 1;
            }
            b'[' => {
                let Some(body) = balanced_delimited_body(code, index, b'[', b']') else {
                    return index;
                };
                index += body.len();
            }
            b'(' => {
                let Some(body) = balanced_delimited_body(code, index, b'(', b')') else {
                    return index;
                };
                index += body.len();
            }
            b'<' => {
                let Some(body) = balanced_delimited_body(code, index, b'<', b'>') else {
                    return index;
                };
                index += body.len();
            }
            _ => break,
        }
    }
    index
}

/// Fail closed unless inventoried broker Swift has no executable `typealias`
/// and does not declare a local type that shadows a reviewed primitive wire
/// type (`String`, `Int`, or `Void`). The closed protocol allowlist matches
/// those names textually; a module-scope alias or type with the same name
/// would otherwise rebind every wire value (for example `String`/`Int` to
/// `Data`, or `Void` to a non-empty payload) while leaving the signature
/// guard unchanged. Plain and well-formed backtick-escaped declaration names
/// are compared on their unescaped spelling (a backtick-escaped `String`
/// declaration rebinds unqualified `String`). Comments and string literals are
/// already masked by the caller.
fn token_broker_type_shadowing_violations(path: &str, code: &str) -> Vec<String> {
    // Reviewed primitive wire types that appear in closed XPC signatures and
    // the pinned protocol version (`static let value: Int = 1`).
    const REVIEWED_PRIMITIVE_WIRE_TYPES: &[&str] = &["String", "Int", "Void"];
    let mut violations = Vec::new();
    if contains_identifier(code, "typealias") {
        violations.push(format!(
            "{path} must not declare `typealias` in inventoried token-broker sources"
        ));
    }
    for keyword in ["struct", "class", "enum", "actor", "protocol"] {
        for (start, _) in code.match_indices(keyword) {
            if !is_identifier_at(code, start, keyword) {
                continue;
            }
            let name_start = skip_ascii_whitespace(code, start + keyword.len());
            let Some(name) = swift_type_declaration_name_at(code, name_start) else {
                continue;
            };
            if let Some(primitive) = REVIEWED_PRIMITIVE_WIRE_TYPES
                .iter()
                .copied()
                .find(|primitive| *primitive == name)
            {
                violations.push(format!(
                    "{path} must not shadow `{primitive}` with a local type declaration in inventoried token-broker sources"
                ));
                break;
            }
        }
    }
    violations
}

/// Type name immediately after a type-introducing keyword. Accepts a plain
/// ASCII identifier or a well-formed backtick-escaped ASCII identifier and
/// returns the unescaped spelling so `` `String` `` compares equal to `String`.
fn swift_type_declaration_name_at(code: &str, name_start: usize) -> Option<&str> {
    let bytes = code.as_bytes();
    if bytes.get(name_start) == Some(&b'`') {
        let inner_start = name_start + 1;
        let name_length = code[inner_start..]
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if name_length == 0 {
            return None;
        }
        let closing = inner_start + name_length;
        if bytes.get(closing) != Some(&b'`') {
            return None;
        }
        return Some(&code[inner_start..closing]);
    }
    let name_length = code[name_start..]
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if name_length == 0 {
        return None;
    }
    Some(&code[name_start..name_start + name_length])
}

/// Pin the reviewed requirement literal via the single executable
/// `static let <constant> =` declaration (comment/string-stripped offsets map
/// back into the original document). String/comment decoys and weakened
/// executable values therefore cannot satisfy the pin. Also pin the exact
/// `newConnection.setCodeSigningRequirement(Self.<constant>)` call on
/// executable code so documentation mentions cannot satisfy or inflate the
/// call count.
fn token_broker_code_signing_requirement_violations(document: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let path = REVIEWED_TOKEN_BROKER_LISTENER_PATH;
    let constant = REVIEWED_TOKEN_BROKER_CODE_SIGNING_REQUIREMENT_CONSTANT;
    let swift_string = format!(
        "\"{}\"",
        REVIEWED_TOKEN_BROKER_CODE_SIGNING_REQUIREMENT_LITERAL.replace('\"', "\\\"")
    );
    // Comments and strings masked; offsets match the original document.
    let code = strip_swift_non_code(document);
    let declaration_starts = executable_static_let_assignment_starts(&code, constant);
    let has_exact_assignment = declaration_starts.len() == 1
        && exact_token_broker_code_signing_requirement_assignment_at(
            document,
            &code,
            declaration_starts[0],
            constant,
            &swift_string,
        );
    if !has_exact_assignment {
        violations.push(format!(
            "{path} must assign the reviewed code-signing requirement literal to `{constant}`"
        ));
    }
    if identifier_occurrence_count(&code, "setCodeSigningRequirement") != 1 {
        violations.push(format!(
            "{path} must call setCodeSigningRequirement exactly once"
        ));
    }
    let call_compact = rust_token_canonical(REVIEWED_TOKEN_BROKER_CODE_SIGNING_REQUIREMENT_CALL);
    let compact_code = rust_token_canonical(&code);
    if compact_code.matches(&call_compact).count() != 1 {
        violations.push(format!(
            "{path} must apply the reviewed code-signing requirement via the exact reviewed call"
        ));
    }
    violations
}

/// Offsets of every executable `static let <constant> =` declaration prefix in
/// comment/string-stripped Swift. Alternate type annotations, computed forms,
/// and non-`static let` bindings are not matched.
fn executable_static_let_assignment_starts(code: &str, constant: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    for (start, _) in code.match_indices("static") {
        if !is_identifier_at(code, start, "static") {
            continue;
        }
        let after_static = skip_ascii_whitespace(code, start + "static".len());
        if !code[after_static..].starts_with("let") || !is_identifier_at(code, after_static, "let")
        {
            continue;
        }
        let after_let = skip_ascii_whitespace(code, after_static + "let".len());
        if !code[after_let..].starts_with(constant) || !is_identifier_at(code, after_let, constant)
        {
            continue;
        }
        let after_constant = skip_ascii_whitespace(code, after_let + constant.len());
        if code.as_bytes().get(after_constant) != Some(&b'=') {
            continue;
        }
        // Reject `==` / `=>` so only a true assignment operator matches.
        if matches!(code.as_bytes().get(after_constant + 1), Some(b'=' | b'>')) {
            continue;
        }
        starts.push(start);
    }
    starts
}

/// True when `document[start..]` is exactly
/// `static let <constant> = <swift_string>` with ASCII whitespace flexibility
/// and a boundary-terminated expression. Termination is checked against
/// `code` (comment/string-masked, byte-offset-preserving) so optional trailing
/// comments remain whitespace while next-line operators, concatenation, calls,
/// members, second literals, and other expression continuations fail closed.
fn exact_token_broker_code_signing_requirement_assignment_at(
    document: &str,
    code: &str,
    start: usize,
    constant: &str,
    swift_string: &str,
) -> bool {
    if start > document.len() || !document[start..].starts_with("static") {
        return false;
    }
    if !is_identifier_at(document, start, "static") {
        return false;
    }
    let after_static = skip_ascii_whitespace(document, start + "static".len());
    if !document[after_static..].starts_with("let")
        || !is_identifier_at(document, after_static, "let")
    {
        return false;
    }
    let after_let = skip_ascii_whitespace(document, after_static + "let".len());
    if !document[after_let..].starts_with(constant)
        || !is_identifier_at(document, after_let, constant)
    {
        return false;
    }
    let after_constant = skip_ascii_whitespace(document, after_let + constant.len());
    if document.as_bytes().get(after_constant) != Some(&b'=') {
        return false;
    }
    if matches!(
        document.as_bytes().get(after_constant + 1),
        Some(b'=' | b'>')
    ) {
        return false;
    }
    let after_equals = skip_ascii_whitespace(document, after_constant + 1);
    if !document[after_equals..].starts_with(swift_string) {
        return false;
    }
    // Masked offsets match the original; next executable token must be a
    // declaration boundary (reviewed file: `func listener(...)`).
    if code.len() != document.len() {
        return false;
    }
    swift_expression_terminates_before_boundary(
        code,
        after_equals + swift_string.len(),
        is_swift_func_signature_boundary,
    )
}

fn validate_tersa_mac_top_level_keys(
    target: &BTreeMap<String, StrictYamlValue>,
    violations: &mut Vec<String>,
) {
    let expected_keys = BTreeSet::from([
        "dependencies",
        "entitlements",
        "info",
        "platform",
        "preBuildScripts",
        "scheme",
        "settings",
        "sources",
        "type",
    ]);
    let actual_keys = target.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        violations.push(
            "the TersaMac target must contain only the exact reviewed top-level XcodeGen keys"
                .to_owned(),
        );
    }
}

fn effective_signing_configuration_violations(
    root: &StrictYamlValue,
    targets: &[ProjectTarget],
) -> Vec<String> {
    let mut violations = Vec::new();
    let Ok(root_mapping) = yaml_mapping(root, "project root") else {
        return vec!["apple/project.yml root must be a mapping".to_owned()];
    };
    validate_project_root_surface(root_mapping, &mut violations);

    for target in targets {
        let Ok(body) = yaml_mapping(&target.body, &format!("target `{}`", target.name)) else {
            continue;
        };
        for key in ["templates", "configFiles"] {
            if body.contains_key(key) {
                violations.push(format!(
                    "target `{}` unsupported signing indirection `{key}` is forbidden",
                    target.name
                ));
            }
        }
        inspect_settings_indirection(
            body.get("settings"),
            &format!("target `{}` settings", target.name),
            &mut violations,
        );
        if let Some(entitlements) = body.get("entitlements") {
            match yaml_mapping(
                entitlements,
                &format!("target `{}` entitlements", target.name),
            ) {
                Ok(entitlements) => {
                    if let Some(path) = entitlements.get("path") {
                        match yaml_string(
                            path,
                            &format!("target `{}` entitlement path", target.name),
                        ) {
                            Ok(path)
                                if !path.contains('$')
                                    && allowed_target_entitlement_path(&target.name, path) => {}
                            _ => violations.push(format!(
                                "target `{}` entitlement path is outside the exact allowlist",
                                target.name
                            )),
                        }
                    }
                }
                Err(error) => violations.push(error),
            }
        }
    }

    let mut sensitive = Vec::new();
    collect_sensitive_configuration(root, &mut Vec::new(), &mut sensitive);
    for (path, value) in sensitive {
        if !allowed_sensitive_configuration(&path, value) {
            violations.push(format!(
                "apple/project.yml sensitive signing configuration `{}` is outside the exact allowlist",
                path.join(".")
            ));
        }
    }

    let mut protected_values = Vec::new();
    collect_protected_values(root, &mut Vec::new(), &mut protected_values);
    for path in protected_values {
        if !allowed_protected_value_path(&path) {
            violations.push(format!(
                "apple/project.yml protected signing value is reused at `{}`",
                path.join(".")
            ));
        }
    }
    violations
}

fn validate_project_root_surface(
    root_mapping: &BTreeMap<String, StrictYamlValue>,
    violations: &mut Vec<String>,
) {
    let expected_root_keys = BTreeSet::from(["name", "options", "settings", "targets"]);
    let actual_root_keys = root_mapping
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_root_keys != expected_root_keys {
        violations.push(
            "apple/project.yml must contain only the exact reviewed project-root XcodeGen keys"
                .to_owned(),
        );
    }
    validate_project_options(root_mapping.get("options"), violations);
    for key in [
        "include",
        "includes",
        "targetTemplates",
        "settingGroups",
        "configFiles",
        "configs",
        "preGenCommand",
        "postGenCommand",
        "schemes",
    ] {
        if root_mapping.contains_key(key) {
            violations.push(format!(
                "apple/project.yml unsupported signing indirection `{key}` is forbidden"
            ));
        }
    }
    inspect_settings_indirection(
        root_mapping.get("settings"),
        "project-wide settings",
        violations,
    );
}

fn allowed_target_entitlement_path(target: &str, path: &str) -> bool {
    matches!(
        (target, path),
        ("TersaMac", TERSA_MAC_ENTITLEMENTS)
            | ("TersaMacTokenBroker", TERSA_MAC_TOKEN_BROKER_ENTITLEMENTS)
            | ("TersaIOS", "ios/TersaIOS.entitlements")
            | ("TersaMimeMac", "mime-macos/TersaMimeMac.entitlements")
    )
}

fn inspect_settings_indirection(
    settings: Option<&StrictYamlValue>,
    context: &str,
    violations: &mut Vec<String>,
) {
    let Some(settings) = settings else {
        return;
    };
    let Ok(settings) = yaml_mapping(settings, context) else {
        violations.push(format!("{context} must be a direct mapping"));
        return;
    };
    for key in ["configs", "groups"] {
        if settings.contains_key(key) {
            violations.push(format!(
                "{context} unsupported signing indirection `{key}` is forbidden"
            ));
        }
    }
}

fn collect_sensitive_configuration<'a>(
    value: &'a StrictYamlValue,
    path: &mut Vec<String>,
    output: &mut Vec<(Vec<String>, &'a StrictYamlValue)>,
) {
    match value {
        StrictYamlValue::Sequence(values) => {
            for (index, value) in values.iter().enumerate() {
                path.push(format!("[{index}]"));
                collect_sensitive_configuration(value, path, output);
                path.pop();
            }
        }
        StrictYamlValue::Mapping(mapping) => {
            for (key, value) in mapping {
                path.push(key.clone());
                if is_sensitive_signing_key(key) {
                    output.push((path.clone(), value));
                }
                collect_sensitive_configuration(value, path, output);
                path.pop();
            }
        }
        StrictYamlValue::Null
        | StrictYamlValue::Bool(_)
        | StrictYamlValue::OtherScalar
        | StrictYamlValue::String(_) => {}
    }
}

fn is_sensitive_signing_key(key: &str) -> bool {
    key.contains("CODE_SIGN")
        || key.contains("DEVELOPMENT_TEAM")
        || key.contains("PROVISIONING_PROFILE")
        || key == "DevelopmentTeam"
        || key.starts_with("DevelopmentTeam[")
        || key == "ProvisioningStyle"
        || key.starts_with("ProvisioningStyle[")
        || key == "TeamIdentifierPrefix"
        || key.starts_with("TeamIdentifierPrefix[")
        || key == "AppIdentifierPrefix"
        || key.starts_with("AppIdentifierPrefix[")
        || key.contains("ENTITLEMENT")
        || [
            "TERSA_MACOS_APP_GROUP",
            "TERSA_MACOS_TOKEN_GROUP",
            "com.apple.security.application-groups",
            "keychain-access-groups",
        ]
        .iter()
        .any(|sensitive| key == *sensitive || key.starts_with(&format!("{sensitive}[")))
}

fn allowed_sensitive_configuration(path: &[String], value: &StrictYamlValue) -> bool {
    let components = path.iter().map(String::as_str).collect::<Vec<_>>();
    match components.as_slice() {
        ["settings", "base", key] => allowed_root_sensitive_base_setting(key, value),
        ["targets", "TersaMac", rest @ ..] => {
            allowed_tersa_mac_sensitive_configuration(rest, value)
        }
        ["targets", "TersaMacTokenBroker", rest @ ..] => {
            allowed_token_broker_sensitive_configuration(rest, value)
        }
        [
            "targets",
            "TersaIOS",
            "settings",
            "base",
            "CODE_SIGN_ENTITLEMENTS",
        ] => {
            matches!(value, StrictYamlValue::String(value) if value == "ios/TersaIOS.entitlements")
        }
        [
            "targets",
            "TersaMimeMac",
            "settings",
            "base",
            "CODE_SIGN_ENTITLEMENTS",
        ] => {
            matches!(value, StrictYamlValue::String(value) if value == "mime-macos/TersaMimeMac.entitlements")
        }
        ["targets", "TersaDioxusIOS", "settings", "base", key] => {
            allowed_tersa_dioxus_ios_sensitive_base_setting(key, value)
        }
        _ => false,
    }
}

fn allowed_root_sensitive_base_setting(key: &str, value: &StrictYamlValue) -> bool {
    match key {
        "CODE_SIGNING_ALLOWED"
        | "CODE_SIGNING_REQUIRED"
        | "TERSA_DIOXUS_CODE_SIGNING_ALLOWED"
        | "TERSA_DIOXUS_CODE_SIGNING_REQUIRED" => {
            matches!(value, StrictYamlValue::String(value) if value == "NO")
        }
        "DEVELOPMENT_TEAM"
        | "TERSA_DIOXUS_DEVELOPMENT_TEAM"
        | "TERSA_DIOXUS_CODE_SIGN_IDENTITY"
        | "TERSA_DIOXUS_PROVISIONING_PROFILE_SPECIFIER" => {
            matches!(value, StrictYamlValue::String(value) if value.is_empty())
        }
        "TERSA_DIOXUS_CODE_SIGN_STYLE" => {
            matches!(value, StrictYamlValue::String(value) if value == "Automatic")
        }
        _ => false,
    }
}

fn allowed_tersa_mac_sensitive_configuration(path: &[&str], value: &StrictYamlValue) -> bool {
    match path {
        ["settings", "base", "TERSA_MACOS_APP_GROUP"] => {
            matches!(value, StrictYamlValue::String(value) if value == BUILD_SETTING_GROUP)
        }
        ["settings", "base", "CODE_SIGN_ENTITLEMENTS"] => {
            matches!(value, StrictYamlValue::String(value) if value == TERSA_MAC_ENTITLEMENTS)
        }
        ["entitlements", "properties", key]
            if *key == "com.apple.security.application-groups"
                || *key == "keychain-access-groups" =>
        {
            yaml_exact_string_array(Some(value), SIGNING_GROUP)
        }
        _ => false,
    }
}

fn allowed_token_broker_sensitive_configuration(path: &[&str], value: &StrictYamlValue) -> bool {
    match path {
        ["settings", "base", "CODE_SIGN_ENTITLEMENTS"] => {
            matches!(
                value,
                StrictYamlValue::String(value) if value == TERSA_MAC_TOKEN_BROKER_ENTITLEMENTS
            )
        }
        ["settings", "base", "TERSA_MACOS_TOKEN_GROUP"] => {
            matches!(value, StrictYamlValue::String(value) if value == TOKEN_BUILD_SETTING_GROUP)
        }
        ["entitlements", "properties", "keychain-access-groups"] => {
            yaml_exact_string_array(Some(value), TOKEN_SIGNING_GROUP)
        }
        _ => false,
    }
}

fn allowed_tersa_dioxus_ios_sensitive_base_setting(key: &str, value: &StrictYamlValue) -> bool {
    match key {
        "CODE_SIGNING_ALLOWED" => {
            matches!(value, StrictYamlValue::String(value) if value == "$(TERSA_DIOXUS_CODE_SIGNING_ALLOWED)")
        }
        "CODE_SIGNING_REQUIRED" => {
            matches!(value, StrictYamlValue::String(value) if value == "$(TERSA_DIOXUS_CODE_SIGNING_REQUIRED)")
        }
        "DEVELOPMENT_TEAM" => {
            matches!(value, StrictYamlValue::String(value) if value == "$(TERSA_DIOXUS_DEVELOPMENT_TEAM)")
        }
        "CODE_SIGN_STYLE" => {
            matches!(value, StrictYamlValue::String(value) if value == "$(TERSA_DIOXUS_CODE_SIGN_STYLE)")
        }
        "CODE_SIGN_IDENTITY" => {
            matches!(value, StrictYamlValue::String(value) if value == "$(TERSA_DIOXUS_CODE_SIGN_IDENTITY)")
        }
        "PROVISIONING_PROFILE_SPECIFIER" => {
            matches!(value, StrictYamlValue::String(value) if value == "$(TERSA_DIOXUS_PROVISIONING_PROFILE_SPECIFIER)")
        }
        _ => false,
    }
}

fn collect_protected_values(
    value: &StrictYamlValue,
    path: &mut Vec<String>,
    output: &mut Vec<Vec<String>>,
) {
    match value {
        StrictYamlValue::String(value)
            if value == TERSA_MAC_ENTITLEMENTS
                || value == TERSA_MAC_TOKEN_BROKER_ENTITLEMENTS
                || value.contains("${TeamIdentifierPrefix}")
                || value.contains("$(TeamIdentifierPrefix)")
                || value.contains("${AppIdentifierPrefix}")
                || value.contains("$(AppIdentifierPrefix)") =>
        {
            output.push(path.clone());
        }
        StrictYamlValue::Sequence(values) => {
            for (index, value) in values.iter().enumerate() {
                path.push(format!("[{index}]"));
                collect_protected_values(value, path, output);
                path.pop();
            }
        }
        StrictYamlValue::Mapping(mapping) => {
            for (key, value) in mapping {
                path.push(key.clone());
                collect_protected_values(value, path, output);
                path.pop();
            }
        }
        StrictYamlValue::Null
        | StrictYamlValue::Bool(_)
        | StrictYamlValue::OtherScalar
        | StrictYamlValue::String(_) => {}
    }
}

fn allowed_protected_value_path(path: &[String]) -> bool {
    let components = path.iter().map(String::as_str).collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        [
            "targets",
            "TersaMac" | "TersaMacTokenBroker",
            "entitlements",
            "path"
        ] | [
            "targets",
            "TersaMac",
            "settings",
            "base",
            "CODE_SIGN_ENTITLEMENTS" | "TERSA_MACOS_APP_GROUP"
        ] | [
            "targets",
            "TersaMac",
            "entitlements",
            "properties",
            "com.apple.security.application-groups" | "keychain-access-groups",
            "[0]"
        ] | [
            "targets",
            "TersaMacTokenBroker",
            "settings",
            "base",
            "CODE_SIGN_ENTITLEMENTS" | "TERSA_MACOS_TOKEN_GROUP"
        ] | [
            "targets",
            "TersaMacTokenBroker",
            "entitlements",
            "properties",
            "keychain-access-groups",
            "[0]"
        ]
    )
}

fn parse_plist_string_array(document: &str, key: &str) -> Result<Vec<String>, String> {
    let root: StrictYamlValue = plist::from_bytes(document.as_bytes())
        .map_err(|error| format!("plist parse failed: {error}"))?;
    let root = yaml_mapping(&root, "plist root")?;
    let value = root
        .get(key)
        .ok_or_else(|| "missing top-level key".to_owned())?;
    let StrictYamlValue::Sequence(array) = value else {
        return Err("top-level value is not an array".to_owned());
    };
    array
        .iter()
        .map(|value| {
            let StrictYamlValue::String(value) = value else {
                return Err("array contains a non-string member".to_owned());
            };
            Ok(value.clone())
        })
        .collect()
}

#[cfg(test)]
fn parse_project_targets(document: &str) -> Result<Vec<ProjectTarget>, String> {
    let root = parse_project_root(document)?;
    project_targets(&root)
}

fn parse_project_root(document: &str) -> Result<StrictYamlValue, String> {
    yaml_serde::from_str(document).map_err(|error| format!("YAML parse failed: {error}"))
}

fn project_targets(root: &StrictYamlValue) -> Result<Vec<ProjectTarget>, String> {
    let root = yaml_mapping(root, "project root")?;
    let targets = root
        .get("targets")
        .ok_or_else(|| "missing top-level targets mapping".to_owned())?;
    let targets = yaml_mapping(targets, "top-level targets")?;
    if targets.is_empty() {
        return Err("targets mapping is empty".to_owned());
    }
    targets
        .iter()
        .map(|(name, body)| {
            let body_mapping = yaml_mapping(body, &format!("target `{name}`"))?;
            let platform = yaml_string(
                body_mapping
                    .get("platform")
                    .ok_or_else(|| format!("target `{name}` is missing a declared platform"))?,
                &format!("target `{name}` platform"),
            )?;
            Ok(ProjectTarget {
                name: name.clone(),
                platform: platform.to_owned(),
                body: body.clone(),
            })
        })
        .collect()
}

fn yaml_mapping<'a>(
    value: &'a StrictYamlValue,
    context: &str,
) -> Result<&'a BTreeMap<String, StrictYamlValue>, String> {
    match value {
        StrictYamlValue::Mapping(mapping) => Ok(mapping),
        _ => Err(format!("{context} is not a mapping")),
    }
}

fn yaml_string<'a>(value: &'a StrictYamlValue, context: &str) -> Result<&'a str, String> {
    match value {
        StrictYamlValue::String(value) => Ok(value),
        _ => Err(format!("{context} is not a string")),
    }
}

fn yaml_path<'a>(value: &'a StrictYamlValue, path: &[&str]) -> Option<&'a StrictYamlValue> {
    path.iter().try_fold(value, |current, component| {
        let StrictYamlValue::Mapping(mapping) = current else {
            return None;
        };
        mapping.get(*component)
    })
}

fn yaml_exact_string_array(value: Option<&StrictYamlValue>, expected: &str) -> bool {
    matches!(
        value,
        Some(StrictYamlValue::Sequence(values))
            if matches!(values.as_slice(), [StrictYamlValue::String(value)] if value == expected)
    )
}

fn yaml_contains_key(value: &StrictYamlValue, key: &str) -> bool {
    match value {
        StrictYamlValue::Sequence(values) => {
            values.iter().any(|value| yaml_contains_key(value, key))
        }
        StrictYamlValue::Mapping(mapping) => {
            mapping.contains_key(key) || mapping.values().any(|value| yaml_contains_key(value, key))
        }
        StrictYamlValue::Null
        | StrictYamlValue::Bool(_)
        | StrictYamlValue::OtherScalar
        | StrictYamlValue::String(_) => false,
    }
}

fn check_gmail_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    violations.extend(gmail_manifest_dependency_violations(
        package_name,
        &dependency.name,
        &dependency.req.to_string(),
        dependency
            .target
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        dependency.uses_default_features,
        &dependency.features,
    ));
}

fn gmail_manifest_dependency_violations(
    package_name: &str,
    dependency_name: &str,
    requirement: &str,
    target: Option<&str>,
    uses_default_features: bool,
    features: &[String],
) -> Vec<String> {
    const OWNER: &str = "tersa-gmail-rest-macos";
    if dependency_name != "reqwest" {
        return Vec::new();
    }
    let mut violations = Vec::new();
    if package_name != OWNER {
        violations.push(format!(
            "{package_name} -> reqwest (reqwest is exclusive to {OWNER})"
        ));
    }
    if requirement != "=0.13.4" {
        violations.push(format!("{package_name} -> reqwest must pin exactly 0.13.4"));
    }
    if target != Some(MACOS_GMAIL_TARGET) {
        violations.push(format!(
            "{package_name} -> reqwest must use target `{MACOS_GMAIL_TARGET}`"
        ));
    }
    if uses_default_features {
        violations.push(format!(
            "{package_name} -> reqwest must disable default features"
        ));
    }
    let features: BTreeSet<&str> = features.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = REQWEST_DIRECT_FEATURES.into_iter().collect();
    if features != expected {
        violations.push(format!(
            "{package_name} -> reqwest must enable only the `native-tls` feature"
        ));
    }
    violations
}

fn check_resolved_architecture(violations: &mut Vec<String>) -> TaskResult {
    for target in [
        "aarch64-apple-darwin",
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
    ] {
        let dependency_graph = MetadataCommand::new()
            .other_options(target_metadata_options(target))
            .exec()?;
        check_sqlcipher_dependency_graph(&dependency_graph, target, violations);
        check_search_dependency_graph(&dependency_graph, target, violations);
        check_mime_dependency_graph(&dependency_graph, target, violations);
        check_blob_dependency_graph(&dependency_graph, target, violations);
        check_gmail_dependency_graph(&dependency_graph, target, violations);
        check_retrieval_crates_off_tokio_graph(&dependency_graph, target, violations);
        check_keychain_dependency_graph(&dependency_graph, target, violations);
        check_rustix_dependency_graph(&dependency_graph, target, violations);
        check_diagnostic_runtime_dependency_graph(&dependency_graph, target, violations);
    }
    Ok(())
}

fn check_rustix_dependency_graph(metadata: &Metadata, target: &str, violations: &mut Vec<String>) {
    let Some(resolve) = &metadata.resolve else {
        violations.push("Cargo metadata did not return a resolved dependency graph".to_owned());
        return;
    };
    let rustix = metadata
        .packages
        .iter()
        .filter(|package| package.name == "rustix")
        .collect::<Vec<_>>();
    if rustix.len() != 1 || rustix[0].version.to_string() != "1.1.4" {
        violations.push(format!(
            "resolved rustix for {target} must be exactly one package at 1.1.4"
        ));
        return;
    }
    let id = &rustix[0].id;
    let Some(node) = resolve.nodes.iter().find(|node| node.id == *id) else {
        violations.push(format!("resolved rustix node is missing for {target}"));
        return;
    };
    let actual = node
        .features
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let expected = RUSTIX_RESOLVED_FEATURES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if actual != expected {
        violations.push(format!(
            "resolved rustix features for {target} changed from the reviewed lock graph"
        ));
    }
}

fn check_gmail_dependency_graph(metadata: &Metadata, target: &str, violations: &mut Vec<String>) {
    let package_names: BTreeMap<String, String> = metadata
        .packages
        .iter()
        .map(|package| (package.id.to_string(), package.name.to_string()))
        .collect();
    let reqwest: BTreeSet<String> = metadata
        .packages
        .iter()
        .filter_map(|package| {
            (package.name == "reqwest")
                .then_some((package.id.to_string(), package.version.to_string()))
        })
        .filter_map(|(id, version)| {
            if version == "0.13.4" {
                Some(id)
            } else {
                violations.push("resolved reqwest must be exactly 0.13.4".to_owned());
                None
            }
        })
        .collect();
    let Some(resolve) = &metadata.resolve else {
        violations.push("Cargo metadata did not return a resolved dependency graph".to_owned());
        return;
    };
    for node in &resolve.nodes {
        if reqwest.contains(&node.id.to_string()) {
            violations.extend(gmail_resolved_feature_violations(
                &node
                    .features
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                target,
            ));
        }
    }
    let dependencies: BTreeMap<String, BTreeSet<String>> = resolve
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.to_string(),
                node.deps
                    .iter()
                    .map(|dependency| dependency.pkg.to_string())
                    .collect(),
            )
        })
        .collect();
    violations.extend(gmail_dependency_graph_violations(
        &package_names,
        &metadata
            .workspace_members
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        &dependencies,
        &reqwest,
        target,
    ));
}

fn check_keychain_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    const KEYCHAIN_APPLE_DEPENDENCIES: [&str; 3] = [
        "core-foundation",
        "objc2-foundation",
        "security-framework-sys",
    ];
    if KEYCHAIN_APPLE_DEPENDENCIES.contains(&dependency.name.as_str())
        && package_name != "tersa-keychain-macos"
    {
        violations.push(format!(
            "{package_name} -> {} is a direct Keychain Apple dependency outside tersa-keychain-macos",
            dependency.name
        ));
        return;
    }
    if package_name != "tersa-keychain-macos" {
        return;
    }
    let expected = match dependency.name.as_str() {
        "security-framework-sys" => Some(("=2.17.0", true, &["OSX_10_15"][..])),
        "core-foundation" => Some(("=0.10.1", true, &[][..])),
        "objc2-foundation" => Some((
            "=0.3.2",
            true,
            &["std", "NSFileManager", "NSString", "NSThread", "NSURL"][..],
        )),
        "hkdf" => Some(("=0.12.4", false, &[][..])),
        "sha2" => Some(("=0.10.9", false, &[][..])),
        "zeroize" => Some(("=1.9.0", false, &[][..])),
        _ => None,
    };
    let Some((version, apple_only, expected_features)) = expected else {
        return;
    };
    if dependency.req.to_string() != version {
        violations.push(format!(
            "{package_name} -> {} must pin exactly {}",
            dependency.name,
            version.trim_start_matches('=')
        ));
    }
    if apple_only
        && dependency
            .target
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            != Some(MACOS_KEYCHAIN_TARGET)
    {
        violations.push(format!(
            "{package_name} -> {} must use target `{MACOS_KEYCHAIN_TARGET}`",
            dependency.name
        ));
    }
    if (apple_only || dependency.name == "zeroize") && dependency.uses_default_features {
        violations.push(format!(
            "{package_name} -> {} must disable default features",
            dependency.name
        ));
    }
    let features: BTreeSet<&str> = dependency.features.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected_features.iter().copied().collect();
    if apple_only && features != expected {
        violations.push(format!(
            "{package_name} -> {} has an unexpected direct feature set",
            dependency.name
        ));
    }
}

fn protected_keychain_dependency_rename_violations(
    package_name: &str,
    dependency_name: &str,
    rename: Option<&str>,
) -> Vec<String> {
    let protected = matches!(
        (package_name, dependency_name),
        (
            "tersa-keychain-macos",
            "core-foundation"
                | "hkdf"
                | "objc2-foundation"
                | "rustix"
                | "security-framework-sys"
                | "sha2"
                | "tersa-application"
                | "tersa-platform"
                | "tersa-presentation"
                | "tersa-store-sqlcipher-macos"
                | "zeroize",
        ) | ("tersa-apple-bridge", "tersa-keychain-macos")
    );
    if protected && let Some(rename) = rename {
        return vec![format!(
            "{package_name} -> {dependency_name} must not rename protected Keychain dependency to `{rename}`"
        )];
    }
    Vec::new()
}

fn keychain_direct_dependency_set_violations(dependencies: &BTreeSet<&str>) -> Vec<String> {
    const REQUIRED: [&str; 11] = [
        "core-foundation",
        "hkdf",
        "objc2-foundation",
        "rustix",
        "security-framework-sys",
        "sha2",
        "tersa-application",
        "tersa-platform",
        "tersa-presentation",
        "tersa-store-sqlcipher-macos",
        "zeroize",
    ];
    let required = REQUIRED.into_iter().collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    for dependency in dependencies.difference(&required) {
        let detail = if *dependency == "hmac" {
            "direct HMAC is forbidden; only resolved HKDF to HMAC reachability is allowed"
        } else {
            "dependency is outside the closed Keychain adapter set"
        };
        violations.push(format!("tersa-keychain-macos -> {dependency} ({detail})"));
    }
    for dependency in required.difference(dependencies) {
        violations.push(format!(
            "tersa-keychain-macos is missing required direct dependency {dependency}"
        ));
    }
    violations
}

fn apple_bridge_direct_dependency_set_violations(dependencies: &BTreeSet<&str>) -> Vec<String> {
    let required = BTreeSet::from([
        "tersa-application",
        "tersa-keychain-macos",
        "tersa-presentation",
        "url",
        "zeroize",
    ]);
    let mut violations = Vec::new();
    for dependency in dependencies.difference(&required) {
        violations.push(format!(
            "tersa-apple-bridge -> {dependency} (dependency is outside the closed Apple bridge set)"
        ));
    }
    for dependency in required.difference(dependencies) {
        violations.push(format!(
            "tersa-apple-bridge is missing required direct dependency {dependency}"
        ));
    }
    violations
}

fn check_rustix_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    if dependency.name != "rustix" {
        return;
    }
    violations.extend(rustix_manifest_dependency_violations(
        package_name,
        &dependency.req.to_string(),
        dependency.uses_default_features,
        dependency
            .target
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        &dependency.features,
    ));
}

fn check_tokio_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    if dependency.name != "tokio" {
        return;
    }
    violations.extend(tokio_manifest_dependency_violations(
        package_name,
        &dependency.req.to_string(),
        dependency.uses_default_features,
        dependency
            .target
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        &dependency.features,
    ));
}

/// tokio (the async runtime) is directly declared only by the trusted
/// composition and the dedicated token-broker FFI; every other crate reaches it
/// transitively through reqwest. Both owners pin an exact, current-thread,
/// macOS-scoped runtime.
fn tokio_manifest_dependency_violations(
    package_name: &str,
    version: &str,
    uses_default_features: bool,
    target: Option<&str>,
    features: &[String],
) -> Vec<String> {
    const OWNERS: [&str; 2] = ["tersa-oauth-sync-macos", "tersa-token-broker-ffi-macos"];
    if !OWNERS.contains(&package_name) {
        return vec![format!(
            "{package_name} -> tokio is outside the closed direct-owner set {OWNERS:?}"
        )];
    }
    let mut violations = Vec::new();
    if version != "=1.52.3" {
        violations.push(format!("{package_name} -> tokio must pin exactly 1.52.3"));
    }
    if uses_default_features {
        violations.push(format!(
            "{package_name} -> tokio must disable default features"
        ));
    }
    if target != Some(MACOS_KEYCHAIN_TARGET) {
        violations.push(format!(
            "{package_name} -> tokio must use target `{MACOS_KEYCHAIN_TARGET}`"
        ));
    }
    let features: BTreeSet<&str> = features.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = ["net", "rt", "sync", "time"].into_iter().collect();
    if features != expected {
        violations.push(format!(
            "{package_name} -> tokio must enable exactly the current-thread runtime features net, rt, sync, time"
        ));
    }
    violations
}

fn rustix_manifest_dependency_violations(
    package_name: &str,
    version: &str,
    uses_default_features: bool,
    target: Option<&str>,
    features: &[String],
) -> Vec<String> {
    const OWNERS: [&str; 3] = [
        "tersa-blob-spike",
        "tersa-keychain-macos",
        "tersa-store-sqlcipher-macos",
    ];
    let mut violations = Vec::new();
    if !OWNERS.contains(&package_name) {
        return vec![format!(
            "{package_name} -> rustix is outside the closed direct-owner set"
        )];
    }
    if version != "=1.1.4" {
        violations.push(format!("{package_name} -> rustix must pin exactly 1.1.4"));
    }
    if uses_default_features {
        violations.push(format!(
            "{package_name} -> rustix must disable default features"
        ));
    }
    if package_name == "tersa-blob-spike" {
        if target.is_some() {
            violations.push(
                "tersa-blob-spike -> rustix must keep its existing untargeted declaration"
                    .to_owned(),
            );
        }
    } else if target != Some(MACOS_STORE_TARGET) {
        violations.push(format!(
            "{package_name} -> rustix must use target `{MACOS_STORE_TARGET}`"
        ));
    }
    let actual: BTreeSet<&str> = features.iter().map(String::as_str).collect();
    let expected = match package_name {
        "tersa-keychain-macos" => BTreeSet::from(["fs", "process", "std"]),
        _ => BTreeSet::from(["fs", "std"]),
    };
    if actual != expected {
        violations.push(format!(
            "{package_name} -> rustix has an unexpected direct feature set"
        ));
    }
    violations
}

fn cli_direct_dependency_set_violations(dependencies: &BTreeSet<&str>) -> Vec<String> {
    let required = BTreeSet::from(["tersa-application", "tersa-domain", "tersa-keychain-macos"]);
    let mut violations = Vec::new();
    for dependency in dependencies.difference(&required) {
        violations.push(format!(
            "tersa-cli-macos -> {dependency} (dependency is outside the closed CLI adapter set)"
        ));
    }
    for dependency in required.difference(dependencies) {
        violations.push(format!(
            "tersa-cli-macos is missing required direct dependency {dependency}"
        ));
    }
    violations
}

/// Asserts the secret-storage and retrieval-only crates never link the async
/// runtime. A full tokio owner-set does not fit — `dioxus-desktop`'s
/// `tokio_runtime` feature legitimately pulls tokio into the Dioxus spike — so
/// this is a targeted denial for exactly the crates whose invariant is "no
/// ambient async runtime": `tersa-keychain-macos` (secret storage) and the
/// retrieval-only `tersa-cli-macos`. It fails closed if any future transitive
/// path (not just reqwest) links tokio into either.
fn check_retrieval_crates_off_tokio_graph(
    metadata: &Metadata,
    target: &str,
    violations: &mut Vec<String>,
) {
    let package_names: BTreeMap<String, String> = metadata
        .packages
        .iter()
        .map(|package| (package.id.to_string(), package.name.to_string()))
        .collect();
    let tokio: BTreeSet<String> = metadata
        .packages
        .iter()
        .filter_map(|package| (package.name == "tokio").then_some(package.id.to_string()))
        .collect();
    let Some(resolve) = &metadata.resolve else {
        violations.push("Cargo metadata did not return a resolved dependency graph".to_owned());
        return;
    };
    let dependencies: BTreeMap<String, BTreeSet<String>> = resolve
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.to_string(),
                node.deps.iter().map(|d| d.pkg.to_string()).collect(),
            )
        })
        .collect();
    let members: Vec<String> = metadata
        .workspace_members
        .iter()
        .map(ToString::to_string)
        .collect();
    violations.extend(retrieval_tokio_denial_violations(
        &package_names,
        &members,
        &dependencies,
        &tokio,
        target,
    ));
}

fn retrieval_tokio_denial_violations(
    package_names: &BTreeMap<String, String>,
    workspace_members: &[String],
    dependencies: &BTreeMap<String, BTreeSet<String>>,
    tokio_packages: &BTreeSet<String>,
    target: &str,
) -> Vec<String> {
    const DENIED: [&str; 2] = ["tersa-keychain-macos", "tersa-cli-macos"];
    let mut violations = Vec::new();
    for member_id in workspace_members {
        let Some(name) = package_names.get(member_id) else {
            continue;
        };
        if DENIED.contains(&name.as_str())
            && dependency_reaches(member_id, tokio_packages, dependencies)
        {
            violations.push(format!(
                "{name} reaches tokio but must stay off the async-runtime graph for {target}"
            ));
        }
    }
    violations
}

fn check_keychain_dependency_graph(
    metadata: &Metadata,
    target: &str,
    violations: &mut Vec<String>,
) {
    const APPLE: [&str; 3] = [
        "core-foundation",
        "objc2-foundation",
        "security-framework-sys",
    ];
    let Some(resolve) = &metadata.resolve else {
        violations.push("Cargo metadata did not return a resolved dependency graph".to_owned());
        return;
    };
    let names: BTreeMap<String, String> = metadata
        .packages
        .iter()
        .map(|p| (p.id.to_string(), p.name.to_string()))
        .collect();
    let dependencies: BTreeMap<String, BTreeSet<String>> = resolve
        .nodes
        .iter()
        .map(|n| {
            (
                n.id.to_string(),
                n.deps.iter().map(|d| d.pkg.to_string()).collect(),
            )
        })
        .collect();
    let apple_by_name: BTreeMap<&str, BTreeSet<String>> = APPLE
        .into_iter()
        .map(|expected| {
            let ids = names
                .iter()
                .filter_map(|(id, name)| (name == expected).then_some(id.clone()))
                .collect();
            (expected, ids)
        })
        .collect();
    for member in &metadata.workspace_members {
        let id = member.to_string();
        let name = &names[&id];
        if name != "tersa-keychain-macos" {
            continue;
        }
        for (dependency_name, package_ids) in &apple_by_name {
            let reaches = dependency_reaches(&id, package_ids, &dependencies);
            if target == "aarch64-apple-darwin" && !reaches {
                violations.push(format!(
                    "{name} does not reach required macOS dependency {dependency_name} for {target}"
                ));
            }
            if target != "aarch64-apple-darwin" && reaches {
                violations.push(format!(
                    "{name} reaches Keychain Apple dependency {dependency_name} outside macOS for {target}"
                ));
            }
        }
    }
}

fn gmail_resolved_feature_violations(features: &[String], target: &str) -> Vec<String> {
    let features: BTreeSet<&str> = features.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = REQWEST_RESOLVED_FEATURES.into_iter().collect();
    if features == expected {
        return Vec::new();
    }
    vec![format!(
        "resolved reqwest features for {target} must be exactly native-tls without defaults, cookies, compression, multipart, proxy, or alternate TLS"
    )]
}

fn gmail_dependency_graph_violations(
    package_names: &BTreeMap<String, String>,
    workspace_members: &[String],
    dependencies: &BTreeMap<String, BTreeSet<String>>,
    reqwest_packages: &BTreeSet<String>,
    target: &str,
) -> Vec<String> {
    // reqwest (network) may be REACHED only by the Gmail adapter that owns it, the
    // one trusted composition that drives it, and the mailbox-sync FFI that exposes
    // that composition to Swift. tersa-keychain-macos and the retrieval-only
    // tersa-cli-macos are deliberately absent: the check must still fire if either
    // ever reaches reqwest.
    const OWNERS: [&str; 4] = [
        "tersa-gmail-rest-macos",
        "tersa-oauth-sync-macos",
        "tersa-mailbox-sync-ffi-macos",
        // ADR-0024 point 3: the token-broker FFI drives Google's token endpoint
        // through the Gmail transport for exchange/refresh/revoke only.
        "tersa-token-broker-ffi-macos",
    ];
    let mut violations = Vec::new();
    for member_id in workspace_members {
        let Some(name) = package_names.get(member_id) else {
            violations.push(format!(
                "workspace member `{member_id}` is absent from the resolved package graph"
            ));
            continue;
        };
        if !dependency_reaches(member_id, reqwest_packages, dependencies) {
            continue;
        }
        if !OWNERS.contains(&name.as_str()) {
            violations.push(format!(
                "{name} reaches reqwest outside the authorized network crates {OWNERS:?} for {target}"
            ));
        } else if target != "aarch64-apple-darwin" {
            violations.push(format!(
                "{name} reaches reqwest on non-macOS target {target}"
            ));
        }
    }
    violations
}

fn target_metadata_options(target: &str) -> Vec<String> {
    vec![
        "--locked".to_owned(),
        "--all-features".to_owned(),
        "--filter-platform".to_owned(),
        target.to_owned(),
    ]
}

fn check_diagnostic_runtime_dependency_graph(
    metadata: &Metadata,
    target: &str,
    violations: &mut Vec<String>,
) {
    let Some(resolve) = &metadata.resolve else {
        violations.push("Cargo metadata did not return a resolved dependency graph".to_owned());
        return;
    };
    let package_names: BTreeMap<String, String> = metadata
        .packages
        .iter()
        .map(|package| (package.id.to_string(), package.name.to_string()))
        .collect();
    let dependencies: BTreeMap<String, BTreeSet<String>> = resolve
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.to_string(),
                node.deps
                    .iter()
                    .map(|dependency| dependency.pkg.to_string())
                    .collect(),
            )
        })
        .collect();
    let workspace_members: BTreeSet<String> = metadata
        .workspace_members
        .iter()
        .map(ToString::to_string)
        .collect();

    check_diagnostic_runtime_reachability(
        &package_names,
        &workspace_members,
        &dependencies,
        target,
        violations,
    );
}

fn check_diagnostic_runtime_reachability(
    package_names: &BTreeMap<String, String>,
    workspace_members: &BTreeSet<String>,
    dependencies: &BTreeMap<String, BTreeSet<String>>,
    target: &str,
    violations: &mut Vec<String>,
) {
    const RUNTIMES: [RuntimeBoundary; 2] = [
        (
            "Slint runtime",
            is_slint_runtime_dependency,
            "tersa-slint-spike",
        ),
        (
            "Dioxus runtime",
            is_dioxus_runtime_dependency,
            "tersa-dioxus-spike",
        ),
    ];

    for (runtime, matches_runtime, allowed_root) in RUNTIMES {
        let runtime_packages: BTreeSet<String> = package_names
            .iter()
            .filter_map(|(id, name)| matches_runtime(name).then_some(id.clone()))
            .collect();
        for member_id in workspace_members {
            let Some(member_name) = package_names.get(member_id) else {
                violations.push(format!(
                    "workspace member `{member_id}` is absent from the resolved package graph"
                ));
                continue;
            };
            if member_name != allowed_root
                && dependency_reaches(member_id, &runtime_packages, dependencies)
            {
                violations.push(format!(
                    "{member_name} reaches {runtime} outside {allowed_root} for {target}"
                ));
            }
        }
    }
}

fn check_mime_dependency_graph(metadata: &Metadata, target: &str, violations: &mut Vec<String>) {
    const MIME_SPIKE: &str = "tersa-mime-spike";
    const MIME_PACKAGES: [&str; 2] = ["ammonia", "mail-parser"];
    let Some(resolve) = &metadata.resolve else {
        violations.push("Cargo metadata did not return a resolved dependency graph".to_owned());
        return;
    };
    let package_names: BTreeMap<String, String> = metadata
        .packages
        .iter()
        .map(|package| (package.id.to_string(), package.name.to_string()))
        .collect();
    let dependencies: BTreeMap<String, BTreeSet<String>> = resolve
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.to_string(),
                node.deps
                    .iter()
                    .map(|dependency| dependency.pkg.to_string())
                    .collect(),
            )
        })
        .collect();
    let mime_packages: BTreeSet<String> = package_names
        .iter()
        .filter_map(|(id, name)| MIME_PACKAGES.contains(&name.as_str()).then_some(id.clone()))
        .collect();
    for member in &metadata.workspace_members {
        let member_id = member.to_string();
        let Some(member_name) = package_names.get(&member_id) else {
            violations.push(format!(
                "workspace member `{member_id}` is absent from the resolved package graph"
            ));
            continue;
        };
        if member_name != MIME_SPIKE
            && dependency_reaches(&member_id, &mime_packages, &dependencies)
        {
            violations.push(format!(
                "{member_name} reaches a MIME parser dependency outside {MIME_SPIKE} for {target}"
            ));
        }
    }
}

fn check_blob_dependency_graph(metadata: &Metadata, target: &str, violations: &mut Vec<String>) {
    let Some(resolve) = &metadata.resolve else {
        violations.push("Cargo metadata did not return a resolved dependency graph".to_owned());
        return;
    };
    let package_names: BTreeMap<String, String> = metadata
        .packages
        .iter()
        .map(|package| (package.id.to_string(), package.name.to_string()))
        .collect();
    let dependencies: BTreeMap<String, BTreeSet<String>> = resolve
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.to_string(),
                node.deps
                    .iter()
                    .map(|dependency| dependency.pkg.to_string())
                    .collect(),
            )
        })
        .collect();
    violations.extend(blob_dependency_graph_violations(
        &package_names,
        &metadata
            .workspace_members
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        &dependencies,
        target,
    ));
}

fn blob_dependency_graph_violations(
    package_names: &BTreeMap<String, String>,
    workspace_members: &[String],
    dependencies: &BTreeMap<String, BTreeSet<String>>,
    target: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    let hmac_packages = package_ids_named(package_names, "hmac");
    let chacha_packages = package_ids_named(package_names, "chacha20poly1305");
    for member_id in workspace_members {
        let Some(member_name) = package_names.get(member_id) else {
            violations.push(format!(
                "workspace member `{member_id}` is absent from the resolved package graph"
            ));
            continue;
        };
        let cli_chain = member_name == "tersa-cli-macos" && target == "aarch64-apple-darwin";
        let bridge_chain = member_name == "tersa-apple-bridge" && target == "aarch64-apple-darwin";
        if bridge_chain && dependency_reaches(member_id, &hmac_packages, dependencies) {
            violations.extend(exact_dependency_path_violations(
                member_id,
                &hmac_packages,
                package_names,
                dependencies,
                &["tersa-apple-bridge", "tersa-keychain-macos", "hkdf", "hmac"],
                "HMAC",
                target,
            ));
        }
        if !HMAC_OWNERS.contains(&member_name.as_str())
            && !cli_chain
            && !bridge_chain
            && dependency_reaches(member_id, &hmac_packages, dependencies)
        {
            violations.push(format!(
                "{member_name} reaches HMAC outside the approved owners for {target}"
            ));
        }
        if !BLOB_DIAGNOSTIC_OWNERS.contains(&member_name.as_str())
            && dependency_reaches(member_id, &chacha_packages, dependencies)
        {
            violations.push(format!(
                "{member_name} reaches ChaCha20-Poly1305 outside {} for {target}",
                BLOB_DIAGNOSTIC_OWNERS[0],
            ));
        }
    }
    violations
}

fn package_ids_named(
    package_names: &BTreeMap<String, String>,
    expected_name: &str,
) -> BTreeSet<String> {
    package_names
        .iter()
        .filter_map(|(id, name)| (name == expected_name).then_some(id.clone()))
        .collect()
}

fn check_search_dependency_graph(metadata: &Metadata, target: &str, violations: &mut Vec<String>) {
    const SEARCH_SPIKE: &str = "tersa-search-spike";
    const FORBIDDEN: [&str; 4] = ["memmap2", "tempfile", "lz4_flex", "zstd"];
    let Some(resolve) = &metadata.resolve else {
        violations.push("Cargo metadata did not return a resolved dependency graph".to_owned());
        return;
    };
    let package_names: BTreeMap<String, String> = metadata
        .packages
        .iter()
        .map(|package| (package.id.to_string(), package.name.to_string()))
        .collect();
    let dependencies: BTreeMap<String, BTreeSet<String>> = resolve
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.to_string(),
                node.deps
                    .iter()
                    .map(|dependency| dependency.pkg.to_string())
                    .collect(),
            )
        })
        .collect();
    let tantivy: BTreeSet<String> = package_names
        .iter()
        .filter_map(|(id, name)| (name == "tantivy").then_some(id.clone()))
        .collect();
    for member in &metadata.workspace_members {
        let member_id = member.to_string();
        if package_names
            .get(&member_id)
            .is_some_and(|name| name != SEARCH_SPIKE)
            && dependency_reaches(&member_id, &tantivy, &dependencies)
        {
            violations.push(format!(
                "{} reaches tantivy outside {SEARCH_SPIKE}",
                package_names[&member_id]
            ));
        }
    }
    let search_id = metadata
        .workspace_members
        .iter()
        .map(ToString::to_string)
        .find(|id| {
            package_names
                .get(id)
                .is_some_and(|name| name == SEARCH_SPIKE)
        });
    if let Some(search_id) = search_id {
        for forbidden in FORBIDDEN {
            let targets: BTreeSet<String> = package_names
                .iter()
                .filter_map(|(id, name)| (name == forbidden).then_some(id.clone()))
                .collect();
            if dependency_reaches(&search_id, &targets, &dependencies) {
                violations.push(format!(
                    "{SEARCH_SPIKE} reaches forbidden package {forbidden} for {target}"
                ));
            }
        }
    }
}

fn check_sqlcipher_dependency_graph(
    metadata: &Metadata,
    target: &str,
    violations: &mut Vec<String>,
) {
    let Some(resolve) = &metadata.resolve else {
        violations.push("Cargo metadata did not return a resolved dependency graph".to_owned());
        return;
    };
    let package_names: BTreeMap<String, String> = metadata
        .packages
        .iter()
        .map(|package| (package.id.to_string(), package.name.to_string()))
        .collect();
    let dependencies: BTreeMap<String, BTreeSet<String>> = resolve
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.to_string(),
                node.deps
                    .iter()
                    .map(|dependency| dependency.pkg.to_string())
                    .collect(),
            )
        })
        .collect();
    let rusqlite_packages: BTreeSet<String> = metadata
        .packages
        .iter()
        .filter_map(|package| {
            if package.name != "rusqlite" {
                return None;
            }
            if package.version.to_string() != "0.39.0" {
                violations.push("resolved rusqlite must be exactly 0.39.0".to_owned());
            }
            Some(package.id.to_string())
        })
        .collect();
    if rusqlite_packages.is_empty() {
        violations.push("resolved dependency graph is missing rusqlite".to_owned());
    }
    for node in &resolve.nodes {
        if rusqlite_packages.contains(&node.id.to_string()) {
            violations.extend(rusqlite_resolved_feature_violations(
                &node
                    .features
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                target,
            ));
        }
    }
    let sqlite_packages: BTreeSet<String> = package_names
        .iter()
        .filter_map(|(id, name)| (name == "libsqlite3-sys").then_some(id.clone()))
        .collect();
    if sqlite_packages.is_empty() {
        violations.push("resolved dependency graph is missing libsqlite3-sys".to_owned());
        return;
    }

    violations.extend(sqlcipher_dependency_graph_violations(
        &package_names,
        &metadata
            .workspace_members
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        &dependencies,
        &sqlite_packages,
        target,
    ));
}

fn rusqlite_resolved_feature_violations(features: &[String], target: &str) -> Vec<String> {
    let features: BTreeSet<&str> = features.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = RUSQLITE_RESOLVED_FEATURES.into_iter().collect();
    if features == expected {
        return Vec::new();
    }
    vec![format!(
        "resolved rusqlite features for {target} must be exactly bundled SQLCipher without extension loading or hooks"
    )]
}

fn sqlcipher_dependency_graph_violations(
    package_names: &BTreeMap<String, String>,
    workspace_members: &[String],
    dependencies: &BTreeMap<String, BTreeSet<String>>,
    sqlite_packages: &BTreeSet<String>,
    target: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    for member_id in workspace_members {
        let Some(member_name) = package_names.get(member_id) else {
            violations.push(format!(
                "workspace member `{member_id}` is absent from the resolved package graph"
            ));
            continue;
        };
        if dependency_reaches(member_id, sqlite_packages, dependencies) {
            let bridge_chain =
                member_name == "tersa-apple-bridge" && target == "aarch64-apple-darwin";
            if bridge_chain {
                violations.extend(exact_dependency_path_violations(
                    member_id,
                    sqlite_packages,
                    package_names,
                    dependencies,
                    &[
                        "tersa-apple-bridge",
                        "tersa-keychain-macos",
                        "tersa-store-sqlcipher-macos",
                        "rusqlite",
                        "libsqlite3-sys",
                    ],
                    "SQLCipher",
                    target,
                ));
            } else if !SQLCIPHER_OWNERS.contains(&member_name.as_str()) {
                violations.push(format!(
                    "{member_name} reaches libsqlite3-sys outside the approved Apple SQLCipher owners for {target}"
                ));
            } else if matches!(
                member_name.as_str(),
                "tersa-store-sqlcipher-macos" | "tersa-keychain-macos" | "tersa-cli-macos"
            ) && target != "aarch64-apple-darwin"
            {
                violations.push(format!(
                    "{member_name} reaches libsqlite3-sys on non-macOS target {target}"
                ));
            }
        }
    }
    violations
}

fn dependency_reaches(
    start: &str,
    targets: &BTreeSet<String>,
    dependencies: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    let mut pending = vec![start.to_owned()];
    let mut visited = BTreeSet::new();
    while let Some(package) = pending.pop() {
        if !visited.insert(package.clone()) {
            continue;
        }
        if targets.contains(&package) {
            return true;
        }
        if let Some(children) = dependencies.get(&package) {
            pending.extend(children.iter().cloned());
        }
    }
    false
}

fn exact_dependency_path_violations(
    start: &str,
    targets: &BTreeSet<String>,
    package_names: &BTreeMap<String, String>,
    dependencies: &BTreeMap<String, BTreeSet<String>>,
    expected: &[&str],
    boundary: &str,
    target: &str,
) -> Vec<String> {
    let mut paths = Vec::new();
    dependency_paths(start, targets, dependencies, &mut Vec::new(), &mut paths);
    if paths.is_empty() {
        return vec![format!(
            "{} does not reach the required {boundary} path for {target}",
            package_names
                .get(start)
                .map_or("unknown workspace member", String::as_str)
        )];
    }
    let mut violations = Vec::new();
    for path in paths {
        let names = path
            .iter()
            .map(|id| package_names.get(id).map_or("<unknown>", String::as_str))
            .collect::<Vec<_>>();
        if names != expected {
            violations.push(format!(
                "{} reaches {boundary} through an unapproved path for {target}",
                package_names
                    .get(start)
                    .map_or("unknown workspace member", String::as_str)
            ));
        }
    }
    violations
}

fn dependency_paths(
    current: &str,
    targets: &BTreeSet<String>,
    dependencies: &BTreeMap<String, BTreeSet<String>>,
    stack: &mut Vec<String>,
    output: &mut Vec<Vec<String>>,
) {
    if stack.iter().any(|entry| entry == current) {
        return;
    }
    stack.push(current.to_owned());
    if targets.contains(current) {
        output.push(stack.clone());
    } else if let Some(children) = dependencies.get(current) {
        for child in children {
            dependency_paths(child, targets, dependencies, stack, output);
        }
    }
    stack.pop();
}

fn check_dioxus_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    const DIOXUS_SPIKE: &str = "tersa-dioxus-spike";
    const APPLE_TARGET: &str = r#"cfg(any(target_os = "macos", target_os = "ios"))"#;

    let dependency_name = dependency.name.as_str();
    if !is_dioxus_runtime_dependency(dependency_name) {
        return;
    }

    if package_name != DIOXUS_SPIKE {
        violations.push(format!(
            "{package_name} -> {dependency_name} (Dioxus is exclusive to {DIOXUS_SPIKE})"
        ));
    }

    let target = dependency.target.as_ref().map(ToString::to_string);
    if target.as_deref() != Some(APPLE_TARGET) {
        violations.push(format!(
            "{package_name} -> {dependency_name} must use target `{APPLE_TARGET}`"
        ));
    }
}

fn is_dioxus_runtime_dependency(dependency_name: &str) -> bool {
    dependency_name == "dioxus"
        || dependency_name.starts_with("dioxus-")
        || matches!(dependency_name, "wry" | "tao" | "manganis")
}

fn is_slint_runtime_dependency(dependency_name: &str) -> bool {
    dependency_name == "slint"
        || dependency_name.starts_with("slint-")
        || dependency_name.starts_with("i-slint-")
}

fn check_slint_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    const SLINT_SPIKE: &str = "tersa-slint-spike";
    const APPLE_TARGET: &str = r#"cfg(any(target_os = "macos", target_os = "ios"))"#;

    let dependency_name = dependency.name.as_str();
    if !is_slint_runtime_dependency(dependency_name) {
        return;
    }

    if package_name != SLINT_SPIKE {
        violations.push(format!(
            "{package_name} -> {dependency_name} (Slint is exclusive to {SLINT_SPIKE})"
        ));
    }

    let target = dependency.target.as_ref().map(ToString::to_string);
    if target.as_deref() != Some(APPLE_TARGET) {
        violations.push(format!(
            "{package_name} -> {dependency_name} must use target `{APPLE_TARGET}`"
        ));
    }
}

fn check_sqlcipher_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    const APPLE_TARGET: &str = r#"cfg(any(target_os = "macos", target_os = "ios"))"#;

    let target = dependency.target.as_ref().map(ToString::to_string);
    let expected_target = if package_name == "tersa-store-sqlcipher-macos" {
        MACOS_STORE_TARGET
    } else {
        APPLE_TARGET
    };
    violations.extend(sqlcipher_manifest_dependency_violations(
        package_name,
        dependency.name.as_str(),
        &dependency.req.to_string(),
        target.as_deref(),
        expected_target,
        dependency.uses_default_features,
        &dependency.features,
    ));
}

fn sqlcipher_manifest_dependency_violations(
    package_name: &str,
    dependency_name: &str,
    requirement: &str,
    target: Option<&str>,
    apple_target: &str,
    uses_default_features: bool,
    features: &[String],
) -> Vec<String> {
    if !matches!(dependency_name, "rusqlite" | "libsqlite3-sys") {
        return Vec::new();
    }

    let mut violations = Vec::new();
    if matches!(package_name, "tersa-keychain-macos" | "tersa-cli-macos") {
        violations.push(format!(
            "{package_name} -> {dependency_name} is forbidden; SQLCipher must be reached only through tersa-store-sqlcipher-macos"
        ));
        return violations;
    }
    if !SQLCIPHER_OWNERS.contains(&package_name) {
        violations.push(format!(
            "{package_name} -> {dependency_name} (SQLCipher is exclusive to approved Apple SQLCipher owners)"
        ));
    }
    if target != Some(apple_target) {
        violations.push(format!(
            "{package_name} -> {dependency_name} must use target `{apple_target}`"
        ));
    }
    if dependency_name == "rusqlite" {
        if requirement != "=0.39.0" {
            violations.push(format!(
                "{package_name} -> rusqlite must pin exactly 0.39.0"
            ));
        }
        if uses_default_features {
            violations.push(format!(
                "{package_name} -> rusqlite must disable default features"
            ));
        }
        let features: BTreeSet<&str> = features.iter().map(String::as_str).collect();
        if features != BTreeSet::from(["bundled-sqlcipher"]) {
            violations.push(format!(
                "{package_name} -> rusqlite must enable only the `bundled-sqlcipher` feature"
            ));
        }
    }
    violations
}

fn check_search_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    const SEARCH_SPIKE: &str = "tersa-search-spike";
    const APPLE_TARGET: &str = r#"cfg(any(target_os = "macos", target_os = "ios"))"#;
    if dependency.name != "tantivy" {
        return;
    }
    if package_name != SEARCH_SPIKE {
        violations.push(format!(
            "{package_name} -> tantivy (Tantivy is exclusive to {SEARCH_SPIKE})"
        ));
    }
    if dependency
        .target
        .as_ref()
        .map(ToString::to_string)
        .as_deref()
        != Some(APPLE_TARGET)
    {
        violations.push(format!(
            "{package_name} -> tantivy must use target `{APPLE_TARGET}`"
        ));
    }
    if dependency.req.to_string() != "=0.26.1" {
        violations.push(format!("{package_name} -> tantivy must pin exactly 0.26.1"));
    }
}

fn check_mime_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    const MIME_SPIKE: &str = "tersa-mime-spike";
    let expected = match dependency.name.as_str() {
        "ammonia" => Some("=4.1.4"),
        "mail-parser" => Some("=0.11.5"),
        _ => None,
    };
    let Some(expected) = expected else {
        return;
    };
    if package_name != MIME_SPIKE {
        violations.push(format!(
            "{package_name} -> {} (MIME parsing is exclusive to {MIME_SPIKE})",
            dependency.name
        ));
    }
    if dependency.req.to_string() != expected {
        violations.push(format!(
            "{package_name} -> {} must pin exactly {}",
            dependency.name,
            expected.trim_start_matches('=')
        ));
    }
}

fn check_blob_dependency(
    package_name: &str,
    dependency: &cargo_metadata::Dependency,
    violations: &mut Vec<String>,
) {
    violations.extend(blob_manifest_dependency_violations(
        package_name,
        dependency.name.as_str(),
        &dependency.req.to_string(),
    ));
}

fn blob_manifest_dependency_violations(
    package_name: &str,
    dependency_name: &str,
    version: &str,
) -> Vec<String> {
    const BLOB_SPIKE: &str = BLOB_DIAGNOSTIC_OWNERS[0];
    if dependency_name == "rustix" {
        return (package_name == BLOB_SPIKE && version != "=1.1.4")
            .then(|| format!("{package_name} -> rustix must pin exactly 1.1.4"))
            .into_iter()
            .collect();
    }
    let expected = match dependency_name {
        "chacha20poly1305" => Some("=0.10.1"),
        "hmac" => Some("=0.12.1"),
        _ => None,
    };
    let Some(expected) = expected else {
        return Vec::new();
    };
    let mut violations = Vec::new();
    let permitted = if dependency_name == "hmac" {
        HMAC_OWNERS.contains(&package_name)
    } else {
        package_name == BLOB_SPIKE
    };
    if !permitted {
        let message = if dependency_name == "hmac" {
            "cryptography ownership is restricted".to_owned()
        } else {
            format!("blob cryptography is exclusive to {BLOB_SPIKE}")
        };
        violations.push(format!("{package_name} -> {dependency_name} ({message})"));
    }
    if version != expected {
        violations.push(format!(
            "{package_name} -> {dependency_name} must pin exactly {}",
            expected.trim_start_matches('=')
        ));
    }
    violations
}

fn reserved_future_policy_violations(
    workspace_resolved_dependencies: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for (package_name, allowed_dependencies) in RESERVED_FUTURE_POLICY {
        let Some(dependencies) = workspace_resolved_dependencies.get(package_name) else {
            continue;
        };

        violations.push(format!(
            "workspace crate `{package_name}` is reserved for a later reviewed policy change"
        ));
        for dependency_name in dependencies {
            if !allowed_dependencies.contains(&dependency_name.as_str()) {
                violations.push(format!(
                    "reserved future crate `{package_name}` -> `{dependency_name}` exceeds its allowed inward dependencies"
                ));
            }
        }
    }
    violations
}

fn workspace_resolved_dependencies(
    metadata: &Metadata,
) -> TaskResult<BTreeMap<String, BTreeSet<String>>> {
    let workspace_member_names: BTreeMap<PackageId, String> = metadata
        .workspace_members
        .iter()
        .map(|member_id| {
            let package = metadata
                .packages
                .iter()
                .find(|package| package.id == *member_id)
                .ok_or_else(|| {
                    io::Error::other(format!(
                        "workspace member `{member_id}` is missing from package metadata"
                    ))
                })?;
            Ok((member_id.clone(), package.name.to_string()))
        })
        .collect::<TaskResult<_>>()?;
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| io::Error::other("cargo metadata did not return resolved dependencies"))?;

    metadata
        .workspace_members
        .iter()
        .map(|member_id| {
            let package_name = workspace_member_names.get(member_id).ok_or_else(|| {
                io::Error::other(format!(
                    "workspace member `{member_id}` is missing from resolved member names"
                ))
            })?;
            let node = resolve
                .nodes
                .iter()
                .find(|node| node.id == *member_id)
                .ok_or_else(|| {
                    io::Error::other(format!(
                        "workspace member `{member_id}` is missing from resolved dependency nodes"
                    ))
                })?;
            Ok((
                package_name.clone(),
                resolved_workspace_dependency_names(
                    node.deps
                        .iter()
                        .map(|dependency| ResolvedDependencyIdentity {
                            package_id: dependency.pkg.clone(),
                        }),
                    &workspace_member_names,
                ),
            ))
        })
        .collect()
}

fn resolved_workspace_dependency_names(
    dependencies: impl IntoIterator<Item = ResolvedDependencyIdentity>,
    workspace_member_names: &BTreeMap<PackageId, String>,
) -> BTreeSet<String> {
    dependencies
        .into_iter()
        .filter_map(|dependency| workspace_member_names.get(&dependency.package_id).cloned())
        .collect()
}

fn future_macos_store_dependency_violation(
    package_name: &str,
    dependency_name: &str,
    target: Option<&str>,
) -> Option<String> {
    let protected_edge = matches!(
        (package_name, dependency_name),
        (
            "tersa-keychain-macos",
            "tersa-store-sqlcipher-macos" | "tersa-application" | "tersa-presentation"
        ) | (
            "tersa-cli-macos" | "tersa-apple-bridge",
            "tersa-keychain-macos"
        ) | (
            // The trusted composition's capability edges must stay macOS-scoped, so
            // no future un-scoping can make it reach the SQLCipher store or the
            // Keychain (and thus HMAC key derivation) on a non-macOS target. Its
            // gmail-rest edge is likewise pinned so it never reaches reqwest off
            // macOS.
            "tersa-oauth-sync-macos",
            "tersa-gmail-rest-macos" | "tersa-keychain-macos" | "tersa-store-sqlcipher-macos"
        ) | (
            // The mailbox-sync FFI's bridge edge carries the grant-claim seam (and
            // the single-archive link); like every other capability edge it must
            // stay macOS-scoped, so a future un-scoping cannot pull the bridge into
            // a non-macOS build of the FFI.
            "tersa-mailbox-sync-ffi-macos",
            "tersa-apple-bridge"
        ) | (
            // ADR-0024 point 3: the token-broker FFI's capability edges must stay
            // macOS-scoped so a future un-scoping cannot pull Keychain, Gmail, or
            // the broker core into a non-macOS build of the service archive.
            "tersa-token-broker-ffi-macos",
            "tersa-gmail-rest-macos" | "tersa-keychain-macos" | "tersa-token-broker-core" | "tokio"
        )
    );
    let store_crypto = package_name == "tersa-store-sqlcipher-macos"
        && matches!(
            dependency_name,
            "rusqlite" | "libsqlite3-sys" | "chacha20poly1305" | "hmac"
        );
    if !protected_edge && !store_crypto {
        return None;
    }

    if target != Some(MACOS_STORE_TARGET) {
        return Some(format!(
            "{package_name} -> {dependency_name} must use target `{MACOS_STORE_TARGET}`"
        ));
    }
    None
}

fn dependency_policy() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    BTreeMap::from([
        (
            "tersa-apple-bridge",
            BTreeSet::from([
                "tersa-application",
                "tersa-keychain-macos",
                "tersa-presentation",
            ]),
        ),
        ("tersa-dioxus-spike", BTreeSet::from(["tersa-presentation"])),
        ("tersa-blob-spike", BTreeSet::new()),
        (
            "tersa-keychain-macos",
            BTreeSet::from([
                "tersa-application",
                "tersa-platform",
                "tersa-presentation",
                "tersa-store-sqlcipher-macos",
            ]),
        ),
        (
            "tersa-cli-macos",
            BTreeSet::from(["tersa-application", "tersa-domain", "tersa-keychain-macos"]),
        ),
        ("tersa-mime-spike", BTreeSet::new()),
        ("tersa-slint-spike", BTreeSet::from(["tersa-presentation"])),
        ("tersa-sqlcipher-spike", BTreeSet::new()),
        (
            "tersa-store-sqlcipher-macos",
            BTreeSet::from(["tersa-application", "tersa-domain"]),
        ),
        (
            // 3d: the sole trusted OAuth token-lifecycle + bounded-sync
            // composition. It is the one crate that consumes both the Keychain
            // token store and the network Gmail adapter; the retrieval-only CLI
            // never depends on it, so the CLI stays off the network graph.
            "tersa-oauth-sync-macos",
            BTreeSet::from([
                "tersa-application",
                "tersa-domain",
                "tersa-gmail-rest-macos",
                "tersa-keychain-macos",
                "tersa-store-sqlcipher-macos",
            ]),
        ),
        (
            // 3d: the macOS C ABI that exposes the trusted composition's bounded-sync
            // worker to Swift, in a sibling static library so the network stack stays
            // out of the minimal bootstrap bridge. It composes nothing itself — it
            // only forwards two public strings to the composition and claims finished
            // grants through the bridge's session registry seams, the edge that lets
            // the application link only this crate's archive.
            "tersa-mailbox-sync-ffi-macos",
            BTreeSet::from([
                "tersa-application",
                "tersa-apple-bridge",
                "tersa-oauth-sync-macos",
            ]),
        ),
        ("tersa-search-spike", BTreeSet::new()),
        ("tersa-domain", BTreeSet::new()),
        ("tersa-application", BTreeSet::from(["tersa-domain"])),
        (
            "tersa-gmail-rest-macos",
            BTreeSet::from(["tersa-application", "tersa-domain"]),
        ),
        ("tersa-platform", BTreeSet::from(["tersa-domain"])),
        (
            "tersa-presentation",
            BTreeSet::from(["tersa-application", "tersa-domain", "tersa-platform"]),
        ),
        (
            // Point 2: the portable token-broker lifecycle composition is
            // platform-agnostic; its sole workspace edge is the application
            // port layer it composes over.
            "tersa-token-broker-core",
            BTreeSet::from(["tersa-application"]),
        ),
        (
            // ADR-0024 point 3: the dedicated token-broker XPC static archive.
            // It composes the portable core with Google transport and the
            // broker-only Keychain store, and never depends on the main app's
            // mailbox-sync FFI or Apple bootstrap bridge.
            "tersa-token-broker-ffi-macos",
            BTreeSet::from([
                "tersa-application",
                "tersa-domain",
                "tersa-gmail-rest-macos",
                "tersa-keychain-macos",
                "tersa-token-broker-core",
            ]),
        ),
    ])
}

fn check_dco(base: &str, head: &str) -> TaskResult {
    let range = format!("{base}..{head}");
    let output = Command::new("git")
        .args([
            "log",
            "--format=%H%x1f%an%x1f%ae%x1f%(trailers:key=Signed-off-by,valueonly,separator=%x1d)%x1e",
            &range,
        ])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git log failed for range `{range}` with status {}",
            output.status
        ))
        .into());
    }

    let log = String::from_utf8(output.stdout)?;
    let mut unsigned = Vec::new();

    for record in log
        .split('\u{1e}')
        .filter(|record| !record.trim().is_empty())
    {
        let mut fields = record.trim().splitn(4, '\u{1f}');
        let commit = required_log_field(&mut fields, "commit")?;
        let author_name = required_log_field(&mut fields, "author name")?;
        let author_email = required_log_field(&mut fields, "author email")?;
        let sign_offs = required_log_field(&mut fields, "sign-off trailers")?;
        let signed_by_author = sign_offs
            .split('\u{1d}')
            .filter_map(parse_identity)
            .any(|(name, email)| name == author_name && email.eq_ignore_ascii_case(author_email));
        if !signed_by_author {
            unsigned.push(commit.trim().to_owned());
        }
    }

    if unsigned.is_empty() {
        println!("DCO sign-off check passed for {range}.");
        return Ok(());
    }

    Err(io::Error::other(format!(
        "commits missing a valid Signed-off-by trailer: {}",
        unsigned.join(", ")
    ))
    .into())
}

fn required_log_field<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
    field: &str,
) -> TaskResult<&'a str> {
    fields
        .next()
        .ok_or_else(|| io::Error::other(format!("git log record is missing {field}")).into())
}

fn parse_identity(identity: &str) -> Option<(&str, &str)> {
    let identity = identity.trim();
    let (name, email) = identity.rsplit_once(" <")?;
    let email = email.strip_suffix('>')?;
    if name.trim().is_empty() || !email.contains('@') {
        return None;
    }
    Some((name.trim(), email))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use cargo_metadata::PackageId;

    use super::{
        APPLE_BRIDGE_C_ABI_COUNT_MESSAGE, CANONICAL_TERSA_MAC_BRIDGING_HEADER,
        CANONICAL_TERSA_RUST_BRIDGE_HEADER, MAILBOX_SYNC_FFI_C_ABI_COUNT_MESSAGE,
        REVIEWED_BROKER_SYNC_SECRETS_DEINIT_PATH, REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH,
        REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_DEINIT_PATH,
        REVIEWED_TOKEN_BROKER_WIRE_STATUSES, ResolvedDependencyIdentity,
        TOKEN_BROKER_ALLOWED_SOURCE_PATHS, TOKEN_BROKER_FFI_C_ABI_COUNT_MESSAGE,
        apple_bridge_direct_dependency_set_violations, blob_dependency_graph_violations,
        blob_manifest_dependency_violations, bridge_bootstrap_source_violations,
        bridge_package_source_surface_violations, canonical_cli_source_anchor_violations,
        check_diagnostic_runtime_reachability, cli_direct_dependency_set_violations,
        cli_keychain_source_violations, collect_entitlement_paths, dependency_policy,
        expected_apple_c_abi_exports, expected_mailbox_sync_ffi_c_abi_exports,
        expected_token_broker_ffi_c_abi_exports, future_macos_store_dependency_violation,
        gmail_dependency_graph_violations, gmail_manifest_dependency_violations,
        gmail_resolved_feature_violations, is_dioxus_runtime_dependency,
        is_slint_runtime_dependency, keychain_direct_dependency_set_violations,
        keychain_mutation_boundary_violations, macos_client_xpc_wiring_violations,
        mailbox_sync_ffi_direct_dependency_set_violations,
        mailbox_sync_ffi_source_surface_violations, non_owner_entitlement_violations,
        oauth_sync_direct_dependency_set_violations, parse_identity, parse_plist_string_array,
        parse_project_targets, project_generation_surface_violations, project_generation_wrapper,
        protected_keychain_dependency_rename_violations, reserved_future_policy_violations,
        resolved_workspace_dependency_names, retrieval_tokio_denial_violations,
        rusqlite_resolved_feature_violations, rust_authority_source_surface_violations,
        rust_exported_c_abi_violations, rustix_manifest_dependency_violations,
        shipped_direct_dependency_names, signing_configuration_violations,
        source_token_broker_entitlement_violations, sqlcipher_dependency_graph_violations,
        sqlcipher_manifest_dependency_violations, strip_rust_non_code, strip_rust_test_modules,
        swift_bootstrap_inventory_violations, swift_bootstrap_source_inventory,
        swift_bootstrap_source_violations, swift_bridge_call_inventory,
        swift_ffi_symbol_inventory_violations, swift_oauth_foreground_handoff_violations,
        swift_source_lexical_violations, target_metadata_options,
        token_broker_bridge_header_c_abi_violations,
        token_broker_code_signing_requirement_violations,
        token_broker_ffi_source_surface_violations, token_broker_protocol_mirror_violations,
        token_broker_source_surface_violations, token_broker_wire_status_coherence_violations,
        tracked_apple_signing_inventory, tracked_project_generation_violations,
    };

    const VALID_ENTITLEMENTS: &str = r#"<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.network.client</key><true/>
<key>com.apple.security.network.server</key><true/>
<key>com.apple.security.application-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
<key>keychain-access-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
</dict></plist>"#;

    const VALID_BROKER_ENTITLEMENTS: &str = r#"<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.network.client</key><true/>
<key>keychain-access-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.token</string></array>
</dict></plist>"#;

    const VALID_SIGNING_PROJECT: &str = r#"
name: Tersa
options:
  bundleIdPrefix: app.tersa
  deploymentTarget:
    macOS: "15.0"
    iOS: "18.0"
  xcodeVersion: "26.0"
settings: {}
targets:
  TersaMac:
    type: application
    platform: macOS
    sources:
      - path: macos
      - path: licenses/THIRD_PARTY_NOTICES-bridge-macos.txt
        buildPhase: resources
    info: {}
    entitlements:
      path: macos/TersaMac.entitlements
      properties:
        com.apple.security.app-sandbox: true
        com.apple.security.network.client: true
        com.apple.security.network.server: true
        com.apple.security.application-groups:
          - ${TeamIdentifierPrefix}app.tersa.shared
        keychain-access-groups:
          - ${TeamIdentifierPrefix}app.tersa.shared
    dependencies:
      - target: TersaMacTokenBroker
        embed: true
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac
        TERSA_MACOS_APP_GROUP: "$(TeamIdentifierPrefix)app.tersa.shared"
        CODE_SIGN_ENTITLEMENTS: macos/TersaMac.entitlements
        OTHER_LDFLAGS:
          - "$(SRCROOT)/build/rust/$(PLATFORM_NAME)/$(CONFIGURATION)/libtersa_mailbox_sync_ffi_macos.a"
    preBuildScripts:
      - name: Build Rust static library
        basedOnDependencyAnalysis: false
        script: 'sh "${SRCROOT}/scripts/build-rust-staticlib.sh" macos "${CONFIGURATION}"'
    scheme:
      testTargets:
        - TersaMacTests
  TersaMacTokenBroker:
    type: xpc-service
    platform: macOS
    sources:
      - path: macos-token-broker
    info:
      path: macos-token-broker/Info.plist
      properties:
        CFBundlePackageType: XPC!
        XPCService:
          ServiceType: Application
        TersaOAuthClientID: "$(TERSA_OAUTH_CLIENT_ID)"
    entitlements:
      path: macos-token-broker/TersaMacTokenBroker.entitlements
      properties:
        com.apple.security.app-sandbox: true
        com.apple.security.network.client: true
        keychain-access-groups:
          - ${TeamIdentifierPrefix}app.tersa.token
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac.token-broker
        PRODUCT_NAME: TersaMacTokenBroker
        MACOSX_DEPLOYMENT_TARGET: "15.0"
        CODE_SIGN_ENTITLEMENTS: macos-token-broker/TersaMacTokenBroker.entitlements
        SKIP_INSTALL: "YES"
        SWIFT_OBJC_BRIDGING_HEADER: macos-token-broker/TersaMacTokenBroker-Bridging-Header.h
        TERSA_MACOS_TOKEN_GROUP: "$(TeamIdentifierPrefix)app.tersa.token"
        ENABLE_USER_SCRIPT_SANDBOXING: "NO"
        OTHER_LDFLAGS:
          - "$(SRCROOT)/build/rust/$(PLATFORM_NAME)/$(CONFIGURATION)/libtersa_token_broker_ffi_macos.a"
    preBuildScripts:
      - name: Build Rust token-broker static library
        basedOnDependencyAnalysis: false
        script: 'sh "${SRCROOT}/scripts/build-rust-staticlib.sh" macos-token-broker "${CONFIGURATION}"'
  TersaMacTests:
    type: bundle.unit-test
    platform: macOS
    sources:
      - path: macos-tests
      - path: macos/ConnectionOperationDeadline.swift
      - path: macos/ConnectionState.swift
      - path: macos/DisconnectIntentStore.swift
      - path: macos/MailboxLifecyclePresentation.swift
      - path: macos/TokenBrokerProtocol.swift
      - path: macos/TokenBrokerClient.swift
      - path: macos/TokenBrokerStatusMapping.swift
      - path: macos/TokenBrokerAuthorizationSession.swift
      - path: macos-token-broker/TokenBrokerCallbackBuffer.swift
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac.tests
        MACOSX_DEPLOYMENT_TARGET: "15.0"
  OtherMac:
    platform: macOS
  OtherIOS:
    platform: iOS
"#;

    static TEMPORARY_REPOSITORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temporary_repository(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tersa-{label}-{}-{}",
            std::process::id(),
            TEMPORARY_REPOSITORY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("temporary repository must be created");
        let status = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["init", "--quiet"])
            .status()
            .expect("git init must execute");
        assert!(status.success(), "git init must succeed");
        root
    }

    fn git_add(repository: &Path, force: bool, paths: &[&str]) {
        let mut command = Command::new("git");
        command.arg("-C").arg(repository).arg("add");
        if force {
            command.arg("--force");
        }
        let status = command
            .args(["--"])
            .args(paths)
            .status()
            .expect("git add must execute");
        assert!(status.success(), "git add must succeed");
    }

    #[test]
    fn parses_a_well_formed_identity() {
        assert_eq!(
            parse_identity("Example Contributor <contributor@example.com>"),
            Some(("Example Contributor", "contributor@example.com"))
        );
    }

    #[test]
    fn rejects_an_incomplete_identity() {
        assert_eq!(parse_identity("Example Contributor"), None);
        assert_eq!(parse_identity("<contributor@example.com>"), None);
        assert_eq!(parse_identity("Example <invalid>"), None);
    }

    #[test]
    fn recognizes_the_complete_dioxus_runtime_boundary() {
        assert!(is_dioxus_runtime_dependency("dioxus"));
        assert!(is_dioxus_runtime_dependency("dioxus-core"));
        assert!(is_dioxus_runtime_dependency("wry"));
        assert!(is_dioxus_runtime_dependency("tao"));
        assert!(!is_dioxus_runtime_dependency("tersa-domain"));
    }

    #[test]
    fn recognizes_the_complete_slint_runtime_boundary() {
        assert!(is_slint_runtime_dependency("slint"));
        assert!(is_slint_runtime_dependency("slint-build"));
        assert!(is_slint_runtime_dependency("slint-macros"));
        assert!(is_slint_runtime_dependency("i-slint-core"));
        assert!(!is_slint_runtime_dependency("tersa-domain"));
    }

    #[test]
    fn activated_store_name_is_not_reserved() {
        assert_eq!(
            dependency_policy()["tersa-store-sqlcipher-macos"],
            BTreeSet::from(["tersa-application", "tersa-domain"])
        );
    }

    #[test]
    fn activates_the_cli_boundary() {
        assert_eq!(
            dependency_policy()["tersa-cli-macos"],
            BTreeSet::from(["tersa-application", "tersa-domain", "tersa-keychain-macos"])
        );
    }

    #[test]
    fn activates_the_keychain_read_boundary() {
        assert_eq!(
            dependency_policy()["tersa-keychain-macos"],
            BTreeSet::from([
                "tersa-application",
                "tersa-platform",
                "tersa-presentation",
                "tersa-store-sqlcipher-macos",
            ])
        );
    }

    #[test]
    fn activates_the_token_broker_core_boundary() {
        assert_eq!(
            dependency_policy()["tersa-token-broker-core"],
            BTreeSet::from(["tersa-application"])
        );
    }

    #[test]
    fn activates_the_token_broker_ffi_boundary() {
        assert_eq!(
            dependency_policy()["tersa-token-broker-ffi-macos"],
            BTreeSet::from([
                "tersa-application",
                "tersa-domain",
                "tersa-gmail-rest-macos",
                "tersa-keychain-macos",
                "tersa-token-broker-core",
            ])
        );
    }

    #[test]
    fn keychain_direct_dependencies_are_a_closed_exact_set() {
        let exact = BTreeSet::from([
            "core-foundation",
            "hkdf",
            "objc2-foundation",
            "rustix",
            "security-framework-sys",
            "sha2",
            "tersa-application",
            "tersa-platform",
            "tersa-presentation",
            "tersa-store-sqlcipher-macos",
            "zeroize",
        ]);
        assert!(keychain_direct_dependency_set_violations(&exact).is_empty());

        let mut unknown = exact.clone();
        unknown.insert("unexpected-crypto");
        assert_eq!(
            keychain_direct_dependency_set_violations(&unknown),
            vec![
                "tersa-keychain-macos -> unexpected-crypto (dependency is outside the closed Keychain adapter set)"
            ]
        );

        let mut missing = exact.clone();
        missing.remove("zeroize");
        assert_eq!(
            keychain_direct_dependency_set_violations(&missing),
            vec!["tersa-keychain-macos is missing required direct dependency zeroize"]
        );

        let mut direct_hmac = exact;
        direct_hmac.insert("hmac");
        assert_eq!(
            keychain_direct_dependency_set_violations(&direct_hmac),
            vec![
                "tersa-keychain-macos -> hmac (direct HMAC is forbidden; only resolved HKDF to HMAC reachability is allowed)"
            ]
        );
    }

    #[test]
    fn apple_bridge_direct_dependencies_are_a_closed_exact_set() {
        let exact = BTreeSet::from([
            "tersa-application",
            "tersa-keychain-macos",
            "tersa-presentation",
            "url",
            "zeroize",
        ]);
        assert!(apple_bridge_direct_dependency_set_violations(&exact).is_empty());

        let mut broadened = exact;
        broadened.insert("tersa-domain");
        assert_eq!(
            apple_bridge_direct_dependency_set_violations(&broadened),
            vec![
                "tersa-apple-bridge -> tersa-domain (dependency is outside the closed Apple bridge set)"
            ]
        );
    }

    #[test]
    fn rustix_direct_ownership_features_and_targets_are_exact() {
        assert!(
            rustix_manifest_dependency_violations(
                "tersa-blob-spike",
                "=1.1.4",
                false,
                None,
                &["fs".to_owned(), "std".to_owned()],
            )
            .is_empty()
        );
        assert!(
            rustix_manifest_dependency_violations(
                "tersa-keychain-macos",
                "=1.1.4",
                false,
                Some(r#"cfg(target_os = "macos")"#),
                &["fs".to_owned(), "process".to_owned(), "std".to_owned()],
            )
            .is_empty()
        );
        assert!(
            rustix_manifest_dependency_violations(
                "tersa-store-sqlcipher-macos",
                "=1.1.4",
                false,
                Some(r#"cfg(target_os = "macos")"#),
                &["fs".to_owned(), "std".to_owned()],
            )
            .is_empty()
        );

        assert!(
            !rustix_manifest_dependency_violations(
                "tersa-store-sqlcipher-macos",
                "=1.1.4",
                false,
                Some(r#"cfg(target_os = "ios")"#),
                &["fs".to_owned(), "process".to_owned(), "std".to_owned()],
            )
            .is_empty()
        );
        assert_eq!(
            rustix_manifest_dependency_violations(
                "tersa-apple-bridge",
                "=1.1.4",
                false,
                Some(r#"cfg(target_os = "macos")"#),
                &["fs".to_owned(), "std".to_owned()],
            ),
            vec!["tersa-apple-bridge -> rustix is outside the closed direct-owner set"]
        );
    }

    #[test]
    fn cli_source_guard_allows_only_retrieval_items_and_rejects_aliases() {
        let allowed = r"
let reader = tersa_keychain_macos::open_default_read_only_mailbox(account)?;
let error = tersa_keychain_macos::ReadOnlyMailboxOpenError::KeyAccess;
";
        assert!(cli_keychain_source_violations("cli.rs", allowed).is_empty());
        let whitespace_equivalent = r"
let reader = tersa_keychain_macos :: open_default_read_only_mailbox(account)?;
let error = tersa_keychain_macos :: ReadOnlyMailboxOpenError::KeyAccess;
";
        assert!(
            cli_keychain_source_violations("cli.rs", whitespace_equivalent).is_empty(),
            "token-equivalent qualified retrieval paths must remain accepted"
        );

        for forbidden in [
            "tersa_keychain_macos::bootstrap_default_account_bytes(bytes);",
            "tersa_keychain_macos :: bootstrap_default_account_bytes(bytes);",
            "tersa_keychain_macos\u{000b}::\u{000b}bootstrap_default_account_bytes\u{000b}(bytes);",
            "let open = tersa_keychain_macos :: open_default_read_only_mailbox;",
            "use tersa_keychain_macos::*;",
            "use tersa_keychain_macos :: open_default_read_only_mailbox;",
            "use tersa_keychain_macos::open_default_read_only_mailbox as open;",
            "pub use tersa_keychain_macos::ProductBootstrapStatus;",
            "extern crate tersa_keychain_macos as keychain;",
            "let model = tersa_keychain_macos::mailbox_read::read_default_inbox(account, limit);",
            "let model = tersa_keychain_macos::mailbox_read::read_default_thread(account, thread, limit);",
            "let model = tersa_keychain_macos::mailbox_read::search_default_mailbox(account, query, limit);",
            "let status = tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok;",
            "use tersa_keychain_macos::mailbox_read::MailboxReadStatus;",
        ] {
            assert!(
                !cli_keychain_source_violations("cli.rs", forbidden).is_empty(),
                "fixture must fail: {forbidden}"
            );
        }
    }

    #[test]
    fn rust_test_module_masking_never_crosses_a_production_item() {
        let directly_governed = strip_rust_non_code(
            r#"
#[cfg(test)]
#[cfg_attr(target_os = "macos", expect(unsafe_code))]
mod tests {
    fn helper() {
        tersa_keychain_macos::bootstrap_default_account_bytes(&[]);
    }
}
fn production() { safe(); }
"#,
        );
        let masked = strip_rust_test_modules(&directly_governed);
        assert!(!masked.contains("bootstrap_default_account_bytes"));
        assert!(masked.contains("fn production"));

        let separated = strip_rust_non_code(
            r"
#[cfg(test)]
const TEST_MARKER: () = ();
fn production() {
    tersa_keychain_macos::bootstrap_default_account_bytes(&[]);
}
mod later {}
",
        );
        let visible = strip_rust_test_modules(&separated);
        assert!(
            visible.contains("bootstrap_default_account_bytes"),
            "a cfg(test) attribute on a non-module item must not mask later production code"
        );

        let unicode = "#[cfg(test)]\nmod tests { const VALUE: &str = \"caffè\"; }\nfn production() { protected(); }\n";
        let unicode_masked = strip_rust_test_modules(unicode);
        assert_eq!(unicode_masked.len(), unicode.len());
        assert!(unicode_masked.contains("fn production() { protected(); }"));

        let literal_pseudo_module = r##"
const EXAMPLE: &str = "#[cfg(test)] mod scratch {";
fn production() { protected(); }
"##;
        let literal_masked = strip_rust_test_modules(literal_pseudo_module);
        assert!(literal_masked.contains("fn production() { protected(); }"));
    }

    #[test]
    fn keychain_mutation_inventory_is_code_aware_and_closed_over_rust_sources() {
        let required = r"
fn boundary() {
    SecItemAdd();
    SecItemCopyMatching();
    SecRandomCopyBytes();
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly();
    kSecUseDataProtectionKeychain();
}
";
        let clean = vec![
            (
                PathBuf::from("adapters/keychain-macos/src/lib.rs"),
                required.to_owned(),
            ),
            (
                PathBuf::from("adapters/keychain-macos/src/helper.rs"),
                "// SecItemDelete();\nconst NOTE: &str = \"ordinary diagnostic\";".to_owned(),
            ),
        ];
        assert!(keychain_mutation_boundary_violations(&clean, &clean).is_empty());

        for source in [
            "fn mutate() { SecItemDelete(); }",
            "fn mutate() { SecItemUpdate(); }",
            "fn mutate() { SecKeychainItemDelete(item); }",
            "fn mutate() { set_generic_password(); }",
            "fn mutate() { dlsym(handle, \"SecItemDelete\"); }",
            "const FORBIDDEN_SYMBOL: &str = \"SecItemDelete\";",
            "#[link_name = \"SecItemUpdate\"] extern \"C\" { fn alias(); }",
            "#[export_name = \"SecItemDelete\"] fn alias() {}",
            "global_asm!(\"call _SecItemDelete\");",
            "asm!(\"call _SecItemUpdate\");",
            r#"
// Historical example: #[cfg(test)] mod scratch {
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    #[link_name = "SecItemDelete"]
    fn hidden_alias(query: *const core::ffi::c_void) -> i32;
}
"#,
            r##"
const EXAMPLE: &str = "#[cfg(test)] mod scratch {";
#[link_name = "SecItemDelete"]
unsafe extern "C" { fn hidden_string_alias(); }
"##,
        ] {
            let mut contaminated = clean.clone();
            contaminated.push((
                PathBuf::from("adapters/keychain-macos/src/nested/authority.rs"),
                source.to_owned(),
            ));
            assert!(
                !keychain_mutation_boundary_violations(&clean, &contaminated).is_empty(),
                "tracked nested Rust source must remain governed: {source}"
            );
        }

        let mut unauthorized_insertion = clean.clone();
        unauthorized_insertion.push((
            PathBuf::from("apple/rust-bridge/src/injected.rs"),
            "fn provision() { SecItemAdd(); }".to_owned(),
        ));
        assert!(
            !keychain_mutation_boundary_violations(&clean, &unauthorized_insertion).is_empty(),
            "Keychain insertion authority must remain exclusive to the owning adapter"
        );

        let comments_only = vec![(
            PathBuf::from("adapters/keychain-macos/src/lib.rs"),
            "// SecItemAdd SecItemCopyMatching SecRandomCopyBytes kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly kSecUseDataProtectionKeychain"
                .to_owned(),
        )];
        assert_eq!(
            keychain_mutation_boundary_violations(&comments_only, &comments_only).len(),
            5,
            "comments must not satisfy required production boundaries"
        );
    }

    #[test]
    fn keychain_token_mutation_is_fixed_to_the_token_service() {
        let root = |body: &str| {
            (
                PathBuf::from("adapters/keychain-macos/src/lib.rs"),
                format!(
                    "fn boundary() {{ SecItemAdd(); SecItemCopyMatching(); SecRandomCopyBytes(); kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly(); kSecUseDataProtectionKeychain(); }}\n{body}"
                ),
            )
        };
        let token = |body: &str| (PathBuf::from(super::TOKEN_MUTATION_FILE), body.to_owned());
        let valid_token = r#"
fn token_ops() {
    const TOKEN_SERVICE: &str = "app.tersa.mac.oauth-refresh-token.v1";
    let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    keychain_item::SecItemUpdate(query, attrs);
    keychain_item::SecItemDelete(query);
}
"#;

        // The canonical token file, scoped to TOKEN_SERVICE, may rotate + delete.
        let clean = vec![root(""), token(valid_token)];
        assert!(
            keychain_mutation_boundary_violations(&clean, &clean).is_empty(),
            "a token file scoped to TOKEN_SERVICE may rotate and delete its item"
        );

        // Every attempt to escape the token boundary must fail closed.
        for bad in [
            // No positive TOKEN_SERVICE / accessibility scope.
            "fn t() { keychain_item::SecItemUpdate(q, a); }",
            // Names the root service identifier.
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; let s = SERVICE; keychain_item::SecItemDelete(q); }",
            // Names the root service literal directly.
            "fn t() { const TOKEN_SERVICE: &str = \"app.tersa.mac.storage-root.v1\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; keychain_item::SecItemDelete(q); }",
            // Uses the root accessibility literal.
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly; keychain_item::SecItemDelete(q); }",
            // Assembles a service string dynamically.
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; let s = format!(\"a{}\", p); keychain_item::SecItemDelete(q); }",
            // Hand-declares the mutation symbol instead of using the sys binding.
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; } #[link_name = \"SecItemDelete\"] unsafe extern \"C\" { fn a(); }",
            // Hides the root separator behind a unicode escape (Sol's bypass).
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; let s = \"app.tersa.mac.storage\\u{2d}root.v1\"; keychain_item::SecItemDelete(q); }",
            // Imports the service from external content.
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; let s = include_str!(\"svc.txt\"); keychain_item::SecItemDelete(q); }",
            // Reads a compile-time env var as the service.
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; let s = env!(\"SVC\"); keychain_item::SecItemDelete(q); }",
            // Builds the root service from a byte-string literal.
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; let s = b\"app.tersa.mac.storage-root.v1\"; keychain_item::SecItemDelete(q); }",
            // Suffixes the token service so a `starts_with` allowlist would admit it.
            "fn t() { const TOKEN_SERVICE: &str = \"app.tersa.mac.oauth-refresh-token.v1.evil\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; keychain_item::SecItemDelete(q); }",
            // Raw byte-string evades a plain `b\"` / `br\"` byte-literal ban.
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; let s = br#\"svc\"#; keychain_item::SecItemDelete(q); }",
            // Suffix with a `/` the continuation-char set missed (Sol round-2b).
            "fn t() { const TOKEN_SERVICE: &str = \"app.tersa.mac.oauth-refresh-token.v1/evil\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; keychain_item::SecItemDelete(q); }",
            // Raw string with an embedded quote defeats a naive closing-quote check.
            "fn t() { const TOKEN_SERVICE: &str = \"x\"; let _ = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; let s = r#\"app.tersa.mac.oauth-refresh-token.v1\"/evil\"#; keychain_item::SecItemDelete(q); }",
        ] {
            let sources = vec![root(""), token(bad)];
            assert!(
                !keychain_mutation_boundary_violations(&sources, &sources).is_empty(),
                "token file must fail closed: {bad}"
            );
        }

        // Every other owner file stays add-only: the root key is immutable.
        for forbidden in ["SecItemUpdate", "SecItemDelete", "set_generic_password"] {
            let sources = vec![
                root(&format!("fn rogue() {{ {forbidden}(); }}")),
                token(valid_token),
            ];
            assert!(
                !keychain_mutation_boundary_violations(&sources, &sources).is_empty(),
                "root-key owner files must stay add-only: {forbidden}"
            );
        }

        // A second owner file (not the canonical token file) may not mutate.
        let second = vec![
            root(""),
            token(valid_token),
            (
                PathBuf::from("adapters/keychain-macos/src/rogue.rs"),
                "fn r() { keychain_item::SecItemUpdate(q, a); }".to_owned(),
            ),
        ];
        assert!(
            !keychain_mutation_boundary_violations(&second, &second).is_empty(),
            "only the canonical token file may mutate the token item"
        );
    }

    #[test]
    fn swift_product_sources_cannot_mutate_the_protected_keychain_record() {
        let owner = vec![(
            PathBuf::from("adapters/keychain-macos/src/lib.rs"),
            r"
fn boundary() {
    SecItemAdd();
    SecItemCopyMatching();
    SecRandomCopyBytes();
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly();
    kSecUseDataProtectionKeychain();
}
"
            .to_owned(),
        )];
        let protected_record = r#"
import Security

let protectedRecord: [CFString: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecAttrService: "app.tersa.mac.storage-root.v1",
    kSecAttrAccount: "default",
]
"#;
        for (mutation, call) in [
            (
                "SecItemAdd",
                "SecItemAdd(protectedRecord as CFDictionary, nil)",
            ),
            (
                "SecItemUpdate",
                "SecItemUpdate(protectedRecord as CFDictionary, [kSecValueData: Data()] as CFDictionary)",
            ),
            (
                "SecItemDelete",
                "SecItemDelete(protectedRecord as CFDictionary)",
            ),
        ] {
            let app_delegate = vec![(
                PathBuf::from("apple/macos/AppDelegate.swift"),
                format!("{protected_record}\nfunc mutateProtectedRecord() {{ {call} }}"),
            )];
            let violations = keychain_mutation_boundary_violations(&owner, &app_delegate);
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(mutation)),
                "direct Swift mutation must fail closed for {mutation}: {violations:?}"
            );
        }

        let inert = vec![(
            PathBuf::from("apple/macos/AppDelegate.swift"),
            r#"
import Security
// SecItemDelete(protectedRecord as CFDictionary)
let diagnostic = "SecItemAdd SecItemUpdate SecItemDelete"
let legacyDiagnostic = "SecKeychainItemDelete"
"#
            .to_owned(),
        )];
        assert!(
            keychain_mutation_boundary_violations(&owner, &inert).is_empty(),
            "inert Swift comments and strings must not create authority"
        );
    }

    #[test]
    fn swift_keychain_authority_rejects_dynamic_aliases_and_source_expansion() {
        let owner = vec![(
            PathBuf::from("adapters/keychain-macos/src/lib.rs"),
            r"
fn boundary() {
    SecItemAdd();
    SecItemCopyMatching();
    SecRandomCopyBytes();
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly();
    kSecUseDataProtectionKeychain();
}
"
            .to_owned(),
        )];
        for source in [
            "let mutation = SecItemDelete",
            "let symbol = dlsym(nil, \"SecItemDelete\")",
            "@_silgen_name(\"SecItemUpdate\") func updateAlias() -> OSStatus",
            "let symbol = CFBundleGetFunctionPointerForName(bundle, \"SecItemAdd\" as CFString)",
            "SecKeychainItemDelete(item)",
        ] {
            let expanded_sources = vec![(
                PathBuf::from("apple/macos/Injected.swift"),
                source.to_owned(),
            )];
            let violations = keychain_mutation_boundary_violations(&owner, &expanded_sources);
            assert!(
                !violations.is_empty(),
                "expanded Swift authority source must fail closed: {source}"
            );
        }
    }

    #[test]
    fn authority_sources_reject_expansion_and_non_ascii_code_outside_inert_text() {
        let path = Path::new("apps/cli-macos/out-of-tree.rs");
        for source in [
            "include!(\"outside.rs\");",
            "#[path = \"outside.rs\"] mod outside;",
            "fn authority() { generated\u{0085}call(); }",
            "fn authority() { generated\u{200e}call(); }",
            "fn authority() { generated\u{200f}call(); }",
            "fn authority() { generated\u{2028}call(); }",
            "fn authority() { generated\u{2029}call(); }",
        ] {
            assert!(
                !rust_authority_source_surface_violations(path, source).is_empty(),
                "governed out-of-tree authority source must fail closed: {source:?}"
            );
        }
        let inert = "// Unicode π is inert.\nconst NOTE: &str = \"Unicode café is inert\";\n#[cfg(test)] mod tests { fn 測試() {} }";
        assert!(rust_authority_source_surface_violations(path, inert).is_empty());
    }

    fn bridge_export_violations(sources: &[(PathBuf, String)]) -> Vec<String> {
        rust_exported_c_abi_violations(
            sources,
            &expected_apple_c_abi_exports(),
            APPLE_BRIDGE_C_ABI_COUNT_MESSAGE,
        )
    }

    #[test]
    fn authority_sources_reject_cfg_attr_path_and_aliased_include_macros() {
        let path = Path::new("apps/cli-macos/out-of-tree.rs");
        for source in [
            "#[cfg_attr(target_os = \"macos\", path = \"payload.inc\")] mod payload;",
            "#[cfg_attr(all(unix), cfg_attr(target_os = \"macos\", path = \"x.inc\"))] mod y;",
            "#[cfg_attr(unix, path(\"payload.inc\"))] mod payload;",
            "#[r#path = \"payload.inc\"] mod payload;",
            "#[r#cfg_attr(unix, path = \"payload.inc\")] mod payload;",
            "use std::include as inject;\ninject!(\"payload.inc\");",
            "use std::include_str as inject_str;\nconst PAYLOAD: &str = inject_str!(\"payload.inc\");",
            "use std::include_bytes as ib;",
            "pub use std::{include as inject};",
            "fn authority() { use std::include as inject; inject!(\"payload.inc\"); }",
        ] {
            assert!(
                !rust_authority_source_surface_violations(path, source).is_empty(),
                "governed out-of-tree authority source must fail closed: {source:?}"
            );
        }
        let violations =
            rust_authority_source_surface_violations(path, "use std::include as inject;");
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("must not alias the include macro `include`")),
            "the include-macro alias violation must name the mechanism: {violations:?}"
        );
        for benign in [
            "#[cfg_attr(unix, inline)]\nfn authority() -> u32 { 1 }\n",
            "#[cfg_attr(all(not(target_os = \"macos\"), not(test)), expect(dead_code, reason = \"inert\"))]\nfn authority() {}\n",
            "#[cfg(test)] mod tests { use std::include as inject; #[cfg_attr(unix, path = \"x.inc\")] mod x; }",
        ] {
            assert!(
                rust_authority_source_surface_violations(path, benign).is_empty(),
                "benign production source must not trip the source-expansion guard: {benign:?}"
            );
        }
    }

    fn reviewed_apple_bridge_export_sources() -> (&'static str, &'static str, &'static str) {
        let lib = r#"
#[unsafe(no_mangle)]
pub extern "C" fn tersa_apple_bridge_version() -> u32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_macos_bootstrap_default_account(
    account_id: *const u8,
    account_id_len: usize,
) -> i32 {}
"#;
        let mailbox = r#"
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_macos_mailbox_read_inbox(
    account_id: *const u8,
    account_id_len: usize,
    limit: u16,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_macos_mailbox_read_thread(
    account_id: *const u8,
    account_id_len: usize,
    thread_id: *const u8,
    thread_id_len: usize,
    limit: u16,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_macos_mailbox_search(
    account_id: *const u8,
    account_id_len: usize,
    query: *const u8,
    query_len: usize,
    limit: u16,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {}
"#;
        let oauth = r#"
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_oauth_ios_begin(
    client_id: *const u8,
    client_id_len: usize,
    redirect_scheme: *const u8,
    redirect_scheme_len: usize,
    output_session_id: *mut u64,
    output_url: *mut u8,
    output_url_capacity: usize,
    output_url_len: *mut usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_oauth_ios_finish(
    session_id: u64,
    callback_url: *const u8,
    callback_url_len: usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub extern "C" fn tersa_oauth_cancel(session_id: u64) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_oauth_macos_begin(
    client_id: *const u8,
    client_id_len: usize,
    output_session_id: *mut u64,
    output_url: *mut u8,
    output_url_capacity: usize,
    output_url_len: *mut usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub extern "C" fn tersa_oauth_macos_poll(session_id: u64) -> i32 {}
#[unsafe(no_mangle)]
pub extern "C" fn tersa_oauth_macos_entitlement_probe() -> i32 {}
"#;
        (lib, mailbox, oauth)
    }

    fn reviewed_apple_bridge_documents(
        lib: String,
        mailbox: String,
        oauth: String,
    ) -> Vec<(PathBuf, String)> {
        vec![
            (PathBuf::from("apple/rust-bridge/src/lib.rs"), lib),
            (PathBuf::from("apple/rust-bridge/src/mailbox.rs"), mailbox),
            (PathBuf::from("apple/rust-bridge/src/oauth.rs"), oauth),
        ]
    }

    #[test]
    fn apple_bridge_export_inventory_pins_every_reviewed_signature() {
        let (lib, mailbox, oauth) = reviewed_apple_bridge_export_sources();
        let reviewed =
            reviewed_apple_bridge_documents(lib.to_owned(), mailbox.to_owned(), oauth.to_owned());
        assert!(bridge_export_violations(&reviewed).is_empty());

        for mutation in [
            lib.replace("account_id_len: usize", "account_id_len: u32"),
            lib.replacen("extern \"C\"", "extern \"system\"", 1),
            lib.replace(
                "tersa_macos_bootstrap_default_account",
                "tersa_macos_bootstrap_default_account_extra",
            ),
        ] {
            let contaminated =
                reviewed_apple_bridge_documents(mutation, mailbox.to_owned(), oauth.to_owned());
            assert!(
                !bridge_export_violations(&contaminated).is_empty(),
                "export name, set, and parameter widths must remain exact"
            );
        }
        for mutation in [
            mailbox.replace("limit: u16", "limit: u32"),
            mailbox.replacen("output: *mut u8", "output: *const u8", 1),
            mailbox.replace(
                "tersa_macos_mailbox_search",
                "tersa_macos_mailbox_search_all",
            ),
        ] {
            let contaminated =
                reviewed_apple_bridge_documents(lib.to_owned(), mutation, oauth.to_owned());
            assert!(
                !bridge_export_violations(&contaminated).is_empty(),
                "read export name, set, and parameter widths must remain exact"
            );
        }

        let twelfth_symbol = reviewed_apple_bridge_documents(
            format!(
                "{lib}\n#[unsafe(no_mangle)] pub extern \"C\" fn unexpected_export() -> i32 {{}}"
            ),
            mailbox.to_owned(),
            oauth.to_owned(),
        );
        let violations = bridge_export_violations(&twelfth_symbol);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("eleven reviewed symbols")),
            "a twelfth symbol must trip the reviewed-count message: {violations:?}"
        );

        let comment_mask_bypass = reviewed_apple_bridge_documents(
            lib.to_owned(),
            mailbox.to_owned(),
            format!(
                r#"{oauth}
mod compatibility {{
    // Historical example: #[cfg(test)] mod scratch {{
    #[unsafe(no_mangle)]
    pub extern "C" fn tersa_oauth_debug_dump(session_id: u64) -> i32 {{ 0 }}
}}
"#
            ),
        );
        assert!(
            !bridge_export_violations(&comment_mask_bypass).is_empty(),
            "a comment containing a pseudo cfg(test) module must not hide a production export"
        );

        let literal_mask_bypass = reviewed_apple_bridge_documents(
            lib.to_owned(),
            mailbox.to_owned(),
            format!(
                r##"{oauth}
mod compatibility {{
    const EXAMPLE: &str = "#[cfg(test)] mod scratch {{";
    #[unsafe(no_mangle)]
    pub extern "C" fn tersa_oauth_literal_dump(session_id: u64) -> i32 {{ 0 }}
}}
"##
            ),
        );
        assert!(
            !bridge_export_violations(&literal_mask_bypass).is_empty(),
            "a literal containing a pseudo cfg(test) module must not hide a production export"
        );
    }

    fn reviewed_mailbox_sync_ffi_export_source() -> &'static str {
        r#"
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_mailbox_macos_broker_sync_begin(
    account_id: *const u8,
    account_id_len: usize,
    access_token: *const u8,
    access_token_len: usize,
    subject: *const u8,
    subject_len: usize,
    output_session_id: *mut u64,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_mailbox_macos_broker_disconnect_prepare(
    account_id: *const u8,
    account_id_len: usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_mailbox_macos_broker_disconnect_finalize(
    account_id: *const u8,
    account_id_len: usize,
    revoke_unconfirmed: i32,
    output_session_id: *mut u64,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_mailbox_macos_broker_subject_store(
    account_id: *const u8,
    account_id_len: usize,
    subject: *const u8,
    subject_len: usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_mailbox_macos_broker_subject_get(
    account_id: *const u8,
    account_id_len: usize,
    output_subject: *mut u8,
    output_subject_capacity: usize,
    output_subject_len: *mut usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_mailbox_macos_lifecycle_get(
    account_id: *const u8,
    account_id_len: usize,
    output_recovery: *mut i32,
    output_last_successful_sync_unix_millis: *mut i64,
) -> i32 {}
#[unsafe(no_mangle)]
pub extern "C" fn tersa_mailbox_macos_sync_poll(session_id: u64) -> i32 {}
"#
    }

    fn reviewed_mailbox_sync_ffi_documents(lib: String) -> Vec<(PathBuf, String)> {
        vec![(
            PathBuf::from("adapters/mailbox-sync-ffi-macos/src/lib.rs"),
            lib,
        )]
    }

    fn ffi_export_violations(sources: &[(PathBuf, String)]) -> Vec<String> {
        rust_exported_c_abi_violations(
            sources,
            &expected_mailbox_sync_ffi_c_abi_exports(),
            MAILBOX_SYNC_FFI_C_ABI_COUNT_MESSAGE,
        )
    }

    fn reviewed_token_broker_ffi_export_source() -> &'static str {
        r#"
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_token_broker_begin_authorization(
    redirect_uri: *const u8,
    redirect_uri_len: usize,
    authorization_url_out: *mut u8,
    authorization_url_capacity: usize,
    authorization_url_len: *mut usize,
    session_handle_out: *mut u8,
    session_handle_capacity: usize,
    session_handle_len: *mut usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_token_broker_complete_authorization(
    session_handle: *const u8,
    session_handle_len: usize,
    callback_url: *const u8,
    callback_url_len: usize,
    access_token_out: *mut u8,
    access_token_capacity: usize,
    access_token_len: *mut usize,
    subject_out: *mut u8,
    subject_capacity: usize,
    subject_len: *mut usize,
    expires_out: *mut i64,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_token_broker_refresh_access_token(
    account_subject: *const u8,
    account_subject_len: usize,
    access_token_out: *mut u8,
    access_token_capacity: usize,
    access_token_len: *mut usize,
    subject_out: *mut u8,
    subject_capacity: usize,
    subject_len: *mut usize,
    expires_out: *mut i64,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_token_broker_revoke_provider_grant(
    account_subject: *const u8,
    account_subject_len: usize,
) -> i32 {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_token_broker_delete_stored_tokens(
    account_subject: *const u8,
    account_subject_len: usize,
) -> i32 {}
"#
    }

    fn reviewed_token_broker_ffi_documents(lib: String) -> Vec<(PathBuf, String)> {
        vec![(
            PathBuf::from("adapters/token-broker-ffi-macos/src/lib.rs"),
            lib,
        )]
    }

    fn token_broker_ffi_export_violations(sources: &[(PathBuf, String)]) -> Vec<String> {
        rust_exported_c_abi_violations(
            sources,
            &expected_token_broker_ffi_c_abi_exports(),
            TOKEN_BROKER_FFI_C_ABI_COUNT_MESSAGE,
        )
    }

    #[test]
    fn token_broker_ffi_export_inventory_pins_every_reviewed_signature() {
        let lib = reviewed_token_broker_ffi_export_source();
        assert!(
            token_broker_ffi_export_violations(&reviewed_token_broker_ffi_documents(
                lib.to_owned()
            ))
            .is_empty()
        );

        // Widening a parameter, changing the ABI, or renaming a symbol must trip.
        for mutation in [
            lib.replace("callback_url_len: usize", "callback_url_len: u32"),
            lib.replacen("extern \"C\"", "extern \"system\"", 1),
            lib.replace(
                "tersa_token_broker_delete_stored_tokens",
                "tersa_token_broker_delete_all_tokens",
            ),
        ] {
            assert!(
                !token_broker_ffi_export_violations(&reviewed_token_broker_ffi_documents(mutation))
                    .is_empty(),
                "token-broker FFI export name, set, and parameter widths must remain exact"
            );
        }

        // A sixth export (refresh-token export) must fail closed.
        let sixth = reviewed_token_broker_ffi_documents(format!(
            "{lib}\n#[unsafe(no_mangle)] pub unsafe extern \"C\" fn tersa_token_broker_export_refresh_token(account_subject: *const u8, account_subject_len: usize) -> i32 {{}}"
        ));
        let violations = token_broker_ffi_export_violations(&sixth);
        assert!(
            violations.iter().any(|violation| violation
                .contains("five reviewed begin, complete, refresh, revoke, and delete")),
            "a sixth token-broker export must trip the reviewed-count message: {violations:?}"
        );

        // Missing one of the five must fail closed.
        let missing = reviewed_token_broker_ffi_documents(lib.replace(
            r#"#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_token_broker_delete_stored_tokens(
    account_subject: *const u8,
    account_subject_len: usize,
) -> i32 {}
"#,
            "",
        ));
        assert!(
            !token_broker_ffi_export_violations(&missing).is_empty(),
            "missing a reviewed token-broker export must fail closed"
        );
    }

    #[test]
    fn token_broker_ffi_source_inventory_and_header_pin_five_symbols() {
        let manifest = "[package]\nname = \"tersa-token-broker-ffi-macos\"\n";
        let clean = vec![
            (
                PathBuf::from("adapters/token-broker-ffi-macos/Cargo.toml"),
                manifest.to_owned(),
            ),
            (
                PathBuf::from("adapters/token-broker-ffi-macos/src/lib.rs"),
                String::new(),
            ),
        ];
        assert!(token_broker_ffi_source_surface_violations(&clean).is_empty());

        let mut with_extra = clean.clone();
        with_extra.push((
            PathBuf::from("adapters/token-broker-ffi-macos/src/extra.rs"),
            String::new(),
        ));
        assert!(
            !token_broker_ffi_source_surface_violations(&with_extra).is_empty(),
            "an unreviewed extra token-broker FFI source must fail closed"
        );

        let header = include_str!("../../apple/macos-token-broker/TersaTokenBrokerBridge.h");
        assert!(
            token_broker_bridge_header_c_abi_violations(header).is_empty(),
            "reviewed bridge header must declare exactly the five C ABI symbols"
        );

        // Sixth header declaration fails closed.
        let sixth_header = format!(
            "{header}\nint32_t tersa_token_broker_export_refresh_token(const uint8_t *account_subject, size_t account_subject_len);\n"
        );
        let sixth_violations = token_broker_bridge_header_c_abi_violations(&sixth_header);
        assert!(
            sixth_violations.iter().any(|violation| {
                violation.contains("tersa_token_broker_export_refresh_token")
                    || violation.contains("exactly the five reviewed")
            }),
            "sixth header symbol must fail closed: {sixth_violations:?}"
        );

        // Missing/renamed header symbol fails closed.
        let renamed = header.replace(
            "tersa_token_broker_delete_stored_tokens",
            "tersa_token_broker_delete_all_tokens",
        );
        assert!(
            !token_broker_bridge_header_c_abi_violations(&renamed).is_empty(),
            "renamed header symbol must fail closed"
        );
        let missing = header.replace(
            "int32_t tersa_token_broker_delete_stored_tokens(\n    const uint8_t *account_subject,\n    size_t account_subject_len\n);\n",
            "",
        );
        assert!(
            !token_broker_bridge_header_c_abi_violations(&missing).is_empty(),
            "missing header symbol must fail closed"
        );
    }

    #[test]
    fn token_broker_wire_status_coherence_pins_rust_and_swift() {
        let rust = include_str!("../../adapters/token-broker-ffi-macos/src/lib.rs");
        let service = include_str!("../../apple/macos-token-broker/TokenBrokerProtocol.swift");
        let client = include_str!("../../apple/macos/TokenBrokerProtocol.swift");
        assert!(
            token_broker_wire_status_coherence_violations(rust, service, client).is_empty(),
            "Rust STATUS_* and Swift status enums must match the reviewed 0..=19 set; got {:?}",
            token_broker_wire_status_coherence_violations(rust, service, client)
        );

        // Renumber on the Rust side fails closed (not a self-comparison).
        let rust_renumbered = rust.replace(
            "const STATUS_IDENTITY_MISMATCH: i32 = 19;",
            "const STATUS_IDENTITY_MISMATCH: i32 = 20;",
        );
        assert!(
            token_broker_wire_status_coherence_violations(&rust_renumbered, service, client)
                .iter()
                .any(|violation| violation.contains("STATUS_*")),
            "Rust status renumber must fail closed"
        );

        // Renumber on the Swift service side fails closed.
        let service_renumbered =
            service.replace("case identityMismatch = 19", "case identityMismatch = 20");
        assert!(
            token_broker_wire_status_coherence_violations(rust, &service_renumbered, client)
                .iter()
                .any(|violation| violation.contains("TersaTokenBrokerStatusV1")),
            "service status renumber must fail closed"
        );

        // Renumber on the client mirror fails closed.
        let client_renumbered =
            client.replace("case identityMismatch = 19", "case identityMismatch = 20");
        assert!(
            token_broker_wire_status_coherence_violations(rust, service, &client_renumbered)
                .iter()
                .any(|violation| violation.contains("TokenBrokerStatus")),
            "client status renumber must fail closed"
        );

        // Inventory table itself is exactly twenty closed pairs 0..=19.
        assert_eq!(REVIEWED_TOKEN_BROKER_WIRE_STATUSES.len(), 20);
        for (index, (name, value)) in REVIEWED_TOKEN_BROKER_WIRE_STATUSES.iter().enumerate() {
            let expected = i64::try_from(index)
                .expect("reviewed wire-status inventory index fits in i64 (table is length 20)");
            assert_eq!(*value, expected, "{name}");
        }
    }

    #[test]
    fn mailbox_sync_ffi_export_inventory_pins_every_reviewed_signature() {
        let lib = reviewed_mailbox_sync_ffi_export_source();
        assert!(
            ffi_export_violations(&reviewed_mailbox_sync_ffi_documents(lib.to_owned())).is_empty()
        );

        // Widening a parameter, changing the ABI, or renaming a symbol must trip.
        for mutation in [
            lib.replace("access_token_len: usize", "access_token_len: u32"),
            lib.replacen("extern \"C\"", "extern \"system\"", 1),
            lib.replace(
                "tersa_mailbox_macos_sync_poll",
                "tersa_mailbox_macos_sync_poll_all",
            ),
        ] {
            assert!(
                !ffi_export_violations(&reviewed_mailbox_sync_ffi_documents(mutation)).is_empty(),
                "FFI export name, set, and parameter widths must remain exact"
            );
        }

        // An eighth exported symbol must trip the reviewed-count message.
        let eighth_symbol = reviewed_mailbox_sync_ffi_documents(format!(
            "{lib}\n#[unsafe(no_mangle)] pub extern \"C\" fn tersa_mailbox_macos_sync_extra() -> i32 {{}}"
        ));
        let violations = ffi_export_violations(&eighth_symbol);
        assert!(
            violations.iter().any(|violation| violation
                .contains("seven reviewed broker sync begin, disconnect prepare/finalize, subject store/get, lifecycle-query, and poll no_mangle exports")),
            "an eighth symbol must trip the reviewed-count message: {violations:?}"
        );

        // A resurrected legacy in-process begin is now an unexpected export and
        // must fail closed like any other unreviewed symbol.
        let legacy_begin = reviewed_mailbox_sync_ffi_documents(format!(
            "{lib}\n#[unsafe(no_mangle)] pub unsafe extern \"C\" fn tersa_mailbox_macos_sync_begin(client_id: *const u8, client_id_len: usize, account_id: *const u8, account_id_len: usize, output_session_id: *mut u64) -> i32 {{}}"
        ));
        assert!(
            !ffi_export_violations(&legacy_begin).is_empty(),
            "a legacy begin re-exported as no_mangle must fail closed"
        );

        // Missing one of the seven must fail closed.
        let missing = reviewed_mailbox_sync_ffi_documents(lib.replace(
            r#"#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_mailbox_macos_broker_disconnect_prepare(
    account_id: *const u8,
    account_id_len: usize,
) -> i32 {}
"#,
            "",
        ));
        assert!(
            !ffi_export_violations(&missing).is_empty(),
            "missing a reviewed broker export must fail closed"
        );
    }

    #[test]
    fn mailbox_sync_ffi_source_inventory_and_closed_dependency_set_pin() {
        let manifest = "[package]\nname = \"tersa-mailbox-sync-ffi-macos\"\n";
        let clean = vec![
            (
                PathBuf::from("adapters/mailbox-sync-ffi-macos/Cargo.toml"),
                manifest.to_owned(),
            ),
            (
                PathBuf::from("adapters/mailbox-sync-ffi-macos/src/lib.rs"),
                String::new(),
            ),
        ];
        assert!(mailbox_sync_ffi_source_surface_violations(&clean).is_empty());

        // An unreviewed extra source or a declared build script fails closed.
        let mut with_extra = clean.clone();
        with_extra.push((
            PathBuf::from("adapters/mailbox-sync-ffi-macos/src/extra.rs"),
            String::new(),
        ));
        assert!(
            !mailbox_sync_ffi_source_surface_violations(&with_extra).is_empty(),
            "an unreviewed extra source must fail closed"
        );
        let with_build = vec![
            (
                PathBuf::from("adapters/mailbox-sync-ffi-macos/Cargo.toml"),
                format!("{manifest}build = \"build.rs\"\n"),
            ),
            (
                PathBuf::from("adapters/mailbox-sync-ffi-macos/src/lib.rs"),
                String::new(),
            ),
        ];
        assert!(
            !mailbox_sync_ffi_source_surface_violations(&with_build).is_empty(),
            "a declared build script must fail closed"
        );

        // The closed direct-dependency set: exactly the five pass; a capability crate
        // or a missing required dependency fails.
        let exact = BTreeSet::from([
            "tersa-application",
            "tersa-apple-bridge",
            "tersa-oauth-sync-macos",
            "url",
            "zeroize",
        ]);
        assert!(mailbox_sync_ffi_direct_dependency_set_violations(&exact).is_empty());
        let mut hostile = exact.clone();
        hostile.insert("rusqlite");
        assert!(!mailbox_sync_ffi_direct_dependency_set_violations(&hostile).is_empty());
        let missing = BTreeSet::from(["tersa-application", "url"]);
        assert!(!mailbox_sync_ffi_direct_dependency_set_violations(&missing).is_empty());
        // ADR-0024: `zeroize` is an intentional direct dependency (short-lived
        // broker access-token buffers), so dropping it must fail closed with the
        // missing-required-dependency diagnostic naming it precisely.
        let without_zeroize = BTreeSet::from([
            "tersa-application",
            "tersa-apple-bridge",
            "tersa-oauth-sync-macos",
            "url",
        ]);
        let violations = mailbox_sync_ffi_direct_dependency_set_violations(&without_zeroize);
        assert!(
            violations.iter().any(|violation| violation
                == "tersa-mailbox-sync-ffi-macos is missing required direct dependency zeroize"),
            "dropping zeroize must fail closed naming the dependency: {violations:?}"
        );
    }

    #[test]
    fn mailbox_sync_ffi_source_surface_rejects_alternate_export_mechanisms() {
        let manifest = "[package]\nname = \"tersa-mailbox-sync-ffi-macos\"\n";
        // An export added through any mechanism other than a reviewed direct
        // `no_mangle` attribute must fail closed even though the `.rs` inventory
        // and the no_mangle count are both untouched.
        for source in [
            "#[unsafe(export_name = \"tersa_mailbox_macos_backdoor\")] pub extern \"C\" fn hidden() -> i32 { 0 }",
            "#[unsafe(link_name = \"tersa_mailbox_macos_backdoor\")] pub extern \"C\" fn hidden() -> i32 { 0 }",
            "#[unsafe(link_section = \"__TEXT,__text\")] pub extern \"C\" fn hidden() -> i32 { 0 }",
        ] {
            let documents = vec![
                (
                    PathBuf::from("adapters/mailbox-sync-ffi-macos/Cargo.toml"),
                    manifest.to_owned(),
                ),
                (
                    PathBuf::from("adapters/mailbox-sync-ffi-macos/src/lib.rs"),
                    source.to_owned(),
                ),
            ];
            assert!(
                !mailbox_sync_ffi_source_surface_violations(&documents).is_empty(),
                "an alternate export mechanism must fail closed: {source}"
            );
        }
    }

    #[test]
    fn mailbox_sync_ffi_source_surface_rejects_production_source_expansion() {
        let manifest = "[package]\nname = \"tersa-mailbox-sync-ffi-macos\"\n";
        // `include!` and `#[path]` expand a non-`.rs` file whose exported symbols
        // the `.rs`-only export inventory never scans.
        for source in [
            "include!(\"payload.inc\");",
            "#[path = \"payload.inc\"] mod payload;",
        ] {
            let documents = vec![
                (
                    PathBuf::from("adapters/mailbox-sync-ffi-macos/Cargo.toml"),
                    manifest.to_owned(),
                ),
                (
                    PathBuf::from("adapters/mailbox-sync-ffi-macos/src/lib.rs"),
                    source.to_owned(),
                ),
            ];
            assert!(
                !mailbox_sync_ffi_source_surface_violations(&documents).is_empty(),
                "production source expansion must fail closed: {source}"
            );
        }
    }

    #[test]
    fn apple_bridge_export_inventory_rejects_cfg_attr_no_mangle_without_text_false_positives() {
        let (lib, mailbox, oauth) = reviewed_apple_bridge_export_sources();
        for mutation in [
            format!(
                "{lib}\n#[cfg_attr(unix, unsafe(no_mangle))]\npub extern \"C\" fn cfg_gated_export() -> i32 {{ 0 }}"
            ),
            format!(
                "{lib}\n#[cfg_attr(unix, unsafe(no_mangle), inline)]\npub extern \"C\" fn cfg_gated_export() -> i32 {{ 0 }}"
            ),
        ] {
            let contaminated =
                reviewed_apple_bridge_documents(mutation, mailbox.to_owned(), oauth.to_owned());
            assert!(
                !bridge_export_violations(&contaminated).is_empty(),
                "production cfg_attr no_mangle exports must not evade the direct-attribute inventory"
            );
        }
        let inert = format!(
            r##"{lib}
// #[cfg_attr(unix, unsafe(no_mangle))]
const NOTE: &str = "#[cfg_attr(unix, unsafe(no_mangle))]";
#[cfg(test)] mod tests {{ #[cfg_attr(unix, unsafe(no_mangle))] pub extern "C" fn test_only_export() -> i32 {{ 0 }} }}
"##
        );
        let sources = reviewed_apple_bridge_documents(inert, mailbox.to_owned(), oauth.to_owned());
        assert!(
            bridge_export_violations(&sources).is_empty(),
            "comments, strings, and Rust test modules must remain inert to the production no_mangle inventory"
        );
    }

    struct BridgeSourceGraphFixture {
        manifest_path: PathBuf,
        lib_path: PathBuf,
        example_path: PathBuf,
        inventory: BTreeSet<PathBuf>,
        clean: Vec<(PathBuf, String)>,
    }

    fn bridge_source_graph_fixture() -> BridgeSourceGraphFixture {
        let manifest_path = PathBuf::from("apple/rust-bridge/Cargo.toml");
        let lib_path = PathBuf::from("apple/rust-bridge/src/lib.rs");
        let mailbox_path = PathBuf::from("apple/rust-bridge/src/mailbox.rs");
        let oauth_path = PathBuf::from("apple/rust-bridge/src/oauth.rs");
        let example_path = PathBuf::from("apple/rust-bridge/examples/oauth_entitlement_probe.rs");
        let inventory =
            BTreeSet::from([lib_path.clone(), mailbox_path.clone(), oauth_path.clone()]);
        let inert_source = r##"
// include!("outside.rs");
const EXAMPLE: &str = "#[path = \"outside.rs\"]";
#[cfg(test)]
mod tests {
    include!("fixture.rs");
    #[path = "helper.rs"] mod helper;
}
"##;
        let clean = vec![
            (
                manifest_path.clone(),
                "[package]\nname = \"tersa-apple-bridge\"\n[lib]\ncrate-type = [\"staticlib\"]\n"
                    .to_owned(),
            ),
            (lib_path.clone(), inert_source.to_owned()),
            (mailbox_path.clone(), String::new()),
            (oauth_path.clone(), String::new()),
            (example_path.clone(), String::new()),
        ];
        BridgeSourceGraphFixture {
            manifest_path,
            lib_path,
            example_path,
            inventory,
            clean,
        }
    }

    #[test]
    fn bridge_source_graph_accepts_the_reviewed_surface_and_rejects_example_injection() {
        let BridgeSourceGraphFixture {
            example_path,
            inventory,
            clean,
            ..
        } = bridge_source_graph_fixture();
        assert!(bridge_package_source_surface_violations(&clean, &inventory).is_empty());

        for injected in [
            "include\u{000b}!(\"../external.rs\");",
            "#\u{000b}[\u{000b}path = \"../external.rs\"] mod external;",
            "tersa_keychain_macos\u{000b}::\u{000b}bootstrap_default_account_bytes(bytes);",
        ] {
            let mut documents = clean.clone();
            documents
                .iter_mut()
                .find(|(path, _document)| path == &example_path)
                .expect("example fixture must exist")
                .1 = injected.to_owned();
            assert!(
                !bridge_package_source_surface_violations(&documents, &inventory).is_empty(),
                "all reviewed target sources must reject source or authority expansion: {injected}"
            );
        }
    }

    #[test]
    fn bridge_source_graph_rejects_unreviewed_source_items() {
        let BridgeSourceGraphFixture {
            inventory, clean, ..
        } = bridge_source_graph_fixture();

        let mut unreviewed = clean.clone();
        unreviewed.push((
            PathBuf::from("apple/rust-bridge/examples/alternate.rs"),
            String::new(),
        ));
        assert!(!bridge_package_source_surface_violations(&unreviewed, &inventory).is_empty());

        let mut unreviewed_keychain_source = clean.clone();
        unreviewed_keychain_source.push((
            PathBuf::from("apple/rust-bridge/src/mailbox_extra.rs"),
            "fn extra(account: &[u8], limit: u16) { let _ = tersa_keychain_macos::mailbox_read::read_default_inbox(account, limit); }"
                .to_owned(),
        ));
        assert!(
            !bridge_package_source_surface_violations(&unreviewed_keychain_source, &inventory)
                .is_empty(),
            "an unreviewed Keychain read source item must fail closed"
        );
    }

    #[test]
    fn bridge_source_graph_rejects_manifest_source_indirection() {
        let BridgeSourceGraphFixture {
            manifest_path,
            lib_path,
            inventory,
            ..
        } = bridge_source_graph_fixture();

        for manifest in [
            "[package]\nname = \"tersa-apple-bridge\"\nbuild = false\n",
            "[package]\nname = \"tersa-apple-bridge\"\n\"build\" = \"generate.rs\"\n",
            "[package]\nname = \"tersa-apple-bridge\"\n[lib]\npath = \"../external.rs\"\n",
        ] {
            let documents = vec![
                (manifest_path.clone(), manifest.to_owned()),
                (lib_path.clone(), String::new()),
            ];
            assert!(
                !bridge_package_source_surface_violations(&documents, &inventory).is_empty(),
                "Cargo source indirection must fail closed: {manifest}"
            );
        }

        let build_script = vec![
            (
                manifest_path.clone(),
                "[package]\nname = \"tersa-apple-bridge\"\n".to_owned(),
            ),
            (lib_path.clone(), String::new()),
            (
                PathBuf::from("apple/rust-bridge/build.rs"),
                "fn main() {}".to_owned(),
            ),
        ];
        assert!(!bridge_package_source_surface_violations(&build_script, &inventory).is_empty());
    }

    #[test]
    fn bridge_source_graph_rejects_production_source_expansion() {
        let BridgeSourceGraphFixture {
            manifest_path,
            lib_path,
            inventory,
            ..
        } = bridge_source_graph_fixture();

        for production_source in [
            "include!(\"../external.rs\");",
            "include ! (concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));",
            "#[path = \"../external.rs\"] mod external;",
            "# [ path = \"../external.rs\" ] mod external;",
            "#[cfg_attr(target_os = \"macos\", path = \"../external.rs\")] mod external;",
            "use std::include as inject;\ninject!(\"../external.rs\");",
        ] {
            let documents = vec![
                (
                    manifest_path.clone(),
                    "[package]\nname = \"tersa-apple-bridge\"\n".to_owned(),
                ),
                (lib_path.clone(), production_source.to_owned()),
            ];
            assert!(
                !bridge_package_source_surface_violations(&documents, &inventory).is_empty(),
                "production source expansion must fail closed: {production_source}"
            );
        }
    }

    fn reviewed_bridge_bootstrap_source() -> &'static str {
        r#"
pub unsafe extern "C" fn tersa_macos_bootstrap_default_account(account_id: *const u8, account_id_len: usize) -> i32 {
if account_id.is_null() || account_id_len == 0 || account_id_len > 256 { return 1; }
let bytes = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();
match tersa_keychain_macos::bootstrap_default_account_bytes(&bytes) {
    tersa_keychain_macos::ProductBootstrapStatus::Ready => 0,
    _ => 1,
}
}
pub unsafe extern "C" fn tersa_macos_mailbox_read_inbox(
    account_id: *const u8,
    account_id_len: usize,
    limit: u16,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
if account_id.is_null() || account_id_len == 0 || account_id_len > 256 || output.is_null() || output_len.is_null() { return tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32; }
let account = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();
let model = match tersa_keychain_macos::mailbox_read::read_default_inbox(&account, limit) {
    Ok(model) => model,
    Err(status) => return status as i32,
};
let encoded = encode_inbox(&model);
if unsafe { write_bounded_output(&encoded, output, output_capacity, output_len) } {
    tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32
} else {
    tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall as i32
}
}
pub unsafe extern "C" fn tersa_macos_mailbox_read_thread(
    account_id: *const u8,
    account_id_len: usize,
    thread_id: *const u8,
    thread_id_len: usize,
    limit: u16,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
if account_id.is_null() || account_id_len == 0 || account_id_len > 256 || thread_id.is_null() || thread_id_len == 0 || thread_id_len > 256 || output.is_null() || output_len.is_null() { return tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32; }
let account = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();
let thread = unsafe { slice::from_raw_parts(thread_id, thread_id_len) }.to_vec();
let model = match tersa_keychain_macos::mailbox_read::read_default_thread(&account, &thread, limit) {
    Ok(model) => model,
    Err(status) => return status as i32,
};
let encoded = encode_thread(&model);
if unsafe { write_bounded_output(&encoded, output, output_capacity, output_len) } {
    tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32
} else {
    tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall as i32
}
}
pub unsafe extern "C" fn tersa_macos_mailbox_search(
    account_id: *const u8,
    account_id_len: usize,
    query: *const u8,
    query_len: usize,
    limit: u16,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
if account_id.is_null() || account_id_len == 0 || account_id_len > 256 || query.is_null() || query_len == 0 || query_len > 256 || output.is_null() || output_len.is_null() { return tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput as i32; }
let account = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();
let query = unsafe { slice::from_raw_parts(query, query_len) }.to_vec();
let model = match tersa_keychain_macos::mailbox_read::search_default_mailbox(&account, &query, limit) {
    Ok(model) => model,
    Err(status) => return status as i32,
};
let encoded = encode_search(&model);
if unsafe { write_bounded_output(&encoded, output, output_capacity, output_len) } {
    tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32
} else {
    tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall as i32
}
}
"#
    }

    #[test]
    fn bridge_source_guard_accepts_the_reviewed_boundary_source() {
        assert!(bridge_bootstrap_source_violations(reviewed_bridge_bootstrap_source()).is_empty());
    }

    #[test]
    fn bridge_source_guard_rejects_bootstrap_boundary_drift() {
        let valid = reviewed_bridge_bootstrap_source();
        for forbidden in [
            valid.replacen(
                "tersa_macos_bootstrap_default_account",
                "tersa_macos_bootstrap_default_account_extra",
                1,
            ),
            valid.replace(
                "bootstrap_default_account_bytes",
                "alternate_bootstrap_entry",
            ),
            format!("{valid}\nuse tersa_keychain_macos as keychain;"),
            format!("{valid}\nlet _ = AccountId::new(value);"),
            format!(
                "{valid}\nlet _ = tersa_keychain_macos::bootstrap_default_account_bytes(&bytes);"
            ),
            valid.replace(".to_vec()", ".to_owned()"),
            valid.replace(
                "tersa_keychain_macos::bootstrap_default_account_bytes(&bytes)",
                "bootstrap(&bytes)",
            ),
            valid.replace(
                "let bytes = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();",
                "let bytes = copy_account(account_id, account_id_len);",
            ),
            format!(
                "{valid}\n#[cfg(any(test, target_os = \"macos\"))]\nmod hidden {{ fn call(bytes: &[u8]) {{ let _ = tersa_keychain_macos::bootstrap_default_account_bytes(bytes); }} }}"
            ),
            format!(
                "{valid}\nuse {{tersa_keychain_macos as kc}};\nlet _ = kc::DataProtectionRootKeyProvisioner;"
            ),
            format!("{valid}\nuse r#tersa_keychain_macos as kc;"),
            valid.replace(
                "match tersa_keychain_macos::bootstrap_default_account_bytes(&bytes) {",
                "let _ = \"tersa_keychain_macos::bootstrap_default_account_bytes(&bytes) { }\";\nmatch bootstrap(&bytes) {",
            ),
        ] {
            assert!(
                !bridge_bootstrap_source_violations(&forbidden).is_empty(),
                "fixture must fail: {forbidden}"
            );
        }
    }

    #[test]
    fn bridge_source_guard_pins_the_single_bounded_validating_call() {
        let valid = reviewed_bridge_bootstrap_source();
        for forbidden_read in [
            // A read function must call only its own single Keychain entry.
            valid.replacen(
                "tersa_keychain_macos::mailbox_read::read_default_inbox(&account, limit)",
                "tersa_keychain_macos::mailbox_read::read_default_thread(&account, &thread, limit)",
                1,
            ),
            // A whitespace-separated second call inside one read function.
            valid.replacen(
                "let model = match tersa_keychain_macos::mailbox_read::read_default_inbox(&account, limit) {",
                "let model = match { let _ = tersa_keychain_macos :: mailbox_read :: read_default_inbox (&account, limit); tersa_keychain_macos::mailbox_read::read_default_inbox(&account, limit) } {",
                1,
            ),
            // A read function keeps its bounded-copy source.
            valid.replace(
                "slice::from_raw_parts(thread_id, thread_id_len) }.to_vec()",
                "slice::from_raw_parts(thread_id, thread_id_len) }.to_owned()",
            ),
            // Each read function uses its reviewed status vocabulary exactly.
            valid.replacen(
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32",
                "0",
                1,
            ),
            // Each read function uses the read status vocabulary, not another one.
            valid.replacen(
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::InvalidInput",
                "tersa_keychain_macos::ProductBootstrapStatus::InvalidAccountIdentifier",
                1,
            ),
            // Keychain references stay inside the canonical boundary functions.
            format!(
                "{valid}\nconst READ_OK: i32 = tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32;"
            ),
        ] {
            assert!(
                !bridge_bootstrap_source_violations(&forbidden_read).is_empty(),
                "read fixture must fail: {forbidden_read}"
            );
        }
    }

    #[test]
    fn bridge_source_guard_pins_the_encode_and_bounded_write_per_read() {
        let valid = reviewed_bridge_bootstrap_source();
        for forbidden_read in [
            // A read function must not skip its command-specific encoder.
            valid.replacen(
                "let encoded = encode_inbox(&model);",
                "let encoded = model;",
                1,
            ),
            // A read function must not call its encoder more than once.
            valid.replacen(
                "let encoded = encode_inbox(&model);",
                "let encoded = encode_inbox(&model);\nlet encoded = encode_inbox(&model);",
                1,
            ),
            // A read function must not drop the model and return Ok without
            // encoding or calling the bounded validating write.
            valid.replacen(
                "let encoded = encode_inbox(&model);\nif unsafe { write_bounded_output(&encoded, output, output_capacity, output_len) } {\n    tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32\n} else {\n    tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall as i32\n}",
                "drop(model);\ntersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32",
                1,
            ),
            // A read function must not write caller output through a direct,
            // unbounded write instead of the single bounded write.
            valid.replacen(
                "if unsafe { write_bounded_output(&encoded, output, output_capacity, output_len) } {",
                "if unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()); output_len.write(encoded.len()); true } {",
                1,
            ),
            // A read function must reference each of the three reviewed
            // status variants; the aggregate count alone is not enough.
            valid.replacen(
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall as i32",
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::Ok as i32",
                1,
            ),
        ] {
            assert!(
                !bridge_bootstrap_source_violations(&forbidden_read).is_empty(),
                "read fixture must fail: {forbidden_read}"
            );
        }
    }

    #[test]
    fn bridge_source_guard_tolerates_formatting_but_not_token_drift() {
        let valid = reviewed_bridge_bootstrap_source();
        for reformatted in [
            // A rustfmt-style reflow of the bounded copy.
            valid.replace(
                "slice::from_raw_parts(account_id, account_id_len) }.to_vec()",
                "slice :: from_raw_parts (account_id,\n    account_id_len) }\n    .to_vec()",
            ),
            // A reformatted encoder call.
            valid.replace(
                "let encoded = encode_inbox(&model);",
                "let encoded\n    = encode_inbox (&model);",
            ),
            // A line-wrapped bounded write in every read function.
            valid.replace(
                "if unsafe { write_bounded_output(&encoded, output, output_capacity, output_len) } {",
                "if unsafe {\n    write_bounded_output (&encoded, output,\n        output_capacity, output_len)\n} {",
            ),
            // A reformatted null-output boundary check.
            valid.replace(
                "output.is_null() || output_len.is_null()",
                "output\n    .is_null()\n    || output_len\n        .is_null()",
            ),
        ] {
            assert!(
                bridge_bootstrap_source_violations(&reformatted).is_empty(),
                "token-equivalent formatting must remain valid: {reformatted}"
            );
        }
        for token_drift in [
            valid.replace("encode_inbox(&model)", "encode_inbox(model)"),
            valid.replace(
                "write_bounded_output(&encoded, output, output_capacity, output_len)",
                "write_bounded_output(&encoded, output, output_capacity)",
            ),
            valid.replace(
                "write_bounded_output(&encoded, output, output_capacity, output_len)",
                "write_unbounded_output(&encoded, output, output_capacity, output_len)",
            ),
            valid.replace("account_id_len == 0", "account_id_len == 1"),
            valid.replacen(
                "MailboxReadStatus::BufferTooSmall",
                "MailboxReadStatus::BufferToSmall",
                1,
            ),
        ] {
            assert!(
                !bridge_bootstrap_source_violations(&token_drift).is_empty(),
                "token drift must fail closed: {token_drift}"
            );
        }
    }

    #[test]
    fn bridge_source_guard_treats_comments_literals_and_whitespace_as_inert() {
        let valid = reviewed_bridge_bootstrap_source();
        let inert_adversarial_text = format!(
            "{valid}\n// tersa_keychain_macos::bootstrap_default_account_bytes(&bytes) {{ }}\nlet _ = r#\"tersa_keychain_macos::bootstrap_default_account_bytes(&bytes) }}\"#;\nlet character = '}}';\nlet byte = b'{{';\nfn lifetime<'a>(value: &'a ()) -> &'a () {{ value }}"
        );
        assert!(bridge_bootstrap_source_violations(&inert_adversarial_text).is_empty());
        let import_after_lifetimes =
            format!("{inert_adversarial_text}\nuse tersa_keychain_macos as provisioning;");
        assert!(!bridge_bootstrap_source_violations(&import_after_lifetimes).is_empty());
        for whitespace_bypass in [
            valid.replace(
                "tersa_keychain_macos::bootstrap_default_account_bytes(&bytes)",
                "tersa_keychain_macos :: bootstrap_default_account_bytes (&bytes)",
            ),
            valid.replace(
                "tersa_keychain_macos::bootstrap_default_account_bytes(&bytes)",
                "tersa_keychain_macos::bootstrap_default_account_bytes (&bytes)",
            ),
            valid.replace(
                "tersa_keychain_macos::mailbox_read::read_default_inbox(&account, limit)",
                "tersa_keychain_macos :: mailbox_read :: read_default_inbox (&account, limit)",
            ),
            valid.replace(
                "tersa_keychain_macos::mailbox_read::MailboxReadStatus::BufferTooSmall",
                "tersa_keychain_macos :: mailbox_read :: MailboxReadStatus :: BufferTooSmall",
            ),
        ] {
            assert!(
                bridge_bootstrap_source_violations(&whitespace_bypass).is_empty(),
                "token-equivalent whitespace must remain valid: {whitespace_bypass}"
            );
        }
    }

    #[test]
    fn bridge_source_guard_rejects_hidden_calls_and_cfg_masking() {
        let valid = reviewed_bridge_bootstrap_source();
        let hidden_second_call = valid.replace(
            "    _ => 1,",
            "    _ => { let _ = tersa_keychain_macos :: bootstrap_default_account_bytes (&bytes); 1 },",
        );
        assert!(
            !bridge_bootstrap_source_violations(&hidden_second_call).is_empty(),
            "a whitespace-separated second bridge call must fail closed"
        );
        let vertical_tab_second_call = valid.replace(
            "    _ => 1,",
            "    _ => { let _ = tersa_keychain_macos\u{000b}::\u{000b}bootstrap_default_account_bytes\u{000b}(&bytes); 1 },",
        );
        assert!(
            !bridge_bootstrap_source_violations(&vertical_tab_second_call).is_empty(),
            "Rust vertical-tab whitespace must not hide a second bridge call"
        );
        let cfg_test_on_non_module = format!(
            "{valid}\n#[cfg(test)]\nconst TEST_MARKER: () = ();\nfn production(bytes: &[u8]) {{ let _ = tersa_keychain_macos::bootstrap_default_account_bytes(bytes); }}\nmod later {{}}"
        );
        assert!(
            !bridge_bootstrap_source_violations(&cfg_test_on_non_module).is_empty(),
            "cfg(test) on a non-module item must not hide later production Keychain access"
        );
    }

    #[test]
    fn bridge_header_canonical_form_rejects_drift() {
        let header_path = PathBuf::from("apple/macos/TersaRustBridge.h");
        // Exercise the same production preprocessing path as
        // `swift_bootstrap_source_inventory`: if comments were stripped before
        // the canonical comparison, the exact reviewed header would be
        // rejected and comment-only drift would pass.
        let header_match_violations = |path: &Path, header: &str| {
            let sources = [(path.to_path_buf(), header.to_owned())];
            swift_bootstrap_source_inventory(&sources)
                .0
                .into_iter()
                .filter(|violation| {
                    violation.contains("must match an exact reviewed TersaMac header")
                })
                .collect::<Vec<_>>()
        };
        assert!(
            header_match_violations(&header_path, CANONICAL_TERSA_RUST_BRIDGE_HEADER).is_empty(),
            "the exact reviewed header, including its comments, must survive production preprocessing"
        );

        for drift in [
            CANONICAL_TERSA_RUST_BRIDGE_HEADER.replace(
                "int32_t tersa_macos_mailbox_search(",
                "int32_t tersa_macos_mailbox_search_all(",
            ),
            CANONICAL_TERSA_RUST_BRIDGE_HEADER.replace("uint16_t limit,", "uint32_t limit,"),
            CANONICAL_TERSA_RUST_BRIDGE_HEADER.replacen(
                "int32_t tersa_macos_mailbox_read_inbox(",
                "",
                1,
            ),
            format!(
                "{CANONICAL_TERSA_RUST_BRIDGE_HEADER}\nint32_t tersa_macos_mailbox_write(const uint8_t *account_id, size_t account_id_len);"
            ),
            // Comment-only drift in the exact reviewed header must stay rejected.
            CANONICAL_TERSA_RUST_BRIDGE_HEADER.replace("Mozilla Public", "Mozilla Community"),
        ] {
            assert!(
                !header_match_violations(&header_path, &drift).is_empty(),
                "header drift must fail closed through production preprocessing: {drift:?}"
            );
        }

        let bridging_header_path = PathBuf::from("apple/macos/TersaMac-Bridging-Header.h");
        assert!(
            header_match_violations(&bridging_header_path, CANONICAL_TERSA_MAC_BRIDGING_HEADER)
                .is_empty(),
            "the exact reviewed bridging header, including its comments, must survive production preprocessing"
        );
        for drift in [
            // Comment-only drift in the exact reviewed header must stay rejected.
            CANONICAL_TERSA_MAC_BRIDGING_HEADER.replace("Mozilla Public", "Mozilla Community"),
            format!(
                "{CANONICAL_TERSA_MAC_BRIDGING_HEADER}\nextern int32_t tersa_macos_unreviewed(void);"
            ),
        ] {
            assert!(
                !header_match_violations(&bridging_header_path, &drift).is_empty(),
                "bridging header drift must fail closed through production preprocessing: {drift:?}"
            );
        }
    }

    fn reviewed_swift_ffi_documents() -> Vec<(PathBuf, String)> {
        [
            (
                "apple/macos/AppDelegate.swift",
                include_str!("../../apple/macos/AppDelegate.swift"),
            ),
            (
                "apple/macos/BootstrapWorker.swift",
                include_str!("../../apple/macos/BootstrapWorker.swift"),
            ),
            (
                "apple/macos/MailboxReadWorker.swift",
                include_str!("../../apple/macos/MailboxReadWorker.swift"),
            ),
            (
                "apple/macos/AccountConnectionViewModel.swift",
                include_str!("../../apple/macos/AccountConnectionViewModel.swift"),
            ),
            (
                "apple/macos/MailboxSyncWorker.swift",
                include_str!("../../apple/macos/MailboxSyncWorker.swift"),
            ),
        ]
        .into_iter()
        .map(|(path, source)| (PathBuf::from(path), source.to_owned()))
        .collect()
    }

    #[test]
    fn swift_ffi_inventory_is_closed_over_reviewed_symbols_and_call_sites() {
        let reviewed = reviewed_swift_ffi_documents();
        assert!(
            swift_ffi_symbol_inventory_violations(&reviewed).is_empty(),
            "reviewed Swift FFI surface must match its closed inventory: {:?}",
            swift_ffi_symbol_inventory_violations(&reviewed)
        );

        let mut extra_call = reviewed.clone();
        let (_, source) = extra_call
            .iter_mut()
            .find(|(path, _)| path == Path::new("apple/macos/MailboxSyncWorker.swift"))
            .expect("mailbox sync worker fixture must exist");
        source.push_str("\nlet extra = tersa_mailbox_macos_sync_poll(0)\n");
        assert!(
            !swift_ffi_symbol_inventory_violations(&extra_call).is_empty(),
            "an extra reviewed FFI call must fail closed"
        );

        let mut moved_call = reviewed.clone();
        let (_, sync_source) = moved_call
            .iter_mut()
            .find(|(path, _)| path == Path::new("apple/macos/MailboxSyncWorker.swift"))
            .expect("mailbox sync worker fixture must exist");
        *sync_source = sync_source.replace(
            "let rawStatus = tersa_mailbox_macos_sync_poll(session.rawValue)",
            "let rawStatus: Int32 = 0",
        );
        let (_, app_source) = moved_call
            .iter_mut()
            .find(|(path, _)| path == Path::new("apple/macos/AppDelegate.swift"))
            .expect("app delegate fixture must exist");
        app_source.push_str("\nlet moved = tersa_mailbox_macos_sync_poll(0)\n");
        assert!(
            !swift_ffi_symbol_inventory_violations(&moved_call).is_empty(),
            "a moved reviewed FFI call must fail closed"
        );

        let mut alternate_invocation = reviewed.clone();
        let (_, sync_source) = alternate_invocation
            .iter_mut()
            .find(|(path, _)| path == Path::new("apple/macos/MailboxSyncWorker.swift"))
            .expect("mailbox sync worker fixture must exist");
        *sync_source = sync_source.replace(
            "tersa_mailbox_macos_sync_poll(session.rawValue)",
            "tersa_mailbox_macos_sync_poll /* recognized formatting */ (session.rawValue)",
        );
        assert!(
            swift_ffi_symbol_inventory_violations(&alternate_invocation).is_empty(),
            "a recognized whitespace/comment-equivalent invocation must remain valid"
        );

        for spelling in ["__asm", "__asm__", "asm"] {
            let alias = format!(
                "extern int32_t alias(uint64_t) {spelling}(\"tersa_mailbox_macos_sync_poll\");"
            );
            let (violations, _) = swift_bridge_call_inventory(
                Path::new("apple/macos/TersaRustBridge.h"),
                true,
                &alias,
            );
            assert!(
                !violations.is_empty(),
                "a C header alias spelling must fail closed: {spelling}"
            );
        }
    }

    #[test]
    fn swift_source_guard_rejects_launch_bootstrap_and_unbounded_queues() {
        let worker = r"
private var running = false
private var pending: (() -> Void)?
else if pending == nil {}
tersa_macos_bootstrap_default_account(pointer, count)
";
        let app = r"
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
func applicationDidFinishLaunching(_ notification: Notification) { _ = version() }
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
}
@main
@MainActor
private enum TersaApplication {
    private static let delegate = AppDelegate()
    static func main() {
        let application = NSApplication.shared
        application.delegate = delegate
        application.run()
    }
}
";
        assert!(swift_bootstrap_source_violations(worker, app).is_empty());
        assert!(
            !swift_bootstrap_source_violations(
                &format!(
                    "{worker}\nprivate var pending: [() -> Void] = []\npending.append(operation)"
                ),
                &app.replace(
                    "_ = version()",
                    "bootstrapWorker.submit(accountIdentifier: Data()) {}"
                ),
            )
            .is_empty()
        );
        assert!(
            !swift_bootstrap_source_violations(
                worker,
                &app.replace(
                    "completion: completion",
                    "completion: { status in completion(status) }",
                ),
            )
            .is_empty()
        );
        assert!(
            !swift_bootstrap_source_violations(
                worker,
                &app.replace("completion: completion", "completion: { _ in }")
            )
            .is_empty()
        );
        for drift in [
            app.replace("application.delegate = delegate", ""),
            app.replace("private static let delegate = AppDelegate()", ""),
            app.replace("application.run()", ""),
            app.replace("@main\n@MainActor\nprivate enum TersaApplication", ""),
            app.replace(
                "application.delegate = delegate\n        application.run()",
                "application.run()\n        application.delegate = delegate",
            ),
            app.replace(
                "application.delegate = delegate",
                "installDelegate(application)\n    }\n    static func installDelegate(_ application: NSApplication) {\n        application.delegate = delegate",
            ),
            app.replace(
                "application.delegate = delegate",
                "if CommandLine.arguments.isEmpty {\n            application.delegate = delegate\n        }",
            ),
            app.replace(
                "application.delegate = delegate",
                "let delegate = AppDelegate()\n        application.delegate = delegate",
            ),
            app.replace(
                "@MainActor\nfinal class AppDelegate",
                "@main\n@MainActor\nfinal class AppDelegate",
            ),
        ] {
            assert!(
                !swift_bootstrap_source_violations(worker, &drift).is_empty(),
                "an uninstalled or ambiguous AppKit entrypoint must fail closed"
            );
        }
    }

    #[test]
    fn swift_oauth_foreground_handoff_accepts_one_shot_activation() {
        let view_model = r"
func authorizeAndConnect(accountIdentifier: Data) {
    let started = session.start { [weak self] outcome in
        guard let self else { return }
        switch outcome {
        case .succeeded(let accessToken, let subject, let expiresInSeconds):
            let brokerToken = TokenBrokerAccessToken(
                accessToken: accessToken,
                subject: subject,
                expiresInSeconds: expiresInSeconds
            )
            self.connectBrokerGrantAfterApplicationActivation(
                accountIdentifier: accountIdentifier,
                brokerToken: brokerToken,
                token: connectToken
            )
        }
    }
}
func connectBrokerGrantAfterApplicationActivation(
    accountIdentifier: Data,
    brokerToken: TokenBrokerAccessToken,
    token: ConnectionOperationToken
) {
    guard !activationPending else {
        cleanupFreshBrokerGrant(subject: brokerToken.subject, token: token)
        return
    }
    activationPending = true
    if NSApp.isActive {
        finishBrokerGrantApplicationActivation(
            accountIdentifier: accountIdentifier,
            brokerToken: brokerToken,
            token: token
        )
        return
    }
    activationObserver = NotificationCenter.default.addObserver(
        forName: NSApplication.didBecomeActiveNotification,
        object: NSApp,
        queue: .main
    ) { _ in
        finishBrokerGrantApplicationActivation(
            accountIdentifier: accountIdentifier,
            brokerToken: brokerToken,
            token: token
        )
    }
    activationTimeout = Timer.scheduledTimer(withTimeInterval: 5, repeats: false) { _ in
        cleanupFreshBrokerGrant(subject: brokerToken.subject, token: token)
    }
    NSApp.activate()
    if NSApp.isActive {
        finishBrokerGrantApplicationActivation(
            accountIdentifier: accountIdentifier,
            brokerToken: brokerToken,
            token: token
        )
    }
}
func finishBrokerGrantApplicationActivation(
    accountIdentifier: Data,
    brokerToken: TokenBrokerAccessToken,
    token: ConnectionOperationToken
) {
    guard activationPending else { return }
    clearApplicationActivation()
    syncWorker.storeBrokerSubject(
        accountIdentifier: accountIdentifier,
        subject: brokerToken.subject
    ) { persisted in
        guard persisted else { return }
        self.connectWithBrokerGrant(
            accountIdentifier: accountIdentifier,
            brokerToken: brokerToken,
            token: token
        )
    }
}
func clearApplicationActivation() {}
func cleanupFreshBrokerGrant(subject: String, token: ConnectionOperationToken) {}
func connectWithBrokerGrant(
    accountIdentifier: Data,
    brokerToken: TokenBrokerAccessToken,
    token: ConnectionOperationToken
) {
    syncWorker.beginBrokerSync(accountIdentifier: accountIdentifier)
}
";
        let sources = vec![(
            PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
            view_model.to_owned(),
        )];

        assert!(
            swift_oauth_foreground_handoff_violations(&sources).is_empty(),
            "the reviewed foreground handoff must pass: {:?}",
            swift_oauth_foreground_handoff_violations(&sources)
        );
    }

    #[test]
    fn swift_oauth_foreground_handoff_rejects_unreviewed_handoff_paths() {
        let valid = r"
func authorizeAndConnect(accountIdentifier: Data) {
    connectBrokerGrantAfterApplicationActivation(
        accountIdentifier: accountIdentifier,
        brokerToken: brokerToken,
        token: token
    )
}
func connectBrokerGrantAfterApplicationActivation(
    accountIdentifier: Data,
    brokerToken: TokenBrokerAccessToken,
    token: ConnectionOperationToken
) {
    activationPending = true
    activationObserver = NotificationCenter.default.addObserver(
        forName: NSApplication.didBecomeActiveNotification,
        object: NSApp,
        queue: .main
    ) { _ in
        finishBrokerGrantApplicationActivation(
            accountIdentifier: accountIdentifier,
            brokerToken: brokerToken,
            token: token
        )
    }
    activationTimeout = Timer.scheduledTimer(withTimeInterval: 5, repeats: false) { _ in
        cleanupFreshBrokerGrant(subject: brokerToken.subject, token: token)
    }
    NSApp.activate()
    finishBrokerGrantApplicationActivation(
        accountIdentifier: accountIdentifier,
        brokerToken: brokerToken,
        token: token
    )
}
func finishBrokerGrantApplicationActivation(
    accountIdentifier: Data,
    brokerToken: TokenBrokerAccessToken,
    token: ConnectionOperationToken
) {
    guard activationPending else { return }
    clearApplicationActivation()
    syncWorker.storeBrokerSubject(
        accountIdentifier: accountIdentifier,
        subject: brokerToken.subject
    ) { persisted in
        connectWithBrokerGrant(
            accountIdentifier: accountIdentifier,
            brokerToken: brokerToken,
            token: token
        )
    }
}
func clearApplicationActivation() {}
func cleanupFreshBrokerGrant(subject: String, token: ConnectionOperationToken) {}
func connectWithBrokerGrant(
    accountIdentifier: Data,
    brokerToken: TokenBrokerAccessToken,
    token: ConnectionOperationToken
) {}
";
        let direct_connect = valid.replace(
            "    connectBrokerGrantAfterApplicationActivation(\n        accountIdentifier: accountIdentifier,\n        brokerToken: brokerToken,\n        token: token\n    )",
            "    connectWithBrokerGrant(\n        accountIdentifier: accountIdentifier,\n        brokerToken: brokerToken,\n        token: token\n    )",
        );
        let late_observer = valid.replace(
            "    activationObserver = NotificationCenter.default.addObserver(\n",
            "    NSApp.activate()\n    activationObserver = NotificationCenter.default.addObserver(\n",
        );
        let background_delivery = valid.replace(
            "    NSApp.activate()\n    finishBrokerGrantApplicationActivation(",
            "    NSApp.activate()\n    connectWithBrokerGrant(",
        );
        let duplicate_activation = format!(
            "{valid}\nfunc connectBrokerGrantAfterApplicationActivation(accountIdentifier: Data, brokerToken: TokenBrokerAccessToken, token: ConnectionOperationToken) {{}}\n"
        );
        let missing_activation = valid.replace(
            r"func connectBrokerGrantAfterApplicationActivation(
    accountIdentifier: Data,
    brokerToken: TokenBrokerAccessToken,
    token: ConnectionOperationToken
) {
    activationPending = true
    activationObserver = NotificationCenter.default.addObserver(
        forName: NSApplication.didBecomeActiveNotification,
        object: NSApp,
        queue: .main
    ) { _ in
        finishBrokerGrantApplicationActivation(
            accountIdentifier: accountIdentifier,
            brokerToken: brokerToken,
            token: token
        )
    }
    activationTimeout = Timer.scheduledTimer(withTimeInterval: 5, repeats: false) { _ in
        cleanupFreshBrokerGrant(subject: brokerToken.subject, token: token)
    }
    NSApp.activate()
    finishBrokerGrantApplicationActivation(
        accountIdentifier: accountIdentifier,
        brokerToken: brokerToken,
        token: token
    )
}
",
            "",
        );
        let missing_finish = valid.replace(
            r"func finishBrokerGrantApplicationActivation(
    accountIdentifier: Data,
    brokerToken: TokenBrokerAccessToken,
    token: ConnectionOperationToken
) {
    guard activationPending else { return }
    clearApplicationActivation()
    syncWorker.storeBrokerSubject(
        accountIdentifier: accountIdentifier,
        subject: brokerToken.subject
    ) { persisted in
        connectWithBrokerGrant(
            accountIdentifier: accountIdentifier,
            brokerToken: brokerToken,
            token: token
        )
    }
}
",
            "",
        );
        let reordered_activation = valid.replace(
            "    clearApplicationActivation()\n    syncWorker.storeBrokerSubject(\n        accountIdentifier: accountIdentifier,\n        subject: brokerToken.subject\n    ) { persisted in\n        connectWithBrokerGrant(",
            "    syncWorker.storeBrokerSubject(\n        accountIdentifier: accountIdentifier,\n        subject: brokerToken.subject\n    ) { persisted in\n        clearApplicationActivation()\n        connectWithBrokerGrant(",
        );
        for drift in [
            direct_connect,
            late_observer,
            background_delivery,
            duplicate_activation,
            missing_activation,
            missing_finish,
            reordered_activation,
        ] {
            let sources = vec![(
                PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
                drift,
            )];
            assert!(
                !swift_oauth_foreground_handoff_violations(&sources).is_empty(),
                "a background-capable OAuth handoff must fail closed"
            );
        }
    }

    #[test]
    fn swift_inventory_rejects_extra_calls_and_indirect_launch_entries() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func applicationDidFinishLaunching(_ notification: Notification) { _ = version() }
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        let sources = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                worker.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/Injected.swift"),
                "// tersa_macos_bootstrap_default_account()".to_owned(),
            ),
        ];
        assert!(
            swift_bootstrap_inventory_violations(&sources).is_empty(),
            "comments are inert"
        );

        let indirect_launch = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                worker.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.replace(
                    "_ = version()",
                    "establishOwnedAccountProfile(Data(), completion: receive)",
                ),
            ),
        ];
        assert!(!swift_bootstrap_inventory_violations(&indirect_launch).is_empty());

        let extra = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                worker.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/Injected.swift"),
                "tersa_macos_bootstrap_default_account(pointer, count)".to_owned(),
            ),
        ];
        assert!(!swift_bootstrap_inventory_violations(&extra).is_empty());

        let string_instead_of_call = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                "let fixture = \"tersa_macos_bootstrap_default_account(pointer, count)\""
                    .to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.to_owned(),
            ),
        ];
        assert!(!swift_bootstrap_inventory_violations(&string_instead_of_call).is_empty());

        let harmless_strings = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                format!(
                    "{worker}\nlet fixture = \"ordinary diagnostic text\"\nlet multiline = \"\"\"\nbootstrap worker diagnostic text\n\"\"\""
                ),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                format!("{delegate}\nlet fixture = \"bootstrapWorker.submit(\""),
            ),
        ];
        assert!(swift_bootstrap_inventory_violations(&harmless_strings).is_empty());

        let header_with_helper = vec![
            (PathBuf::from("apple/macos/BootstrapWorker.swift"), worker.to_owned()),
            (PathBuf::from("apple/macos/AppDelegate.swift"), delegate.to_owned()),
            (PathBuf::from("apple/macos/TersaRustBridge.h"), "int32_t tersa_macos_bootstrap_default_account(const uint8_t *account_id, size_t account_id_len);\nstatic inline void helper(void) { tersa_macos_bootstrap_default_account(0, 0); }".to_owned()),
        ];
        assert!(!swift_bootstrap_inventory_violations(&header_with_helper).is_empty());
    }

    #[test]
    fn swift_inventory_rejects_unqualified_worker_submissions() {
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func applicationDidFinishLaunching(_ notification: Notification) { _ = version() }
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        let inert_worker = r#"class BootstrapWorker {
    func submit(accountIdentifier: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) {}
    func retainReferences() {
        func submit(_ value: Int) {}
        let callback = submit
        let selector = #selector(submit(accountIdentifier:completion:))
        let diagnostic = "submit(accountIdentifier: Data(), completion: receive)"
        // submit(accountIdentifier: Data(), completion: receive)
    }
}
tersa_macos_bootstrap_default_account(pointer, count)"#;
        let inert_sources = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                inert_worker.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.to_owned(),
            ),
        ];
        assert!(
            swift_bootstrap_inventory_violations(&inert_sources).is_empty(),
            "declarations, function references, selectors, comments, strings, and the reviewed qualified call are inert"
        );

        for unreviewed_body in [
            "func alternateOwner() { submit(accountIdentifier: Data(), completion: receive) }",
            "func alternateOwner() { submit\n    (accountIdentifier: Data(), completion: receive) }",
            "func alternateOwner() { submit /* hidden spacing */ \u{000b} (accountIdentifier: Data(), completion: receive) }",
            "func alternateOwner() { `submit`(accountIdentifier: Data(), completion: receive) }",
            "func alternateOwner() { if case submit(accountIdentifier: Data(), completion: receive) = callback {} }",
            "func alternateOwner() { switch callback { case submit(accountIdentifier: Data(), completion: receive): break default: break } }",
            "var alternateOwner: Void { submit(accountIdentifier: Data(), completion: receive) }",
            "let alternateOwner = { submit(accountIdentifier: Data(), completion: receive) }",
            "func alternateOwner() { let selector = #selector(submit(accountIdentifier:completion:)); submit(accountIdentifier: Data(), completion: receive) }",
        ] {
            let worker = format!(
                "class BootstrapWorker {{\n    func submit(accountIdentifier: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) {{}}\n    {unreviewed_body}\n}}\ntersa_macos_bootstrap_default_account(pointer, count)"
            );
            let sources = vec![
                (PathBuf::from("apple/macos/BootstrapWorker.swift"), worker),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&sources).is_empty(),
                "unqualified BootstrapWorker submission must fail closed: {unreviewed_body}"
            );
        }

        let escaped_member = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                inert_worker.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.replace("bootstrapWorker.submit", "bootstrapWorker.`submit`"),
            ),
        ];
        assert!(
            !swift_bootstrap_inventory_violations(&escaped_member).is_empty(),
            "escaped Swift member syntax must not evade the bootstrap submission inventory"
        );
    }

    #[test]
    fn swift_inventory_rejects_every_unreviewed_bootstrap_entry() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        for unreviewed_entry in [
            "func awakeFromNib() { establishOwnedAccountProfile(Data(), completion: receive) }",
            "func arbitraryHelper() { establishOwnedAccountProfile(Data(), completion: receive) }",
            "func establishOwnedAccountProfile() { establishOwnedAccountProfile(Data(), completion: receive) }",
        ] {
            let sources = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    format!("{delegate}\n{unreviewed_entry}"),
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&sources).is_empty(),
                "every unreviewed bootstrap entry must fail closed: {unreviewed_entry}"
            );
        }
    }

    #[test]
    fn swift_inventory_fails_closed_on_chains_sources_and_string_bypasses() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        for chain in [
            "func launchBridge() { establishOwnedAccountProfile(Data(), completion: receive) }\nfunc applicationDidFinishLaunching(_ notification: Notification) { launchBridge() }",
            "func firstHop() { establishOwnedAccountProfile(Data(), completion: receive) }\nfunc secondHop() { firstHop() }\nfunc applicationDidFinishLaunching(_ notification: Notification) { secondHop() }",
        ] {
            let sources = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    format!("{delegate}\n{chain}"),
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&sources).is_empty(),
                "launch reachability must reject chain: {chain}"
            );
        }
        let cross_file_chain = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                worker.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                format!(
                    "{delegate}\nfunc applicationDidFinishLaunching(_ notification: Notification) {{ externalHop() }}"
                ),
            ),
            (
                PathBuf::from("apple/macos/External.swift"),
                "func externalHop() { establishOwnedAccountProfile(Data(), completion: receive) }"
                    .to_owned(),
            ),
        ];
        assert!(
            !swift_bootstrap_inventory_violations(&cross_file_chain).is_empty(),
            "launch reachability must cross inventoried Swift source files"
        );
        for extension in [
            "m", "mm", "c", "cpp", "s", "S", "asm", "metal", "y", "l", "mig", "rs",
        ] {
            let sources = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
                (
                    PathBuf::from(format!("apple/macos/Injected.{extension}")),
                    String::new(),
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&sources).is_empty(),
                ".{extension} must fail closed"
            );
        }
        for bypass in [
            "let text = \"\\(tersa_macos_bootstrap_default_account(pointer, count))\"",
            "let text = #\"tersa_macos_bootstrap_default_account(pointer, count)\"#",
        ] {
            let sources = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    format!("{worker}\n{bypass}"),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&sources).is_empty(),
                "Swift string bypass must fail closed: {bypass}"
            );
        }
    }

    #[test]
    fn swift_inventory_accepts_single_reviewed_intent_entry_and_stops_propagation() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        let view_model = r"
func connect(_ identifier: Data) { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(identifier, completion: receive) }
";
        // A user-intent handler in a third file may call the reviewed entry;
        // propagation stops at the intent entry, so the handler stays inert.
        // An initializer and body that do NOT reach bootstrap must not trip the
        // automatic-entry rule (no false positive on ordinary construction).
        // A benign initializer, a default-closure parameter, and a `.init(...)`
        // call expression must not be parsed into a bootstrap entry; none is
        // a false positive.
        let root_view = r"
init(config: Int) { configure() }
func configure(onReady: () -> Void = {}) { let helper = Helper.init(callback: {}) }
func handleConnectTapped() { model.connect(Data()) }
func renderBody() { handleConnectTapped() }
";
        let sources = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                worker.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
                view_model.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/RootView.swift"),
                root_view.to_owned(),
            ),
        ];
        assert!(
            swift_bootstrap_inventory_violations(&sources).is_empty(),
            "a single reviewed view-model intent entry and its callers must pass: {:?}",
            swift_bootstrap_inventory_violations(&sources)
        );
    }

    #[test]
    fn swift_inventory_rejects_unreviewed_intent_entries() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        let with_view_model = |view_model: &str, extra: Option<(&str, &str)>| {
            let mut sources = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
                    view_model.to_owned(),
                ),
            ];
            if let Some((path, content)) = extra {
                sources.push((PathBuf::from(path), content.to_owned()));
            }
            sources
        };
        // The reviewed owner may not be referenced outside AppDelegate and the
        // single reviewed view-model.
        assert!(
            !swift_bootstrap_inventory_violations(&with_view_model(
                "func connect(_ id: Data) { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(id, completion: receive) }",
                Some((
                    "apple/macos/RootView.swift",
                    "func rogue() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }",
                )),
            ))
            .is_empty(),
            "an owner reference outside the reviewed files must fail closed"
        );
        // At most one intent entry: a second view-model reference fails closed.
        assert!(
            !swift_bootstrap_inventory_violations(&with_view_model(
                "func connect(_ id: Data) { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(id, completion: receive) }\nfunc reconnect(_ id: Data) { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(id, completion: receive) }",
                None,
            ))
            .is_empty(),
            "a second view-model intent entry must fail closed"
        );
        // A single intent function may reference the owner only once.
        assert!(
            !swift_bootstrap_inventory_violations(&with_view_model(
                "func connect(_ id: Data) { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(id, completion: receive); (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(id, completion: receive) }",
                None,
            ))
            .is_empty(),
            "a doubled owner reference in one intent entry must fail closed"
        );
        // The owner may not be reached from a closure-valued stored property.
        assert!(
            !swift_bootstrap_inventory_violations(&with_view_model(
                "let autoConnect: () -> Void = { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }",
                None,
            ))
            .is_empty(),
            "a closure-property bootstrap entry must fail closed"
        );
        // AppDelegate must declare the owner but never call it.
        assert!(
            !swift_bootstrap_inventory_violations(&[
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    format!(
                        "{delegate}\nfunc applicationDidFinishLaunching(_ notification: Notification) {{ establishOwnedAccountProfile(Data(), completion: receive) }}"
                    ),
                ),
            ])
            .is_empty(),
            "AppDelegate calling the owner must fail closed"
        );
    }

    #[test]
    fn swift_inventory_rejects_automatic_and_laundered_bootstrap_entries() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        let with_view_model = |view_model: &str| {
            vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
                    view_model.to_owned(),
                ),
            ]
        };
        // An initializer runs at construction, never on user intent: a direct
        // owner reference inside `init` must fail closed.
        assert!(
            !swift_bootstrap_inventory_violations(&with_view_model(
                "init() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }",
            ))
            .is_empty(),
            "an owner reference inside a view-model initializer must fail closed"
        );
        // ... and an initializer that merely CALLS the reviewed intent entry
        // (the terminal-propagation stop must not exempt constructors).
        assert!(
            !swift_bootstrap_inventory_violations(&with_view_model(
                "func connect() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }\ninit() { connect() }",
            ))
            .is_empty(),
            "a view-model initializer reaching the reviewed intent must fail closed"
        );
        // An AppDelegate launch/lifecycle hook may not reach the reviewed intent
        // entry either (bootstrap must never start automatically at launch).
        assert!(
            !swift_bootstrap_inventory_violations(&[
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    format!(
                        "{delegate}\nfunc applicationDidFinishLaunching(_ notification: Notification) {{ model.connect() }}"
                    ),
                ),
                (
                    PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
                    "func connect() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }".to_owned(),
                ),
            ])
            .is_empty(),
            "an AppDelegate launch hook reaching the reviewed intent must fail closed"
        );
        // The same hook hidden in a cross-file `extension AppDelegate` must also
        // fail closed (AppDelegate members belong only in AppDelegate.swift).
        assert!(
            !swift_bootstrap_inventory_violations(&[
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegateLaunch.swift"),
                    "extension AppDelegate { func applicationWillFinishLaunching(_ notification: Notification) { model.connect() } }".to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
                    "func connect() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }".to_owned(),
                ),
            ])
            .is_empty(),
            "a cross-file AppDelegate extension reaching the reviewed intent must fail closed"
        );
        // Declarations whose bodies the func/init inventory does not parse are
        // refused, so a body-less `func` cannot launder an owner call site.
        for laundering in [
            "func connect()\nsubscript(index: Int) -> Void { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }",
            "deinit { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }",
            "protocol Connectable { func connect() }\nfunc connect() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }",
        ] {
            assert!(
                !swift_bootstrap_inventory_violations(&with_view_model(laundering)).is_empty(),
                "a body-parse-laundering construct must fail closed: {laundering}"
            );
        }
        // Initializer forms whose body the parser must attribute correctly: a
        // default-closure parameter (`= {}`) in the signature and a generic
        // initializer. Both reach the reviewed intent from construction and must
        // fail closed.
        for initializer in [
            "func connect() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }\ninit(callback: () -> Void = {}) { connect() }",
            "func connect() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }\ninit<T>(value: T) { connect() }",
        ] {
            assert!(
                !swift_bootstrap_inventory_violations(&with_view_model(initializer)).is_empty(),
                "a tricky-signature initializer reaching the reviewed intent must fail closed: {initializer}"
            );
        }
    }

    #[test]
    fn swift_inventory_rejects_underscored_attributes_without_text_false_positives() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        for attribute in [
            "@_extern(c, \"SecItemDelete\")\nfunc hiddenKeychainCall() {}",
            "@_extern(c, \"tersa_macos_bootstrap_default_account\")\nfunc hiddenBootstrapCall() {}",
            "@_expose(Cxx)\nfunc exposedBootstrapCall() {}",
            "@_dynamicReplacement(for: establishedOwner)\nfunc replacement() {}",
            "@`_extern`(c, \"SecItemDelete\")\nfunc escapedKeychainCall() {}",
            "@ /* hidden spacing */ `_dynamicReplacement`(for: establishedOwner)\nfunc escapedReplacement() {}",
        ] {
            let sources = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    format!("{worker}\n{attribute}"),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&sources).is_empty(),
                "underscored Swift attributes must fail closed: {attribute}"
            );
        }
        let inert = format!(
            r#"{worker}
// @_extern(c, "SecItemDelete")
// @`_extern`(c, "SecItemDelete")
let note = "@_dynamicReplacement(for: establishedOwner) @`_expose`(Cxx) SecItemDelete""#
        );
        let sources = vec![
            (PathBuf::from("apple/macos/BootstrapWorker.swift"), inert),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.to_owned(),
            ),
        ];
        assert!(
            swift_bootstrap_inventory_violations(&sources).is_empty(),
            "underscored attributes and protected symbols in Swift comments and strings must remain inert"
        );
    }

    #[test]
    fn swift_inventory_closes_launch_properties_extensions_and_symbol_aliases() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        let cross_file_launch_extension = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                worker.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegateLaunch.swift"),
                "extension AppDelegate { func applicationWillFinishLaunching(_ notification: Notification) { establishOwnedAccountProfile(Data(), completion: receive) } }"
                    .to_owned(),
            ),
        ];
        assert!(
            !swift_bootstrap_inventory_violations(&cross_file_launch_extension).is_empty(),
            "launch hooks in an inventoried Swift extension must be enforced"
        );

        for property_bridge in [
            "var ownedRoute: (() -> Void) { { establishOwnedAccountProfile(Data(), completion: receive) } }\nfunc applicationDidFinishLaunching(_ notification: Notification) { ownedRoute() }",
            "let ownedRoute: () -> Void = { establishOwnedAccountProfile(Data(), completion: receive) }\nfunc applicationDidFinishLaunching(_ notification: Notification) { ownedRoute() }",
            "var ownedRoute: (() -> Void)\n{ { establishOwnedAccountProfile(Data(), completion: receive) } }\nfunc applicationDidFinishLaunching(_ notification: Notification) { ownedRoute() }",
            "var ownedRoute:\n    (() -> Void)\n{ { establishOwnedAccountProfile(Data(), completion: receive) } }\nfunc applicationDidFinishLaunching(_ notification: Notification) { ownedRoute() }",
            "lazy var ownedRoute = establishOwnedAccountProfile\nfunc applicationDidFinishLaunching(_ notification: Notification) { ownedRoute(Data(), completion: receive) }",
            "lazy\u{000b}var ownedRoute =\n    establishOwnedAccountProfile\nfunc applicationDidFinishLaunching(_ notification: Notification) { ownedRoute(Data(), completion: receive) }",
            "let firstRoute = establishOwnedAccountProfile\nlet secondRoute = firstRoute\nfunc applicationDidFinishLaunching(_ notification: Notification) { secondRoute(Data(), completion: receive) }",
            "func harmless() {}\nlazy var ownedRoute = establishOwnedAccountProfile\nfunc applicationWillBecomeActive(_ notification: Notification) { ownedRoute(Data(), completion: receive) }",
        ] {
            let sources = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/LaunchRoute.swift"),
                    property_bridge.to_owned(),
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&sources).is_empty(),
                "computed and closure-valued launch routes must fail closed: {property_bridge}"
            );
        }

        for alias_source in [
            "let bootstrapAlias = tersa_macos_bootstrap_default_account",
            "@_silgen_name(\"tersa_macos_bootstrap_default_account\") func bootstrapAlias(_ pointer: UnsafePointer<UInt8>?, _ count: Int) -> Int32",
            "@_cdecl(\"tersa_macos_bootstrap_default_account\") func bootstrapAlias(_ pointer: UnsafePointer<UInt8>?, _ count: Int) -> Int32 { 0 }",
            "let bootstrapAlias = unsafeBitCast(dlsym(handle, \"tersa_macos_bootstrap_default_account\"), to: (@convention(c) (UnsafePointer<UInt8>?, Int) -> Int32).self)",
            "let bootstrapAlias = CFBundleGetFunctionPointerForName(bundle, \"tersa_macos_bootstrap_default_account\" as CFString)",
        ] {
            let sources = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/Alias.swift"),
                    alias_source.to_owned(),
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&sources).is_empty(),
                "source-level bootstrap ABI aliases must fail closed: {alias_source}"
            );
        }
    }

    #[test]
    fn swift_inventory_rejects_alternate_worker_construction_and_receivers() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        for alternate_authority in [
            delegate
                .replace(
                    "private let bootstrapWorker = BootstrapWorker()",
                    "private let alternateWorker = BootstrapWorker()",
                )
                .replace("bootstrapWorker.submit", "alternateWorker.submit"),
            format!(
                "{delegate}\nprivate let alternateWorker = BootstrapWorker()\nfunc alternateOwner() {{ alternateWorker.submit(accountIdentifier: Data(), completion: receive) }}"
            ),
            format!("{delegate}\nlet submitAlias = bootstrapWorker.submit"),
        ] {
            let sources = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    alternate_authority,
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&sources).is_empty(),
                "alternate BootstrapWorker receiver or construction must fail closed"
            );
        }
    }

    #[test]
    fn swift_inventory_separates_the_mailbox_sync_worker_from_product_bootstrap() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        let view_model = r"
func connect() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }
";
        // The reviewed mailbox-sync surface: same bare names as the reviewed
        // intent entry, but it reaches only the mailbox-sync C ABI.
        let sync_worker = r"
enum MailboxBeginStatus { init?(rawValue: Int32) { self = .started } }
enum MailboxPollStatus { init?(rawValue: Int32) { self = .running } }
final class MailboxSyncWorker {
    func connect(accountIdentifier: Data, completion: @escaping @MainActor (MailboxPollStatus) -> Void) { enqueueBegin(.brokerSync(accountIdentifier), completion: completion) }
    func disconnect(accountIdentifier: Data, completion: @escaping @MainActor (MailboxPollStatus) -> Void) { enqueueBegin(.brokerDisconnectFinalize(accountIdentifier), completion: completion) }
    func sync(accountIdentifier: Data, completion: @escaping @MainActor (MailboxPollStatus) -> Void) { enqueueBegin(.brokerSync(accountIdentifier), completion: completion) }
    private func performBegin(_ request: BeginRequest) -> (status: Int32, sessionID: UInt64) {
        var sessionID: UInt64 = 0
        let status: Int32
        switch request {
        case .brokerSync(let accountIdentifier):
            status = tersa_mailbox_macos_broker_sync_begin(accountIdentifier, &sessionID)
        case .brokerDisconnectFinalize(let accountIdentifier):
            status = tersa_mailbox_macos_broker_disconnect_finalize(accountIdentifier, &sessionID)
        }
        return (status, sessionID)
    }
}
";
        // A third-party state file whose `init` merely names a local of the same
        // name the worker uses must not be dragged in by a namesake.
        let connection_state = r"
enum ConnectionState { init(status: ProductBootstrapStatus) { switch status { case .ready: self = .connected } } }
";
        let sources = |sync: &str| {
            vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
                    view_model.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/ConnectionState.swift"),
                    connection_state.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/MailboxSyncWorker.swift"),
                    sync.to_owned(),
                ),
            ]
        };
        assert!(
            swift_bootstrap_inventory_violations(&sources(sync_worker)).is_empty(),
            "the reviewed mailbox-sync worker must not be a bootstrap entry: {:?}",
            swift_bootstrap_inventory_violations(&sources(sync_worker))
        );
        // The exemption is structural, never a file allowlist: a real product
        // bootstrap entry added to the SAME file must still fail closed.
        for real_entry in [
            "func rogueBootstrap() { bootstrapWorker.submit(accountIdentifier: Data(), completion: receive) }",
            "func rogueBootstrap() { submit(accountIdentifier: Data(), completion: receive) }",
            "func rogueBootstrap() { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }",
            "init() { connect(accountIdentifier: Data(), completion: receive) }",
            "let autoStart: () -> Void = { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }",
        ] {
            let injected = format!("{sync_worker}\n{real_entry}");
            assert!(
                !swift_bootstrap_inventory_violations(&sources(&injected)).is_empty(),
                "a real bootstrap entry in the mailbox-sync worker must fail closed: {real_entry}"
            );
        }
        // Namesake isolation must not become a bypass: a function that shares the
        // reviewed intent entry's bare name but submits itself still fails closed.
        assert!(
            !swift_bootstrap_inventory_violations(&[
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
                    view_model.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/Rogue.swift"),
                    "func connect() { bootstrapWorker.submit(accountIdentifier: Data(), completion: receive) }".to_owned(),
                ),
            ])
            .is_empty(),
            "a namesake of the reviewed intent entry may not submit product bootstrap"
        );
    }

    #[test]
    fn swift_inventory_accepts_the_bootstrap_then_sync_intent_ladder() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        let sync_worker = r"
final class MailboxSyncWorker {
    func connect(accountIdentifier: Data, completion: @escaping @MainActor (MailboxPollStatus) -> Void) { enqueueBegin(.connect(accountIdentifier), completion: completion) }
    func sync(clientID: String, accountIdentifier: Data, completion: @escaping @MainActor (MailboxPollStatus) -> Void) { enqueueBegin(.sync(clientID, accountIdentifier), completion: completion) }
}
";
        // 3e-2c: the ONE reviewed intent entry drives product bootstrap AND the
        // mailbox-sync worker (bootstrap -> sync -> needsReconnect -> OAuth ->
        // connect). Touching the worker must not unreview the intent entry.
        let ladder = r"
func connect() {
    (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: { status in
        guard status == .ready else { return }
        self.syncWorker.sync(clientID: self.clientID, accountIdentifier: Data()) { poll in
            guard poll == .needsReconnect else { return }
            self.startOAuth { session in
                self.syncWorker.connect(accountIdentifier: Data(), completion: self.receive)
            }
        }
    })
}
func startOAuth(_ handoff: @escaping (OAuthSessionID) -> Void) { session.start(onOutcome: handoff) }
";
        let sources = vec![
            (
                PathBuf::from("apple/macos/BootstrapWorker.swift"),
                worker.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AppDelegate.swift"),
                delegate.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
                ladder.to_owned(),
            ),
            (
                PathBuf::from("apple/macos/MailboxSyncWorker.swift"),
                sync_worker.to_owned(),
            ),
        ];
        assert!(
            swift_bootstrap_inventory_violations(&sources).is_empty(),
            "the reviewed intent ladder may drive bootstrap and the sync worker: {:?}",
            swift_bootstrap_inventory_violations(&sources)
        );
        // ... and the ladder must still never run automatically.
        let mut automatic = sources.clone();
        automatic[1].1 = format!(
            "{delegate}\nfunc applicationDidFinishLaunching(_ notification: Notification) {{ model.connect() }}"
        );
        assert!(
            !swift_bootstrap_inventory_violations(&automatic).is_empty(),
            "a launch hook driving the ladder must still fail closed"
        );
        let mut constructed = sources.clone();
        constructed[2].1 = format!("{ladder}\ninit() {{ connect() }}");
        assert!(
            !swift_bootstrap_inventory_violations(&constructed).is_empty(),
            "an initializer driving the ladder must still fail closed"
        );
    }

    #[test]
    fn swift_inventory_rejects_every_c_header_alias_spelling() {
        let worker = r"class BootstrapWorker {}
tersa_macos_bootstrap_default_account(pointer, count)";
        let delegate = r"
private let bootstrapWorker = BootstrapWorker()
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
";
        for spelling in ["__asm", "__asm__", "asm"] {
            let header_symbol_alias = vec![
                (
                    PathBuf::from("apple/macos/BootstrapWorker.swift"),
                    worker.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/AppDelegate.swift"),
                    delegate.to_owned(),
                ),
                (
                    PathBuf::from("apple/macos/TersaRustBridge.h"),
                    format!(
                        "extern int32_t alias(const uint8_t *, size_t) {spelling}(\"tersa_macos_bootstrap_default_account\");"
                    ),
                ),
            ];
            assert!(
                !swift_bootstrap_inventory_violations(&header_symbol_alias).is_empty(),
                "C header alias spelling must fail closed: {spelling}"
            );
        }
    }

    #[test]
    fn cli_source_inventory_requires_both_canonical_anchors() {
        let complete = BTreeSet::from([
            PathBuf::from("apps/cli-macos/src/lib.rs"),
            PathBuf::from("apps/cli-macos/src/main.rs"),
        ]);
        assert!(canonical_cli_source_anchor_violations(&complete).is_empty());
        assert_eq!(
            canonical_cli_source_anchor_violations(&BTreeSet::from([PathBuf::from(
                "apps/cli-macos/src/lib.rs"
            )])),
            vec!["the CLI canonical source `apps/cli-macos/src/main.rs` must be tracked"]
        );
    }

    #[test]
    fn protected_keychain_dependency_renames_are_rejected() {
        assert_eq!(
            protected_keychain_dependency_rename_violations(
                "tersa-apple-bridge",
                "tersa-keychain-macos",
                Some("provisioning"),
            ),
            vec![
                "tersa-apple-bridge -> tersa-keychain-macos must not rename protected Keychain dependency to `provisioning`"
            ]
        );
        for dependency in ["tersa-application", "tersa-presentation"] {
            assert_eq!(
                protected_keychain_dependency_rename_violations(
                    "tersa-keychain-macos",
                    dependency,
                    Some("aliased"),
                ),
                vec![format!(
                    "tersa-keychain-macos -> {dependency} must not rename protected Keychain dependency to `aliased`"
                )]
            );
        }
        assert!(
            protected_keychain_dependency_rename_violations(
                "tersa-apple-bridge",
                "url",
                Some("public_url"),
            )
            .is_empty()
        );
    }

    #[test]
    fn cli_direct_dependencies_are_a_closed_exact_set() {
        let exact = BTreeSet::from(["tersa-application", "tersa-domain", "tersa-keychain-macos"]);
        assert!(cli_direct_dependency_set_violations(&exact).is_empty());
        assert_eq!(
            cli_direct_dependency_set_violations(&BTreeSet::from([
                "tersa-application",
                "tersa-domain",
                "tersa-store-sqlcipher-macos",
            ])),
            vec![
                "tersa-cli-macos -> tersa-store-sqlcipher-macos (dependency is outside the closed CLI adapter set)",
                "tersa-cli-macos is missing required direct dependency tersa-keychain-macos",
            ]
        );
    }

    #[test]
    fn plist_array_parser_rejects_malformed_or_non_exact_arrays() {
        let malformed = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>keychain-access-groups</key><string>group</string>
</dict></plist>"#;
        assert_eq!(
            parse_plist_string_array(malformed, "keychain-access-groups"),
            Err("top-level value is not an array".to_owned())
        );
        let mixed = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>keychain-access-groups</key><array><string>group</string><true/></array>
</dict></plist>"#;
        assert_eq!(
            parse_plist_string_array(mixed, "keychain-access-groups"),
            Err("array contains a non-string member".to_owned())
        );

        let nested = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>nested</key><dict>
    <key>keychain-access-groups</key><array><string>group</string></array>
  </dict>
</dict></plist>"#;
        assert_eq!(
            parse_plist_string_array(nested, "keychain-access-groups"),
            Err("missing top-level key".to_owned())
        );

        let duplicate = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>keychain-access-groups</key><array><string>first</string></array>
  <key>keychain-access-groups</key><array><string>second</string></array>
</dict></plist>"#;
        assert!(
            parse_plist_string_array(duplicate, "keychain-access-groups")
                .expect_err("duplicate plist keys must fail")
                .contains("duplicate mapping key `keychain-access-groups`")
        );
    }

    fn valid_signing_project_with_interleaved_targets() -> String {
        VALID_SIGNING_PROJECT
            .replacen(
                "  deploymentTarget:\n    macOS: \"15.0\"\n    iOS: \"18.0\"\n",
                "  deploymentTarget: { macOS: \"15.0\", iOS: \"18.0\" }\n",
                1,
            )
            .replacen(
                "targets:\n  TersaMac:",
                "targets:\n  FirstIOS:\n    platform: iOS\n  TersaMac:",
                1,
            )
            .replacen(
                "  OtherMac:\n    platform: macOS\n  OtherIOS:\n    platform: iOS\n",
                "  MiddleMac:\n    platform: macOS\n  LastIOS:\n    platform: iOS\n",
                1,
            )
    }

    #[test]
    fn signing_parser_uses_declared_platform_with_interleaved_targets() {
        let entitlements = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>com.apple.security.app-sandbox</key><true/>
  <key>com.apple.security.network.client</key><true/>
  <key>com.apple.security.network.server</key><true/>
  <key>com.apple.security.application-groups</key>
  <array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
  <key>keychain-access-groups</key>
  <array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
</dict></plist>"#;
        let project = valid_signing_project_with_interleaved_targets();
        let targets = match parse_project_targets(&project) {
            Ok(targets) => targets,
            Err(error) => panic!("interleaved target fixture must parse: {error}"),
        };
        assert_eq!(
            targets
                .iter()
                .map(|target| (target.name.as_str(), target.platform.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("FirstIOS", "iOS"),
                ("LastIOS", "iOS"),
                ("MiddleMac", "macOS"),
                ("TersaMac", "macOS"),
                ("TersaMacTests", "macOS"),
                ("TersaMacTokenBroker", "macOS"),
            ]
        );
        assert!(
            signing_configuration_violations(entitlements, VALID_BROKER_ENTITLEMENTS, &project,)
                .is_empty()
        );

        let malformed_array = project.replace(
            "        keychain-access-groups:\n          - ${TeamIdentifierPrefix}app.tersa.shared",
            "        keychain-access-groups: ${TeamIdentifierPrefix}app.tersa.shared",
        );
        assert!(
            signing_configuration_violations(
                entitlements,
                VALID_BROKER_ENTITLEMENTS,
                &malformed_array,
            )
            .iter()
            .any(|violation| violation.contains("`keychain-access-groups`"))
        );

        let contaminated = project.replace(
            "  LastIOS:\n    platform: iOS",
            "  LastIOS:\n    platform: iOS\n    settings:\n      base:\n        TERSA_MACOS_APP_GROUP: forbidden",
        );
        assert!(
            signing_configuration_violations(
                entitlements,
                VALID_BROKER_ENTITLEMENTS,
                &contaminated,
            )
            .iter()
            .any(|violation| {
                violation.contains("targets.LastIOS.settings.base.TERSA_MACOS_APP_GROUP")
            })
        );
    }

    #[test]
    fn signing_parser_accepts_quoted_flow_mappings_and_resolved_aliases() {
        let project = r#"
"targets": {"TersaMac": {"platform": "macOS", "entitlements": {"path": "macos/TersaMac.entitlements", "properties": {"com.apple.security.application-groups": ["${TeamIdentifierPrefix}app.tersa.shared"], "keychain-access-groups": ["${TeamIdentifierPrefix}app.tersa.shared"]}}, "settings": {"base": {"TERSA_MACOS_APP_GROUP": "$(TeamIdentifierPrefix)app.tersa.shared", "CODE_SIGN_ENTITLEMENTS": "macos/TersaMac.entitlements"}}}}
"#;
        let targets = parse_project_targets(project).expect("quoted flow YAML must parse");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "TersaMac");

        let aliased = r#"
ios: &ios
  platform: iOS
  settings:
    base:
      TERSA_MACOS_APP_GROUP: forbidden
options:
  bundleIdPrefix: app.tersa
  deploymentTarget: { macOS: "15.0", iOS: "18.0" }
  xcodeVersion: "26.0"
settings: {}
targets:
  TersaMac:
    type: application
    platform: macOS
    sources: []
    info: {}
    entitlements:
      path: macos/TersaMac.entitlements
      properties:
        com.apple.security.app-sandbox: true
        com.apple.security.network.client: true
        com.apple.security.network.server: true
        com.apple.security.application-groups: ["${TeamIdentifierPrefix}app.tersa.shared"]
        keychain-access-groups: ["${TeamIdentifierPrefix}app.tersa.shared"]
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac
        TERSA_MACOS_APP_GROUP: "$(TeamIdentifierPrefix)app.tersa.shared"
        CODE_SIGN_ENTITLEMENTS: macos/TersaMac.entitlements
    preBuildScripts:
      - name: Build Rust static library
        basedOnDependencyAnalysis: false
        script: 'sh "${SRCROOT}/scripts/build-rust-staticlib.sh" macos "${CONFIGURATION}"'
    scheme:
      testTargets: []
  AliasedIOS: *ios
"#;
        assert!(
            signing_configuration_violations(
                r#"<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.network.client</key><true/>
<key>com.apple.security.network.server</key><true/>
<key>com.apple.security.application-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
<key>keychain-access-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
</dict></plist>"#,
                VALID_BROKER_ENTITLEMENTS,
                aliased,
            )
            .iter()
            .any(|violation| {
                violation.contains("targets.AliasedIOS.settings.base.TERSA_MACOS_APP_GROUP")
            })
        );
    }

    #[test]
    fn signing_parser_fails_closed_on_ambiguous_or_extended_yaml() {
        let duplicate = r"
targets:
  TersaMac: { platform: macOS }
  TersaMac: { platform: macOS }
";
        assert!(
            parse_project_targets(duplicate)
                .expect_err("duplicate target must fail")
                .contains("duplicate mapping key `TersaMac`")
        );

        let merge = r"
base: &base { platform: macOS }
targets:
  TersaMac:
    <<: *base
";
        assert!(
            parse_project_targets(merge)
                .expect_err("merge keys must fail")
                .contains("YAML merge keys are forbidden")
        );

        let tagged = r"
targets:
  TersaMac:
    platform: !platform macOS
";
        assert!(parse_project_targets(tagged).is_err());

        let non_string_key = r"
targets:
  TersaMac:
    platform: macOS
    1: forbidden
";
        assert!(parse_project_targets(non_string_key).is_err());
    }

    #[test]
    fn signing_configuration_requires_one_exact_nonempty_group_in_each_array() {
        let project = r#"
options:
  bundleIdPrefix: app.tersa
  deploymentTarget: { macOS: "15.0", iOS: "18.0" }
  xcodeVersion: "26.0"
settings: {}
targets:
  TersaMac:
    type: application
    platform: macOS
    sources: []
    info: {}
    entitlements:
      path: macos/TersaMac.entitlements
      properties:
        com.apple.security.app-sandbox: true
        com.apple.security.network.client: true
        com.apple.security.network.server: true
        com.apple.security.application-groups: []
        keychain-access-groups:
          - wrong.group
          - ${TeamIdentifierPrefix}app.tersa.shared
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac
        TERSA_MACOS_APP_GROUP: "$(TeamIdentifierPrefix)app.tersa.shared"
        CODE_SIGN_ENTITLEMENTS: macos/TersaMac.entitlements
    preBuildScripts:
      - name: Build Rust static library
        basedOnDependencyAnalysis: false
        script: 'sh "${SRCROOT}/scripts/build-rust-staticlib.sh" macos "${CONFIGURATION}"'
    scheme:
      testTargets: []
"#;
        let entitlements = r#"<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.network.client</key><true/>
<key>com.apple.security.network.server</key><true/>
<key>com.apple.security.application-groups</key><array></array>
<key>keychain-access-groups</key><array><string>wrong.group</string></array>
</dict></plist>"#;
        let violations =
            signing_configuration_violations(entitlements, VALID_BROKER_ENTITLEMENTS, project);
        assert!(violations.len() >= 4);
        assert!(
            violations
                .iter()
                .filter(|violation| violation.contains("com.apple.security.application-groups"))
                .count()
                >= 2
        );
        assert!(
            violations
                .iter()
                .filter(|violation| violation.contains("keychain-access-groups"))
                .count()
                >= 2
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one exhaustive mutation table asserting every unsupported xcodegen bypass fails closed"
    )]
    fn effective_signing_policy_rejects_every_unsupported_xcodegen_bypass() {
        assert!(
            signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                VALID_SIGNING_PROJECT,
            )
            .is_empty()
        );

        let project_wide = VALID_SIGNING_PROJECT.replace(
            "settings: {}",
            "settings:\n  base:\n    TERSA_MACOS_APP_GROUP: forbidden",
        );
        let per_config = VALID_SIGNING_PROJECT.replace(
            "    settings:\n      base:",
            "    settings:\n      configs:\n        Debug:\n          TERSA_MACOS_APP_GROUP: forbidden\n      base:",
        );
        let wrong_code_sign = VALID_SIGNING_PROJECT.replace(
            "CODE_SIGN_ENTITLEMENTS: macos/TersaMac.entitlements",
            "CODE_SIGN_ENTITLEMENTS: $(UNREVIEWED_ENTITLEMENTS)",
        );
        let unreviewed_entitlement_path = VALID_SIGNING_PROJECT.replace(
            "macos/TersaMac.entitlements",
            "macos/Unreviewed.entitlements",
        );
        let other_mac = VALID_SIGNING_PROJECT.replace(
            "  OtherMac:\n    platform: macOS",
            "  OtherMac:\n    platform: macOS\n    settings:\n      base:\n        TERSA_MACOS_APP_GROUP: forbidden",
        );
        let other_ios = VALID_SIGNING_PROJECT.replace(
            "  OtherIOS:\n    platform: iOS",
            "  OtherIOS:\n    platform: iOS\n    entitlements:\n      properties:\n        keychain-access-groups: [forbidden]",
        );
        let target_template =
            format!("targetTemplates:\n  SharedSigning: {{}}\n{VALID_SIGNING_PROJECT}").replace(
                "    platform: macOS",
                "    platform: macOS\n    templates: [SharedSigning]",
            );
        let setting_group =
            format!("settingGroups:\n  SharedSigning: {{}}\n{VALID_SIGNING_PROJECT}").replace(
                "    settings:\n      base:",
                "    settings:\n      groups: [SharedSigning]\n      base:",
            );
        let config_file = VALID_SIGNING_PROJECT.replace(
            "    platform: macOS",
            "    platform: macOS\n    configFiles:\n      Debug: Config/Signing.xcconfig",
        );
        let included = format!("include: Config/Signing.yml\n{VALID_SIGNING_PROJECT}");
        let reused_path = VALID_SIGNING_PROJECT.replace(
            "  OtherMac:\n    platform: macOS",
            "  OtherMac:\n    platform: macOS\n    entitlements:\n      path: macos/TersaMac.entitlements",
        );
        let conditional = VALID_SIGNING_PROJECT.replace(
            "        TERSA_MACOS_APP_GROUP: \"$(TeamIdentifierPrefix)app.tersa.shared\"",
            "        TERSA_MACOS_APP_GROUP: \"$(TeamIdentifierPrefix)app.tersa.shared\"\n        TERSA_MACOS_APP_GROUP[sdk=macosx*]: forbidden",
        );
        // The single-archive link rule: swapping in the bridge archive, adding a
        // SECOND archive, or dropping the pin entirely must all fail closed — the
        // linker only rejects one archive ordering, so this gate is the guard.
        let bridge_archive = VALID_SIGNING_PROJECT.replace(
            "libtersa_mailbox_sync_ffi_macos.a",
            "libtersa_apple_bridge.a",
        );
        let both_archives = VALID_SIGNING_PROJECT.replace(
            "          - \"$(SRCROOT)/build/rust/$(PLATFORM_NAME)/$(CONFIGURATION)/libtersa_mailbox_sync_ffi_macos.a\"",
            "          - \"$(SRCROOT)/build/rust/$(PLATFORM_NAME)/$(CONFIGURATION)/libtersa_mailbox_sync_ffi_macos.a\"\n          - \"$(SRCROOT)/build/rust/$(PLATFORM_NAME)/$(CONFIGURATION)/libtersa_apple_bridge.a\"",
        );
        let missing_ldflags = VALID_SIGNING_PROJECT.replace(
            "        OTHER_LDFLAGS:\n          - \"$(SRCROOT)/build/rust/$(PLATFORM_NAME)/$(CONFIGURATION)/libtersa_mailbox_sync_ffi_macos.a\"\n",
            "",
        );

        for (label, project, expected) in [
            (
                "project-wide settings",
                project_wide,
                "outside the exact allowlist",
            ),
            ("per-config override", per_config, "indirection `configs`"),
            (
                "CODE_SIGN_ENTITLEMENTS",
                wrong_code_sign,
                "CODE_SIGN_ENTITLEMENTS",
            ),
            (
                "unreviewed entitlement path",
                unreviewed_entitlement_path,
                "entitlement path is outside the exact allowlist",
            ),
            ("other macOS target", other_mac, "targets.OtherMac"),
            ("other iOS target", other_ios, "targets.OtherIOS"),
            ("target template", target_template, "targetTemplates"),
            ("setting group", setting_group, "settingGroups"),
            ("config file", config_file, "configFiles"),
            ("include", included, "indirection `include`"),
            (
                "entitlement path reuse",
                reused_path,
                "protected signing value is reused",
            ),
            (
                "conditional setting",
                conditional,
                "TERSA_MACOS_APP_GROUP[sdk=macosx*]",
            ),
            (
                "bridge archive substituted",
                bridge_archive,
                "OTHER_LDFLAGS must link exactly the single mailbox-sync FFI archive",
            ),
            (
                "both archives linked",
                both_archives,
                "OTHER_LDFLAGS must link exactly the single mailbox-sync FFI archive",
            ),
            (
                "missing OTHER_LDFLAGS",
                missing_ldflags,
                "OTHER_LDFLAGS must link exactly the single mailbox-sync FFI archive",
            ),
        ] {
            let violations = signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &project,
            );
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected)),
                "{label} must fail closed; got {violations:?}"
            );
        }
    }

    #[test]
    fn xcodegen_options_reject_nested_generation_hooks_and_unknown_keys() {
        for (label, project) in [
            (
                "pre-generation hook",
                VALID_SIGNING_PROJECT.replace(
                    "  bundleIdPrefix: app.tersa",
                    "  bundleIdPrefix: app.tersa\n  preGenCommand: sh unreviewed.sh",
                ),
            ),
            (
                "post-generation hook",
                VALID_SIGNING_PROJECT.replace(
                    "  xcodeVersion: \"26.0\"",
                    "  xcodeVersion: \"26.0\"\n  postGenCommand: sh unreviewed.sh",
                ),
            ),
            (
                "unknown option",
                VALID_SIGNING_PROJECT.replace(
                    "  xcodeVersion: \"26.0\"",
                    "  xcodeVersion: \"26.0\"\n  createIntermediateGroups: true",
                ),
            ),
        ] {
            let violations = signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &project,
            );
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains("options must contain only")),
                "{label} must fail closed; got {violations:?}"
            );
        }
    }

    #[test]
    fn project_and_tersa_mac_top_level_keys_are_closed_allowlists() {
        let cases = [
            (
                "missing project name",
                VALID_SIGNING_PROJECT.replacen("name: Tersa\n", "", 1),
                "project-root XcodeGen keys",
            ),
            (
                "project attributes",
                VALID_SIGNING_PROJECT.replace(
                    "settings: {}",
                    "attributes:\n  DevelopmentTeam: ATTACKER\nsettings: {}",
                ),
                "project-root XcodeGen keys",
            ),
            (
                "missing reviewed target key",
                VALID_SIGNING_PROJECT.replace(
                    "    sources:\n      - path: macos\n      - path: licenses/THIRD_PARTY_NOTICES-bridge-macos.txt\n        buildPhase: resources\n",
                    "",
                ),
                "TersaMac target must contain only",
            ),
            (
                "nested legacy target",
                VALID_SIGNING_PROJECT.replace(
                    "    type: application",
                    "    type: application\n    legacy:\n      toolPath: /tmp/unreviewed",
                ),
                "TersaMac target must contain only",
            ),
            (
                "nested unreviewed dependency",
                VALID_SIGNING_PROJECT.replace(
                    "    dependencies:\n      - target: TersaMacTokenBroker\n        embed: true\n",
                    "    dependencies:\n      - target: Unreviewed\n        embed: true\n",
                ),
                "embed exactly the TersaMacTokenBroker XPC dependency",
            ),
            (
                "missing embedded broker dependency",
                VALID_SIGNING_PROJECT.replace(
                    "    dependencies:\n      - target: TersaMacTokenBroker\n        embed: true\n",
                    "",
                ),
                "TersaMac target must contain only",
            ),
            (
                "nested target attributes",
                VALID_SIGNING_PROJECT.replace(
                    "    type: application",
                    "    type: application\n    attributes:\n      DevelopmentTeam: ATTACKER\n      ProvisioningStyle: Manual",
                ),
                "TersaMac target must contain only",
            ),
        ];
        for (label, project, expected) in cases {
            let violations = signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &project,
            );
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected)),
                "{label} must fail closed; got {violations:?}"
            );
        }

        let defensive_attributes = VALID_SIGNING_PROJECT.replace(
            "  OtherMac:\n    platform: macOS",
            "  OtherMac:\n    platform: macOS\n    attributes:\n      DevelopmentTeam: ATTACKER\n      ProvisioningStyle: Manual",
        );
        let violations = signing_configuration_violations(
            VALID_ENTITLEMENTS,
            VALID_BROKER_ENTITLEMENTS,
            &defensive_attributes,
        );
        for key in ["DevelopmentTeam", "ProvisioningStyle"] {
            assert!(
                violations.iter().any(|violation| violation.contains(key)),
                "{key} must be recognized defensively; got {violations:?}"
            );
        }
    }

    #[test]
    fn tersa_mac_sources_are_an_exact_ordered_reviewed_sequence() {
        assert!(
            signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                VALID_SIGNING_PROJECT,
            )
            .is_empty()
        );
        for project in [
            VALID_SIGNING_PROJECT.replace(
                "        buildPhase: resources",
                "        buildPhase: resources\n      - path: macos/Injected.swift",
            ),
            VALID_SIGNING_PROJECT.replace(
                "      - path: macos\n      - path: licenses/THIRD_PARTY_NOTICES-bridge-macos.txt\n        buildPhase: resources",
                "      - path: licenses/THIRD_PARTY_NOTICES-bridge-macos.txt\n        buildPhase: resources\n      - path: macos",
            ),
        ] {
            assert!(
                signing_configuration_violations(
                    VALID_ENTITLEMENTS,
                    VALID_BROKER_ENTITLEMENTS,
                    &project,
                )
                .iter()
                .any(|violation| {
                    violation.contains("exact reviewed source and resource sequence")
                }),
                "source sequence bypass must fail closed"
            );
        }
    }

    #[test]
    fn tersa_mac_tests_sources_are_exact_including_reviewed_callback_buffer() {
        const EXPECTED: &str = "the TersaMacTests sources must be exactly macos-tests and the reviewed pure Swift client/model surface";

        // Positive: exact ordered list with the single reviewed shared
        // callback-buffer path passes closed.
        assert!(
            signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                VALID_SIGNING_PROJECT,
            )
            .is_empty(),
            "exact TersaMacTests source list including TokenBrokerCallbackBuffer.swift must pass"
        );

        let reviewed_callback =
            "      - path: macos-token-broker/TokenBrokerCallbackBuffer.swift\n";
        let cases = [
            (
                "extra arbitrary broker source",
                VALID_SIGNING_PROJECT.replace(
                    reviewed_callback,
                    "      - path: macos-token-broker/TokenBrokerCallbackBuffer.swift\n      - path: macos-token-broker/TokenBrokerService.swift\n",
                ),
            ),
            (
                "alternate path spelling (directory root)",
                VALID_SIGNING_PROJECT.replace(
                    "macos-token-broker/TokenBrokerCallbackBuffer.swift",
                    "macos-token-broker",
                ),
            ),
            (
                "alternate path spelling (case drift)",
                VALID_SIGNING_PROJECT.replace(
                    "macos-token-broker/TokenBrokerCallbackBuffer.swift",
                    "macos-token-broker/TokenBrokerCallbackbuffer.swift",
                ),
            ),
            (
                "alternate path spelling (underscore separator)",
                VALID_SIGNING_PROJECT.replace(
                    "macos-token-broker/TokenBrokerCallbackBuffer.swift",
                    "macos_token_broker/TokenBrokerCallbackBuffer.swift",
                ),
            ),
            (
                "removal of reviewed callback buffer source",
                VALID_SIGNING_PROJECT.replace(reviewed_callback, ""),
            ),
            (
                "order drift (callback buffer before authorization session)",
                VALID_SIGNING_PROJECT.replace(
                    "      - path: macos/TokenBrokerAuthorizationSession.swift\n      - path: macos-token-broker/TokenBrokerCallbackBuffer.swift\n",
                    "      - path: macos-token-broker/TokenBrokerCallbackBuffer.swift\n      - path: macos/TokenBrokerAuthorizationSession.swift\n",
                ),
            ),
        ];
        for (label, project) in cases {
            let violations = signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &project,
            );
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(EXPECTED)),
                "{label} must fail closed; got {violations:?}"
            );
        }
    }

    #[test]
    fn tersa_mac_entitlement_dictionaries_are_exact_five_key_typed_allowlists() {
        let source_cases = [
            VALID_ENTITLEMENTS.replace(
                "</dict>",
                "<key>com.apple.security.get-task-allow</key><true/></dict>",
            ),
            VALID_ENTITLEMENTS.replace(
                "<key>com.apple.security.app-sandbox</key><true/>",
                "<key>com.apple.security.app-sandbox</key><false/>",
            ),
            VALID_ENTITLEMENTS.replace(
                "<key>com.apple.security.network.client</key><true/>",
                "<key>com.apple.security.network.client</key><string>true</string>",
            ),
            VALID_ENTITLEMENTS.replace("<key>com.apple.security.network.server</key><true/>", ""),
        ];
        for source in source_cases {
            let violations = signing_configuration_violations(
                &source,
                VALID_BROKER_ENTITLEMENTS,
                VALID_SIGNING_PROJECT,
            );
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains("apple/macos/TersaMac.entitlements")),
                "source entitlement mutation must fail closed; got {violations:?}"
            );
        }

        let property_cases = [
            VALID_SIGNING_PROJECT.replace(
                "        com.apple.security.app-sandbox: true",
                "        com.apple.security.app-sandbox: true\n        com.apple.security.get-task-allow: true",
            ),
            VALID_SIGNING_PROJECT.replace(
                "        com.apple.security.app-sandbox: true",
                "        com.apple.security.app-sandbox: false",
            ),
            VALID_SIGNING_PROJECT.replace(
                "        com.apple.security.network.client: true",
                "        com.apple.security.network.client: \"true\"",
            ),
            VALID_SIGNING_PROJECT.replace(
                "        com.apple.security.network.server: true\n",
                "",
            ),
        ];
        for project in property_cases {
            let violations = signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &project,
            );
            assert!(
                violations.iter().any(|violation| {
                    violation.contains("TersaMac XcodeGen entitlement properties")
                }),
                "XcodeGen entitlement mutation must fail closed; got {violations:?}"
            );
        }
    }

    #[test]
    fn tersa_mac_execution_and_signing_surface_is_exact() {
        let extra_pre_build = VALID_SIGNING_PROJECT.replace(
            "        script: 'sh \"${SRCROOT}/scripts/build-rust-staticlib.sh\" macos \"${CONFIGURATION}\"'",
            "        script: 'sh \"${SRCROOT}/scripts/build-rust-staticlib.sh\" macos \"${CONFIGURATION}\"'\n      - name: Unreviewed\n        basedOnDependencyAnalysis: false\n        script: sh unreviewed.sh",
        );
        let cases = [
            (
                "aggregate target",
                VALID_SIGNING_PROJECT.replace("    type: application", "    type: aggregate"),
                "type must be exactly application",
            ),
            (
                "legacy target",
                VALID_SIGNING_PROJECT.replace("    type: application", "    type: legacy"),
                "type must be exactly application",
            ),
            (
                "changed script name",
                VALID_SIGNING_PROJECT.replace(
                    "name: Build Rust static library",
                    "name: Unreviewed build",
                ),
                "exact reviewed Rust pre-build script",
            ),
            (
                "changed script body",
                VALID_SIGNING_PROJECT.replace(
                    "build-rust-staticlib.sh",
                    "unreviewed-build.sh",
                ),
                "exact reviewed Rust pre-build script",
            ),
            (
                "extra pre-build script",
                extra_pre_build,
                "exact reviewed Rust pre-build script",
            ),
            (
                "post-build script",
                VALID_SIGNING_PROJECT.replace(
                    "    scheme:\n      testTargets:\n        - TersaMacTests",
                    "    postBuildScripts:\n      - name: Unreviewed\n        script: sh unreviewed.sh\n    scheme:\n      testTargets:\n        - TersaMacTests",
                ),
                "postBuildScripts",
            ),
            (
                "scheme action",
                VALID_SIGNING_PROJECT.replace(
                    "    scheme:\n      testTargets:\n        - TersaMacTests",
                    "    scheme:\n      testTargets:\n        - TersaMacTests\n      preActions:\n        - script: sh unreviewed.sh",
                ),
                "no executable actions",
            ),
            (
                "project scheme",
                format!(
                    "schemes:\n  Unreviewed:\n    build:\n      targets: {{ TersaMac: all }}\n    preActions:\n      - script: sh unreviewed.sh\n{VALID_SIGNING_PROJECT}"
                ),
                "indirection `schemes`",
            ),
            (
                "build rule",
                VALID_SIGNING_PROJECT.replace(
                    "    preBuildScripts:",
                    "    buildRules:\n      - name: Unreviewed\n        script: sh unreviewed.sh\n    preBuildScripts:",
                ),
                "buildRules",
            ),
            (
                "build-tool plugin",
                VALID_SIGNING_PROJECT.replace(
                    "    preBuildScripts:",
                    "    buildToolPlugins:\n      - plugin: Unreviewed\n    preBuildScripts:",
                ),
                "buildToolPlugins",
            ),
            (
                "conditional bundle identifier",
                VALID_SIGNING_PROJECT.replace(
                    "        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac\n        TERSA_MACOS_APP_GROUP:",
                    "        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac\n        PRODUCT_BUNDLE_IDENTIFIER[sdk=macosx*]: app.attacker\n        TERSA_MACOS_APP_GROUP:",
                ),
                "without conditional overrides",
            ),
        ];
        for (label, project, expected) in cases {
            let violations = signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &project,
            );
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected)),
                "{label} must fail closed; got {violations:?}"
            );
        }
    }

    #[test]
    fn additional_signing_controls_and_expansion_roots_fail_closed() {
        for (label, injected, expected) in [
            (
                "other code-sign flags",
                "        OTHER_CODE_SIGN_FLAGS: --deep",
                "OTHER_CODE_SIGN_FLAGS",
            ),
            (
                "conditional code-signing control",
                "        CODE_SIGNING_ALLOWED[sdk=macosx*]: YES",
                "CODE_SIGNING_ALLOWED[sdk=macosx*]",
            ),
            (
                "entitlement modification control",
                "        CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION: YES",
                "CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION",
            ),
            (
                "expanded code-sign identity",
                "        EXPANDED_CODE_SIGN_IDENTITY: ATTACKER",
                "EXPANDED_CODE_SIGN_IDENTITY",
            ),
            (
                "team expansion root",
                "        TeamIdentifierPrefix: ATTACKER",
                "TeamIdentifierPrefix",
            ),
            (
                "application expansion root",
                "        AppIdentifierPrefix: ATTACKER",
                "AppIdentifierPrefix",
            ),
        ] {
            let project = VALID_SIGNING_PROJECT.replace(
                "        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac\n        TERSA_MACOS_APP_GROUP:",
                &format!(
                    "        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac\n{injected}\n        TERSA_MACOS_APP_GROUP:"
                ),
            );
            let violations = signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &project,
            );
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected)),
                "{label} must fail closed; got {violations:?}"
            );
        }

        let reused_prefix = VALID_SIGNING_PROJECT.replace(
            "  OtherMac:\n    platform: macOS",
            "  OtherMac:\n    platform: macOS\n    settings:\n      base:\n        UNREVIEWED: ${TeamIdentifierPrefix}app.tersa.shared",
        );
        assert!(
            signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &reused_prefix,
            )
            .iter()
            .any(|violation| violation.contains("protected signing value is reused"))
        );
    }

    #[test]
    fn project_generation_must_use_the_exact_no_env_wrapper() {
        let wrapper = project_generation_wrapper();
        let ci = "sh apple/scripts/generate-project.sh\n".repeat(3);
        let consumer = "sh apple/scripts/generate-project.sh\n";
        assert!(
            project_generation_surface_violations(&wrapper, &ci, consumer, consumer).is_empty()
        );

        let missing_no_env = wrapper.replace(" --no-env", "");
        assert!(
            project_generation_surface_violations(&missing_no_env, &ci, consumer, consumer)
                .iter()
                .any(|violation| violation.contains("exact reviewed --no-env wrapper"))
        );
        let direct = concat!(
            "xcodegen",
            " generate --spec apple/project.yml --project apple\n"
        );
        assert!(
            project_generation_surface_violations(&wrapper, &(ci + direct), consumer, consumer,)
                .iter()
                .any(|violation| violation.contains("must not bypass"))
        );
        let root_form = "xcodegen --spec apple/project.yml --project apple\n";
        assert!(
            project_generation_surface_violations(
                &wrapper,
                &format!("{consumer}{consumer}{consumer}{root_form}"),
                consumer,
                consumer,
            )
            .iter()
            .any(|violation| violation.contains("must not bypass"))
        );
    }

    const STATIC_PROJECT_GENERATION_BYPASS_FIXTURES: &[(&str, &str)] = &[
        (
            "combined bash login-command flags",
            "bash -lc 'xcodegen --spec unreviewed.yml'\n",
        ),
        (
            "combined sh error-command flags",
            "sh -ec 'xcodegen -s unreviewed.yml'\n",
        ),
        (
            "static alias indirection",
            "alias xcg=xcodegen; xcg --spec unreviewed.yml\n",
        ),
        (
            "static variable indirection",
            "XCODEGEN=xcodegen; \"$XCODEGEN\" --spec unreviewed.yml\n",
        ),
        (
            "double-quoted GitHub Actions scalar",
            "- run: \"xcodegen generate --spec unreviewed.yml\"\n",
        ),
        (
            "single-quoted GitHub Actions scalar",
            "- run: 'xcodegen generate --spec unreviewed.yml'\n",
        ),
        (
            "eval wrapper",
            "eval 'xcodegen generate --spec unreviewed.yml'\n",
        ),
        ("nohup wrapper", "nohup xcodegen --spec unreviewed.yml\n"),
        (
            "timeout wrapper",
            "timeout 30 xcodegen --spec unreviewed.yml\n",
        ),
        (
            "nice wrapper",
            "nice -n 10 xcodegen --spec unreviewed.yml\n",
        ),
        (
            "xargs wrapper",
            "printf input | xargs xcodegen --spec unreviewed.yml\n",
        ),
        (
            "unknown shell wrapper",
            "project-tool xcodegen --spec unreviewed.yml\n",
        ),
        (
            "variable shell wrapper",
            "$PROJECT_WRAPPER xcodegen --spec unreviewed.yml\n",
        ),
    ];

    #[test]
    fn every_tracked_project_generation_command_is_inventory_checked() {
        let repository = temporary_repository("xcodegen-inventory");
        fs::create_dir_all(repository.join("apple/scripts"))
            .expect("script directory must be created");
        fs::create_dir_all(repository.join("docs")).expect("docs directory must be created");
        fs::write(
            repository.join("apple/scripts/generate-project.sh"),
            project_generation_wrapper(),
        )
        .expect("wrapper must be written");
        fs::write(repository.join("docs/development.md"), "initial fixture\n")
            .expect("tracked fixture must be written");
        git_add(
            &repository,
            false,
            &["apple/scripts/generate-project.sh", "docs/development.md"],
        );

        for (label, invocation) in [
            (
                "explicit generate subcommand",
                concat!("xcodegen", " generate --spec unreviewed.yml\n"),
            ),
            ("root long spec option", "xcodegen --spec unreviewed.yml\n"),
            (
                "root attached long spec option",
                "xcodegen --spec=unreviewed.yml\n",
            ),
            ("root short spec option", "xcodegen -s unreviewed.yml\n"),
            ("bare invocation", "xcodegen\n"),
            (
                "path-qualified executable",
                "/opt/local/bin/xcodegen --spec unreviewed.yml\n",
            ),
            (
                "quoted variable-qualified executable",
                "\"$RUNNER_TEMP/xcodegen/bin/xcodegen\" -s unreviewed.yml\n",
            ),
            (
                "ordinary whitespace variation",
                "  xcodegen\t  --spec\t unreviewed.yml  \n",
            ),
            (
                "backslash-newline continuation",
                "xcodegen \\\n  --spec unreviewed.yml\n",
            ),
        ]
        .into_iter()
        .chain(STATIC_PROJECT_GENERATION_BYPASS_FIXTURES.iter().copied())
        {
            fs::write(repository.join("docs/development.md"), invocation)
                .expect("direct command fixture must be written");
            let violations = tracked_project_generation_violations(&repository)
                .expect("tracked command inventory must succeed");
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains("docs/development.md")),
                "{label} must fail closed; got {violations:?}"
            );
        }

        fs::write(
            repository.join("docs/development.md"),
            concat!(
                "sh apple/scripts/generate-project.sh\n",
                "command -v xcodegen >/dev/null\n",
                "\"$RUNNER_TEMP/xcodegen/bin/xcodegen\" --version | grep Version\n",
                "xcodegen --help\n",
                "/opt/local/bin/xcodegen help\n",
                "- run: \"echo xcodegen\"\n",
                "\"xcodegen is quoted prose, not a command\"\n",
                "curl https://example.invalid/xcodegen/releases/xcodegen.zip\n",
                "XCODEGEN_PATH=/opt/local/bin/xcodegen\n",
                "echo xcodegen\n",
                "xcodegen is mentioned here as prose, not executed successfully.\n",
                "The /opt/local/bin/xcodegen path is documentation.\n",
                "XcodeGen 2.45.4 is the pinned project generator.\n",
            ),
        )
        .expect("legitimate occurrences must be written");
        assert!(
            tracked_project_generation_violations(&repository)
                .expect("tracked command inventory must succeed")
                .is_empty(),
            "version, install, prose, argument, and path occurrences must remain allowed"
        );

        fs::write(
            repository.join("apple/scripts/generate-project.sh"),
            format!("{}# unreviewed change\n", project_generation_wrapper()),
        )
        .expect("wrapper mutation must be written");
        let violations = tracked_project_generation_violations(&repository)
            .expect("tracked command inventory must succeed");
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("apple/scripts/generate-project.sh")),
            "non-exact wrapper must fail closed; got {violations:?}"
        );
        fs::remove_dir_all(repository).expect("temporary repository must be removed");
    }

    #[test]
    fn tracked_apple_inventory_rejects_force_added_build_entries_and_entitlement_symlinks() {
        let repository = temporary_repository("tracked-apple-inventory");
        fs::create_dir_all(repository.join("apple/build/DerivedData"))
            .expect("ignored build directory must be created");
        fs::create_dir_all(repository.join("apple/source"))
            .expect("source directory must be created");
        fs::write(repository.join(".gitignore"), "apple/build/\n")
            .expect("ignore file must be written");
        fs::write(
            repository.join("apple/build/DerivedData/Forced.txt"),
            "tracked generated content",
        )
        .expect("force-added fixture must be written");
        fs::write(
            repository.join("apple/source/Regular.entitlements"),
            "<plist version=\"1.0\"><dict/></plist>",
        )
        .expect("regular entitlement must be written");
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            Path::new("Regular.entitlements"),
            repository.join("apple/source/Linked.entitlements"),
        )
        .expect("entitlement symlink must be created");
        git_add(
            &repository,
            false,
            &[
                ".gitignore",
                "apple/source/Regular.entitlements",
                "apple/source/Linked.entitlements",
            ],
        );
        git_add(&repository, true, &["apple/build/DerivedData/Forced.txt"]);

        let inventory = tracked_apple_signing_inventory(&repository)
            .expect("tracked Apple inventory must succeed");
        assert_eq!(
            inventory.entitlement_paths,
            vec![std::path::PathBuf::from(
                "apple/source/Regular.entitlements"
            )]
        );
        assert!(
            inventory
                .violations
                .iter()
                .any(|violation| violation.contains("apple/build/DerivedData/Forced.txt")),
            "force-added ignored content must fail closed; got {:?}",
            inventory.violations
        );
        #[cfg(unix)]
        assert!(
            inventory
                .violations
                .iter()
                .any(|violation| violation.contains("Linked.entitlements")),
            "tracked entitlement symlink must fail closed; got {:?}",
            inventory.violations
        );
        fs::remove_dir_all(repository).expect("temporary repository must be removed");
    }

    #[test]
    fn entitlement_inventory_ignores_generated_build_only_and_rejects_source_symlinks() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "tersa-entitlement-inventory-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let source = root.join("source");
        let generated = root.join("build/DerivedData");
        fs::create_dir_all(&source).expect("source inventory directory must be created");
        fs::create_dir_all(&generated).expect("generated directory must be created");
        let protected = r#"<plist version="1.0"><dict><key>keychain-access-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array></dict></plist>"#;
        let source_entitlement = source.join("Unreviewed.entitlements");
        fs::write(&source_entitlement, protected).expect("source fixture must be written");
        fs::write(generated.join("Copied.entitlements"), protected)
            .expect("generated copy must be written");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&source_entitlement, generated.join("Linked.entitlements"))
            .expect("generated symlink must be created");

        let mut paths = Vec::new();
        collect_entitlement_paths(&root, &root, &mut paths)
            .expect("generated build inventory must be ignored");
        assert_eq!(paths, vec![source_entitlement.clone()]);
        assert!(
            !non_owner_entitlement_violations(&source_entitlement.to_string_lossy(), protected,)
                .is_empty()
        );

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                Path::new("Unreviewed.entitlements"),
                source.join("Alias.entitlements"),
            )
            .expect("source symlink must be created");
            let error = collect_entitlement_paths(&root, &root, &mut Vec::new())
                .expect_err("source symlinks must fail closed");
            assert!(error.to_string().contains("must not be a symbolic link"));

            let real_root = root.with_extension("real");
            fs::create_dir_all(&real_root).expect("real inventory root must be created");
            let linked_root = root.with_extension("linked");
            std::os::unix::fs::symlink(&real_root, &linked_root)
                .expect("inventory root symlink must be created");
            let error = collect_entitlement_paths(&linked_root, &linked_root, &mut Vec::new())
                .expect_err("inventory root symlink must fail closed");
            assert!(error.to_string().contains("root"));
            fs::remove_file(linked_root).expect("inventory root symlink must be removed");
            fs::remove_dir_all(real_root).expect("real inventory root must be removed");

            let build_link_root = root.with_extension("build-link");
            let generated_target = root.with_extension("generated-target");
            fs::create_dir_all(&build_link_root)
                .expect("build-link inventory root must be created");
            fs::create_dir_all(&generated_target).expect("generated target must be created");
            std::os::unix::fs::symlink(&generated_target, build_link_root.join("build"))
                .expect("excluded build-root symlink must be created");
            let error =
                collect_entitlement_paths(&build_link_root, &build_link_root, &mut Vec::new())
                    .expect_err("excluded build-root symlink must fail closed");
            assert!(error.to_string().contains("excluded Apple build root"));
            fs::remove_dir_all(build_link_root).expect("build-link inventory root must be removed");
            fs::remove_dir_all(generated_target).expect("generated target must be removed");
        }
        fs::remove_dir_all(&root).expect("inventory fixture must be removed");
    }

    #[test]
    fn non_owner_entitlement_files_cannot_claim_the_protected_groups() {
        let clean = r#"<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>"#;
        assert!(non_owner_entitlement_violations("clean.entitlements", clean).is_empty());

        let contaminated = r#"<plist version="1.0"><dict>
<key>keychain-access-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
</dict></plist>"#;
        assert_eq!(
            non_owner_entitlement_violations("other.entitlements", contaminated),
            vec![
                "other.entitlements must not contain protected entitlement `keychain-access-groups`"
            ]
        );
    }

    #[test]
    fn token_broker_entitlements_are_exact_and_disjoint_from_tersa_mac() {
        assert!(source_token_broker_entitlement_violations(VALID_BROKER_ENTITLEMENTS).is_empty());
        assert!(
            signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                VALID_SIGNING_PROJECT,
            )
            .is_empty()
        );

        for (label, mutated, expected) in [
            (
                "shared app group on broker",
                VALID_BROKER_ENTITLEMENTS.replace(
                    "</dict>",
                    "<key>com.apple.security.application-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array></dict>",
                ),
                "forbidden capability `com.apple.security.application-groups`",
            ),
            (
                "network server on broker",
                VALID_BROKER_ENTITLEMENTS.replace(
                    "</dict>",
                    "<key>com.apple.security.network.server</key><true/></dict>",
                ),
                "forbidden capability `com.apple.security.network.server`",
            ),
            (
                "get-task-allow on broker",
                VALID_BROKER_ENTITLEMENTS.replace(
                    "</dict>",
                    "<key>com.apple.security.get-task-allow</key><true/></dict>",
                ),
                "forbidden capability `com.apple.security.get-task-allow`",
            ),
            (
                "library-validation exception on broker",
                VALID_BROKER_ENTITLEMENTS.replace(
                    "</dict>",
                    "<key>com.apple.security.cs.disable-library-validation</key><true/></dict>",
                ),
                "forbidden capability `com.apple.security.cs.disable-library-validation`",
            ),
            (
                "wrong token group",
                VALID_BROKER_ENTITLEMENTS.replace(
                    "${TeamIdentifierPrefix}app.tersa.token",
                    "${TeamIdentifierPrefix}app.tersa.shared",
                ),
                "dedicated token group",
            ),
        ] {
            let violations = source_token_broker_entitlement_violations(&mutated);
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected)),
                "{label} must fail closed; got {violations:?}"
            );
        }
    }

    #[test]
    fn token_broker_project_surface_rejects_unreviewed_broker_mutations() {
        let shared_group_on_broker_project = VALID_SIGNING_PROJECT.replace(
            "          - ${TeamIdentifierPrefix}app.tersa.token",
            "          - ${TeamIdentifierPrefix}app.tersa.shared",
        );
        assert!(
            signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &shared_group_on_broker_project,
            )
            .iter()
            .any(|violation| {
                violation.contains("dedicated token group")
                    || violation.contains("protected signing value is reused")
                    || violation.contains("outside the exact allowlist")
            })
        );

        let broker_with_extra_script = VALID_SIGNING_PROJECT.replace(
            "        script: 'sh \"${SRCROOT}/scripts/build-rust-staticlib.sh\" macos-token-broker \"${CONFIGURATION}\"'\n",
            "        script: 'sh \"${SRCROOT}/scripts/build-rust-staticlib.sh\" macos-token-broker \"${CONFIGURATION}\"'\n      - name: Unreviewed\n        script: sh unreviewed.sh\n",
        );
        assert!(
            signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &broker_with_extra_script,
            )
            .iter()
            .any(|violation| {
                violation
                    .contains("TersaMacTokenBroker preBuildScripts must be exactly the reviewed")
                    || violation
                        .contains("TersaMacTokenBroker target must contain only the exact reviewed")
            })
        );

        let broker_with_wrong_archive = VALID_SIGNING_PROJECT.replace(
            "libtersa_token_broker_ffi_macos.a",
            "libtersa_mailbox_sync_ffi_macos.a",
        );
        assert!(
            signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &broker_with_wrong_archive,
            )
            .iter()
            .any(|violation| {
                violation.contains("TersaMacTokenBroker settings must contain only the reviewed")
            })
        );

        let broker_with_server = VALID_SIGNING_PROJECT.replace(
            "        com.apple.security.network.client: true\n        keychain-access-groups:\n          - ${TeamIdentifierPrefix}app.tersa.token\n",
            "        com.apple.security.network.client: true\n        com.apple.security.network.server: true\n        keychain-access-groups:\n          - ${TeamIdentifierPrefix}app.tersa.token\n",
        );
        assert!(
            signing_configuration_violations(
                VALID_ENTITLEMENTS,
                VALID_BROKER_ENTITLEMENTS,
                &broker_with_server,
            )
            .iter()
            .any(|violation| {
                violation.contains("TersaMacTokenBroker XcodeGen entitlement properties")
            })
        );
    }

    fn reviewed_token_broker_sources() -> [(PathBuf, String); 9] {
        [
            (
                PathBuf::from("apple/macos-token-broker/main.swift"),
                include_str!("../../apple/macos-token-broker/main.swift").to_owned(),
            ),
            (
                PathBuf::from("apple/macos-token-broker/TokenBrokerProtocol.swift"),
                include_str!("../../apple/macos-token-broker/TokenBrokerProtocol.swift").to_owned(),
            ),
            (
                PathBuf::from("apple/macos-token-broker/TokenBrokerService.swift"),
                include_str!("../../apple/macos-token-broker/TokenBrokerService.swift").to_owned(),
            ),
            (
                PathBuf::from("apple/macos-token-broker/TokenBrokerCallbackBuffer.swift"),
                include_str!("../../apple/macos-token-broker/TokenBrokerCallbackBuffer.swift")
                    .to_owned(),
            ),
            (
                PathBuf::from("apple/macos-token-broker/TokenBrokerListenerDelegate.swift"),
                include_str!("../../apple/macos-token-broker/TokenBrokerListenerDelegate.swift")
                    .to_owned(),
            ),
            (
                PathBuf::from("apple/macos-token-broker/Info.plist"),
                include_str!("../../apple/macos-token-broker/Info.plist").to_owned(),
            ),
            (
                PathBuf::from("apple/macos-token-broker/TersaMacTokenBroker.entitlements"),
                include_str!("../../apple/macos-token-broker/TersaMacTokenBroker.entitlements")
                    .to_owned(),
            ),
            (
                PathBuf::from("apple/macos-token-broker/TersaTokenBrokerBridge.h"),
                include_str!("../../apple/macos-token-broker/TersaTokenBrokerBridge.h").to_owned(),
            ),
            (
                PathBuf::from("apple/macos-token-broker/TersaMacTokenBroker-Bridging-Header.h"),
                include_str!(
                    "../../apple/macos-token-broker/TersaMacTokenBroker-Bridging-Header.h"
                )
                .to_owned(),
            ),
        ]
    }

    fn assert_token_broker_surface_contains(
        sources: &[(PathBuf, String)],
        expected: &str,
        label: &str,
    ) {
        let violations = token_broker_source_surface_violations(sources);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "{label} must fail closed; got {violations:?}"
        );
    }

    fn assert_reviewed_token_broker_client_xpc_wiring_is_pinned() {
        let macos_client = [(
            PathBuf::from("apple/macos/AccountConnectionViewModel.swift"),
            "let connection = NSXPCConnection(serviceName: \"app.tersa.mac.token-broker\")\n"
                .to_owned(),
        )];
        assert!(
            macos_client_xpc_wiring_violations(&macos_client)
                .iter()
                .any(|violation| violation.contains("NSXPCConnection")),
            "XPC wiring outside the reviewed TokenBroker client allowlist must fail closed"
        );
        assert!(
            macos_client_xpc_wiring_violations(&[(
                PathBuf::from("apple/macos/AppDelegate.swift"),
                include_str!("../../apple/macos/AppDelegate.swift").to_owned(),
            )])
            .is_empty()
        );
        // Reviewed allowlisted client files may connect only via the exact
        // pinned constant assignment plus `NSXPCConnection(serviceName:)`.
        let reviewed_client = include_str!("../../apple/macos/TokenBrokerClient.swift");
        assert!(
            macos_client_xpc_wiring_violations(&[(
                PathBuf::from("apple/macos/TokenBrokerClient.swift"),
                reviewed_client.to_owned(),
            )])
            .is_empty(),
            "reviewed TokenBrokerClient.swift must pass the XPC wiring pin"
        );
        // A decoy TokenBroker* filename must not inherit the closed allowlist
        // exemption even when it mirrors the reviewed connection construction.
        let decoy_pinned = "static let serviceBundleIdentifier = \"app.tersa.mac.token-broker\"\n\
             let connection = NSXPCConnection(serviceName: Self.serviceBundleIdentifier)\n";
        let decoy_violations = macos_client_xpc_wiring_violations(&[(
            PathBuf::from("apple/macos/TokenBrokerDecoy.swift"),
            decoy_pinned.to_owned(),
        )]);
        assert!(
            decoy_violations.iter().any(|violation| {
                violation.contains("outside the closed reviewed TokenBroker client allowlist")
            }),
            "decoy TokenBroker*.swift must not inherit the reviewed client allowlist; got {decoy_violations:?}"
        );
        assert!(
            decoy_violations
                .iter()
                .any(|violation| violation.contains("NSXPCConnection")),
            "decoy TokenBroker*.swift must still fail closed on XPC wiring; got {decoy_violations:?}"
        );
        for (label, document) in [
            (
                "wrong service name",
                "let connection = NSXPCConnection(serviceName: \"app.attacker.broker\")\n"
                    .to_owned(),
            ),
            (
                "comment decoy with wrong executable service",
                "// app.tersa.mac.token-broker\n\
                 // static let serviceBundleIdentifier = \"app.tersa.mac.token-broker\"\n\
                 let connection = NSXPCConnection(serviceName: \"app.attacker.broker\")\n"
                    .to_owned(),
            ),
            (
                "unrelated string decoy with wrong executable service",
                "let decoy = \"app.tersa.mac.token-broker\"\n\
                 let connection = NSXPCConnection(serviceName: \"app.attacker.broker\")\n"
                    .to_owned(),
            ),
            (
                "alternate initializer with correct constant",
                "static let serviceBundleIdentifier = \"app.tersa.mac.token-broker\"\n\
                 let connection = NSXPCConnection(machServiceName: Self.serviceBundleIdentifier)\n"
                    .to_owned(),
            ),
            (
                "literal serviceName bypassing the reviewed constant",
                "static let serviceBundleIdentifier = \"app.tersa.mac.token-broker\"\n\
                 let connection = NSXPCConnection(serviceName: \"app.tersa.mac.token-broker\")\n"
                    .to_owned(),
            ),
        ] {
            assert!(
                macos_client_xpc_wiring_violations(&[(
                    PathBuf::from("apple/macos/TokenBrokerClient.swift"),
                    document,
                )])
                .iter()
                .any(|violation| violation.contains("embedded token-broker service bundle id")),
                "{label} must fail closed"
            );
        }
    }

    #[test]
    fn token_broker_source_surface_is_closed_and_fail_closed() {
        let sources = reviewed_token_broker_sources();
        assert!(token_broker_source_surface_violations(&sources).is_empty());

        for (label, path, document, expected) in [
            (
                "processIdentifier auth",
                "apple/macos-token-broker/TokenBrokerListenerDelegate.swift",
                "func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool { let pid = newConnection.processIdentifier; return pid > 0 }\n",
                "processIdentifier",
            ),
            (
                "keychain call",
                "apple/macos-token-broker/TokenBrokerService.swift",
                "func deleteStoredTokens(accountSubject: String, withReply reply: @escaping (Int) -> Void) { _ = SecItemDelete(nil as CFDictionary); reply(1) }\n",
                "SecItemDelete",
            ),
            (
                "generic data RPC",
                "apple/macos-token-broker/TokenBrokerProtocol.swift",
                "@objc protocol OpenRPC { func invoke(payload: Data, withReply reply: @escaping (Data?) -> Void) }\n",
                "exact reviewed closed broker protocol operations",
            ),
            (
                "refresh token field",
                "apple/macos-token-broker/TokenBrokerProtocol.swift",
                "func leak(refreshToken: String, withReply reply: @escaping (Int) -> Void)\n",
                "refreshToken",
            ),
            (
                "network call",
                "apple/macos-token-broker/TokenBrokerService.swift",
                "func ping() { _ = URLSession.shared }\n",
                "URLSession",
            ),
        ] {
            let mut mutated = sources.clone();
            if let Some(entry) = mutated
                .iter_mut()
                .find(|(candidate, _)| candidate == Path::new(path))
            {
                entry.1 = document.to_owned();
            }
            assert_token_broker_surface_contains(&mutated, expected, label);
        }

        assert_reviewed_token_broker_client_xpc_wiring_is_pinned();
    }

    #[test]
    fn token_broker_source_inventory_and_signing_call_are_fail_closed() {
        let sources = reviewed_token_broker_sources();
        assert_eq!(
            sources.len(),
            TOKEN_BROKER_ALLOWED_SOURCE_PATHS.len(),
            "reviewed fixture inventory must list exactly the closed nine broker paths"
        );

        let mut with_extra = sources.to_vec();
        with_extra.push((
            PathBuf::from("apple/macos-token-broker/ExtraBrokerSurface.swift"),
            "import Foundation\n".to_owned(),
        ));
        assert_token_broker_surface_contains(
            &with_extra,
            "outside the closed TersaMacTokenBroker source allowlist",
            "extra broker file outside the closed nine-path inventory",
        );

        let mut missing_required = sources.to_vec();
        missing_required.retain(|(path, _)| {
            path != Path::new("apple/macos-token-broker/TokenBrokerService.swift")
        });
        assert_token_broker_surface_contains(
            &missing_required,
            "source inventory is missing required path",
            "missing required broker path",
        );

        let mut without_signing_call = sources.to_vec();
        if let Some(entry) = without_signing_call.iter_mut().find(|(path, _)| {
            path == Path::new("apple/macos-token-broker/TokenBrokerListenerDelegate.swift")
        }) {
            entry.1 = entry.1.replace(
                "        newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)\n",
                "",
            );
        }
        assert_token_broker_surface_contains(
            &without_signing_call,
            "setCodeSigningRequirement",
            "removed setCodeSigningRequirement call",
        );
    }

    #[test]
    fn token_broker_protocol_declaration_is_exact_path_and_form_only() {
        let protocol_path = Path::new("apple/macos-token-broker/TokenBrokerProtocol.swift");
        let reviewed =
            include_str!("../../apple/macos-token-broker/TokenBrokerProtocol.swift").to_owned();

        // Positive: the reviewed declaration at the exact path is accepted.
        assert!(
            swift_source_lexical_violations(protocol_path, &reviewed).is_empty(),
            "reviewed TokenBrokerProtocol.swift must pass the lexical protocol guard"
        );

        // Negative: a second protocol declaration in the reviewed file fails.
        let second_protocol =
            format!("{reviewed}\n@objc(ExtraBrokerProtocol)\nprotocol ExtraBrokerProtocol {{}}\n");
        assert!(
            swift_source_lexical_violations(protocol_path, &second_protocol)
                .iter()
                .any(|violation| violation.contains("must not declare `protocol`")),
            "a second protocol declaration must fail closed"
        );

        // Negative: renaming the reviewed protocol rejects the declaration.
        let renamed = reviewed
            .replace(
                "@objc(TersaMacTokenBrokerProtocolV1)",
                "@objc(TersaMacTokenBrokerProtocolV2)",
            )
            .replace(
                "protocol TersaMacTokenBrokerProtocolV1",
                "protocol TersaMacTokenBrokerProtocolV2",
            );
        assert!(
            swift_source_lexical_violations(protocol_path, &renamed)
                .iter()
                .any(|violation| violation.contains("must not declare `protocol`")),
            "a renamed protocol declaration must fail closed"
        );

        // Negative: inheritance after the reviewed name hides selectors.
        let inherited = reviewed.replace(
            "protocol TersaMacTokenBrokerProtocolV1 {",
            "protocol TersaMacTokenBrokerProtocolV1: NSObjectProtocol {",
        );
        assert!(
            swift_source_lexical_violations(protocol_path, &inherited)
                .iter()
                .any(|violation| violation.contains("must not declare `protocol`")),
            "inherited protocol declaration must fail closed"
        );

        // Negative: a where clause after the reviewed name is rejected.
        let with_where = reviewed.replace(
            "protocol TersaMacTokenBrokerProtocolV1 {",
            "protocol TersaMacTokenBrokerProtocolV1 where Self: AnyObject {",
        );
        assert!(
            swift_source_lexical_violations(protocol_path, &with_where)
                .iter()
                .any(|violation| violation.contains("must not declare `protocol`")),
            "protocol declaration with where clause must fail closed"
        );

        // Negative: the same reviewed form in another broker file fails.
        let other_broker_path = Path::new("apple/macos-token-broker/TokenBrokerService.swift");
        let moved_declaration = "\
@objc(TersaMacTokenBrokerProtocolV1)
protocol TersaMacTokenBrokerProtocolV1 {
    func ping(withReply reply: @escaping (Int) -> Void)
}
";
        assert!(
            swift_source_lexical_violations(other_broker_path, moved_declaration)
                .iter()
                .any(|violation| violation.contains("must not declare `protocol`")),
            "protocol declaration outside TokenBrokerProtocol.swift must fail closed"
        );

        // Negative: a multi-byte character that makes the @objc pin land mid-UTF-8
        // sequence must not panic; fail closed with the protocol declaration
        // violation. `é` is two bytes (C3 A9); replacing leading `@` with `é`
        // keeps the preceding span attr.len() bytes long so attr_start is the
        // continuation byte A9.
        let multibyte_attr_boundary = reviewed.replace(
            "@objc(TersaMacTokenBrokerProtocolV1)",
            "éobjc(TersaMacTokenBrokerProtocolV1)",
        );
        assert!(
            swift_source_lexical_violations(protocol_path, &multibyte_attr_boundary)
                .iter()
                .any(|violation| violation.contains("must not declare `protocol`")),
            "multi-byte @objc pin boundary must fail closed without panicking"
        );
    }

    fn exact_token_broker_session_resource_bag_deinit_fixture() -> &'static str {
        "\
final class TokenBrokerSessionResourceBag: @unchecked Sendable {
    func release() {}
    deinit { release() }
}
"
    }

    fn reviewed_token_broker_session_resource_bag_deinit_path() -> &'static Path {
        Path::new(REVIEWED_TOKEN_BROKER_SESSION_RESOURCE_BAG_DEINIT_PATH)
    }

    fn assert_swift_source_has_no_lexical_violations(path: &Path, code: &str, message: &str) {
        let violations = swift_source_lexical_violations(path, code);
        assert!(violations.is_empty(), "{message}; got {violations:?}");
    }

    fn assert_swift_source_rejects_deinit(path: &Path, code: &str, message: &str) {
        assert!(
            swift_source_lexical_violations(path, code)
                .iter()
                .any(|violation| violation.contains("must not declare `deinit`")),
            "{message}"
        );
    }

    #[test]
    fn token_broker_session_resource_bag_deinit_accepts_reviewed_source_and_exact_fixture() {
        let path = reviewed_token_broker_session_resource_bag_deinit_path();
        // Positive: the reviewed abandoned-session cleanup at the exact path,
        // owner class, and body form is accepted.
        assert_swift_source_has_no_lexical_violations(
            path,
            include_str!("../../apple/macos/TokenBrokerAuthorizationSession.swift"),
            "reviewed TokenBrokerAuthorizationSession.swift must pass the lexical deinit guard",
        );
        // Positive fixture: the exact reviewed form on the exact owner is accepted.
        assert_swift_source_has_no_lexical_violations(
            path,
            exact_token_broker_session_resource_bag_deinit_fixture(),
            "exact TokenBrokerSessionResourceBag deinit {{ release() }} fixture must pass",
        );
    }

    #[test]
    fn token_broker_session_resource_bag_deinit_rejects_wrong_path_and_owner() {
        let path = reviewed_token_broker_session_resource_bag_deinit_path();
        let exact = exact_token_broker_session_resource_bag_deinit_fixture();
        // Negative: wrong path with the exact form fails closed.
        assert_swift_source_rejects_deinit(
            Path::new("apple/macos/TokenBrokerClient.swift"),
            exact,
            "deinit outside TokenBrokerAuthorizationSession.swift must fail closed",
        );
        // Negative: wrong owner class at the reviewed path fails closed.
        assert_swift_source_rejects_deinit(
            path,
            "\
final class OtherSessionResourceBag: @unchecked Sendable {
    func release() {}
    deinit { release() }
}
",
            "deinit on a non-reviewed owner class must fail closed",
        );
    }

    #[test]
    fn token_broker_session_resource_bag_deinit_rejects_body_form_mutations() {
        let path = reviewed_token_broker_session_resource_bag_deinit_path();
        let exact = exact_token_broker_session_resource_bag_deinit_fixture();
        // Negative: extra statement before release() fails closed.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace("deinit { release() }", "deinit { _ = 0; release() }"),
            "deinit with a statement before release() must fail closed",
        );
        // Negative: extra statement after release() fails closed.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace("deinit { release() }", "deinit { release(); _ = 1 }"),
            "deinit with a statement after release() must fail closed",
        );
        // Negative: alternate call fails closed.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace("deinit { release() }", "deinit { self.release() }"),
            "deinit with a different call than release() must fail closed",
        );
    }

    #[test]
    fn token_broker_session_resource_bag_deinit_rejects_second_decoy_laundering_and_nested() {
        let path = reviewed_token_broker_session_resource_bag_deinit_path();
        let exact = exact_token_broker_session_resource_bag_deinit_fixture();
        // Negative: a second deinit fails closed even when both match the form.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace(
                "deinit { release() }",
                "deinit { release() }\n    deinit { release() }",
            ),
            "a second deinit declaration must fail closed",
        );
        // Negative: comment/string decoys of the reviewed form must not satisfy
        // the exception when the executable deinit is mutated.
        assert_swift_source_rejects_deinit(
            path,
            "\
final class TokenBrokerSessionResourceBag: @unchecked Sendable {
    func release() {}
    // deinit { release() }
    let decoy = \"deinit { release() }\"
    deinit { cancel() }
}
",
            "comment/string deinit decoys must not satisfy the reviewed exception",
        );
        // Negative: the historical body-parse laundering fixture still fails.
        assert_swift_source_rejects_deinit(
            path,
            "\
final class TokenBrokerSessionResourceBag: @unchecked Sendable {
    deinit { (NSApp.delegate as? AppDelegate)?.establishOwnedAccountProfile(Data(), completion: receive) }
}
",
            "the old deinit body-parse laundering fixture must still fail closed",
        );
        // Negative: nested placement inside the reviewed class fails closed.
        assert_swift_source_rejects_deinit(
            path,
            "\
final class TokenBrokerSessionResourceBag: @unchecked Sendable {
    final class Nested {
        deinit { release() }
    }
    func release() {}
}
",
            "deinit nested inside another type must fail closed",
        );
    }

    #[test]
    fn token_broker_session_resource_bag_deinit_keeps_subscript_unconditionally_forbidden() {
        let path = reviewed_token_broker_session_resource_bag_deinit_path();
        // subscript remains unconditionally forbidden alongside the deinit exception.
        let with_subscript = format!(
            "{}\nsubscript(index: Int) -> Int {{ index }}\n",
            exact_token_broker_session_resource_bag_deinit_fixture()
        );
        assert!(
            swift_source_lexical_violations(path, &with_subscript)
                .iter()
                .any(|violation| violation.contains("must not declare `subscript`")),
            "subscript must remain unconditionally forbidden"
        );
    }

    fn exact_broker_sync_secrets_deinit_fixture() -> &'static str {
        "\
final class MailboxSyncWorker: @unchecked Sendable {
    private final class BrokerSyncSecrets: @unchecked Sendable {
        private func wipe() {}
        deinit { wipe() }
    }
}
"
    }

    fn reviewed_broker_sync_secrets_deinit_path() -> &'static Path {
        Path::new(REVIEWED_BROKER_SYNC_SECRETS_DEINIT_PATH)
    }

    #[test]
    fn broker_sync_secrets_deinit_accepts_reviewed_source_and_exact_fixture() {
        let path = reviewed_broker_sync_secrets_deinit_path();
        // Positive: the reviewed abandoned-request cleanup at the exact path,
        // direct owner class, and body form is accepted.
        assert_swift_source_has_no_lexical_violations(
            path,
            include_str!("../../apple/macos/MailboxSyncWorker.swift"),
            "reviewed MailboxSyncWorker.swift must pass the lexical deinit guard",
        );
        // Positive fixture: the exact reviewed form on the exact nested owner
        // is accepted.
        assert_swift_source_has_no_lexical_violations(
            path,
            exact_broker_sync_secrets_deinit_fixture(),
            "exact BrokerSyncSecrets deinit {{ wipe() }} fixture must pass",
        );
    }

    #[test]
    fn broker_sync_secrets_deinit_rejects_wrong_path_and_owner() {
        let path = reviewed_broker_sync_secrets_deinit_path();
        let exact = exact_broker_sync_secrets_deinit_fixture();
        // Negative: wrong path with the exact form fails closed.
        assert_swift_source_rejects_deinit(
            Path::new("apple/macos/TokenBrokerAuthorizationSession.swift"),
            exact,
            "BrokerSyncSecrets deinit outside MailboxSyncWorker.swift must fail closed",
        );
        // Negative: the resource-bag exception does not leak into the reviewed
        // MailboxSyncWorker.swift path.
        assert_swift_source_rejects_deinit(
            path,
            exact_token_broker_session_resource_bag_deinit_fixture(),
            "TokenBrokerSessionResourceBag deinit in MailboxSyncWorker.swift must fail closed",
        );
        // Negative: wrong direct owner class name at the reviewed path fails.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace("class BrokerSyncSecrets", "class OtherSyncSecrets"),
            "deinit on a non-reviewed owner class must fail closed",
        );
        // Negative: the reviewed owner nested in a non-reviewed outer class
        // fails closed.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace(
                "final class MailboxSyncWorker",
                "final class OtherSyncWorker",
            ),
            "BrokerSyncSecrets nested in a non-reviewed outer class must fail closed",
        );
    }

    #[test]
    fn broker_sync_secrets_deinit_rejects_body_form_mutations() {
        let path = reviewed_broker_sync_secrets_deinit_path();
        let exact = exact_broker_sync_secrets_deinit_fixture();
        // Negative: extra statement before wipe() fails closed.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace("deinit { wipe() }", "deinit { _ = 0; wipe() }"),
            "deinit with a statement before wipe() must fail closed",
        );
        // Negative: extra statement after wipe() fails closed.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace("deinit { wipe() }", "deinit { wipe(); _ = 1 }"),
            "deinit with a statement after wipe() must fail closed",
        );
        // Negative: alternate call fails closed.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace("deinit { wipe() }", "deinit { self.wipe() }"),
            "deinit with a different call than wipe() must fail closed",
        );
        // Negative: attached modifier fails closed.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace("deinit { wipe() }", "private deinit { wipe() }"),
            "deinit with an attached modifier must fail closed",
        );
        // Negative: parameters fail closed.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace("deinit { wipe() }", "deinit(x: Int) { wipe() }"),
            "deinit with parameters must fail closed",
        );
    }

    #[test]
    fn broker_sync_secrets_deinit_rejects_second_decoy_laundering_and_nested() {
        let path = reviewed_broker_sync_secrets_deinit_path();
        let exact = exact_broker_sync_secrets_deinit_fixture();
        // Negative: a second deinit fails closed even when both match the form.
        assert_swift_source_rejects_deinit(
            path,
            &exact.replace(
                "deinit { wipe() }",
                "deinit { wipe() }\n        deinit { wipe() }",
            ),
            "a second deinit declaration must fail closed",
        );
        // Negative: comment/string decoys of the reviewed form must not satisfy
        // the exception when the executable deinit is mutated.
        assert_swift_source_rejects_deinit(
            path,
            "\
final class MailboxSyncWorker: @unchecked Sendable {
    private final class BrokerSyncSecrets: @unchecked Sendable {
        private func wipe() {}
        // deinit { wipe() }
        let decoy = \"deinit { wipe() }\"
        deinit { cancel() }
    }
}
",
            "comment/string deinit decoys must not satisfy the reviewed exception",
        );
        // Negative: deinit nested inside a further type in the reviewed owner
        // class fails closed.
        assert_swift_source_rejects_deinit(
            path,
            "\
final class MailboxSyncWorker: @unchecked Sendable {
    private final class BrokerSyncSecrets: @unchecked Sendable {
        final class Nested {
            deinit { wipe() }
        }
        private func wipe() {}
    }
}
",
            "deinit nested inside another type must fail closed",
        );
        // Negative: a file-scope BrokerSyncSecrets decoy that is not nested in
        // MailboxSyncWorker fails closed.
        assert_swift_source_rejects_deinit(
            path,
            "\
final class BrokerSyncSecrets: @unchecked Sendable {
    private func wipe() {}
    deinit { wipe() }
}
",
            "file-scope BrokerSyncSecrets decoy must fail closed",
        );
    }

    #[test]
    fn broker_sync_secrets_deinit_keeps_subscript_unconditionally_forbidden() {
        let path = reviewed_broker_sync_secrets_deinit_path();
        // subscript remains unconditionally forbidden alongside the deinit exception.
        let with_subscript = format!(
            "{}\nsubscript(index: Int) -> Int {{ index }}\n",
            exact_broker_sync_secrets_deinit_fixture()
        );
        assert!(
            swift_source_lexical_violations(path, &with_subscript)
                .iter()
                .any(|violation| violation.contains("must not declare `subscript`")),
            "subscript must remain unconditionally forbidden"
        );
    }

    #[test]
    fn token_broker_protocol_and_status_mirrors_are_coherent() {
        let service =
            include_str!("../../apple/macos-token-broker/TokenBrokerProtocol.swift").to_owned();
        let client = include_str!("../../apple/macos/TokenBrokerProtocol.swift").to_owned();
        assert!(
            token_broker_protocol_mirror_violations(&service, &client).is_empty(),
            "service and client v1 protocol/status mirrors must match; got {:?}",
            token_broker_protocol_mirror_violations(&service, &client)
        );

        let delete_tokens_signature = "\
    func deleteStoredTokens(
        accountSubject: String,
        withReply reply: @escaping @Sendable (_ status: Int) -> Void
    )";
        // Mutations must stay inside the protocol body: body-scoped parsing is
        // the mirror authority and ignores helper `func` text outside `{...}`.
        for (label, mutated_client, expected) in [
            (
                "client protocol method drift",
                client.replace(
                    delete_tokens_signature,
                    "func deleteStoredTokens(\n        accountSubject: String,\n        withReply reply: @escaping @Sendable (_ status: Int, _ detail: String?) -> Void\n    )",
                ),
                REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH,
            ),
            (
                "missing reviewed operation",
                client.replace(delete_tokens_signature, ""),
                REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH,
            ),
            (
                "sixth protocol operation",
                client.replace(
                    delete_tokens_signature,
                    &format!(
                        "{delete_tokens_signature}\n    func exportStoredSecret(withReply reply: @escaping @Sendable (Int) -> Void)"
                    ),
                ),
                REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH,
            ),
            (
                "async/throws effect on reviewed operation",
                client.replace(
                    delete_tokens_signature,
                    &format!("{delete_tokens_signature} async throws"),
                ),
                REVIEWED_TOKEN_BROKER_CLIENT_PROTOCOL_PATH,
            ),
            (
                "malformed missing-paren operation",
                client.replace(
                    delete_tokens_signature,
                    &format!("{delete_tokens_signature}\n    func exportStoredSecret"),
                ),
                "parseable closed broker protocol operations",
            ),
        ] {
            assert!(
                token_broker_protocol_mirror_violations(&service, &mutated_client)
                    .iter()
                    .any(|violation| violation.contains(expected)),
                "{label} must fail closed; got {:?}",
                token_broker_protocol_mirror_violations(&service, &mutated_client)
            );
        }

        let drifted_status =
            client.replace("case identityMismatch = 19", "case identityMismatch = 20");
        assert!(
            token_broker_protocol_mirror_violations(&service, &drifted_status)
                .iter()
                .any(|violation| violation.contains("same closed raw-value case set")),
            "client status raw-value drift must fail closed"
        );
    }

    #[test]
    fn token_broker_protocol_surface_rejects_non_allowlisted_operations() {
        let protocol_path = Path::new("apple/macos-token-broker/TokenBrokerProtocol.swift");
        let reviewed =
            include_str!("../../apple/macos-token-broker/TokenBrokerProtocol.swift").to_owned();
        let delete_tokens_signature = "\
    func deleteStoredTokens(
        accountSubject: String,
        withReply reply: @escaping @Sendable (_ status: Int) -> Void
    )";
        for (label, document) in [
            (
                "broadened Data RPC",
                format!(
                    "{reviewed}\nfunc invoke(payload: Data, withReply reply: @escaping (Data?) -> Void)\n"
                ),
            ),
            (
                "array Data parameter",
                format!(
                    "{reviewed}\nfunc invoke(payload: [Data], withReply reply: @escaping (Int) -> Void)\n"
                ),
            ),
            (
                "NSData parameter",
                format!(
                    "{reviewed}\nfunc invoke(payload: NSData, withReply reply: @escaping (Int) -> Void)\n"
                ),
            ),
            (
                "Foundation.Data parameter",
                format!(
                    "{reviewed}\nfunc invoke(payload: Foundation.Data, withReply reply: @escaping (Int) -> Void)\n"
                ),
            ),
            (
                "UInt8 array parameter",
                format!(
                    "{reviewed}\nfunc invoke(payload: [UInt8], withReply reply: @escaping (Int) -> Void)\n"
                ),
            ),
            (
                "top-level Data return",
                format!("{reviewed}\nfunc snapshot() -> Data\n"),
            ),
            // Mutate an existing allowlisted op so a silent effect truncate cannot
            // hide behind a signature-count mismatch.
            (
                "throws Data return on reviewed op",
                reviewed.replace(
                    delete_tokens_signature,
                    &format!("{delete_tokens_signature} throws -> Data"),
                ),
            ),
            (
                "async throws Data return on reviewed op",
                reviewed.replace(
                    delete_tokens_signature,
                    &format!("{delete_tokens_signature} async throws -> Data"),
                ),
            ),
            (
                "throws effect only on reviewed op",
                reviewed.replace(
                    delete_tokens_signature,
                    &format!("{delete_tokens_signature} throws"),
                ),
            ),
        ] {
            assert_token_broker_protocol_operations_fail_closed(protocol_path, document, label);
        }
    }

    /// A sixth declaration must fail closed even when its name is not a plain
    /// ASCII identifier the scanner can compact (backtick/operator/unicode) or
    /// when `(` is missing after a real `func` keyword. The exact five reviewed
    /// methods still pass via the baseline surface checks.
    #[test]
    fn token_broker_protocol_surface_rejects_unparsable_sixth_operations() {
        let protocol_path = Path::new("apple/macos-token-broker/TokenBrokerProtocol.swift");
        let reviewed =
            include_str!("../../apple/macos-token-broker/TokenBrokerProtocol.swift").to_owned();
        for (label, document) in [
            (
                "backtick-escaped sixth operation",
                format!(
                    "{reviewed}\n    func `exportStoredSecret`(withReply reply: @escaping (Int) -> Void)\n"
                ),
            ),
            (
                "operator sixth operation",
                format!("{reviewed}\n    func + (lhs: Int, rhs: Int) -> Int\n"),
            ),
            (
                "unicode-named sixth operation",
                format!(
                    "{reviewed}\n    func exportStoredSécret(withReply reply: @escaping (Int) -> Void)\n"
                ),
            ),
            (
                "missing-paren sixth operation",
                format!("{reviewed}\n    func exportStoredSecret\n"),
            ),
        ] {
            assert_token_broker_protocol_operations_fail_closed(protocol_path, document, label);
        }
    }

    fn assert_token_broker_protocol_operations_fail_closed(
        protocol_path: &Path,
        document: String,
        label: &str,
    ) {
        let mut mutated = reviewed_token_broker_sources();
        if let Some(entry) = mutated.iter_mut().find(|(path, _)| path == protocol_path) {
            entry.1 = document;
        }
        let violations = token_broker_source_surface_violations(&mutated);
        assert!(
            violations.iter().any(|violation| {
                violation.contains("exact reviewed closed broker protocol operations")
                    || violation.contains("parseable closed broker protocol operations")
            }),
            "{label} must fail closed; got {violations:?}"
        );
    }

    #[test]
    fn token_broker_protocol_surface_rejects_wrong_version() {
        let protocol_path = Path::new("apple/macos-token-broker/TokenBrokerProtocol.swift");
        let reviewed =
            include_str!("../../apple/macos-token-broker/TokenBrokerProtocol.swift").to_owned();

        for (label, assignment) in [
            ("wrong constant value", "static let value: Int = 2"),
            ("underscore suffix", "static let value: Int = 1_0"),
            ("addition expression", "static let value: Int = 1 + 1"),
            ("shift expression", "static let value: Int = 1 << 4"),
            ("value 3 in reviewed enum", "static let value: Int = 3"),
            // Next-line arithmetic/bitshift/call continuations must not widen `= 1`.
            (
                "next-line addition",
                "static let value: Int = 1\n        + 1",
            ),
            (
                "next-line bitshift",
                "static let value: Int = 1\n        << 4",
            ),
            (
                "next-line member call continuation",
                "static let value: Int = 1\n        .advanced(by: 1)",
            ),
        ] {
            let mutated_version = reviewed.replace("static let value: Int = 1", assignment);
            let mut mutated = reviewed_token_broker_sources();
            if let Some(entry) = mutated.iter_mut().find(|(path, _)| path == protocol_path) {
                entry.1 = mutated_version;
            }
            assert_token_broker_surface_contains(
                &mutated,
                "exact reviewed protocol version constant",
                label,
            );
        }
    }

    #[test]
    fn token_broker_protocol_version_enum_body_is_scoped_and_exact() {
        let protocol_path = Path::new("apple/macos-token-broker/TokenBrokerProtocol.swift");
        let reviewed =
            include_str!("../../apple/macos-token-broker/TokenBrokerProtocol.swift").to_owned();
        let reviewed_enum =
            "enum TersaMacTokenBrokerProtocolVersion {\n    static let value: Int = 1\n}";

        for (label, replacement) in [
            (
                "missing version enum",
                reviewed.replace(&format!("{reviewed_enum}\n\n"), ""),
            ),
            (
                "duplicate assignment in reviewed enum",
                reviewed.replace(
                    "static let value: Int = 1",
                    "static let value: Int = 1\n    static let value: Int = 1",
                ),
            ),
            (
                "inheritance drift on version enum",
                reviewed.replace(
                    "enum TersaMacTokenBrokerProtocolVersion {",
                    "enum TersaMacTokenBrokerProtocolVersion: Int {",
                ),
            ),
            (
                "generic drift on version enum",
                reviewed.replace(
                    "enum TersaMacTokenBrokerProtocolVersion {",
                    "enum TersaMacTokenBrokerProtocolVersion<T> {",
                ),
            ),
            (
                "where clause drift on version enum",
                reviewed.replace(
                    "enum TersaMacTokenBrokerProtocolVersion {",
                    "enum TersaMacTokenBrokerProtocolVersion where Self: Sendable {",
                ),
            ),
            (
                "decoy enum with good assignment and reviewed value 3",
                reviewed.replace("static let value: Int = 1", "static let value: Int = 3")
                    + "\nenum DecoyVersion {\n    static let value: Int = 1\n}\n",
            ),
            (
                "duplicate version enum",
                format!("{reviewed}\n{reviewed_enum}\n"),
            ),
            (
                "unbalanced version enum body",
                reviewed.replace(
                    "enum TersaMacTokenBrokerProtocolVersion {\n    static let value: Int = 1\n}",
                    "enum TersaMacTokenBrokerProtocolVersion {\n    static let value: Int = 1\n",
                ),
            ),
        ] {
            let mut mutated = reviewed_token_broker_sources();
            if let Some(entry) = mutated.iter_mut().find(|(path, _)| path == protocol_path) {
                entry.1 = replacement;
            }
            let violations = token_broker_source_surface_violations(&mutated);
            assert!(
                violations.iter().any(|violation| {
                    violation.contains("TersaMacTokenBrokerProtocolVersion")
                        || violation.contains("exact reviewed protocol version constant")
                }),
                "{label} must fail closed; got {violations:?}"
            );
        }
    }

    #[test]
    fn token_broker_code_signing_requirement_is_exact_literal_and_call() {
        let listener_path = Path::new("apple/macos-token-broker/TokenBrokerListenerDelegate.swift");
        let reviewed =
            include_str!("../../apple/macos-token-broker/TokenBrokerListenerDelegate.swift")
                .to_owned();
        let reviewed_literal = "\"identifier \\\"app.tersa.mac\\\" and anchor apple generic\"";
        // Positive: reviewed doc-comment mention plus one executable call passes.
        // The doc reference must not inflate the executable call count.
        assert!(
            token_broker_code_signing_requirement_violations(&reviewed).is_empty(),
            "reviewed listener with doc mention + one executable call must pass; got {:?}",
            token_broker_code_signing_requirement_violations(&reviewed)
        );
        let sources = reviewed_token_broker_sources();
        assert!(token_broker_source_surface_violations(&sources).is_empty());

        for (label, document) in [
            (
                "empty requirement",
                reviewed.replace(reviewed_literal, "\"\""),
            ),
            (
                "anchor-only requirement",
                reviewed.replace(reviewed_literal, "\"anchor apple generic\""),
            ),
            (
                "changed identifier",
                reviewed.replace(
                    reviewed_literal,
                    "\"identifier \\\"app.tersa.other\\\" and anchor apple generic\"",
                ),
            ),
            (
                "changed constant reference",
                reviewed.replace(
                    "newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)",
                    "newConnection.setCodeSigningRequirement(Self.otherRequirement)",
                ),
            ),
            (
                "missing call",
                reviewed.replace(
                    "        newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)\n",
                    "",
                ),
            ),
            (
                "comment-only marker",
                reviewed.replace(
                    "        newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)\n",
                    "        // newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)\n",
                ),
            ),
            (
                "string-only marker",
                reviewed.replace(
                    "        newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)\n",
                    "        let _ = \"newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)\"\n",
                ),
            ),
            (
                "duplicate call",
                reviewed.replace(
                    "        newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)\n",
                    "        newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)\n        newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)\n",
                ),
            ),
            (
                "wrong literal",
                reviewed.replace(
                    reviewed_literal,
                    "\"identifier \\\"app.tersa.mac\\\" and anchor apple developer id\"",
                ),
            ),
        ] {
            assert_token_broker_listener_signing_fails(&sources, listener_path, document, label);
        }
    }

    /// Fixture for mutating the reviewed listener assignment while keeping the
    /// rest of the inventoried broker surface intact.
    fn listener_signing_assignment_fixture() -> (String, String, &'static str, &'static str) {
        let reviewed =
            include_str!("../../apple/macos-token-broker/TokenBrokerListenerDelegate.swift")
                .to_owned();
        let reviewed_literal = "\"identifier \\\"app.tersa.mac\\\" and anchor apple generic\"";
        let reviewed_assignment = format!(
            "    static let embeddingAppCodeSigningRequirement =\n        {reviewed_literal}"
        );
        let weakened_assignment =
            "    static let embeddingAppCodeSigningRequirement =\n        \"anchor apple generic\"";
        (
            reviewed,
            reviewed_assignment,
            weakened_assignment,
            reviewed_literal,
        )
    }

    fn assert_listener_signing_assignment_cases(cases: &[(&str, String)]) {
        let listener_path = Path::new("apple/macos-token-broker/TokenBrokerListenerDelegate.swift");
        let sources = reviewed_token_broker_sources();
        // Baseline: reviewed inventory still pins the exact assignment/call.
        assert!(
            token_broker_source_surface_violations(&sources).is_empty(),
            "reviewed broker baseline must pass code-signing pin; got {:?}",
            token_broker_source_surface_violations(&sources)
        );
        for (label, document) in cases {
            assert_token_broker_listener_signing_fails(
                &sources,
                listener_path,
                document.clone(),
                label,
            );
        }
    }

    #[test]
    fn token_broker_code_signing_requirement_rejects_comment_decoys() {
        let (reviewed, reviewed_assignment, weakened_assignment, reviewed_literal) =
            listener_signing_assignment_fixture();
        assert_listener_signing_assignment_cases(&[
            (
                "decoy comment assignment with weakened executable",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    // static let embeddingAppCodeSigningRequirement = {reviewed_literal}\n{weakened_assignment}"
                    ),
                ),
            ),
            (
                "comment-only assignment",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    // static let embeddingAppCodeSigningRequirement = {reviewed_literal}"
                    ),
                ),
            ),
        ]);
    }

    #[test]
    fn token_broker_code_signing_requirement_rejects_string_assignment_decoys() {
        let (reviewed, reviewed_assignment, weakened_assignment, reviewed_literal) =
            listener_signing_assignment_fixture();
        assert_listener_signing_assignment_cases(&[
            (
                "multiline-string decoy assignment with weakened executable",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    let decoy = \"\"\"\n    static let embeddingAppCodeSigningRequirement =\n        {reviewed_literal}\n    \"\"\"\n{weakened_assignment}"
                    ),
                ),
            ),
            (
                "single-line string decoy assignment with weakened executable",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    let decoy = \"static let embeddingAppCodeSigningRequirement = {reviewed_literal}\"\n{weakened_assignment}"
                    ),
                ),
            ),
            (
                "raw-string decoy assignment with weakened executable",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    let decoy = #\"static let embeddingAppCodeSigningRequirement = {reviewed_literal}\"#\n{weakened_assignment}"
                    ),
                ),
            ),
            (
                "raw-string-only assignment decoy",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    let decoy = #\"static let embeddingAppCodeSigningRequirement = {reviewed_literal}\"#"
                    ),
                ),
            ),
        ]);
    }

    #[test]
    fn token_broker_code_signing_requirement_rejects_wrong_assignment_forms() {
        let (reviewed, reviewed_assignment, weakened_assignment, reviewed_literal) =
            listener_signing_assignment_fixture();
        assert_listener_signing_assignment_cases(&[
            (
                "correct literal on different constant with weakened reviewed constant",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    static let otherRequirement =\n        {reviewed_literal}\n{weakened_assignment}"
                    ),
                ),
            ),
            (
                "alternate type annotation with correct literal",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    static let embeddingAppCodeSigningRequirement: String =\n        {reviewed_literal}"
                    ),
                ),
            ),
            (
                "concatenated literal value",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    static let embeddingAppCodeSigningRequirement =\n        {reviewed_literal} + \"\""
                    ),
                ),
            ),
            // Next-line / same-line expression continuations widen the requirement.
            (
                "next-line concatenation",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    static let embeddingAppCodeSigningRequirement =\n        {reviewed_literal}\n        + \" or anchor apple\""
                    ),
                ),
            ),
            (
                "next-line operator call continuation",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    static let embeddingAppCodeSigningRequirement =\n        {reviewed_literal}\n        .appending(\" or anchor apple\")"
                    ),
                ),
            ),
            (
                "same-line member continuation",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!(
                        "    static let embeddingAppCodeSigningRequirement =\n        {reviewed_literal}.appending(\"\")"
                    ),
                ),
            ),
            (
                "duplicate executable assignment",
                reviewed.replace(
                    &reviewed_assignment,
                    &format!("{reviewed_assignment}\n{reviewed_assignment}"),
                ),
            ),
        ]);
    }

    /// Fail-closed fixtures for typealias rebinding and local type declarations
    /// that shadow reviewed primitive wire types (`String`, `Int`, `Void`).
    fn primitive_wire_type_shadowing_cases(
        protocol_path: &Path,
        service_path: &Path,
        reviewed_protocol: &str,
        reviewed_service: &str,
    ) -> Vec<(String, PathBuf, String, String)> {
        let mut cases = vec![
            (
                "typealias String = Data".to_owned(),
                protocol_path.to_path_buf(),
                format!("{reviewed_protocol}\ntypealias String = Data\n"),
                "typealias".to_owned(),
            ),
            (
                "indirect typealias chain".to_owned(),
                protocol_path.to_path_buf(),
                format!(
                    "{reviewed_protocol}\ntypealias WireText = Data\ntypealias String = WireText\n"
                ),
                "typealias".to_owned(),
            ),
            (
                "typealias in another broker source file".to_owned(),
                service_path.to_path_buf(),
                format!("{reviewed_service}\ntypealias String = Data\n"),
                "typealias".to_owned(),
            ),
        ];
        for primitive in ["String", "Int", "Void"] {
            cases.push((
                format!("struct {primitive} shadow"),
                protocol_path.to_path_buf(),
                format!("{reviewed_protocol}\nstruct {primitive} {{}}\n"),
                format!("shadow `{primitive}`"),
            ));
            cases.push((
                format!("class {primitive} shadow"),
                service_path.to_path_buf(),
                format!("{reviewed_service}\nclass {primitive} {{}}\n"),
                format!("shadow `{primitive}`"),
            ));
            cases.push((
                format!("enum {primitive} shadow"),
                protocol_path.to_path_buf(),
                format!("{reviewed_protocol}\nenum {primitive} {{ case decoy }}\n"),
                format!("shadow `{primitive}`"),
            ));
        }
        // Backtick-escaped declaration names resolve to the same local type as
        // the unescaped form; textual wire signatures stay pinned while the
        // resolved type is rebound. Ordinary non-primitive backtick names are
        // not in the reviewed set and must not bypass these primitives.
        cases.push((
            "backtick-escaped struct `String` shadow".to_owned(),
            protocol_path.to_path_buf(),
            format!("{reviewed_protocol}\nstruct `String` {{}}\n"),
            "shadow `String`".to_owned(),
        ));
        cases.push((
            "backtick-escaped class `Int` shadow".to_owned(),
            service_path.to_path_buf(),
            format!("{reviewed_service}\nclass `Int` {{}}\n"),
            "shadow `Int`".to_owned(),
        ));
        cases.push((
            "backtick-escaped enum `Void` shadow".to_owned(),
            protocol_path.to_path_buf(),
            format!("{reviewed_protocol}\nenum `Void` {{ case decoy }}\n"),
            "shadow `Void`".to_owned(),
        ));
        cases
    }

    /// Comments and string mentions of typealias/primitives must not fail closed.
    fn assert_inert_primitive_wire_type_mentions_do_not_fail_closed(
        sources: &[(PathBuf, String)],
        protocol_path: &Path,
        reviewed_protocol: &str,
    ) {
        let inert = reviewed_protocol.to_owned()
            + "\n// typealias String = Data\n/* struct Int {} */\n/* class Void {} */\nlet _ = \"typealias String = Data\"\nlet _ = \"struct Int {}\"\nlet _ = \"class Void {}\"\n";
        let mut with_inert = sources.to_vec();
        if let Some(entry) = with_inert
            .iter_mut()
            .find(|(candidate, _)| candidate == protocol_path)
        {
            entry.1 = inert;
        }
        assert!(
            token_broker_source_surface_violations(&with_inert).is_empty(),
            "inert comment/string typealias/primitive mentions must not fail closed; got {:?}",
            token_broker_source_surface_violations(&with_inert)
        );
    }

    #[test]
    fn token_broker_sources_reject_primitive_wire_type_shadowing() {
        let sources = reviewed_token_broker_sources();
        assert!(token_broker_source_surface_violations(&sources).is_empty());

        let protocol_path = Path::new("apple/macos-token-broker/TokenBrokerProtocol.swift");
        let service_path = Path::new("apple/macos-token-broker/TokenBrokerService.swift");
        let reviewed_protocol =
            include_str!("../../apple/macos-token-broker/TokenBrokerProtocol.swift").to_owned();
        let reviewed_service =
            include_str!("../../apple/macos-token-broker/TokenBrokerService.swift").to_owned();

        for (label, path, document, expected) in primitive_wire_type_shadowing_cases(
            protocol_path,
            service_path,
            &reviewed_protocol,
            &reviewed_service,
        ) {
            let mut mutated = sources.clone();
            if let Some(entry) = mutated.iter_mut().find(|(candidate, _)| candidate == &path) {
                entry.1 = document;
            }
            assert_token_broker_surface_contains(&mutated, &expected, &label);
        }

        assert_inert_primitive_wire_type_mentions_do_not_fail_closed(
            &sources,
            protocol_path,
            &reviewed_protocol,
        );
    }

    fn assert_token_broker_listener_signing_fails(
        sources: &[(PathBuf, String)],
        listener_path: &Path,
        document: String,
        label: &str,
    ) {
        let mut mutated = sources.to_vec();
        if let Some(entry) = mutated.iter_mut().find(|(path, _)| path == listener_path) {
            entry.1 = document;
        }
        let violations = token_broker_source_surface_violations(&mutated);
        assert!(
            violations.iter().any(|violation| {
                violation.contains("code-signing requirement")
                    || violation.contains("setCodeSigningRequirement")
            }),
            "{label} must fail the exact code-signing pin; got {violations:?}"
        );
    }

    #[test]
    fn active_cli_is_not_treated_as_a_reservation() {
        let resolved = BTreeMap::from([(
            "tersa-cli-macos".to_owned(),
            BTreeSet::from([
                "tersa-application".to_owned(),
                "tersa-domain".to_owned(),
                "tersa-keychain-macos".to_owned(),
                "tersa-platform".to_owned(),
                "tersa-store-sqlcipher-macos".to_owned(),
            ]),
        )]);

        assert!(reserved_future_policy_violations(&resolved).is_empty());
    }

    #[test]
    fn ignores_reservations_while_the_future_crates_are_absent() {
        let resolved = BTreeMap::from([
            ("tersa-application".to_owned(), BTreeSet::new()),
            ("tersa-platform".to_owned(), BTreeSet::new()),
        ]);

        assert!(reserved_future_policy_violations(&resolved).is_empty());
    }

    #[test]
    fn no_longer_reports_cli_as_a_reserved_boundary() {
        let resolved = BTreeMap::from([(
            "tersa-cli-macos".to_owned(),
            BTreeSet::from([
                "tersa-application".to_owned(),
                "tersa-platform".to_owned(),
                "tersa-search-spike".to_owned(),
            ]),
        )]);

        assert!(reserved_future_policy_violations(&resolved).is_empty());
    }

    #[test]
    fn recognizes_a_patched_dependency_resolved_to_a_workspace_member() {
        let workspace_member_names = BTreeMap::from([
            (
                package_id("path+file:///workspace/apps/store"),
                "tersa-store-sqlcipher-macos".to_owned(),
            ),
            (
                package_id("path+file:///workspace/crates/application"),
                "tersa-application".to_owned(),
            ),
            (
                package_id("path+file:///workspace/crates/domain"),
                "tersa-domain".to_owned(),
            ),
            (
                package_id("path+file:///workspace/crates/platform"),
                "tersa-platform".to_owned(),
            ),
        ]);
        let workspace_resolved_dependencies = BTreeMap::from([(
            "tersa-store-sqlcipher-macos".to_owned(),
            resolved_workspace_dependency_names(
                [
                    ResolvedDependencyIdentity {
                        package_id: package_id(
                            "registry+https://github.com/rust-lang/crates.io-index#rusqlite@0.32.1",
                        ),
                    },
                    ResolvedDependencyIdentity {
                        package_id: package_id("path+file:///workspace/crates/application"),
                    },
                    ResolvedDependencyIdentity {
                        package_id: package_id("path+file:///workspace/crates/domain"),
                    },
                    ResolvedDependencyIdentity {
                        package_id: package_id("path+file:///workspace/crates/platform"),
                    },
                ],
                &workspace_member_names,
            ),
        )]);

        assert_eq!(
            workspace_resolved_dependencies["tersa-store-sqlcipher-macos"],
            BTreeSet::from([
                "tersa-application".to_owned(),
                "tersa-domain".to_owned(),
                "tersa-platform".to_owned(),
            ])
        );
    }

    #[test]
    fn ignores_an_external_package_with_a_workspace_member_name() {
        let workspace_member_names = BTreeMap::from([(
            package_id("path+file:///workspace/crates/domain"),
            "tersa-domain".to_owned(),
        )]);

        assert!(
            resolved_workspace_dependency_names(
                [ResolvedDependencyIdentity {
                    package_id: package_id(
                        "registry+https://github.com/rust-lang/crates.io-index#tersa-domain@1.0.0",
                    ),
                }],
                &workspace_member_names,
            )
            .is_empty()
        );
    }

    fn package_id(repr: &str) -> PackageId {
        PackageId {
            repr: repr.to_owned(),
        }
    }

    #[test]
    fn permits_store_crypto_dependencies_only_under_the_exact_macos_cfg() {
        for dependency_name in ["rusqlite", "libsqlite3-sys", "chacha20poly1305", "hmac"] {
            let violation = future_macos_store_dependency_violation(
                "tersa-store-sqlcipher-macos",
                dependency_name,
                Some(r#"cfg(target_os = "macos")"#),
            );
            assert_eq!(violation, None, "{dependency_name}: {violation:?}");
        }
    }

    #[test]
    fn rejects_untargeted_or_ios_store_sqlcipher_dependencies() {
        for target in [
            None,
            Some(r#"cfg(target_os = "ios")"#),
            Some(r#"cfg(any(target_os = "macos", target_os = "ios"))"#),
        ] {
            let violation = future_macos_store_dependency_violation(
                "tersa-store-sqlcipher-macos",
                "rusqlite",
                target,
            );
            assert!(violation.is_some(), "target: {target:?}");
        }
    }

    #[test]
    fn composition_edges_require_the_exact_macos_cfg() {
        for (owner, dependency) in [
            ("tersa-keychain-macos", "tersa-store-sqlcipher-macos"),
            ("tersa-keychain-macos", "tersa-application"),
            ("tersa-keychain-macos", "tersa-presentation"),
            ("tersa-cli-macos", "tersa-keychain-macos"),
            ("tersa-apple-bridge", "tersa-keychain-macos"),
            // The composition's capability edges are equally pinned to macOS, so a
            // future un-scoping cannot reach SQLCipher / Keychain / reqwest off macOS.
            ("tersa-oauth-sync-macos", "tersa-gmail-rest-macos"),
            ("tersa-oauth-sync-macos", "tersa-keychain-macos"),
            ("tersa-oauth-sync-macos", "tersa-store-sqlcipher-macos"),
            // The FFI's bridge edge (the grant-claim seam and single-archive link)
            // is pinned to macOS for the same reason.
            ("tersa-mailbox-sync-ffi-macos", "tersa-apple-bridge"),
            // ADR-0024 point 3: token-broker FFI capability edges stay macOS-only.
            ("tersa-token-broker-ffi-macos", "tersa-gmail-rest-macos"),
            ("tersa-token-broker-ffi-macos", "tersa-keychain-macos"),
            ("tersa-token-broker-ffi-macos", "tersa-token-broker-core"),
            ("tersa-token-broker-ffi-macos", "tokio"),
        ] {
            assert_eq!(
                future_macos_store_dependency_violation(
                    owner,
                    dependency,
                    Some(r#"cfg(target_os = "macos")"#),
                ),
                None
            );
            for target in [
                None,
                Some(r#"cfg(target_os = "ios")"#),
                Some(r#"cfg(any(target_os = "macos", target_os = "ios"))"#),
            ] {
                assert!(
                    future_macos_store_dependency_violation(owner, dependency, target).is_some(),
                    "target must fail closed for {owner} -> {dependency}: {target:?}"
                );
            }
        }
    }

    #[test]
    fn resolves_target_graphs_with_all_features() {
        assert_eq!(
            target_metadata_options("aarch64-apple-darwin"),
            vec![
                "--locked",
                "--all-features",
                "--filter-platform",
                "aarch64-apple-darwin",
            ]
        );
    }

    #[test]
    fn rejects_unauthorized_sqlcipher_and_aead_manifest_dependencies() {
        assert_eq!(
            sqlcipher_manifest_dependency_violations(
                "tersa-application",
                "rusqlite",
                "=0.39.0",
                Some(r#"cfg(any(target_os = "macos", target_os = "ios"))"#),
                r#"cfg(any(target_os = "macos", target_os = "ios"))"#,
                false,
                &["bundled-sqlcipher".to_owned()],
            ),
            vec![
                "tersa-application -> rusqlite (SQLCipher is exclusive to approved Apple SQLCipher owners)"
            ]
        );
        assert_eq!(
            blob_manifest_dependency_violations("tersa-application", "chacha20poly1305", "=0.10.1",),
            vec![
                "tersa-application -> chacha20poly1305 (blob cryptography is exclusive to tersa-blob-spike)"
            ]
        );
        for owner in ["tersa-keychain-macos", "tersa-cli-macos"] {
            assert_eq!(
                sqlcipher_manifest_dependency_violations(
                    owner,
                    "rusqlite",
                    "=0.39.0",
                    Some(r#"cfg(target_os = "macos")"#),
                    r#"cfg(target_os = "macos")"#,
                    false,
                    &["bundled-sqlcipher".to_owned()],
                ),
                vec![format!(
                    "{owner} -> rusqlite is forbidden; SQLCipher must be reached only through tersa-store-sqlcipher-macos"
                )]
            );
        }
    }

    #[test]
    fn enforces_exact_rusqlite_version_and_features() {
        assert!(
            sqlcipher_manifest_dependency_violations(
                "tersa-store-sqlcipher-macos",
                "rusqlite",
                "=0.39.0",
                Some(r#"cfg(target_os = "macos")"#),
                r#"cfg(target_os = "macos")"#,
                false,
                &["bundled-sqlcipher".to_owned()],
            )
            .is_empty()
        );
        assert_eq!(
            sqlcipher_manifest_dependency_violations(
                "tersa-store-sqlcipher-macos",
                "rusqlite",
                "^0.39",
                Some(r#"cfg(target_os = "macos")"#),
                r#"cfg(target_os = "macos")"#,
                true,
                &["bundled-sqlcipher".to_owned(), "load_extension".to_owned()],
            ),
            vec![
                "tersa-store-sqlcipher-macos -> rusqlite must pin exactly 0.39.0",
                "tersa-store-sqlcipher-macos -> rusqlite must disable default features",
                "tersa-store-sqlcipher-macos -> rusqlite must enable only the `bundled-sqlcipher` feature",
            ]
        );
        assert!(
            rusqlite_resolved_feature_violations(
                &[
                    "bundled".to_owned(),
                    "bundled-sqlcipher".to_owned(),
                    "modern_sqlite".to_owned(),
                ],
                "aarch64-apple-darwin",
            )
            .is_empty()
        );
        assert_eq!(
            rusqlite_resolved_feature_violations(
                &[
                    "bundled".to_owned(),
                    "bundled-sqlcipher".to_owned(),
                    "load_extension".to_owned(),
                    "modern_sqlite".to_owned(),
                ],
                "aarch64-apple-darwin",
            ),
            vec![
                "resolved rusqlite features for aarch64-apple-darwin must be exactly bundled SQLCipher without extension loading or hooks"
            ]
        );
    }

    #[test]
    fn enforces_exact_macos_only_reqwest_manifest_ownership() {
        assert!(
            gmail_manifest_dependency_violations(
                "tersa-gmail-rest-macos",
                "reqwest",
                "=0.13.4",
                Some(r#"cfg(target_os = "macos")"#),
                false,
                &["native-tls".to_owned()],
            )
            .is_empty()
        );
        assert_eq!(
            gmail_manifest_dependency_violations(
                "tersa-application",
                "reqwest",
                "^0.13",
                None,
                true,
                &["gzip".to_owned()],
            ),
            vec![
                "tersa-application -> reqwest (reqwest is exclusive to tersa-gmail-rest-macos)",
                "tersa-application -> reqwest must pin exactly 0.13.4",
                "tersa-application -> reqwest must use target `cfg(target_os = \"macos\")`",
                "tersa-application -> reqwest must disable default features",
                "tersa-application -> reqwest must enable only the `native-tls` feature",
            ]
        );
        assert!(
            gmail_resolved_feature_violations(
                &[
                    "__native-tls".to_owned(),
                    "__native-tls-alpn".to_owned(),
                    "__tls".to_owned(),
                    "native-tls".to_owned(),
                ],
                "aarch64-apple-darwin",
            )
            .is_empty()
        );
        assert_eq!(
            gmail_resolved_feature_violations(
                &[
                    "__native-tls".to_owned(),
                    "__native-tls-alpn".to_owned(),
                    "__tls".to_owned(),
                    "gzip".to_owned(),
                    "native-tls".to_owned(),
                ],
                "aarch64-apple-darwin",
            ),
            vec![
                "resolved reqwest features for aarch64-apple-darwin must be exactly native-tls without defaults, cookies, compression, multipart, proxy, or alternate TLS"
            ]
        );
    }

    #[test]
    fn rejects_reqwest_graph_reachability_outside_the_macos_adapter() {
        let package_names = BTreeMap::from([
            ("application".to_owned(), "tersa-application".to_owned()),
            ("gmail".to_owned(), "tersa-gmail-rest-macos".to_owned()),
            ("wrapper".to_owned(), "network-wrapper".to_owned()),
            ("reqwest".to_owned(), "reqwest".to_owned()),
        ]);
        let workspace_members = vec!["application".to_owned(), "gmail".to_owned()];
        let dependencies = BTreeMap::from([
            (
                "application".to_owned(),
                BTreeSet::from(["wrapper".to_owned()]),
            ),
            ("gmail".to_owned(), BTreeSet::from(["reqwest".to_owned()])),
            ("wrapper".to_owned(), BTreeSet::from(["reqwest".to_owned()])),
        ]);
        let reqwest = BTreeSet::from(["reqwest".to_owned()]);

        assert_eq!(
            gmail_dependency_graph_violations(
                &package_names,
                &workspace_members,
                &dependencies,
                &reqwest,
                "aarch64-apple-darwin",
            ),
            vec![
                "tersa-application reaches reqwest outside the authorized network crates [\"tersa-gmail-rest-macos\", \"tersa-oauth-sync-macos\", \"tersa-mailbox-sync-ffi-macos\", \"tersa-token-broker-ffi-macos\"] for aarch64-apple-darwin"
            ]
        );
        assert_eq!(
            gmail_dependency_graph_violations(
                &package_names,
                &workspace_members,
                &dependencies,
                &reqwest,
                "aarch64-apple-ios",
            ),
            vec![
                "tersa-application reaches reqwest outside the authorized network crates [\"tersa-gmail-rest-macos\", \"tersa-oauth-sync-macos\", \"tersa-mailbox-sync-ffi-macos\", \"tersa-token-broker-ffi-macos\"] for aarch64-apple-ios",
                "tersa-gmail-rest-macos reaches reqwest on non-macOS target aarch64-apple-ios",
            ]
        );
    }

    #[test]
    fn retrieval_only_cli_and_keychain_stay_off_the_network_graph() {
        // The reqwest reachability owner-set authorizes only the Gmail adapter
        // and the trusted composition. The retrieval-only CLI and the Keychain
        // crate must fail closed if they ever reach reqwest, so a future change
        // wiring network code into either is rejected at the graph level.
        let package_names = BTreeMap::from([
            ("gmail".to_owned(), "tersa-gmail-rest-macos".to_owned()),
            ("sync".to_owned(), "tersa-oauth-sync-macos".to_owned()),
            ("keychain".to_owned(), "tersa-keychain-macos".to_owned()),
            ("cli".to_owned(), "tersa-cli-macos".to_owned()),
            ("reqwest".to_owned(), "reqwest".to_owned()),
        ]);
        let workspace_members = vec![
            "gmail".to_owned(),
            "sync".to_owned(),
            "keychain".to_owned(),
            "cli".to_owned(),
        ];
        // Every crate reaches reqwest in this hostile graph; only gmail + sync
        // are authorized.
        let dependencies = BTreeMap::from([
            ("gmail".to_owned(), BTreeSet::from(["reqwest".to_owned()])),
            ("sync".to_owned(), BTreeSet::from(["reqwest".to_owned()])),
            (
                "keychain".to_owned(),
                BTreeSet::from(["reqwest".to_owned()]),
            ),
            ("cli".to_owned(), BTreeSet::from(["reqwest".to_owned()])),
        ]);
        let reqwest = BTreeSet::from(["reqwest".to_owned()]);
        let violations = gmail_dependency_graph_violations(
            &package_names,
            &workspace_members,
            &dependencies,
            &reqwest,
            "aarch64-apple-darwin",
        );
        // The authorized crates produce no violation; the CLI and Keychain do.
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("tersa-cli-macos reaches reqwest")),
            "the retrieval-only CLI reaching reqwest must fail closed: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("tersa-keychain-macos reaches reqwest")),
            "the Keychain crate reaching reqwest must fail closed: {violations:?}"
        );
        assert!(
            !violations.iter().any(|violation| violation
                .contains("tersa-gmail-rest-macos reaches reqwest outside")
                || violation.contains("tersa-oauth-sync-macos reaches reqwest outside")),
            "the Gmail adapter and the composition are authorized to reach reqwest: {violations:?}"
        );
    }

    #[test]
    fn secret_and_retrieval_crates_fail_closed_on_a_transitive_tokio_path() {
        // A hostile transitive path (e.g. a future `hyper` in tersa-application)
        // links tokio into the CLI and Keychain WITHOUT reqwest. Both must fail
        // closed, while a legitimate non-denied tokio user (the Dioxus spike, via
        // dioxus-desktop's tokio_runtime) is not flagged.
        let package_names = BTreeMap::from([
            ("keychain".to_owned(), "tersa-keychain-macos".to_owned()),
            ("cli".to_owned(), "tersa-cli-macos".to_owned()),
            ("dioxus".to_owned(), "tersa-dioxus-spike".to_owned()),
            ("app".to_owned(), "tersa-application".to_owned()),
            ("hyper".to_owned(), "hyper".to_owned()),
            ("tokio".to_owned(), "tokio".to_owned()),
        ]);
        let workspace_members = vec![
            "keychain".to_owned(),
            "cli".to_owned(),
            "dioxus".to_owned(),
            "app".to_owned(),
        ];
        let dependencies = BTreeMap::from([
            ("keychain".to_owned(), BTreeSet::from(["app".to_owned()])),
            ("cli".to_owned(), BTreeSet::from(["keychain".to_owned()])),
            ("app".to_owned(), BTreeSet::from(["hyper".to_owned()])),
            ("hyper".to_owned(), BTreeSet::from(["tokio".to_owned()])),
            ("dioxus".to_owned(), BTreeSet::from(["tokio".to_owned()])),
        ]);
        let tokio = BTreeSet::from(["tokio".to_owned()]);
        let violations = retrieval_tokio_denial_violations(
            &package_names,
            &workspace_members,
            &dependencies,
            &tokio,
            "aarch64-apple-darwin",
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("tersa-keychain-macos reaches tokio")),
            "the Keychain crate reaching tokio must fail closed: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("tersa-cli-macos reaches tokio")),
            "the retrieval-only CLI reaching tokio must fail closed: {violations:?}"
        );
        assert!(
            !violations
                .iter()
                .any(|violation| violation.contains("tersa-dioxus-spike")),
            "the Dioxus spike legitimately uses tokio and must not be flagged: {violations:?}"
        );
    }

    #[test]
    fn oauth_sync_composition_dependency_set_is_closed() {
        let exact = BTreeSet::from([
            "tersa-application",
            "tersa-domain",
            "tersa-gmail-rest-macos",
            "tersa-keychain-macos",
            "tersa-store-sqlcipher-macos",
            "tokio",
            "zeroize",
        ]);
        assert!(oauth_sync_direct_dependency_set_violations(&exact).is_empty());
        // Directly declaring a capability crate (bypassing the store or the
        // key-derivation abstraction it is only allowed to REACH) is rejected.
        for capability in ["rusqlite", "hmac", "reqwest"] {
            let mut hostile = exact.clone();
            hostile.insert(capability);
            assert!(
                !oauth_sync_direct_dependency_set_violations(&hostile).is_empty(),
                "the composition must not directly declare `{capability}`"
            );
        }
        let mut missing = exact.clone();
        missing.remove("tersa-gmail-rest-macos");
        assert!(!oauth_sync_direct_dependency_set_violations(&missing).is_empty());
    }

    #[test]
    fn shipped_dependency_names_exclude_dev_and_build_dependencies() {
        fn dependency(name: &str, kind: &str) -> cargo_metadata::Dependency {
            serde_json::from_value(serde_json::json!({
                "name": name,
                "source": null,
                "req": "*",
                "kind": kind,
                "rename": null,
                "optional": false,
                "uses_default_features": true,
                "features": [],
                "target": null,
                "registry": null,
                "path": null,
            }))
            .expect("valid dependency fixture")
        }
        let dependencies = [
            dependency("tersa-application", "normal"),
            dependency("url", "dev"),
            dependency("cc", "build"),
        ];
        let names = shipped_direct_dependency_names(&dependencies);
        // Normal deps are governed by the closed-composition set; dev- and
        // build-dependencies never ship, so they are excluded — this is what
        // admits the `url` dev-dependency without widening the production set.
        assert!(names.contains("tersa-application"));
        assert!(!names.contains("url"));
        assert!(!names.contains("cc"));
    }

    #[test]
    fn rejects_unauthorized_transitive_sqlcipher_and_aead_graph_reachability() {
        let package_names = BTreeMap::from([
            ("application".to_owned(), "tersa-application".to_owned()),
            ("wrapper".to_owned(), "optional-crypto-wrapper".to_owned()),
            ("sqlite".to_owned(), "libsqlite3-sys".to_owned()),
            ("aead".to_owned(), "chacha20poly1305".to_owned()),
        ]);
        let workspace_members = vec!["application".to_owned()];
        let dependencies = BTreeMap::from([
            (
                "application".to_owned(),
                BTreeSet::from(["wrapper".to_owned()]),
            ),
            (
                "wrapper".to_owned(),
                BTreeSet::from(["sqlite".to_owned(), "aead".to_owned()]),
            ),
        ]);
        let sqlcipher_violations = sqlcipher_dependency_graph_violations(
            &package_names,
            &workspace_members,
            &dependencies,
            &BTreeSet::from(["sqlite".to_owned()]),
            "aarch64-apple-darwin",
        );
        let blob_violations = blob_dependency_graph_violations(
            &package_names,
            &workspace_members,
            &dependencies,
            "aarch64-apple-darwin",
        );

        assert_eq!(
            sqlcipher_violations,
            vec![
                "tersa-application reaches libsqlite3-sys outside the approved Apple SQLCipher owners for aarch64-apple-darwin"
            ]
        );
        assert_eq!(
            blob_violations,
            vec![
                "tersa-application reaches ChaCha20-Poly1305 outside tersa-blob-spike for aarch64-apple-darwin"
            ]
        );
    }

    #[test]
    fn permits_only_the_exact_bridge_crypto_paths_on_macos() {
        let package_names = BTreeMap::from([
            ("bridge".to_owned(), "tersa-apple-bridge".to_owned()),
            ("keychain".to_owned(), "tersa-keychain-macos".to_owned()),
            ("store".to_owned(), "tersa-store-sqlcipher-macos".to_owned()),
            ("hkdf".to_owned(), "hkdf".to_owned()),
            ("hmac".to_owned(), "hmac".to_owned()),
            ("rusqlite".to_owned(), "rusqlite".to_owned()),
            ("sqlite".to_owned(), "libsqlite3-sys".to_owned()),
        ]);
        let workspace_members = vec!["bridge".to_owned()];
        let dependencies = BTreeMap::from([
            ("bridge".to_owned(), BTreeSet::from(["keychain".to_owned()])),
            (
                "keychain".to_owned(),
                BTreeSet::from(["hkdf".to_owned(), "store".to_owned()]),
            ),
            ("hkdf".to_owned(), BTreeSet::from(["hmac".to_owned()])),
            ("store".to_owned(), BTreeSet::from(["rusqlite".to_owned()])),
            ("rusqlite".to_owned(), BTreeSet::from(["sqlite".to_owned()])),
        ]);
        assert!(
            blob_dependency_graph_violations(
                &package_names,
                &workspace_members,
                &dependencies,
                "aarch64-apple-darwin",
            )
            .is_empty()
        );
        assert!(
            sqlcipher_dependency_graph_violations(
                &package_names,
                &workspace_members,
                &dependencies,
                &BTreeSet::from(["sqlite".to_owned()]),
                "aarch64-apple-darwin",
            )
            .is_empty()
        );

        let mut broadened = dependencies;
        broadened.insert(
            "bridge".to_owned(),
            BTreeSet::from(["hmac".to_owned(), "keychain".to_owned()]),
        );
        assert_eq!(
            blob_dependency_graph_violations(
                &package_names,
                &workspace_members,
                &broadened,
                "aarch64-apple-darwin",
            ),
            vec![
                "tersa-apple-bridge reaches HMAC through an unapproved path for aarch64-apple-darwin"
            ]
        );
    }

    #[test]
    fn rejects_bridge_crypto_reachability_outside_macos() {
        let package_names = BTreeMap::from([
            ("bridge".to_owned(), "tersa-apple-bridge".to_owned()),
            ("keychain".to_owned(), "tersa-keychain-macos".to_owned()),
            ("hkdf".to_owned(), "hkdf".to_owned()),
            ("hmac".to_owned(), "hmac".to_owned()),
        ]);
        let dependencies = BTreeMap::from([
            ("bridge".to_owned(), BTreeSet::from(["keychain".to_owned()])),
            ("keychain".to_owned(), BTreeSet::from(["hkdf".to_owned()])),
            ("hkdf".to_owned(), BTreeSet::from(["hmac".to_owned()])),
        ]);
        assert_eq!(
            blob_dependency_graph_violations(
                &package_names,
                &["bridge".to_owned()],
                &dependencies,
                "aarch64-apple-ios",
            ),
            vec![
                "tersa-apple-bridge reaches HMAC outside the approved owners for aarch64-apple-ios"
            ]
        );
    }

    #[test]
    fn rejects_production_store_sqlcipher_reachability_on_ios() {
        let package_names = BTreeMap::from([
            ("store".to_owned(), "tersa-store-sqlcipher-macos".to_owned()),
            ("sqlite".to_owned(), "libsqlite3-sys".to_owned()),
        ]);
        let workspace_members = vec!["store".to_owned()];
        let dependencies =
            BTreeMap::from([("store".to_owned(), BTreeSet::from(["sqlite".to_owned()]))]);

        assert_eq!(
            sqlcipher_dependency_graph_violations(
                &package_names,
                &workspace_members,
                &dependencies,
                &BTreeSet::from(["sqlite".to_owned()]),
                "aarch64-apple-ios",
            ),
            vec![
                "tersa-store-sqlcipher-macos reaches libsqlite3-sys on non-macOS target aarch64-apple-ios"
            ]
        );
    }

    #[test]
    fn rejects_the_entire_cli_sqlcipher_chain_on_ios() {
        let package_names = BTreeMap::from([
            ("cli".to_owned(), "tersa-cli-macos".to_owned()),
            ("keychain".to_owned(), "tersa-keychain-macos".to_owned()),
            ("store".to_owned(), "tersa-store-sqlcipher-macos".to_owned()),
            ("sqlite".to_owned(), "libsqlite3-sys".to_owned()),
        ]);
        let workspace_members = vec!["cli".to_owned(), "keychain".to_owned(), "store".to_owned()];
        let dependencies = BTreeMap::from([
            ("cli".to_owned(), BTreeSet::from(["keychain".to_owned()])),
            ("keychain".to_owned(), BTreeSet::from(["store".to_owned()])),
            ("store".to_owned(), BTreeSet::from(["sqlite".to_owned()])),
        ]);

        assert_eq!(
            sqlcipher_dependency_graph_violations(
                &package_names,
                &workspace_members,
                &dependencies,
                &BTreeSet::from(["sqlite".to_owned()]),
                "aarch64-apple-ios",
            ),
            vec![
                "tersa-cli-macos reaches libsqlite3-sys on non-macOS target aarch64-apple-ios",
                "tersa-keychain-macos reaches libsqlite3-sys on non-macOS target aarch64-apple-ios",
                "tersa-store-sqlcipher-macos reaches libsqlite3-sys on non-macOS target aarch64-apple-ios",
            ]
        );
    }

    #[test]
    fn rejects_indirect_diagnostic_runtime_reachability_from_a_non_spike() {
        let package_names = BTreeMap::from([
            ("application".to_owned(), "tersa-application".to_owned()),
            ("adapter".to_owned(), "diagnostic-adapter".to_owned()),
            ("slint".to_owned(), "i-slint-core".to_owned()),
            ("dioxus".to_owned(), "dioxus-core".to_owned()),
            ("wry".to_owned(), "wry".to_owned()),
            ("tao".to_owned(), "tao".to_owned()),
        ]);
        let workspace_members = BTreeSet::from(["application".to_owned()]);
        let dependencies = BTreeMap::from([
            (
                "application".to_owned(),
                BTreeSet::from(["adapter".to_owned()]),
            ),
            (
                "adapter".to_owned(),
                BTreeSet::from([
                    "slint".to_owned(),
                    "dioxus".to_owned(),
                    "wry".to_owned(),
                    "tao".to_owned(),
                ]),
            ),
        ]);
        let mut violations = Vec::new();

        check_diagnostic_runtime_reachability(
            &package_names,
            &workspace_members,
            &dependencies,
            "aarch64-apple-darwin",
            &mut violations,
        );

        assert_eq!(
            violations,
            vec![
                "tersa-application reaches Slint runtime outside tersa-slint-spike for aarch64-apple-darwin",
                "tersa-application reaches Dioxus runtime outside tersa-dioxus-spike for aarch64-apple-darwin",
            ]
        );
    }

    #[test]
    fn allows_indirect_diagnostic_runtime_reachability_from_its_spike() {
        let package_names = BTreeMap::from([
            ("slint-spike".to_owned(), "tersa-slint-spike".to_owned()),
            ("dioxus-spike".to_owned(), "tersa-dioxus-spike".to_owned()),
            ("slint-adapter".to_owned(), "slint-adapter".to_owned()),
            ("dioxus-adapter".to_owned(), "dioxus-adapter".to_owned()),
            ("slint".to_owned(), "slint".to_owned()),
            ("dioxus".to_owned(), "dioxus".to_owned()),
            ("tao".to_owned(), "tao".to_owned()),
        ]);
        let workspace_members =
            BTreeSet::from(["slint-spike".to_owned(), "dioxus-spike".to_owned()]);
        let dependencies = BTreeMap::from([
            (
                "slint-spike".to_owned(),
                BTreeSet::from(["slint-adapter".to_owned()]),
            ),
            (
                "dioxus-spike".to_owned(),
                BTreeSet::from(["dioxus-adapter".to_owned()]),
            ),
            (
                "slint-adapter".to_owned(),
                BTreeSet::from(["slint".to_owned()]),
            ),
            (
                "dioxus-adapter".to_owned(),
                BTreeSet::from(["dioxus".to_owned(), "tao".to_owned()]),
            ),
        ]);
        let mut violations = Vec::new();

        check_diagnostic_runtime_reachability(
            &package_names,
            &workspace_members,
            &dependencies,
            "aarch64-apple-ios",
            &mut violations,
        );

        assert!(violations.is_empty());
    }
}
