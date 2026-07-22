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

const SQLCIPHER_OWNERS: [&str; 6] = [
    "tersa-search-spike",
    "tersa-sqlcipher-spike",
    "tersa-store-sqlcipher-macos",
    "tersa-keychain-macos",
    "tersa-cli-macos",
    // 3d: the trusted composition reconciles sync into the encrypted store.
    "tersa-oauth-sync-macos",
];
const BLOB_DIAGNOSTIC_OWNERS: [&str; 1] = ["tersa-blob-spike"];
const HMAC_OWNERS: [&str; 3] = [
    "tersa-blob-spike",
    "tersa-keychain-macos",
    // 3d: reaches HMAC transitively through the Keychain HKDF key derivation.
    "tersa-oauth-sync-macos",
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
    violations
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
    let project = fs::read_to_string("apple/project.yml")?;
    violations.extend(signing_configuration_violations(&entitlements, &project));
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
    violations.extend(keychain_mutation_boundary_violations(
        &keychain_owner_sources,
        &keychain_authority_sources,
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
    violations.extend(rust_exported_c_abi_violations(&bridge_package_sources));
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

fn rust_authority_dynamic_alias_violations(path: &Path, document: &str) -> Vec<String> {
    const FORBIDDEN_SYMBOLS: [&str; 4] = [
        "SecItemUpdate",
        "SecItemDelete",
        "SecKeychain",
        "set_generic_password",
    ];
    const FORBIDDEN_MECHANISMS: [&str; 8] = [
        "asm",
        "dlopen",
        "dlsym",
        "export_name",
        "global_asm",
        "link_name",
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

fn rust_exported_c_abi_violations(package_documents: &[(PathBuf, String)]) -> Vec<String> {
    let expected = expected_apple_c_abi_exports();
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
        violations.push(
            "the Apple bridge production exported C ABI set must match the eleven reviewed symbols, including the unexposed entitlement probe"
                .to_owned(),
        );
    }
    for (name, expected_signature) in expected {
        if actual
            .get(name)
            .is_none_or(|signatures| signatures != &[expected_signature])
        {
            violations.push(format!(
                "Apple bridge export `{name}` must retain its exact reviewed Rust C ABI signature"
            ));
        }
    }
    violations
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
            "{} must not expand the production Rust source graph with #[path]",
            path.display()
        ));
    }
    if rust_has_macro_invocation(&policy_code, "include") {
        violations.push(format!(
            "{} must not expand the production Rust source graph with include!",
            path.display()
        ));
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
        if &name[..name_length] == "path" {
            return true;
        }
        index = opening + attribute.len();
    }
    false
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
    violations
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
        let (bridge_violations, bridge_count) = swift_bridge_call_inventory(path, is_header, &code);
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

const CANONICAL_TERSA_RUST_BRIDGE_HEADER: &str = r"#ifndef TERSA_RUST_BRIDGE_H
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
int32_t tersa_oauth_macos_begin(
const uint8_t *client_id,
size_t client_id_len,
uint64_t *output_session_id,
uint8_t *output_url,
size_t output_url_capacity,
size_t *output_url_len
);
int32_t tersa_oauth_macos_poll(uint64_t session_id);
int32_t tersa_oauth_cancel(uint64_t session_id);
#endif";

const CANONICAL_TERSA_MAC_BRIDGING_HEADER: &str = "#include \"TersaRustBridge.h\"";

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
    let target_code = sources
        .iter()
        .filter(|(path, _document)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("swift")
        })
        .map(|(_path, document)| strip_swift_non_code(document))
        .collect::<Vec<_>>()
        .join("\n");
    // Two reachability closures over the same call graph:
    // - `terminal_reachable` stops propagation at the reviewed intent entry, so
    //   only functions reaching bootstrap through a NON-intent path appear here;
    // - `strict_reachable` ignores the exemption, so it contains every function
    //   that transitively reaches bootstrap, including callers of the intent.
    let reachability = BootstrapReachability {
        owner_entries,
        intent_entries: &intent_entries,
        terminal_reachable: &swift_bootstrap_reachable_entries(
            &target_code,
            owner_entries,
            &intent_entries,
        ),
        strict_reachable: &swift_bootstrap_reachable_entries(
            &target_code,
            owner_entries,
            &BTreeSet::new(),
        ),
    };
    for (path, document) in sources {
        if path.extension().and_then(|extension| extension.to_str()) != Some("swift") {
            continue;
        }
        let code = strip_swift_non_code(document);
        for (name, body, is_initializer) in swift_function_declarations_with_kind(&code) {
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
        for (property, bodies) in swift_named_property_bodies(&code) {
            if bodies.iter().any(|body| {
                swift_member_call_count(body, "submit") != 0
                    || swift_unqualified_call_count(body, "submit") != 0
                    || reachability
                        .terminal_reachable
                        .iter()
                        .any(|entry| contains_identifier(body, entry))
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
    terminal_reachable: &'a BTreeSet<String>,
    strict_reachable: &'a BTreeSet<String>,
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
    if !calls_submit && !reachability.strict_reachable.contains(name) {
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
        !calls_submit && !reachability.terminal_reachable.contains(name);
    let is_automatic_entry = is_initializer || path == app_delegate_path;
    !reaches_only_through_intent || is_automatic_entry
}

fn swift_bootstrap_reachable_entries(
    document: &str,
    owner_entries: &BTreeSet<String>,
    intent_entries: &BTreeSet<String>,
) -> BTreeSet<String> {
    let entries = swift_named_entry_bodies(document);
    let mut reachable = owner_entries.clone();
    loop {
        let mut changed = false;
        for (name, bodies) in &entries {
            if reachable.contains(name) {
                continue;
            }
            // Reviewed intent entries are reachable sinks: they are validated on
            // their own, but callers reaching only through them do not enter
            // bootstrap, so they never seed further propagation.
            if bodies.iter().any(|body| {
                reachable
                    .iter()
                    .filter(|entry| !intent_entries.contains(entry.as_str()))
                    .any(|entry| contains_identifier(body, entry))
            }) {
                reachable.insert(name.clone());
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
    let mut properties = BTreeMap::<String, Vec<&str>>::new();
    for declaration in ["let", "var"] {
        for (start, _) in document.match_indices(declaration) {
            if !is_identifier_at(document, start, declaration) {
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

/// Declarations forbidden in inventoried macOS sources because they run code the
/// func/init body inventory cannot safely parse (`deinit`, `protocol`,
/// `subscript`) or would place an app-lifecycle entry point outside
/// `AppDelegate.swift` (a cross-file `extension AppDelegate`). Returns the first
/// violation, if any.
fn swift_forbidden_declaration_violation(path: &Path, code: &str) -> Option<String> {
    for forbidden in ["deinit", "protocol", "subscript"] {
        if contains_identifier(code, forbidden) {
            return Some(format!(
                "{} must not declare `{forbidden}` in inventoried macOS sources",
                path.display()
            ));
        }
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

/// Swift has the same comment forms as Rust, plus multiline string literals.
/// Mask them before applying the deliberately textual inventory rules.
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
        for byte in &bytes[start..end] {
            output.push(if *byte == b'\n' { b'\n' } else { b' ' });
        }
    }
    String::from_utf8(output).expect("masking valid Swift source preserves UTF-8")
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
                declarations.push((name, body, is_initializer));
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
const TERSA_MAC_ENTITLEMENTS: &str = "macos/TersaMac.entitlements";
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

fn signing_configuration_violations(entitlements: &str, project: &str) -> Vec<String> {
    let mut violations = source_tersa_mac_entitlement_violations(entitlements);
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
    let Some(application) = targets.iter().find(|target| target.name == "TersaMac") else {
        violations.push("apple/project.yml is missing the TersaMac target".to_owned());
        return violations;
    };
    if application.platform != "macOS" {
        violations.push("the TersaMac target must declare platform macOS".to_owned());
    }
    violations.extend(tersa_mac_target_surface_violations(&application.body));
    if !matches!(
        yaml_path(&application.body, &["entitlements", "path"]),
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
        if !yaml_exact_string_array(yaml_path(&application.body, path), SIGNING_GROUP) {
            violations.push(format!(
                "the TersaMac target `{label}` must contain exactly the registered macOS group"
            ));
        }
    }
    match yaml_path(&application.body, &["entitlements", "properties"]) {
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
        yaml_path(
            &application.body,
            &["settings", "base", "TERSA_MACOS_APP_GROUP"]
        ),
        Some(StrictYamlValue::String(value)) if value == BUILD_SETTING_GROUP
    ) {
        violations.push(
            "the TersaMac target TERSA_MACOS_APP_GROUP setting must exactly match its entitlement group"
                .to_owned(),
        );
    }
    if !matches!(
        yaml_path(
            &application.body,
            &["settings", "base", "CODE_SIGN_ENTITLEMENTS"]
        ),
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

fn tersa_mac_target_surface_violations(target: &StrictYamlValue) -> Vec<String> {
    let mut violations = Vec::new();
    let Ok(target) = yaml_mapping(target, "TersaMac target") else {
        return vec!["the TersaMac target must be a direct mapping".to_owned()];
    };
    validate_tersa_mac_top_level_keys(target, &mut violations);
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
    if !yaml_exact_tersa_mac_sources(target.get("sources")) {
        violations.push(
            "the TersaMac target sources must match the exact reviewed source and resource sequence"
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

    let valid_script = match target.get("preBuildScripts") {
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
    };
    if !valid_script {
        violations.push(
            "the TersaMac target must contain only the exact reviewed Rust pre-build script"
                .to_owned(),
        );
    }

    let valid_scheme = match target.get("scheme") {
        Some(StrictYamlValue::Mapping(scheme)) => {
            scheme.len() == 1
                && matches!(
                    scheme.get("testTargets"),
                    Some(StrictYamlValue::Sequence(targets)) if targets.is_empty()
                )
        }
        _ => false,
    };
    if !valid_scheme {
        violations.push(
            "the TersaMac scheme must contain only an empty testTargets list and no executable actions"
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

fn validate_tersa_mac_top_level_keys(
    target: &BTreeMap<String, StrictYamlValue>,
    violations: &mut Vec<String>,
) {
    let expected_keys = BTreeSet::from([
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
            "com.apple.security.application-groups",
            "keychain-access-groups",
        ]
        .iter()
        .any(|sensitive| key == *sensitive || key.starts_with(&format!("{sensitive}[")))
}

fn allowed_sensitive_configuration(path: &[String], value: &StrictYamlValue) -> bool {
    let components = path.iter().map(String::as_str).collect::<Vec<_>>();
    match components.as_slice() {
        [
            "settings",
            "base",
            "CODE_SIGNING_ALLOWED" | "CODE_SIGNING_REQUIRED",
        ] => {
            matches!(value, StrictYamlValue::String(value) if value == "NO")
        }
        ["settings", "base", "DEVELOPMENT_TEAM"] => {
            matches!(value, StrictYamlValue::String(value) if value.is_empty())
        }
        ["settings", "base", key] => match *key {
            "TERSA_DIOXUS_CODE_SIGNING_ALLOWED" | "TERSA_DIOXUS_CODE_SIGNING_REQUIRED" => {
                matches!(value, StrictYamlValue::String(value) if value == "NO")
            }
            "TERSA_DIOXUS_DEVELOPMENT_TEAM"
            | "TERSA_DIOXUS_CODE_SIGN_IDENTITY"
            | "TERSA_DIOXUS_PROVISIONING_PROFILE_SPECIFIER" => {
                matches!(value, StrictYamlValue::String(value) if value.is_empty())
            }
            "TERSA_DIOXUS_CODE_SIGN_STYLE" => {
                matches!(value, StrictYamlValue::String(value) if value == "Automatic")
            }
            _ => false,
        },
        [
            "targets",
            "TersaMac",
            "settings",
            "base",
            "TERSA_MACOS_APP_GROUP",
        ] => {
            matches!(value, StrictYamlValue::String(value) if value == BUILD_SETTING_GROUP)
        }
        [
            "targets",
            "TersaMac",
            "settings",
            "base",
            "CODE_SIGN_ENTITLEMENTS",
        ] => {
            matches!(value, StrictYamlValue::String(value) if value == TERSA_MAC_ENTITLEMENTS)
        }
        ["targets", "TersaMac", "entitlements", "properties", key]
            if *key == "com.apple.security.application-groups"
                || *key == "keychain-access-groups" =>
        {
            yaml_exact_string_array(Some(value), SIGNING_GROUP)
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
        ["targets", "TersaDioxusIOS", "settings", "base", key] => match *key {
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
        },
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
    match components.as_slice() {
        ["targets", "TersaMac", "entitlements", "path"] => true,
        ["targets", "TersaMac", "settings", "base", key]
            if *key == "CODE_SIGN_ENTITLEMENTS" || *key == "TERSA_MACOS_APP_GROUP" =>
        {
            true
        }
        [
            "targets",
            "TersaMac",
            "entitlements",
            "properties",
            key,
            "[0]",
        ] if *key == "com.apple.security.application-groups"
            || *key == "keychain-access-groups" =>
        {
            true
        }
        _ => false,
    }
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
/// composition; every other crate reaches it transitively through reqwest. The
/// composition pins an exact, current-thread, macOS-scoped runtime.
fn tokio_manifest_dependency_violations(
    package_name: &str,
    version: &str,
    uses_default_features: bool,
    target: Option<&str>,
    features: &[String],
) -> Vec<String> {
    const OWNER: &str = "tersa-oauth-sync-macos";
    if package_name != OWNER {
        return vec![format!(
            "{package_name} -> tokio is outside the trusted composition owner {OWNER}"
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
    // reqwest (network) may be REACHED only by the Gmail adapter that owns it
    // and the one trusted composition that drives it. tersa-keychain-macos and
    // the retrieval-only tersa-cli-macos are deliberately absent: the check must
    // still fire if either ever reaches reqwest.
    const OWNERS: [&str; 2] = ["tersa-gmail-rest-macos", "tersa-oauth-sync-macos"];
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
        CANONICAL_TERSA_RUST_BRIDGE_HEADER, ResolvedDependencyIdentity,
        apple_bridge_direct_dependency_set_violations, blob_dependency_graph_violations,
        blob_manifest_dependency_violations, bridge_bootstrap_source_violations,
        bridge_package_source_surface_violations, canonical_cli_source_anchor_violations,
        check_diagnostic_runtime_reachability, cli_direct_dependency_set_violations,
        cli_keychain_source_violations, collect_entitlement_paths, dependency_policy,
        future_macos_store_dependency_violation, gmail_dependency_graph_violations,
        gmail_manifest_dependency_violations, gmail_resolved_feature_violations,
        is_dioxus_runtime_dependency, is_slint_runtime_dependency,
        keychain_direct_dependency_set_violations, keychain_mutation_boundary_violations,
        non_owner_entitlement_violations, oauth_sync_direct_dependency_set_violations,
        parse_identity, parse_plist_string_array, parse_project_targets,
        project_generation_surface_violations, project_generation_wrapper,
        protected_keychain_dependency_rename_violations, reserved_future_policy_violations,
        resolved_workspace_dependency_names, retrieval_tokio_denial_violations,
        rusqlite_resolved_feature_violations, rust_authority_source_surface_violations,
        rust_exported_c_abi_violations, rustix_manifest_dependency_violations,
        shipped_direct_dependency_names, signing_configuration_violations,
        sqlcipher_dependency_graph_violations, sqlcipher_manifest_dependency_violations,
        strip_rust_non_code, strip_rust_test_modules, swift_bootstrap_inventory_violations,
        swift_bootstrap_source_violations, swift_bridge_call_inventory, target_metadata_options,
        tracked_apple_signing_inventory, tracked_project_generation_violations,
    };

    const VALID_ENTITLEMENTS: &str = r#"<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.network.client</key><true/>
<key>com.apple.security.network.server</key><true/>
<key>com.apple.security.application-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
<key>keychain-access-groups</key><array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
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
        assert!(rust_exported_c_abi_violations(&reviewed).is_empty());

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
                !rust_exported_c_abi_violations(&contaminated).is_empty(),
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
                !rust_exported_c_abi_violations(&contaminated).is_empty(),
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
        let violations = rust_exported_c_abi_violations(&twelfth_symbol);
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
            !rust_exported_c_abi_violations(&comment_mask_bypass).is_empty(),
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
            !rust_exported_c_abi_violations(&literal_mask_bypass).is_empty(),
            "a literal containing a pseudo cfg(test) module must not hide a production export"
        );
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
                !rust_exported_c_abi_violations(&contaminated).is_empty(),
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
            rust_exported_c_abi_violations(&sources).is_empty(),
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
        let path = Path::new("apple/macos/TersaRustBridge.h");
        let (violations, calls) =
            swift_bridge_call_inventory(path, true, CANONICAL_TERSA_RUST_BRIDGE_HEADER);
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(calls, 0);

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
        ] {
            let (violations, _) = swift_bridge_call_inventory(path, true, &drift);
            assert!(
                !violations.is_empty(),
                "header drift must fail closed: {drift:?}"
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
func applicationDidFinishLaunching(_ notification: Notification) { _ = version() }
func establishOwnedAccountProfile(_ bytes: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) { bootstrapWorker.submit(accountIdentifier: bytes, completion: completion) }
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
        let project = r#"name: Tersa
options:
  bundleIdPrefix: app.tersa
  deploymentTarget: { macOS: "15.0", iOS: "18.0" }
  xcodeVersion: "26.0"
settings: {}
targets:
  FirstIOS:
    platform: iOS
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
  MiddleMac:
    platform: macOS
  LastIOS:
    platform: iOS
"#;
        let targets = match parse_project_targets(project) {
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
            ]
        );
        assert!(signing_configuration_violations(entitlements, project).is_empty());

        let malformed_array = project.replace(
            "        keychain-access-groups:\n          - ${TeamIdentifierPrefix}app.tersa.shared",
            "        keychain-access-groups: ${TeamIdentifierPrefix}app.tersa.shared",
        );
        assert!(
            signing_configuration_violations(entitlements, &malformed_array)
                .iter()
                .any(|violation| violation.contains("`keychain-access-groups`"))
        );

        let contaminated = project.replace(
            "  LastIOS:\n    platform: iOS",
            "  LastIOS:\n    platform: iOS\n    settings:\n      base:\n        TERSA_MACOS_APP_GROUP: forbidden",
        );
        assert!(
            signing_configuration_violations(entitlements, &contaminated)
                .iter()
                .any(|violation| violation
                    .contains("targets.LastIOS.settings.base.TERSA_MACOS_APP_GROUP"))
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
                aliased,
            )
            .iter()
            .any(|violation| violation.contains("targets.AliasedIOS.settings.base.TERSA_MACOS_APP_GROUP"))
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
        let violations = signing_configuration_violations(entitlements, project);
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
    fn effective_signing_policy_rejects_every_unsupported_xcodegen_bypass() {
        assert!(
            signing_configuration_violations(VALID_ENTITLEMENTS, VALID_SIGNING_PROJECT).is_empty()
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
        ] {
            let violations = signing_configuration_violations(VALID_ENTITLEMENTS, &project);
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
            let violations = signing_configuration_violations(VALID_ENTITLEMENTS, &project);
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
                "nested dependency",
                VALID_SIGNING_PROJECT.replace(
                    "    type: application",
                    "    type: application\n    dependencies:\n      - target: Unreviewed",
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
            let violations = signing_configuration_violations(VALID_ENTITLEMENTS, &project);
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
        let violations =
            signing_configuration_violations(VALID_ENTITLEMENTS, &defensive_attributes);
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
            signing_configuration_violations(VALID_ENTITLEMENTS, VALID_SIGNING_PROJECT).is_empty()
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
                signing_configuration_violations(VALID_ENTITLEMENTS, &project)
                    .iter()
                    .any(|violation| violation.contains("exact reviewed source and resource sequence")),
                "source sequence bypass must fail closed"
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
            let violations = signing_configuration_violations(&source, VALID_SIGNING_PROJECT);
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
            let violations = signing_configuration_violations(VALID_ENTITLEMENTS, &project);
            assert!(
                violations.iter().any(|violation| violation.contains(
                    "TersaMac XcodeGen entitlement properties"
                )),
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
                    "    scheme:\n      testTargets: []",
                    "    postBuildScripts:\n      - name: Unreviewed\n        script: sh unreviewed.sh\n    scheme:\n      testTargets: []",
                ),
                "postBuildScripts",
            ),
            (
                "scheme action",
                VALID_SIGNING_PROJECT.replace(
                    "    scheme:\n      testTargets: []",
                    "    scheme:\n      testTargets: []\n      preActions:\n        - script: sh unreviewed.sh",
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
                    "        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac",
                    "        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac\n        PRODUCT_BUNDLE_IDENTIFIER[sdk=macosx*]: app.attacker",
                ),
                "without conditional overrides",
            ),
        ];
        for (label, project, expected) in cases {
            let violations = signing_configuration_violations(VALID_ENTITLEMENTS, &project);
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
                "        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac",
                &format!("        PRODUCT_BUNDLE_IDENTIFIER: app.tersa.mac\n{injected}"),
            );
            let violations = signing_configuration_violations(VALID_ENTITLEMENTS, &project);
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
            signing_configuration_violations(VALID_ENTITLEMENTS, &reused_prefix)
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
                "tersa-application reaches reqwest outside the authorized network crates [\"tersa-gmail-rest-macos\", \"tersa-oauth-sync-macos\"] for aarch64-apple-darwin"
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
                "tersa-application reaches reqwest outside the authorized network crates [\"tersa-gmail-rest-macos\", \"tersa-oauth-sync-macos\"] for aarch64-apple-ios",
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
