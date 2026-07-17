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

use cargo_metadata::{Metadata, MetadataCommand, PackageId};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

// Rust guideline compliant 1.0.

type TaskResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
type RuntimeBoundary = (&'static str, fn(&str) -> bool, &'static str);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedDependencyIdentity {
    package_id: PackageId,
}

const SQLCIPHER_OWNERS: [&str; 5] = [
    "tersa-search-spike",
    "tersa-sqlcipher-spike",
    "tersa-store-sqlcipher-macos",
    "tersa-keychain-macos",
    "tersa-cli-macos",
];
const BLOB_DIAGNOSTIC_OWNERS: [&str; 1] = ["tersa-blob-spike"];
const HMAC_OWNERS: [&str; 2] = ["tersa-blob-spike", "tersa-keychain-macos"];
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

        if package_name == "tersa-blob-spike"
            && !package
                .dependencies
                .iter()
                .any(|dependency| dependency.name == "rustix")
        {
            violations
                .push("tersa-blob-spike must depend directly on exact-pinned rustix".to_owned());
        }

        if package_name == "tersa-keychain-macos" {
            let direct_dependencies = package
                .dependencies
                .iter()
                .map(|dependency| dependency.name.as_str())
                .collect();
            violations.extend(keychain_direct_dependency_set_violations(
                &direct_dependencies,
            ));
        }

        if package_name == "tersa-apple-bridge" {
            let direct_dependencies = package
                .dependencies
                .iter()
                .map(|dependency| dependency.name.as_str())
                .collect();
            violations.extend(apple_bridge_direct_dependency_set_violations(
                &direct_dependencies,
            ));
        }

        if package_name == "tersa-cli-macos" {
            let direct_dependencies = package
                .dependencies
                .iter()
                .map(|dependency| dependency.name.as_str())
                .collect();
            violations.extend(cli_direct_dependency_set_violations(&direct_dependencies));
        }

        for dependency in &package.dependencies {
            check_slint_dependency(&package_name, dependency, &mut violations);
            check_dioxus_dependency(&package_name, dependency, &mut violations);
            check_sqlcipher_dependency(&package_name, dependency, &mut violations);
            check_search_dependency(&package_name, dependency, &mut violations);
            check_mime_dependency(&package_name, dependency, &mut violations);
            check_blob_dependency(&package_name, dependency, &mut violations);
            check_gmail_dependency(&package_name, dependency, &mut violations);
            check_keychain_dependency(&package_name, dependency, &mut violations);
            check_rustix_dependency(&package_name, dependency, &mut violations);
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

    let adapter = fs::read_to_string("adapters/keychain-macos/src/lib.rs")?;
    for required in [
        "SecItemAdd",
        "SecItemCopyMatching",
        "SecRandomCopyBytes",
        "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        "kSecUseDataProtectionKeychain",
    ] {
        if !adapter.contains(required) {
            violations.push(format!(
                "the macOS Keychain adapter is missing required boundary `{required}`"
            ));
        }
    }
    for forbidden in ["SecItemUpdate", "SecItemDelete", "set_generic_password"] {
        if adapter.contains(forbidden) {
            violations.push(format!(
                "the macOS Keychain adapter contains forbidden mutation boundary `{forbidden}`"
            ));
        }
    }
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
            violations.extend(cli_keychain_source_violations(
                &path.to_string_lossy(),
                &document,
            ));
        }
    }

    let bridge_sources = tracked_source_documents(repository_root, "apple/rust-bridge/src")?;
    let bridge_document = bridge_sources
        .iter()
        .filter(|(path, _document)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("rs")
        })
        .map(|(_path, document)| document.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    violations.extend(bridge_bootstrap_source_violations(&bridge_document));

    let worker_path = repository_root.join("apple/macos/BootstrapWorker.swift");
    let app_delegate_path = repository_root.join("apple/macos/AppDelegate.swift");
    let tracked_macos_sources = tracked_source_documents(repository_root, "apple/macos")?
        .into_iter()
        .map(|(path, _document)| path)
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
    }
    Ok(violations)
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

fn referenced_items<'a>(document: &'a str, prefix: &str) -> Vec<&'a str> {
    document
        .match_indices(prefix)
        .map(|(index, _matched)| {
            let rest = &document[index + prefix.len()..];
            let length = rest
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                .count();
            &rest[..length]
        })
        .collect()
}

fn cli_keychain_source_violations(path: &str, document: &str) -> Vec<String> {
    const ALLOWED: [&str; 2] = ["ReadOnlyMailboxOpenError", "open_default_read_only_mailbox"];
    const FORBIDDEN_BOOTSTRAP: [&str; 4] = [
        "DataProtectionRootKeyProvisioner",
        "InstallationRootKeyProvisioner",
        "ProductBootstrapStatus",
        "bootstrap_default_account_bytes",
    ];
    let mut violations = Vec::new();
    for item in referenced_items(document, "tersa_keychain_macos::") {
        if !ALLOWED.contains(&item) {
            violations.push(format!(
                "{path} references forbidden Keychain adapter item `{item}`"
            ));
        }
    }
    for line in document
        .lines()
        .filter(|line| line.contains("tersa_keychain_macos"))
    {
        let trimmed = line.trim_start();
        if trimmed.starts_with("use ")
            || trimmed.starts_with("pub use ")
            || trimmed.starts_with("extern crate ")
            || line.contains(" as ")
            || line.contains("::*")
        {
            violations.push(format!(
                "{path} must use only fully qualified, non-aliased Keychain retrieval items"
            ));
        }
    }
    for symbol in FORBIDDEN_BOOTSTRAP {
        if document.contains(symbol) {
            violations.push(format!(
                "{path} contains forbidden bootstrap symbol `{symbol}`"
            ));
        }
    }
    violations
}

fn bridge_bootstrap_source_violations(document: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for forbidden in [
        "tersa_domain",
        "use tersa_keychain_macos",
        "pub use tersa_keychain_macos",
        "extern crate tersa_keychain_macos",
    ] {
        if document.contains(forbidden) {
            violations.push(format!(
                "the Apple bridge contains forbidden bootstrap boundary `{forbidden}`"
            ));
        }
    }
    if contains_identifier(document, "AccountId") {
        violations
            .push("the Apple bridge contains forbidden bootstrap boundary `AccountId`".to_owned());
    }
    for item in referenced_items(document, "tersa_keychain_macos::") {
        if !matches!(
            item,
            "ProductBootstrapStatus" | "bootstrap_default_account_bytes"
        ) {
            violations.push(format!(
                "the Apple bridge references forbidden Keychain adapter item `{item}`"
            ));
        }
    }
    if document
        .matches("tersa_keychain_macos::bootstrap_default_account_bytes(")
        .count()
        != 1
    {
        violations.push(
            "the Apple bridge must call exactly one validating Keychain bootstrap entry".to_owned(),
        );
    }
    for required in [
        "account_id.is_null()",
        "account_id_len == 0",
        "account_id_len > 256",
        "slice::from_raw_parts(account_id, account_id_len)",
        ".to_vec()",
    ] {
        if !document.contains(required) {
            violations.push(format!(
                "the Apple bridge is missing required bounded-copy source `{required}`"
            ));
        }
    }
    violations
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

fn swift_bootstrap_source_violations(worker: &str, app_delegate: &str) -> Vec<String> {
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
    if app_delegate.matches("bootstrapWorker.submit(").count() != 1 {
        violations.push(
            "AppDelegate.swift must contain exactly one product bootstrap worker call site"
                .to_owned(),
        );
    }
    if app_delegate.contains("local-profile-owner") {
        violations.push("AppDelegate.swift must not bootstrap a placeholder account".to_owned());
    }
    if let Some(launch) = app_delegate.split("applicationDidFinishLaunching").nth(1) {
        let end = ["\n    func ", "\nfunc "]
            .into_iter()
            .filter_map(|boundary| launch.find(boundary))
            .min()
            .unwrap_or(launch.len());
        let launch = &launch[..end];
        if launch.contains("bootstrapWorker.submit(") {
            violations.push("AppDelegate.swift must not bootstrap an account at launch".to_owned());
        }
    }
    violations
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
            "xcodegen" => return xcodegen_arguments_generate(&tokens[index + 1..]),
            _ if static_binding_is_xcodegen(&tokens[index], bindings) => {
                return xcodegen_arguments_generate(&tokens[index + 1..]);
            }
            _ => return false,
        }
    }
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

fn keychain_direct_dependency_set_violations(dependencies: &BTreeSet<&str>) -> Vec<String> {
    const REQUIRED: [&str; 9] = [
        "core-foundation",
        "hkdf",
        "objc2-foundation",
        "rustix",
        "security-framework-sys",
        "sha2",
        "tersa-platform",
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
    const OWNER: &str = "tersa-gmail-rest-macos";
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
        if name != OWNER {
            violations.push(format!(
                "{name} reaches reqwest outside {OWNER} for {target}"
            ));
        } else if target != "aarch64-apple-darwin" {
            violations.push(format!(
                "{OWNER} reaches reqwest on non-macOS target {target}"
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
        "ammonia" => Some("=4.1.3"),
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
        ("tersa-keychain-macos", "tersa-store-sqlcipher-macos")
            | (
                "tersa-cli-macos" | "tersa-apple-bridge",
                "tersa-keychain-macos"
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
            BTreeSet::from(["tersa-platform", "tersa-store-sqlcipher-macos"]),
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
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use cargo_metadata::PackageId;

    use super::{
        ResolvedDependencyIdentity, apple_bridge_direct_dependency_set_violations,
        blob_dependency_graph_violations, blob_manifest_dependency_violations,
        bridge_bootstrap_source_violations, check_diagnostic_runtime_reachability,
        cli_direct_dependency_set_violations, cli_keychain_source_violations,
        collect_entitlement_paths, dependency_policy, future_macos_store_dependency_violation,
        gmail_dependency_graph_violations, gmail_manifest_dependency_violations,
        gmail_resolved_feature_violations, is_dioxus_runtime_dependency,
        is_slint_runtime_dependency, keychain_direct_dependency_set_violations,
        non_owner_entitlement_violations, parse_identity, parse_plist_string_array,
        parse_project_targets, project_generation_surface_violations, project_generation_wrapper,
        reserved_future_policy_violations, resolved_workspace_dependency_names,
        rusqlite_resolved_feature_violations, rustix_manifest_dependency_violations,
        signing_configuration_violations, sqlcipher_dependency_graph_violations,
        sqlcipher_manifest_dependency_violations, swift_bootstrap_source_violations,
        target_metadata_options, tracked_apple_signing_inventory,
        tracked_project_generation_violations,
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
    sources: []
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
    fn keychain_direct_dependencies_are_a_closed_exact_set() {
        let exact = BTreeSet::from([
            "core-foundation",
            "hkdf",
            "objc2-foundation",
            "rustix",
            "security-framework-sys",
            "sha2",
            "tersa-platform",
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

        for forbidden in [
            "tersa_keychain_macos::bootstrap_default_account_bytes(bytes);",
            "use tersa_keychain_macos::*;",
            "use tersa_keychain_macos::open_default_read_only_mailbox as open;",
            "pub use tersa_keychain_macos::ProductBootstrapStatus;",
            "extern crate tersa_keychain_macos as keychain;",
        ] {
            assert!(
                !cli_keychain_source_violations("cli.rs", forbidden).is_empty(),
                "fixture must fail: {forbidden}"
            );
        }
    }

    #[test]
    fn bridge_source_guard_pins_the_single_bounded_validating_call() {
        let valid = r"
if account_id.is_null() || account_id_len == 0 || account_id_len > 256 { return 1; }
let bytes = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();
match tersa_keychain_macos::bootstrap_default_account_bytes(&bytes) {
    tersa_keychain_macos::ProductBootstrapStatus::Ready => 0,
    _ => 1,
}
";
        assert!(bridge_bootstrap_source_violations(valid).is_empty());

        for forbidden in [
            valid.replace(
                "bootstrap_default_account_bytes",
                "alternate_bootstrap_entry",
            ),
            format!("{valid}\nuse tersa_keychain_macos as keychain;"),
            format!("{valid}\nlet _ = AccountId::new(value);"),
            format!(
                "{valid}\nlet _ = tersa_keychain_macos::bootstrap_default_account_bytes(&bytes);"
            ),
        ] {
            assert!(!bridge_bootstrap_source_violations(&forbidden).is_empty());
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
func bootstrapAccount(_ bytes: Data) { bootstrapWorker.submit(accountIdentifier: bytes) {} }
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
    sources: []
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
                VALID_SIGNING_PROJECT.replace("    sources: []\n", ""),
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
            ("tersa-cli-macos", "tersa-keychain-macos"),
            ("tersa-apple-bridge", "tersa-keychain-macos"),
        ] {
            assert_eq!(
                future_macos_store_dependency_violation(
                    owner,
                    dependency,
                    Some(r#"cfg(target_os = "macos")"#),
                ),
                None
            );
            for target in [None, Some(r#"cfg(target_os = "ios")"#)] {
                assert!(
                    future_macos_store_dependency_violation(owner, dependency, target).is_some()
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
                "tersa-application reaches reqwest outside tersa-gmail-rest-macos for aarch64-apple-darwin"
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
                "tersa-application reaches reqwest outside tersa-gmail-rest-macos for aarch64-apple-ios",
                "tersa-gmail-rest-macos reaches reqwest on non-macOS target aarch64-apple-ios",
            ]
        );
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
