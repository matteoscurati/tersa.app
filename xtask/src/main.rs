// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Repository automation for tersa.app.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::process::{Command, ExitCode};

use cargo_metadata::{Metadata, MetadataCommand, PackageId};

// Rust guideline compliant 1.0.

type TaskResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
type RuntimeBoundary = (&'static str, fn(&str) -> bool, &'static str);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedDependencyIdentity {
    package_id: PackageId,
}

const SQLCIPHER_OWNERS: [&str; 3] = [
    "tersa-search-spike",
    "tersa-sqlcipher-spike",
    "tersa-store-sqlcipher-macos",
];
const BLOB_DIAGNOSTIC_OWNERS: [&str; 1] = ["tersa-blob-spike"];
const HMAC_OWNERS: [&str; 2] = ["tersa-blob-spike", "tersa-keychain-macos"];
const RESERVED_FUTURE_POLICY: [(&str, &[&str]); 1] = [(
    "tersa-cli-macos",
    &[
        "tersa-application",
        "tersa-domain",
        "tersa-keychain-macos",
        "tersa-platform",
        "tersa-store-sqlcipher-macos",
    ],
)];
const MACOS_STORE_TARGET: &str = r#"cfg(target_os = "macos")"#;
const MACOS_GMAIL_TARGET: &str = r#"cfg(target_os = "macos")"#;
const MACOS_KEYCHAIN_TARGET: &str = r#"cfg(target_os = "macos")"#;
const REQWEST_DIRECT_FEATURES: [&str; 1] = ["native-tls"];
const REQWEST_RESOLVED_FEATURES: [&str; 4] =
    ["__native-tls", "__native-tls-alpn", "__tls", "native-tls"];
const RUSQLITE_RESOLVED_FEATURES: [&str; 3] = ["bundled", "bundled-sqlcipher", "modern_sqlite"];

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

        for dependency in &package.dependencies {
            check_slint_dependency(&package_name, dependency, &mut violations);
            check_dioxus_dependency(&package_name, dependency, &mut violations);
            check_sqlcipher_dependency(&package_name, dependency, &mut violations);
            check_search_dependency(&package_name, dependency, &mut violations);
            check_mime_dependency(&package_name, dependency, &mut violations);
            check_blob_dependency(&package_name, dependency, &mut violations);
            check_gmail_dependency(&package_name, dependency, &mut violations);
            check_keychain_dependency(&package_name, dependency, &mut violations);
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

    if violations.is_empty() {
        println!("Architecture dependency boundaries passed.");
        return Ok(());
    }

    Err(io::Error::other(format!(
        "architecture dependency violations: {}",
        violations.join(", ")
    ))
    .into())
}

fn check_macos_keychain_signing_configuration(violations: &mut Vec<String>) -> TaskResult {
    let entitlements = fs::read_to_string("apple/macos/TersaMac.entitlements")?;
    let project = fs::read_to_string("apple/project.yml")?;
    violations.extend(signing_configuration_violations(&entitlements, &project));

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
    Ok(())
}

const SIGNING_GROUP: &str = "${TeamIdentifierPrefix}app.tersa.shared";
const BUILD_SETTING_GROUP: &str = "$(TeamIdentifierPrefix)app.tersa.shared";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectTarget {
    name: String,
    platform: String,
    keys: Vec<Vec<String>>,
    scalars: BTreeMap<Vec<String>, String>,
    sequences: BTreeMap<Vec<String>, Vec<String>>,
}

fn signing_configuration_violations(entitlements: &str, project: &str) -> Vec<String> {
    let mut violations = Vec::new();
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

    let targets = match parse_project_targets(project) {
        Ok(targets) => targets,
        Err(error) => {
            violations.push(format!(
                "apple/project.yml target structure is invalid: {error}"
            ));
            return violations;
        }
    };
    let Some(application) = targets.iter().find(|target| target.name == "TersaMac") else {
        violations.push("apple/project.yml is missing the TersaMac target".to_owned());
        return violations;
    };
    if application.platform != "macOS" {
        violations.push("the TersaMac target must declare platform macOS".to_owned());
    }

    let entitlement_prefix = ["entitlements", "properties"];
    let application_group_path = entitlement_prefix
        .iter()
        .chain(["com.apple.security.application-groups"].iter())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let keychain_group_path = entitlement_prefix
        .iter()
        .chain(["keychain-access-groups"].iter())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let setting_path = ["settings", "base", "TERSA_MACOS_APP_GROUP"]
        .into_iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    for (path, label) in [
        (
            &application_group_path,
            "com.apple.security.application-groups",
        ),
        (&keychain_group_path, "keychain-access-groups"),
    ] {
        if application
            .keys
            .iter()
            .filter(|candidate| *candidate == path)
            .count()
            != 1
            || application.sequences.get(path) != Some(&vec![SIGNING_GROUP.to_owned()])
        {
            violations.push(format!(
                "the TersaMac target `{label}` must contain exactly the registered macOS group"
            ));
        }
    }
    if application
        .keys
        .iter()
        .filter(|candidate| *candidate == &setting_path)
        .count()
        != 1
        || application.scalars.get(&setting_path).map(String::as_str) != Some(BUILD_SETTING_GROUP)
    {
        violations.push(
            "the TersaMac target TERSA_MACOS_APP_GROUP setting must exactly match its entitlement group"
                .to_owned(),
        );
    }

    for target in &targets {
        if target.platform == "iOS"
            && (target_contains_key(target, "TERSA_MACOS_APP_GROUP")
                || target_contains_key(target, "com.apple.security.application-groups")
                || target_contains_key(target, "keychain-access-groups"))
        {
            violations.push(format!(
                "iOS target `{}` must not receive the Phase 1 macOS Keychain/App Group configuration",
                target.name
            ));
        }
    }
    violations
}

fn parse_plist_string_array(document: &str, key: &str) -> Result<Vec<String>, String> {
    let marker = format!("<key>{key}</key>");
    let mut matches = document.match_indices(&marker);
    let Some((offset, _)) = matches.next() else {
        return Err("missing key".to_owned());
    };
    if matches.next().is_some() {
        return Err("duplicate key".to_owned());
    }
    let mut remaining = document[offset + marker.len()..].trim_start();
    remaining = remaining
        .strip_prefix("<array>")
        .ok_or_else(|| "value is not an array".to_owned())?;
    let mut values = Vec::new();
    loop {
        remaining = remaining.trim_start();
        if remaining.starts_with("</array>") {
            return Ok(values);
        }
        remaining = remaining
            .strip_prefix("<string>")
            .ok_or_else(|| "array contains a non-string member or is unterminated".to_owned())?;
        let end = remaining
            .find("</string>")
            .ok_or_else(|| "unterminated string member".to_owned())?;
        let value = &remaining[..end];
        if value.contains('<') || value.contains('&') {
            return Err("string member uses unsupported nested or escaped content".to_owned());
        }
        values.push(value.to_owned());
        remaining = &remaining[end + "</string>".len()..];
    }
}

fn parse_project_targets(document: &str) -> Result<Vec<ProjectTarget>, String> {
    let lines = document.lines().collect::<Vec<_>>();
    let target_start = lines
        .iter()
        .position(|line| *line == "targets:")
        .ok_or_else(|| "missing top-level targets mapping".to_owned())?;
    let mut targets = Vec::new();
    let mut index = target_start + 1;
    while index < lines.len() {
        let line = lines[index];
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            index += 1;
            continue;
        }
        let indent = leading_spaces(line)?;
        if indent == 0 {
            break;
        }
        if indent != 2 || !line.trim_end().ends_with(':') {
            return Err(format!("unexpected target entry `{}`", line.trim()));
        }
        let name = line.trim().trim_end_matches(':').to_owned();
        let body_start = index + 1;
        index = body_start;
        while index < lines.len() {
            let candidate = lines[index];
            if !candidate.trim().is_empty()
                && !candidate.trim_start().starts_with('#')
                && leading_spaces(candidate)? <= 2
            {
                break;
            }
            index += 1;
        }
        targets.push(parse_project_target(&name, &lines[body_start..index])?);
    }
    if targets.is_empty() {
        return Err("targets mapping is empty".to_owned());
    }
    Ok(targets)
}

fn parse_project_target(name: &str, lines: &[&str]) -> Result<ProjectTarget, String> {
    let mut keys = Vec::new();
    let mut scalars = BTreeMap::new();
    let mut sequences = BTreeMap::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_spaces(line)?;
        if indent < 4 {
            return Err(format!("target `{name}` contains an invalid indentation"));
        }
        while stack.last().is_some_and(|(level, _)| *level >= indent) {
            stack.pop();
        }
        if let Some(value) = trimmed.strip_prefix("- ") {
            if stack.is_empty() {
                return Err(format!("target `{name}` contains an unowned sequence item"));
            }
            let path = stack.iter().map(|(_, key)| key.clone()).collect::<Vec<_>>();
            sequences
                .entry(path)
                .or_insert_with(Vec::new)
                .push(unquote_yaml_scalar(value));
            continue;
        }
        let (key, value) = trimmed.split_once(':').ok_or_else(|| {
            format!("target `{name}` contains malformed mapping entry `{trimmed}`")
        })?;
        if key.is_empty() {
            return Err(format!("target `{name}` contains an empty mapping key"));
        }
        let mut path = stack.iter().map(|(_, key)| key.clone()).collect::<Vec<_>>();
        path.push(key.to_owned());
        keys.push(path.clone());
        if value.trim().is_empty() {
            stack.push((indent, key.to_owned()));
        } else {
            scalars.insert(path, unquote_yaml_scalar(value.trim()));
        }
    }
    let platform_path = vec!["platform".to_owned()];
    let platform = scalars
        .get(&platform_path)
        .cloned()
        .ok_or_else(|| format!("target `{name}` is missing a declared platform"))?;
    Ok(ProjectTarget {
        name: name.to_owned(),
        platform,
        keys,
        scalars,
        sequences,
    })
}

fn leading_spaces(line: &str) -> Result<usize, String> {
    if line.contains('\t') {
        return Err("tabs are not permitted in project YAML indentation".to_owned());
    }
    Ok(line.len() - line.trim_start_matches(' ').len())
}

fn unquote_yaml_scalar(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value)
        .to_owned()
}

fn target_contains_key(target: &ProjectTarget, key: &str) -> bool {
    target
        .keys
        .iter()
        .any(|path| path.last().is_some_and(|candidate| candidate == key))
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
        check_diagnostic_runtime_dependency_graph(&dependency_graph, target, violations);
    }
    Ok(())
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
            &["std", "NSFileManager", "NSString", "NSURL"][..],
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
    const REQUIRED: [&str; 7] = [
        "core-foundation",
        "hkdf",
        "objc2-foundation",
        "security-framework-sys",
        "sha2",
        "tersa-platform",
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
        if !HMAC_OWNERS.contains(&member_name.as_str())
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
            if !SQLCIPHER_OWNERS.contains(&member_name.as_str()) {
                violations.push(format!(
                    "{member_name} reaches libsqlite3-sys outside the approved Apple SQLCipher owners for {target}"
                ));
            } else if member_name == "tersa-store-sqlcipher-macos"
                && target != "aarch64-apple-darwin"
            {
                violations.push(format!(
                    "tersa-store-sqlcipher-macos reaches libsqlite3-sys on non-macOS target {target}"
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
    if package_name != "tersa-store-sqlcipher-macos"
        || !matches!(
            dependency_name,
            "rusqlite" | "libsqlite3-sys" | "chacha20poly1305" | "hmac"
        )
    {
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
            BTreeSet::from(["tersa-application", "tersa-presentation"]),
        ),
        ("tersa-dioxus-spike", BTreeSet::from(["tersa-presentation"])),
        ("tersa-blob-spike", BTreeSet::new()),
        ("tersa-keychain-macos", BTreeSet::from(["tersa-platform"])),
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

    use cargo_metadata::PackageId;

    use super::{
        RESERVED_FUTURE_POLICY, ResolvedDependencyIdentity, blob_dependency_graph_violations,
        blob_manifest_dependency_violations, check_diagnostic_runtime_reachability,
        dependency_policy, future_macos_store_dependency_violation,
        gmail_dependency_graph_violations, gmail_manifest_dependency_violations,
        gmail_resolved_feature_violations, is_dioxus_runtime_dependency,
        is_slint_runtime_dependency, keychain_direct_dependency_set_violations, parse_identity,
        parse_plist_string_array, parse_project_targets, reserved_future_policy_violations,
        resolved_workspace_dependency_names, rusqlite_resolved_feature_violations,
        signing_configuration_violations, sqlcipher_dependency_graph_violations,
        sqlcipher_manifest_dependency_violations, target_metadata_options,
    };

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
    fn reserves_only_the_future_cli_boundary() {
        assert_eq!(
            RESERVED_FUTURE_POLICY,
            [(
                "tersa-cli-macos",
                &[
                    "tersa-application",
                    "tersa-domain",
                    "tersa-keychain-macos",
                    "tersa-platform",
                    "tersa-store-sqlcipher-macos",
                ][..],
            ),]
        );
    }

    #[test]
    fn keychain_direct_dependencies_are_a_closed_exact_set() {
        let exact = BTreeSet::from([
            "core-foundation",
            "hkdf",
            "objc2-foundation",
            "security-framework-sys",
            "sha2",
            "tersa-platform",
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
    fn plist_array_parser_rejects_malformed_or_non_exact_arrays() {
        let malformed = "<key>keychain-access-groups</key><string>group</string>";
        assert_eq!(
            parse_plist_string_array(malformed, "keychain-access-groups"),
            Err("value is not an array".to_owned())
        );
        let mixed = "<key>keychain-access-groups</key><array><string>group</string><true/></array>";
        assert_eq!(
            parse_plist_string_array(mixed, "keychain-access-groups"),
            Err("array contains a non-string member or is unterminated".to_owned())
        );
    }

    #[test]
    fn signing_parser_uses_declared_platform_with_interleaved_targets() {
        let entitlements = r"
<key>com.apple.security.application-groups</key>
<array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
<key>keychain-access-groups</key>
<array><string>${TeamIdentifierPrefix}app.tersa.shared</string></array>
";
        let project = r#"targets:
  FirstIOS:
    platform: iOS
  TersaMac:
    platform: macOS
    entitlements:
      properties:
        com.apple.security.application-groups:
          - ${TeamIdentifierPrefix}app.tersa.shared
        keychain-access-groups:
          - ${TeamIdentifierPrefix}app.tersa.shared
    settings:
      base:
        TERSA_MACOS_APP_GROUP: "$(TeamIdentifierPrefix)app.tersa.shared"
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
                ("TersaMac", "macOS"),
                ("MiddleMac", "macOS"),
                ("LastIOS", "iOS"),
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
        assert_eq!(
            signing_configuration_violations(entitlements, &contaminated),
            vec![
                "iOS target `LastIOS` must not receive the Phase 1 macOS Keychain/App Group configuration"
            ]
        );
    }

    #[test]
    fn fails_closed_when_a_reserved_crate_appears() {
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

        assert_eq!(
            reserved_future_policy_violations(&resolved),
            vec![
                "workspace crate `tersa-cli-macos` is reserved for a later reviewed policy change",
            ]
        );
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
    fn reports_dependencies_beyond_the_cli_reserved_boundary() {
        let resolved = BTreeMap::from([(
            "tersa-cli-macos".to_owned(),
            BTreeSet::from([
                "tersa-application".to_owned(),
                "tersa-platform".to_owned(),
                "tersa-search-spike".to_owned(),
            ]),
        )]);

        assert_eq!(
            reserved_future_policy_violations(&resolved),
            vec![
                "workspace crate `tersa-cli-macos` is reserved for a later reviewed policy change",
                "reserved future crate `tersa-cli-macos` -> `tersa-search-spike` exceeds its allowed inward dependencies",
            ]
        );
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
