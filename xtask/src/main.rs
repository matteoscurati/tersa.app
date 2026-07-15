// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Repository automation for tersa.app.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::io;
use std::process::{Command, ExitCode};

use cargo_metadata::{Metadata, MetadataCommand};

// Rust guideline compliant 1.0.

type TaskResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
type RuntimeBoundary = (&'static str, fn(&str) -> bool, &'static str);

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
    let metadata = MetadataCommand::new().no_deps().exec()?;
    let workspace_packages = metadata.workspace_packages();
    let workspace_names: BTreeSet<String> = workspace_packages
        .iter()
        .map(|package| package.name.to_string())
        .collect();
    let policy = dependency_policy();
    let mut violations = Vec::new();

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

        for dependency in &package.dependencies {
            let dependency_name = dependency.name.clone();
            if workspace_names.contains(&dependency_name)
                && !allowed.contains(&dependency_name.as_str())
            {
                violations.push(format!("{package_name} -> {dependency_name}"));
            }

            check_slint_dependency(&package_name, dependency, &mut violations);
            check_dioxus_dependency(&package_name, dependency, &mut violations);
            check_sqlcipher_dependency(&package_name, dependency, &mut violations);
            check_search_dependency(&package_name, dependency, &mut violations);
            check_mime_dependency(&package_name, dependency, &mut violations);
        }
    }

    for target in [
        "aarch64-apple-darwin",
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
    ] {
        let dependency_graph = MetadataCommand::new()
            .other_options(vec![
                "--locked".to_owned(),
                "--filter-platform".to_owned(),
                target.to_owned(),
            ])
            .exec()?;
        check_sqlcipher_dependency_graph(&dependency_graph, target, &mut violations);
        check_search_dependency_graph(&dependency_graph, target, &mut violations);
        check_mime_dependency_graph(&dependency_graph, target, &mut violations);
        check_diagnostic_runtime_dependency_graph(&dependency_graph, target, &mut violations);
    }

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
    const SQLCIPHER_CONSUMERS: [&str; 2] = ["tersa-search-spike", "tersa-sqlcipher-spike"];

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
    let sqlite_packages: BTreeSet<String> = package_names
        .iter()
        .filter_map(|(id, name)| (name == "libsqlite3-sys").then_some(id.clone()))
        .collect();
    if sqlite_packages.is_empty() {
        violations.push("resolved dependency graph is missing libsqlite3-sys".to_owned());
        return;
    }

    for member in &metadata.workspace_members {
        let member_id = member.to_string();
        let Some(member_name) = package_names.get(&member_id) else {
            violations.push(format!(
                "workspace member `{member_id}` is absent from the resolved package graph"
            ));
            continue;
        };
        if !SQLCIPHER_CONSUMERS.contains(&member_name.as_str())
            && dependency_reaches(&member_id, &sqlite_packages, &dependencies)
        {
            violations.push(format!(
                "{member_name} reaches libsqlite3-sys outside the Apple SQLCipher diagnostics for {target}"
            ));
        }
    }
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
    const SQLCIPHER_CONSUMERS: [&str; 2] = ["tersa-search-spike", "tersa-sqlcipher-spike"];
    const APPLE_TARGET: &str = r#"cfg(any(target_os = "macos", target_os = "ios"))"#;

    let dependency_name = dependency.name.as_str();
    if !matches!(dependency_name, "rusqlite" | "libsqlite3-sys") {
        return;
    }

    if !SQLCIPHER_CONSUMERS.contains(&package_name) {
        violations.push(format!(
            "{package_name} -> {dependency_name} (SQLCipher is exclusive to the Apple SQLCipher diagnostics)"
        ));
    }

    let target = dependency.target.as_ref().map(ToString::to_string);
    if target.as_deref() != Some(APPLE_TARGET) {
        violations.push(format!(
            "{package_name} -> {dependency_name} must use target `{APPLE_TARGET}`"
        ));
    }
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

fn dependency_policy() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    BTreeMap::from([
        (
            "tersa-apple-bridge",
            BTreeSet::from(["tersa-application", "tersa-presentation"]),
        ),
        ("tersa-dioxus-spike", BTreeSet::from(["tersa-presentation"])),
        ("tersa-mime-spike", BTreeSet::new()),
        ("tersa-slint-spike", BTreeSet::from(["tersa-presentation"])),
        ("tersa-sqlcipher-spike", BTreeSet::new()),
        ("tersa-search-spike", BTreeSet::new()),
        ("tersa-domain", BTreeSet::new()),
        ("tersa-application", BTreeSet::from(["tersa-domain"])),
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

    use super::{
        check_diagnostic_runtime_reachability, is_dioxus_runtime_dependency,
        is_slint_runtime_dependency, parse_identity,
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
