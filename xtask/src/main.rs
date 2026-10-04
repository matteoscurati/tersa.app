// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Repository automation for tersa.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::process::{Command, ExitCode};

use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, Package};

type TaskResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Core crates and the workspace crates each may depend on.
///
/// Core crates hold domain types, ports, and pure policy. Every new crate
/// under `crates/` must be listed here before it can build in CI.
const CORE_POLICY: [(&str, &[&str]); 4] = [
    ("tersa-domain", &[]),
    ("tersa-platform", &["tersa-domain"]),
    ("tersa-application", &["tersa-domain"]),
    ("tersa-presentation", &["tersa-domain", "tersa-application"]),
];

/// External crates that perform I/O, own a runtime, or reach the OS.
///
/// Core crates must stay free of them so they remain portable and
/// deterministic; adapters and apps own these capabilities.
const CORE_FORBIDDEN_DEPENDENCIES: [&str; 14] = [
    "core-foundation",
    "crossterm",
    "hyper",
    "keyring",
    "libc",
    "objc2",
    "objc2-foundation",
    "ratatui",
    "reqwest",
    "rusqlite",
    "rustix",
    "security-framework",
    "security-framework-sys",
    "tokio",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Layer {
    Core,
    Adapter,
    App,
    Tool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
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
        Some("check-pkg") => {
            let package = required_argument(&mut arguments, "package name")?;
            reject_extra_arguments(arguments)?;
            check_pkg(&package)
        }
        Some("test-pkg") => {
            let package = required_argument(&mut arguments, "package name")?;
            reject_extra_arguments(arguments)?;
            test_pkg(&package)
        }
        Some("clippy-pkg") => {
            let package = required_argument(&mut arguments, "package name")?;
            reject_extra_arguments(arguments)?;
            clippy_pkg(&package)
        }
        Some("preflight") => {
            let class = required_argument(&mut arguments, "preflight class")?;
            let package = optional_package_flag(&mut arguments)?;
            reject_extra_arguments(arguments)?;
            preflight(&class, package.as_deref())
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

fn optional_package_flag(
    arguments: &mut impl Iterator<Item = String>,
) -> TaskResult<Option<String>> {
    let Some(first) = arguments.next() else {
        return Ok(None);
    };
    if first == "--package" || first == "-p" {
        return Ok(Some(required_argument(arguments, "package name")?));
    }
    if let Some(package) = first.strip_prefix("--package=") {
        return Ok(Some(package.to_owned()));
    }
    Err(io::Error::other(format!(
        "unexpected argument `{first}`; expected --package <crate> or no further arguments"
    ))
    .into())
}

fn print_help() {
    println!(
        "\
Repository automation for tersa

Usage:
  cargo xtask verify                    Run the full verification suite (merge quality)
  cargo xtask architecture              Check workspace layering and core purity
  cargo xtask dco <base> <head>         Check DCO sign-offs in a commit range
  cargo xtask check-pkg <package>       cargo check  -p <package> --all-targets (locked)
  cargo xtask test-pkg <package>        cargo test   -p <package> --all-targets (locked)
  cargo xtask clippy-pkg <package>      cargo clippy -p <package> --all-targets -D warnings
  cargo xtask preflight <class> [--package <crate>]
                                        Change-class minimum loop (see agent playbook)
  cargo xtask help                      Show this help

preflight classes: domain, application, presentation, adapter (needs --package),
  tui, policy, docs"
    );
}

// --- Cargo helpers -------------------------------------------------------

fn cargo(arguments: &[&str]) -> Command {
    let mut command = Command::new("cargo");
    command.args(arguments);
    command
}

fn run_command(label: &str, mut command: Command) -> TaskResult {
    println!("Running {label}...");
    let status = command.status()?;
    if status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!("{label} exited with status {status}")).into())
}

fn workspace_metadata(no_deps: bool) -> TaskResult<Metadata> {
    let mut command = MetadataCommand::new();
    if no_deps {
        command.no_deps();
    }
    command
        .other_options(vec!["--locked".to_owned()])
        .exec()
        .map_err(|error| io::Error::other(format!("cargo metadata failed: {error}")).into())
}

fn require_workspace_package(package: &str) -> TaskResult {
    let metadata = workspace_metadata(true)?;
    let names = metadata
        .workspace_packages()
        .into_iter()
        .map(|candidate| candidate.name.to_string())
        .collect::<BTreeSet<_>>();
    if names.contains(package) {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "unknown package `{package}`; workspace packages: {}",
        names.into_iter().collect::<Vec<_>>().join(", ")
    ))
    .into())
}

fn check_pkg(package: &str) -> TaskResult {
    require_workspace_package(package)?;
    run_command(
        &format!("check {package}"),
        cargo(&["check", "--locked", "-p", package, "--all-targets"]),
    )
}

fn test_pkg(package: &str) -> TaskResult {
    require_workspace_package(package)?;
    run_command(
        &format!("tests {package}"),
        cargo(&["test", "--locked", "-p", package, "--all-targets"]),
    )
}

fn clippy_pkg(package: &str) -> TaskResult {
    require_workspace_package(package)?;
    run_command(
        &format!("Clippy {package}"),
        cargo(&[
            "clippy",
            "--locked",
            "-p",
            package,
            "--all-targets",
            "--",
            "--deny",
            "warnings",
        ]),
    )
}

// --- verify --------------------------------------------------------------

fn verify() -> TaskResult {
    check_architecture()?;
    run_command("format check", cargo(&["fmt", "--all", "--check"]))?;
    run_command(
        "Clippy",
        cargo(&[
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
        cargo(&[
            "test",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
        ]),
    )?;
    run_command(
        "documentation tests",
        cargo(&["test", "--locked", "--workspace", "--doc", "--all-features"]),
    )?;
    let mut documentation = cargo(&[
        "doc",
        "--locked",
        "--workspace",
        "--no-deps",
        "--all-features",
    ]);
    documentation.env("RUSTDOCFLAGS", "--deny warnings");
    run_command("documentation", documentation)?;

    println!("Verification passed.");
    Ok(())
}

// --- preflight -----------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreflightClass {
    Domain,
    Application,
    Presentation,
    Adapter,
    Tui,
    Policy,
    Docs,
}

fn parse_preflight_class(raw: &str) -> Option<PreflightClass> {
    match raw {
        "domain" => Some(PreflightClass::Domain),
        "application" => Some(PreflightClass::Application),
        "presentation" => Some(PreflightClass::Presentation),
        "adapter" | "adapter-rust" => Some(PreflightClass::Adapter),
        "tui" => Some(PreflightClass::Tui),
        "policy" | "policy-xtask" => Some(PreflightClass::Policy),
        "docs" | "docs-only" => Some(PreflightClass::Docs),
        _ => None,
    }
}

fn preflight(class_raw: &str, package: Option<&str>) -> TaskResult {
    let class = parse_preflight_class(class_raw).ok_or_else(|| {
        io::Error::other(format!(
            "unknown preflight class `{class_raw}`; run `cargo xtask help`"
        ))
    })?;
    match class {
        PreflightClass::Domain => test_pkg("tersa-domain"),
        PreflightClass::Application => test_pkg("tersa-application"),
        PreflightClass::Presentation => test_pkg("tersa-presentation"),
        PreflightClass::Adapter => {
            let package = package
                .ok_or_else(|| io::Error::other("preflight adapter requires --package <crate>"))?;
            test_pkg(package)
        }
        PreflightClass::Tui => {
            let metadata = workspace_metadata(true)?;
            for app in metadata
                .workspace_packages()
                .into_iter()
                .filter(|candidate| package_layer(candidate) == Some(Layer::App))
            {
                clippy_pkg(app.name.as_str())?;
                test_pkg(app.name.as_str())?;
            }
            Ok(())
        }
        PreflightClass::Policy => {
            check_architecture()?;
            test_pkg("xtask")
        }
        PreflightClass::Docs => {
            println!("preflight docs: no cargo suite; run `typos` if installed");
            Ok(())
        }
    }
}

// --- architecture --------------------------------------------------------

fn package_layer(package: &Package) -> Option<Layer> {
    let manifest = package.manifest_path.as_str().replace('\\', "/");
    if manifest.contains("/crates/") {
        Some(Layer::Core)
    } else if manifest.contains("/adapters/") {
        Some(Layer::Adapter)
    } else if manifest.contains("/apps/") {
        Some(Layer::App)
    } else if manifest.ends_with("/xtask/Cargo.toml") {
        Some(Layer::Tool)
    } else {
        None
    }
}

/// One workspace crate as seen by the layering rules.
#[derive(Debug)]
struct CrateFacts<'a> {
    name: &'a str,
    layer: Layer,
    /// Normal (shipped) dependencies on other workspace crates.
    workspace_dependencies: BTreeSet<&'a str>,
    /// Normal (shipped) dependencies on external crates.
    external_dependencies: BTreeSet<&'a str>,
}

fn layering_violations(crates: &[CrateFacts<'_>]) -> Vec<String> {
    let layers = crates
        .iter()
        .map(|facts| (facts.name, facts.layer))
        .collect::<BTreeMap<_, _>>();
    let core_policy = CORE_POLICY.into_iter().collect::<BTreeMap<_, _>>();
    let mut violations = Vec::new();

    for facts in crates {
        for dependency in &facts.workspace_dependencies {
            match layers.get(dependency) {
                Some(Layer::App | Layer::Tool) => violations.push(format!(
                    "{} -> {dependency}: apps and xtask are leaves; nothing may depend on them",
                    facts.name
                )),
                Some(Layer::Adapter) if facts.layer == Layer::Core => violations.push(format!(
                    "{} -> {dependency}: core crates must not depend on adapters",
                    facts.name
                )),
                _ => {}
            }
        }

        if facts.layer != Layer::Core {
            continue;
        }
        match core_policy.get(facts.name) {
            None => violations.push(format!(
                "{}: core crate is missing from CORE_POLICY in xtask",
                facts.name
            )),
            Some(allowed) => {
                for dependency in &facts.workspace_dependencies {
                    if !allowed.contains(dependency) {
                        violations.push(format!(
                            "{} -> {dependency}: not allowed by CORE_POLICY",
                            facts.name
                        ));
                    }
                }
            }
        }
        for dependency in &facts.external_dependencies {
            if CORE_FORBIDDEN_DEPENDENCIES.contains(dependency) {
                violations.push(format!(
                    "{} -> {dependency}: core crates must stay free of I/O and OS crates",
                    facts.name
                ));
            }
        }
    }
    violations
}

fn check_architecture() -> TaskResult {
    let metadata = workspace_metadata(true)?;
    let workspace_names = metadata
        .workspace_packages()
        .into_iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();

    let mut violations = Vec::new();
    let mut crates = Vec::new();
    for package in metadata.workspace_packages() {
        let Some(layer) = package_layer(package) else {
            violations.push(format!(
                "{}: workspace crate lives outside crates/, adapters/, apps/, or xtask/",
                package.name
            ));
            continue;
        };
        let (workspace_dependencies, external_dependencies) = package
            .dependencies
            .iter()
            .filter(|dependency| dependency.kind == DependencyKind::Normal)
            .map(|dependency| dependency.name.as_str())
            .partition(|name| workspace_names.contains(name));
        if layer == Layer::Core {
            violations.extend(core_unsafe_violation(package)?);
        }
        crates.push(CrateFacts {
            name: package.name.as_str(),
            layer,
            workspace_dependencies,
            external_dependencies,
        });
    }
    violations.extend(layering_violations(&crates));

    if violations.is_empty() {
        println!("Architecture check passed.");
        return Ok(());
    }
    for violation in &violations {
        eprintln!("architecture: {violation}");
    }
    Err(io::Error::other(format!(
        "{} architecture violation(s) found",
        violations.len()
    ))
    .into())
}

fn core_unsafe_violation(package: &Package) -> TaskResult<Option<String>> {
    for target in &package.targets {
        if !target.is_lib() {
            continue;
        }
        let source = fs::read_to_string(&target.src_path)?;
        if !source.contains("#![forbid(unsafe_code)]") {
            return Ok(Some(format!(
                "{}: core crate root must declare #![forbid(unsafe_code)]",
                package.name
            )));
        }
    }
    Ok(None)
}

// --- DCO -----------------------------------------------------------------

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
    let unsigned = unsigned_commits(&log)?;
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

fn unsigned_commits(log: &str) -> TaskResult<Vec<String>> {
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
    Ok(unsigned)
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
    use std::collections::BTreeSet;

    use super::{
        CrateFacts, Layer, PreflightClass, layering_violations, parse_identity,
        parse_preflight_class, unsigned_commits,
    };

    fn facts<'a>(
        name: &'a str,
        layer: Layer,
        workspace: &[&'a str],
        external: &[&'a str],
    ) -> CrateFacts<'a> {
        CrateFacts {
            name,
            layer,
            workspace_dependencies: workspace.iter().copied().collect::<BTreeSet<_>>(),
            external_dependencies: external.iter().copied().collect::<BTreeSet<_>>(),
        }
    }

    #[test]
    fn accepts_current_layering() {
        let crates = [
            facts("tersa-domain", Layer::Core, &[], &[]),
            facts(
                "tersa-application",
                Layer::Core,
                &["tersa-domain"],
                &["url"],
            ),
            facts(
                "tersa-store",
                Layer::Adapter,
                &["tersa-application"],
                &["rusqlite"],
            ),
            facts(
                "tersa",
                Layer::App,
                &["tersa-store", "tersa-domain"],
                &["ratatui"],
            ),
        ];
        assert!(layering_violations(&crates).is_empty());
    }

    #[test]
    fn rejects_core_io_and_upward_dependencies() {
        let crates = [
            facts("tersa-domain", Layer::Core, &["tersa-store"], &["tokio"]),
            facts("tersa-store", Layer::Adapter, &["tersa"], &[]),
            facts("tersa", Layer::App, &[], &[]),
            facts("tersa-new-core", Layer::Core, &[], &[]),
        ];
        let violations = layering_violations(&crates);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("must not depend on adapters"))
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("not allowed by CORE_POLICY"))
        );
        assert!(violations.iter().any(|v| v.contains("free of I/O")));
        assert!(violations.iter().any(|v| v.contains("leaves")));
        assert!(
            violations
                .iter()
                .any(|v| v.contains("missing from CORE_POLICY"))
        );
    }

    #[test]
    fn parses_preflight_aliases() {
        assert_eq!(
            parse_preflight_class("adapter-rust"),
            Some(PreflightClass::Adapter)
        );
        assert_eq!(parse_preflight_class("tui"), Some(PreflightClass::Tui));
        assert_eq!(
            parse_preflight_class("policy-xtask"),
            Some(PreflightClass::Policy)
        );
        assert_eq!(parse_preflight_class("swift-ui"), None);
    }

    #[test]
    fn dco_requires_author_sign_off() {
        let log = "aaa\u{1f}Ada\u{1f}ada@example.com\u{1f}Ada <ADA@example.com>\u{1e}\
                   bbb\u{1f}Bob\u{1f}bob@example.com\u{1f}Eve <eve@example.com>\u{1e}";
        assert_eq!(
            unsigned_commits(log).expect("parse"),
            vec!["bbb".to_owned()]
        );
        assert_eq!(parse_identity("No Email"), None);
    }
}
