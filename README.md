# tersa.app

tersa.app is a privacy-first, open-source Gmail client for iOS and macOS.

The project is currently in **M0 feasibility work**. It is not yet usable as an
email client and has no published application builds.

The repository currently contains the shared-core workspace and governance
foundation. Product behavior is added only after its feasibility gate passes.

## Product boundaries

- iOS 18 or later and macOS 15 or later on Apple Silicon
- a shared Rust core with minimal Apple platform adapters
- Gmail through the official Gmail API
- encrypted local persistence and no project-operated backend
- honest platform limits: no reliable background push on iOS and no guaranteed
  send-later scheduling while a device is unavailable

## Project status

M0 validates the UI stack, Apple distribution, OAuth, encrypted storage,
search, MIME handling, security policy, and Google API compliance before
production feature development begins. See the [roadmap](docs/roadmap.md) for
the milestone sequence and MVP exclusions.

The accepted [product constraints](docs/architecture/adr-0006-product-constraints.md)
and authoritative [M0 gate register](docs/m0/gate-register.json) define what
counts as current evidence. See the [threat model](docs/security/threat-model.md)
and [security data flow](docs/security/data-flow.md) for the current security
boundaries.

## Development

The workspace pins Rust 1.91.1. Run its baseline verification suite with:

```sh
cargo xtask verify
```

See [Development](docs/development.md) and
[Dependency rules](docs/architecture/dependency-rules.md) for the contributor
workflow.

## Contributing and security

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
- Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).
- Repository artifacts follow the [English language policy](docs/governance/language-policy.md).
- Source code is licensed under the [Mozilla Public License 2.0](LICENSE).

<a href="https://slint.dev"><img src="docs/assets/made-with-slint.svg" alt="Made with Slint" width="120"></a>
