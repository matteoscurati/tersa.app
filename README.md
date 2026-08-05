# tersa.app

tersa.app is a privacy-first, open-source Gmail client for iOS and macOS.

The project is currently in early product development on the macOS-first path.
It is not yet usable as a complete email client and has no published application
builds.

The repository contains the shared Rust core, Apple bridge, and product
surfaces. The M0 diagnostic program is retired; a short
[historical summary](docs/history/m0-summary.md) and preserved ADRs record what
it learned.

## Product boundaries

- iOS 18 or later and macOS 15 or later on Apple Silicon
- a shared Rust core with minimal Apple platform adapters
- Gmail through the official Gmail API
- encrypted local persistence and no project-operated backend
- honest platform limits: no reliable background push on iOS and no guaranteed
  send-later scheduling while a device is unavailable

## Project status

See the [roadmap](docs/roadmap.md) for the milestone sequence and MVP
exclusions. The accepted
[product constraints](docs/architecture/adr-0006-product-constraints.md) remain
in force. See the [threat model](docs/security/threat-model.md) and
[security data flow](docs/security/data-flow.md) for the current security
boundaries. Physical-device and signed-distribution closure follows the
[Apple physical-device and distribution protocol](docs/release/apple-distribution.md).
macOS UI and release acceptance are defined by the
[macOS acceptance protocol](docs/quality/macos-acceptance.md) and the
[macOS performance harness](docs/quality/macos-performance.md).

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
