# Security policy

tersa.app handles email and authentication material, so vulnerability reports
must minimize disclosure and avoid real user data.

## Supported versions

The project is in M0 and has no supported public release. After the first
release, this file will list supported versions and security update windows.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting for this repository. Do not open a
public issue, discussion, or pull request for an active vulnerability.

Include only the minimum reproduction details needed. Use synthetic data and
redact paths, account identifiers, email content, OAuth tokens, API keys,
Keychain material, encryption keys, and private diagnostic bundles. Do not send
secrets to maintainers; describe how they can reproduce the issue with their
own test credentials.

The maintainers will acknowledge the report, assess severity, coordinate a fix,
and agree on disclosure timing through the private report. Public disclosure
must wait until affected users have a reasonable remediation path.

## Scope

Reports involving OAuth, local encryption, key handling, MIME or HTML parsing,
attachment processing, Apple platform bridges, supply-chain integrity, or data
isolation are especially valuable. Reports based only on the declared absence
of a backend, reliable iOS push, or guaranteed offline scheduling are product
limitations rather than vulnerabilities.

The current [threat model](docs/security/threat-model.md) and
[security data flow](docs/security/data-flow.md) describe the assets, trust
boundaries, controls, and explicitly unopened future boundaries.
