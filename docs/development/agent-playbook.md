# Agent playbook

This playbook is the machine-oriented operating map for coding agents working
in this repository. Humans may use it; the primary consumer is an implementer
agent that must classify a change, touch only the owned surface, and run a
**scoped** verify loop before escalating to full gates.

It does **not** weaken product constraints: no required proprietary backend,
encrypted local store, closed bridge ABI, token process isolation, macOS
acceptance bar, and **no production demo-data or fixture injection**
([ADR-0021](../architecture/adr-0021-macos-ui-vertical-slice.md)).

Full merge quality remains:

```sh
cargo xtask verify
```

plus path-scoped Apple product CI when the change classifier enables
`product_apple`. Day-to-day agent iterations use the minimum loop for the
change class, not the full suite after every edit.

## Change classes

One task maps to **one** class unless the lead explicitly splits work. Unknown
crates or paths: treat as full fanout and ask the lead.

| Class | Allowed paths (typical) | Forbidden without explicit task | Min verify loop | Escalate when |
|-------|-------------------------|----------------------------------|-----------------|---------------|
| `domain` | `crates/domain/**` | adapters, `apple/**`, `xtask/**` | `cargo xtask preflight domain` (or `cargo test -p tersa-domain`) | policy/deps change |
| `application` | `crates/application/**` (and `domain` only if required) | Swift UI, FFI ABI surface | `cargo xtask preflight application` | port shape or store contract change |
| `presentation` | `crates/presentation/**` | store, keychain, gmail adapters | `cargo xtask preflight presentation` | bridge consumer / DTO wire change |
| `adapter-rust` | exactly one of `adapters/<name>/**` | other adapters unless task says so | `cargo xtask preflight adapter --package <crate>` | `Cargo.toml` / `deny.toml` |
| `bridge-ffi` | `apple/rust-bridge/**`, related headers, at most one related FFI crate | broad Swift UI rewrite | `cargo xtask preflight bridge` | exported C ABI / allowlist change |
| `swift-ui` | `apple/macos/**`, `apple/macos-tests/**` as needed | Rust core, adapters, `xtask/**` | unsigned `xcodebuild` `TersaMac` test (see below) | any bridge/header or `project.yml` inventory change |
| `token-broker` | broker crates + `apple/macos-token-broker/**` + main-app broker client mapping | mailbox-sync FFI production surface | `cargo xtask preflight token-broker` | protocol or status set change |
| `policy-xtask` | `xtask/**`, maybe `deny.toml` / CI scripts | product features in the same PR | `cargo xtask architecture` then full `verify` | always high scrutiny |
| `docs-only` | `docs/**`, root `*.md` (non-code) | code | none / CI classifier only | n/a |

### Package names (workspace)

Use exact Cargo package names with `*-pkg` / `preflight adapter --package`:

- `tersa-domain`, `tersa-application`, `tersa-presentation`, `tersa-platform`
- `tersa-gmail-rest-macos`, `tersa-keychain-macos`, `tersa-store-sqlcipher-macos`
- `tersa-oauth-sync-macos`, `tersa-mailbox-sync-ffi-macos`
- `tersa-token-broker-core`, `tersa-token-broker-ffi-macos`
- `tersa-apple-bridge`, `tersa-cli-macos`, `xtask`

## Default agent loop

1. **Classify** the change (exactly one class from the table).
2. **List owned files**; refuse multi-class work without a lead split.
3. **Read** only the 1–2 ADRs linked for that class (below), not the full ADR set.
4. **Implement** within owned paths.
5. **Run** the min verify loop for the class.
6. **Run** `cargo xtask architecture` if any workspace edge, bridge export,
   Apple source inventory, or entitlement/project shape might change.
7. **Run** full `cargo xtask verify` only before ready-for-review / integration,
   not after every file edit.
8. **Run** Apple product `xcodebuild` only for `swift-ui`, `bridge-ffi`,
   `token-broker`, or when the change-scope classifier enables `product_apple`.

### Before ready-for-review

```sh
git diff --name-only main...HEAD | python3 scripts/ci-change-scope.py --agent
cargo xtask verify   # always for code PRs
```

If the classifier reports `product_apple=true`, budget for the macOS product
and quality lanes.

## ADR pointers by class

| Class | Start here |
|-------|------------|
| `domain` / `application` / `presentation` | [ADR-0015](../architecture/adr-0015-mailbox-contract-seam.md), [ADR-0021](../architecture/adr-0021-macos-ui-vertical-slice.md) |
| `adapter-rust` (Gmail) | [ADR-0016](../architecture/adr-0016-gmail-rest-adapter.md) |
| `adapter-rust` (store) | [ADR-0017](../architecture/adr-0017-production-macos-account-store.md), [ADR-0011](../architecture/adr-0011-sqlcipher-schema-and-migration-ownership.md) |
| `bridge-ffi` / `swift-ui` | [ADR-0020](../architecture/adr-0020-macos-production-ui-toolkit.md), [ADR-0021](../architecture/adr-0021-macos-ui-vertical-slice.md) |
| `token-broker` | [ADR-0024](../architecture/adr-0024-macos-token-process-isolation.md), [ADR-0023](../architecture/adr-0023-step3-oauth-and-bounded-sync.md) |
| `policy-xtask` | [dependency-rules](../architecture/dependency-rules.md), [ADR-0014](../architecture/adr-0014-macos-production-dependency-boundaries.md) |

## Scoped commands

Package and class lanes (see `cargo xtask help`):

```sh
cargo xtask check-pkg <package>
cargo xtask test-pkg <package>
cargo xtask clippy-pkg <package>
cargo xtask preflight <class> [--package <crate>]
```

`preflight` classes match the table above (`adapter` / `adapter-rust` require
`--package`). `preflight swift-ui` prints the unsigned `xcodebuild` lines and
does not invoke Xcode (Linux-safe). Full `cargo xtask verify` and
`cargo xtask architecture` remain the merge gates.

### Unsigned macOS UI tests (`swift-ui`)

```sh
sh apple/scripts/generate-project.sh   # only if project.yml or XcodeGen inputs changed
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac \
  -configuration Debug -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath apple/build/DerivedData CODE_SIGNING_ALLOWED=NO test
```

Do not treat unsigned or Apple Development captures as
`P1-MACOS-001`/`002`/`003` evidence.

## Anti-patterns

- Do **not** run full `verify` after every file save.
- Do **not** touch `xtask` to “make the feature pass” unless the task is policy.
- Do **not** inject production demo fixtures or mailbox rows into shipped paths
  ([ADR-0021](../architecture/adr-0021-macos-ui-vertical-slice.md)).
- Do **not** expand the C ABI without a dedicated bridge task and allowlist plan.
- Do **not** mix Swift layout polish with Rust sync or store logic in one PR.
- Do **not** expand the change class mid-task without lead re-plan.

## Implementer return format

Every implementer result should include:

1. **Change class**
2. **Files touched** (paths only)
3. **Commands run** (exact)
4. **Residual risks** (ABI, a11y, signing, open evidence)
5. **What was not done** (explicit non-claims)

## Indicative timings (not a gate)

Recorded after package preflight tooling lands; replace with measured values on
a warm incremental tree:

| Loop | Indicative |
|------|------------|
| `preflight domain` | tens of seconds |
| `preflight application` | tens of seconds to low minutes |
| full `verify` | many minutes |
| unsigned `TersaMac` test (staticlib warm) | low minutes |

No CI assertion on wall-clock.
