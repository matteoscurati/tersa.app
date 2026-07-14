# Dependency rules

tersa.app uses inward-facing dependency boundaries so the shared core remains
independent of Apple frameworks, UI toolkits, storage engines, and transports.

The initial workspace has four shared architectural layers plus three platform
adapters:

| Crate | Responsibility | Allowed workspace dependencies |
|---|---|---|
| `tersa-domain` | Domain types and invariants | None |
| `tersa-application` | Commands, queries, and use cases | `tersa-domain` |
| `tersa-platform` | Operating-system capability ports | `tersa-domain` |
| `tersa-presentation` | UI-neutral view models | All three inward layers |
| `tersa-apple-bridge` | C ABI and Apple capability adapters | `tersa-application`, `tersa-presentation` |
| `tersa-slint-spike` | Apple-only diagnostic Slint executable | `tersa-presentation` |
| `tersa-dioxus-spike` | Apple-only diagnostic Dioxus executable | `tersa-presentation` |

Executable adapters may depend on these layers, but the layers must never
depend on an executable, Apple API, or UI framework. `tersa-slint-spike` and
`tersa-dioxus-spike` are the only workspace crates allowed to depend on their
respective UI runtimes, and every UI dependency is target-gated to Apple. New
workspace crates must be added explicitly to the policy in `xtask`; an unknown
crate fails CI.

The Apple bridge may call application use cases directly when the operating
system owns the transport. The M0 OAuth adapter uses this edge for the browser
callback while keeping PKCE and callback validation in portable Rust.

Run the boundary check with:

```sh
cargo xtask architecture
```
