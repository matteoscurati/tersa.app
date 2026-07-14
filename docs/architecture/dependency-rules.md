# Dependency rules

tersa.app uses inward-facing dependency boundaries so the shared core remains
independent of Apple frameworks, UI toolkits, storage engines, and transports.

The initial workspace has four architectural layers:

| Crate | Responsibility | Allowed workspace dependencies |
|---|---|---|
| `tersa-domain` | Domain types and invariants | None |
| `tersa-application` | Commands, queries, and use cases | `tersa-domain` |
| `tersa-platform` | Operating-system capability ports | `tersa-domain` |
| `tersa-presentation` | UI-neutral view models | All three inward layers |

Executable adapters may depend on these layers, but the layers must never
depend on an executable, Apple API, or UI framework. New workspace crates must
be added explicitly to the policy in `xtask`; an unknown crate fails CI.

Run the boundary check with:

```sh
cargo xtask architecture
```
