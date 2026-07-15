# DCO attestations

This register records exceptional Developer Certificate of Origin 1.1
attestations for immutable published commits whose contribution was certified
before merge but whose squash transport made the Git trailer unparsable.

An entry does not waive DCO. It preserves the author's certification in the
repository and links to the matching public attestation. New merges must use a
parseable `Signed-off-by` trailer and pass `cargo xtask dco HEAD^ HEAD`.

## 2026-07-15 — PR #20

- Merge commit: `8555b6ba4b1568e1c3d701ff34a5ee4d1bf29ad3`
- Pull request: [#20](https://github.com/matteoscurati/tersa.app/pull/20)
- Certified author: `Matteo Scurati <matteo.scurati@gmail.com>`
- Exact reviewed head: `6b9d649e345d620cb560a1900163afc89cc3e278`
- Reason: the squash command stored literal backslash-n sequences (`\n\n`)
  before the sign-off, so Git could not parse the otherwise present
  certification.
- Public attestation:
  [PR #20 comment](https://github.com/matteoscurati/tersa.app/pull/20#issuecomment-4983823330)

Signed-off-by: Matteo Scurati <matteo.scurati@gmail.com>
