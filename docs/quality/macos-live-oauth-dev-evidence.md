# macOS live OAuth development evidence

## Purpose and status

This is a model-reviewed, **Apple Development** local record for the
token-broker isolation work. The committed evidence is
[`macos-live-oauth-development.json`](evidence/98fdfa455d02c8278b024dead93f34df1df04895/macos-live-oauth-development.json).
It is deliberately non-gate: it does not close ADR-0024 Item 5, Item 6, or
issue #51. Item 5 still needs formal human-reviewed, retained evidence; Item 6
still needs the exact Developer ID signed and notarized candidate.

The file's `evidence_kind` is the discriminator
`macos-live-oauth-development`. Its candidate commit is the historical
live-artifact candidate, not the later commit that stores the redacted record.
The manifest is canonical bytes: sorted JSON keys, two-space indentation,
ASCII escaping, and one trailing newline. `--validate` rejects a full manifest
whose bytes are valid JSON but not that canonical serialization.

The producer/validator was added after the candidate commit. Accordingly, this
committed historical record has `record_provenance` set to later-tooling
canonicalization and `emitted_by_capture_at_candidate: false`: it was
canonicalized and validated by later tooling, not emitted by `--capture` at the
candidate. That provenance is also non-gate.

## What is recomputed and what is operator-attested

The capture never starts OAuth, opens a browser, reads mail, reads credentials,
or prints command output. It resolves the caller-provided absolute observation
path before changing to the repository root, then snapshots that exact input
once into a private directory. The renderer validates and consumes the private
snapshot, not the caller path.

`candidate`, `wrong_group_probes`, bundle digest, binary digests, and signing
tier are locally recomputed from the supplied signed artifact. The artifact is
hashed both before and after the two probe executions, and a mismatch fails
capture. `artifact.toolchain` instead records the capture host's macOS/Xcode
versions at capture time; it equals the build toolchain only when capture runs
on the build host and is not artifact-derived.

`operator_observations` is explicitly marked
`operator-attested-not-locally-recomputable`. It contains browser/console OAuth
outcomes and redacted build provenance. Its `token_path` and
`production_archive_surface` fields are marked `attested_not_proven`: they are
claims about the observed setup, not proof supplied by this manifest.

The requested authorization scope is read at validation and capture time from
`crates/application/src/oauth.rs` `REQUESTED_SCOPE`; the callback scope must be
the same two ordered scope tokens. The manifest's normative `nonclaims` list is
defined by the validator. In particular, it covers testing-token expiry,
durability, cold refresh after process death, legacy-state absence, distribution
and accessibility, and the issue #51 boundary without copying a second
authoritative list here.

## Redaction and output safety

The contract accepts only closed keys and categorical vocabulary. It rejects
duplicate keys, email addresses, absolute filesystem-path tokens, Apple team or
certificate identifiers, and account identifiers. It accepts exactly one build
provenance source label, `apple/local.xcconfig-values-redacted`; no values from
that file are read or emitted.

The tool sets `umask 077`, uses a private `0700` scratch directory, retains
tool/log output only there, and reports fixed failures. The final renderer
creates the requested output once using exclusive `0600` creation; it does not
check-then-install, overwrite, or follow an existing output symlink.

## Validation, digest, and capture

These commands need no provider, account, bundle, or secret:

```sh
sh apple/scripts/capture-macos-live-oauth-dev-evidence.sh --validate \
  docs/quality/evidence/98fdfa455d02c8278b024dead93f34df1df04895/macos-live-oauth-development.json

sh apple/scripts/capture-macos-live-oauth-dev-evidence.sh --canonicalize \
  docs/quality/evidence/98fdfa455d02c8278b024dead93f34df1df04895/macos-live-oauth-development.json
```

`--digest` is read-only and emits fixed compact JSON for the supplied bundle:

```sh
sh apple/scripts/capture-macos-live-oauth-dev-evidence.sh --digest Tersa.app
```

`bundle_regular_file_manifest_sha256` is the SHA-256 of `LC_ALL=C`-ordered
lines formed from each non-symlink regular file inside the bundle:
`<file_sha256><two spaces><bundle-relative regular-file path>\n`. Paths are
UTF-8 byte-sorted, normalized to `/`, and line-breaking paths are rejected.
The same function supplies both `--digest` and capture.

Local capture requires a clean worktree. The manual observation and final output
must each be absolute paths outside the repository; the bundle may be supplied
from its signed artifact location. For example:

```sh
sh apple/scripts/capture-macos-live-oauth-dev-evidence.sh --capture \
  /tmp/tersa-live-oauth-observation.json /tmp/Tersa.app \
  /tmp/tersa-live-oauth-development.json
```

The manual input is limited to this shape. Values shown are categorical examples
from the historical record; no email, token, account identifier, path, or mail
content belongs in it.

```json
{
  "record_type": "macos-live-oauth-development-manual-observation-v2",
  "operator_observations": {
    "attestation": "operator-attested-not-locally-recomputable",
    "build_input_provenance": {
      "source": "apple/local.xcconfig-values-redacted",
      "client_secret_used": true,
      "scheme": "TersaMac",
      "configuration": "Release"
    },
    "token_path": {
      "value": "embedded-xpc-broker",
      "attested_not_proven": true
    },
    "production_archive_surface": {
      "value": true,
      "attested_not_proven": true
    },
    "oauth_lifecycle": {
      "authorization_request_scope": "openid https://www.googleapis.com/auth/gmail.readonly",
      "callback_scopes": [
        "openid",
        "https://www.googleapis.com/auth/gmail.readonly"
      ],
      "consent": {
        "publishing_status": "testing",
        "user_type": "external",
        "test_user": true,
        "gmail_readonly_granular_scope_selected": true
      },
      "exchange": "pass",
      "refresh_token_persistence": {
        "temperature": "warm",
        "outcome": "pass"
      },
      "initial_sync": {
        "outcome": "pass",
        "message_count": 50
      },
      "stored_credential_refresh": {
        "temperature": "warm",
        "outcome": "pass"
      },
      "stored_credential_refresh_after_relaunch": {
        "observed": false,
        "outcome": "not-run"
      },
      "disconnect": {
        "revoke": "pass",
        "token_delete": "pass",
        "local_purge": "pass"
      },
      "linked_app_after_disconnect": false,
      "local_database_after_disconnect": false,
      "relaunch_state": "not-connected"
    }
  }
}
```

Capture verifies both Apple Development signatures, computes the bundle and
binary digests, runs the exact query-only main-app and broker wrong-group probes
with exit `0`, empty stderr, and byte-exact redacted JSON, then passes those
actual observations into the renderer. It does not perform normal token,
network, browser, mailbox, or OAuth work.

## Historical record

The recorded candidate is
`98fdfa455d02c8278b024dead93f34df1df04895` with tree
`bc9060d62e64ad96363b6966ec8827ccb9f87939`. Its recomputed live-artifact
bundle digest is
`52916f779a2633cf5a1e4ea21cd78e852cb690a7fb55b2e4aff11b503163e1ae`;
the main and broker binary digests are recorded in the manifest. The observed
OAuth lifecycle records the read-only request/callback scopes, Testing/External
test-user configuration, exchange and warm refresh persistence, an initial
50-message sync, warm stored-credential refresh, and completed disconnect.

The fixed-placeholder development capture hash
`25ec8ba33e11e11ac9572188dcf14ab908a66bd9de6c9142a6733cc72268e092`
is a different artifact, not `live-artifact`, and is not used for Item 5
co-location or performance evidence.
