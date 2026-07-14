# Repository language policy

English is the canonical language of the tersa.app repository.

## Required English surfaces

Use English for:

- source code, identifiers, comments, and public API documentation;
- architecture records, security documents, schemas, and migrations;
- tests, fixtures, examples, snapshots, and benchmark descriptions;
- commit messages, pull requests, reviews, issues, and release notes;
- CI names and output, CLI help, errors, logs, and diagnostic reports;
- canonical website, privacy, support, and compliance content.

Do not include real Gmail data or untranslated private content as a fixture.
Synthetic non-English mail content is allowed only when a test explicitly
validates international text handling and documents that purpose in English.

## Localization

English is the source locale for user-facing copy and translation keys. Italian
is introduced during M3 as a complete translation with deterministic fallback
to English. Other translations may follow after the MVP.

Language-policy violations are actionable review findings and block merge.
