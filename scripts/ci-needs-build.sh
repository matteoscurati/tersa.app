#!/bin/sh
# Prints "true" when the commit range BASE..HEAD touches anything other than
# documentation, so CI must build and test; prints "false" otherwise.
# An unknown or all-zero base (a new branch) always builds. Any failure exits
# non-zero, and the workflow builds on anything but an explicit "false".
set -eu

base=${1:-}
head=${2:-HEAD}

case "$base" in
  "" | 0000000000000000000000000000000000000000) echo true; exit 0 ;;
esac
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  echo true
  exit 0
fi

# Without --no-renames a rename lists only its new path, so moving a build
# input under docs/ would look documentation-only.
files=$(git diff --no-renames --name-only "$base" "$head")
if [ -z "$files" ]; then
  echo false
  exit 0
fi

# Paths that cannot affect the build, the tests, or the dependency checks.
docs_only='^(docs/.*|[^/]*\.md|LICENSE|licenses/.*|_typos\.toml|\.github/(ISSUE_TEMPLATE/.*|pull_request_template\.md|CODEOWNERS))$'

if printf '%s\n' "$files" | grep -Eqv "$docs_only"; then
  echo true
else
  echo false
fi
