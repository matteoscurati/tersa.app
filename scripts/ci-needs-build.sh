#!/bin/sh
# Prints "true" when the commit range BASE..HEAD touches anything other than
# documentation, so CI must build and test; prints "false" otherwise.
# An unknown or all-zero base (a new branch) always builds.
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

# Paths that cannot affect the build, the tests, or the dependency checks.
docs_only='^(docs/.*|[^/]*\.md|LICENSE|licenses/.*|_typos\.toml|\.github/(ISSUE_TEMPLATE/.*|pull_request_template\.md|CODEOWNERS))$'

if git diff --name-only "$base" "$head" | grep -Eqv "$docs_only"; then
  echo true
else
  echo false
fi
