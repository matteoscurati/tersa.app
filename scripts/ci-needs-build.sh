#!/bin/sh
# Prints "true" when the commit range BASE..HEAD touches anything other than
# documentation, so CI must build and test; prints "false" otherwise.
# An unknown or all-zero base (a new branch) always builds. Any failure exits
# non-zero, and the workflow fails on any output other than "true" or "false".
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

# grep exits 0 when some path is not documentation, 1 when none is, and
# above 1 on an error, which must not read as "documentation only".
set +e
printf '%s\n' "$files" | grep -Eqv "$docs_only"
status=$?
set -e
case $status in
  0) echo true ;;
  1) echo false ;;
  *) exit "$status" ;;
esac
