#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -eu

if [ "$#" -ne 0 ]; then
  echo 'Usage: sh apple/scripts/generate-project.sh' >&2
  exit 2
fi

workspace_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$workspace_dir"

command -v xcodegen >/dev/null 2>&1 || {
  echo 'xcodegen is required.' >&2
  exit 2
}

exec xcodegen generate --no-env --spec apple/project.yml --project apple
