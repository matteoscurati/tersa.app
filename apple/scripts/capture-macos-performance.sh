#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Step-4 unsigned macOS pre-measurement harness. It uses only synthetic mailbox
# rows, emits aggregate metrics, and never reads the product Keychain or Gmail
# cache. Its output cannot pass a gate or substitute for Developer-ID evidence.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/tersa-performance.XXXXXX")"
DERIVED="$SCRATCH/DerivedData"
APP="$DERIVED/Build/Products/Release/Tersa.app"
DMG="$SCRATCH/Tersa.dmg"
DMG_ROOT="$SCRATCH/dmg-root"
trap 'rm -rf "$SCRATCH"' EXIT HUP INT TERM

cd "$ROOT"

[ -z "$(git status --porcelain --untracked-files=all)" ] || {
  printf 'error: commit-bound capture requires a clean worktree\n' >&2
  exit 1
}

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/test_macos_performance_report.py >/dev/null

cargo test --locked --release -p tersa-store-sqlcipher-macos \
  performance_harness_sample --no-run --message-format=json \
  >"$SCRATCH/cargo-messages.json"
TEST_EXECUTABLE="$(python3 - "$SCRATCH/cargo-messages.json" <<'PY'
import json
from pathlib import Path
import sys

executables = []
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    message = json.loads(line)
    target = message.get("target", {})
    executable = message.get("executable")
    if executable and target.get("name") == "tersa_store_sqlcipher_macos" and "lib" in target.get("kind", []):
        executables.append(executable)
if len(executables) != 1:
    raise SystemExit("expected exactly one SQLCipher store test executable")
print(executables[0])
PY
)"

sh apple/scripts/generate-project.sh >/dev/null
xcodebuild -project apple/Tersa.xcodeproj -scheme TersaMac -configuration Release \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO \
  TERSA_OAUTH_CLIENT_ID=public-performance-harness.apps.googleusercontent.com \
  TERSA_OAUTH_REDIRECT_SCHEME=app.tersa.oauth.performance-harness \
  build >/dev/null

mkdir -p "$DMG_ROOT"
ditto "$APP" "$DMG_ROOT/Tersa.app"
hdiutil create -quiet -fs HFS+ -format UDZO -srcfolder "$DMG_ROOT" -volname Tersa "$DMG"

python3 scripts/macos-performance-report.py capture \
  --executable "$TEST_EXECUTABLE" \
  --app "$APP" \
  --dmg "$DMG" \
  --commit "$(git rev-parse HEAD)"
