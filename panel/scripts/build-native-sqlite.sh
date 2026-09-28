#!/usr/bin/env bash
# Rebuild better-sqlite3 for Debian 11's glibc when the npm package bundles a
# binary built against a newer glibc. Called after npm install by install.sh and
# update.sh; harmless on all other systems.
set -euo pipefail

readonly BUILD_MARKER="/var/lib/rixxx-panel/debian11-build-native-from-source"
readonly SQLITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../node_modules/better-sqlite3" 2>/dev/null && pwd || true)"
readonly PREBUILT="${SQLITE_DIR}/prebuilds/linux-x64.node"

[[ -f "$BUILD_MARKER" ]] || exit 0
[[ -d "$SQLITE_DIR" ]] || {
  echo "[native-sqlite] better-sqlite3 is not installed; skipping rebuild" >&2
  exit 0
}
[[ -f "$PREBUILT" ]] || exit 0

echo "[native-sqlite] Rebuilding better-sqlite3 against Debian 11's glibc"
(cd "$SQLITE_DIR" && npm run build-release --silent)
rm -f "$PREBUILT"
echo "[native-sqlite] Using the locally compiled better-sqlite3 binary"
