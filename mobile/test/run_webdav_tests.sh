#!/usr/bin/env bash
# Simple helper to run the PROPFIND processor unit test
set -euo pipefail

# From the mobile project root, run:
#   bash test/run_webdav_tests.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOBILE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
OPENLIST_ROOT="$MOBILE_ROOT/openlist-lib"
cd "$OPENLIST_ROOT"

go test ./openlistlib/encrypt -run TestProcessPropfindResponse -v
