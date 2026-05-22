#!/usr/bin/env bash
# Simple helper to run the PROPFIND processor unit test
set -e

# From repo root, run:
#   bash test/run_webdav_tests.sh

go test ./openlist-lib/openlistlib/encrypt -run TestProcessPropfindResponse -v
