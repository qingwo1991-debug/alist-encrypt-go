#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_INPUT="${OPENLIST_LIB_ROOT:-$SCRIPT_DIR/..}"

if [ ! -d "$ROOT_INPUT" ]; then
    echo "OpenList library root does not exist: $ROOT_INPUT" >&2
    exit 1
fi

OPENLIST_ROOT="$(cd "$ROOT_INPUT" && pwd -P)"
if [ "$OPENLIST_ROOT" = "/" ]; then
    echo "Refusing to clean the filesystem root" >&2
    exit 1
fi

# Only directories produced by the local build/bootstrap scripts belong here.
# OPENLIST_LIB_ROOT allows this whitelist to be exercised safely in a temp tree.
GENERATED_DIRS=(
    ".codex-backup"
    "openlistlib_custom"
    "output"
    "dist"
    "build"
    "tmp"
    "scripts/dist"
)

for relative_path in "${GENERATED_DIRS[@]}"; do
    target="$OPENLIST_ROOT/$relative_path"
    if [ -d "$target" ] || [ -L "$target" ]; then
        echo "Removing generated directory: $target"
        rm -rf -- "$target"
    fi
done
