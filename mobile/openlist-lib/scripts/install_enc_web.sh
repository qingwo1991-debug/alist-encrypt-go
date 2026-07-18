#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENLIST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
SOURCE_INPUT="${1:-$SCRIPT_DIR/../../enc-webui/dist}"

if [ ! -d "$SOURCE_INPUT" ] || [ ! -f "$SOURCE_INPUT/index.html" ]; then
    echo "Built mobile Web UI is missing or incomplete: $SOURCE_INPUT" >&2
    exit 1
fi

SOURCE_DIR="$(cd "$SOURCE_INPUT" && pwd -P)"
TARGET_PARENT="$OPENLIST_ROOT/public/dist"
TARGET_DIR="$TARGET_PARENT/enc"
mkdir -p "$TARGET_PARENT"

STAGING_DIR="$(mktemp -d "$TARGET_PARENT/.enc-web.XXXXXX")"
BACKUP_DIR="$TARGET_PARENT/.enc-web.previous"
cleanup() {
    rm -rf -- "$STAGING_DIR"
}
trap cleanup EXIT

cp -a "$SOURCE_DIR/." "$STAGING_DIR/"
if [ ! -s "$STAGING_DIR/index.html" ]; then
    echo "Refusing to install a mobile Web UI without a non-empty index.html" >&2
    exit 1
fi

rm -rf -- "$BACKUP_DIR"
if [ -e "$TARGET_DIR" ]; then
    mv -- "$TARGET_DIR" "$BACKUP_DIR"
fi
if ! mv -- "$STAGING_DIR" "$TARGET_DIR"; then
    if [ -e "$BACKUP_DIR" ]; then
        mv -- "$BACKUP_DIR" "$TARGET_DIR"
    fi
    exit 1
fi
rm -rf -- "$BACKUP_DIR"
trap - EXIT

echo "Installed reviewed mobile Web UI into $TARGET_DIR"
