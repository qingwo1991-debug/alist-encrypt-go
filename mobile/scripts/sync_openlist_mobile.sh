#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOBILE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
UPSTREAM_DIR="${1:-/root/AI/OpenList-Mobile}"
BACKUP_DIR="$MOBILE_DIR/.codex-backup-openlist-mobile"

if [ ! -d "$UPSTREAM_DIR" ]; then
    echo "Upstream directory not found: $UPSTREAM_DIR" >&2
    exit 1
fi

echo "Syncing OpenList-Mobile app layer from: $UPSTREAM_DIR"
echo "Working in: $MOBILE_DIR"

rm -rf "$BACKUP_DIR"

PRESERVE_FILES=(
    "android/app/src/main/AndroidManifest.xml"
    "lib/main.dart"
    "lib/pages/settings/settings.dart"
    "lib/utils/download_manager.dart"
    "lib/pages/web/web.dart"
)

for rel in "${PRESERVE_FILES[@]}"; do
    if [ -f "$MOBILE_DIR/$rel" ]; then
        mkdir -p "$BACKUP_DIR/$(dirname "$rel")"
        cp "$MOBILE_DIR/$rel" "$BACKUP_DIR/$rel"
    fi
done

SYNC_DIRS=(
    "android"
    "assets"
    "images"
    "lib"
    "pigeons"
    "test"
)

for dir in "${SYNC_DIRS[@]}"; do
    if [ -d "$UPSTREAM_DIR/$dir" ]; then
        rm -rf "$MOBILE_DIR/$dir"
        mkdir -p "$MOBILE_DIR/$dir"
        cp -r "$UPSTREAM_DIR/$dir"/. "$MOBILE_DIR/$dir/"
    fi
done

SYNC_FILES=(
    "pubspec.yaml"
    "analysis_options.yaml"
    "README.md"
    "README_EN.md"
)

for rel in "${SYNC_FILES[@]}"; do
    if [ -f "$UPSTREAM_DIR/$rel" ]; then
        cp "$UPSTREAM_DIR/$rel" "$MOBILE_DIR/$rel"
    fi
done

for rel in "${PRESERVE_FILES[@]}"; do
    if [ -f "$BACKUP_DIR/$rel" ]; then
        mkdir -p "$MOBILE_DIR/$(dirname "$rel")"
        cp "$BACKUP_DIR/$rel" "$MOBILE_DIR/$rel"
        echo "Restored local override: $rel"
    fi
done

rm -rf "$BACKUP_DIR"

echo "OpenList-Mobile sync complete."
