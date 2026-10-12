#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
OPENLIST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
SHARED_ROOT="$OPENLIST_ROOT/../../shared/encryptcore"
MEGA_ROOT="$OPENLIST_ROOT/../../shared/go-mega"
if [ ! -f "$MEGA_ROOT/go.mod" ] || ! awk '$1 == "module" && $2 == "github.com/t3rm1n4l/go-mega" { found = 1 } END { exit !found }' "$MEGA_ROOT/go.mod"; then
    echo "Missing reviewed fixed MEGA module or unexpected identity" >&2
    exit 1
fi
SUM_SEED="$SCRIPT_DIR/module_overlay.sum"

if [ ! -f "$SHARED_ROOT/go.mod" ] || [ ! -f "$SUM_SEED" ]; then
    echo "Missing shared module or reviewed checksum seed" >&2
    exit 1
fi
if ! awk '$1 == "module" && $2 == "github.com/alist-encrypt-go/shared/encryptcore" { found = 1 } END { exit !found }' "$SHARED_ROOT/go.mod"; then
    echo "Unexpected shared module identity" >&2
    exit 1
fi

SUM_TEMP=""
trap '[ -z "$SUM_TEMP" ] || rm -f -- "$SUM_TEMP"' EXIT

apply_overlay() {
    local module_dir="$1" relative="$2"
    if [ ! -f "$module_dir/go.mod" ] || [ ! -f "$module_dir/go.sum" ]; then
        echo "Missing OpenList module files: $module_dir" >&2
        exit 1
    fi
    if ! awk '$1 == "module" && $2 == "github.com/OpenListTeam/OpenList/v4" { found = 1 } END { exit !found }' "$module_dir/go.mod"; then
        echo "Unexpected OpenList module identity: $module_dir" >&2
        exit 1
    fi

    # Merge only reviewed checksums; never replace upstream's dependency sums.
    # Reject conflicting hashes before changing this module's files.
    SUM_TEMP="$(mktemp "$module_dir/.module-overlay-sum.XXXXXX")"
    awk '
        NF != 3 { print "Invalid checksum line: " $0 > "/dev/stderr"; exit 1 }
        {
            key = $1 " " $2
            if (key in hashes && hashes[key] != $3) {
                print "Conflicting checksum: " key > "/dev/stderr"
                exit 1
            }
            hashes[key] = $3
            if (!seen[key]++) print
        }
    ' "$module_dir/go.sum" "$SUM_SEED" > "$SUM_TEMP"
    LC_ALL=C sort -o "$SUM_TEMP" "$SUM_TEMP"

    # Editing declarations does not resolve/download the module graph. Keep the
    # upstream module identity, dependencies and compatibility replacements.
    GOWORK=off go -C "$module_dir" mod edit \
        -go=1.25.0 \
        -toolchain=go1.26.5 \
        -require=github.com/alist-encrypt-go/shared/encryptcore@v0.0.0 \
        -require=golang.org/x/crypto@v0.51.0 \
        -require=golang.org/x/sync@v0.20.0 \
        -require=golang.org/x/sys@v0.45.0 \
        -require=golang.org/x/mobile@v0.0.0-20250606033058-a2a15c67f36f \
        -require=golang.org/x/net@v0.53.0 \
        -require=golang.org/x/mod@v0.35.0 \
        -require=golang.org/x/term@v0.43.0 \
        -require=golang.org/x/text@v0.37.0 \
        -require=golang.org/x/tools@v0.44.0 \
        -replace="github.com/alist-encrypt-go/shared/encryptcore=$relative" \
        -replace="github.com/t3rm1n4l/go-mega=${relative%/encryptcore}/go-mega"
    # Preserve the destination permissions and avoid replacing identical files.
    if ! cmp -s "$SUM_TEMP" "$module_dir/go.sum"; then
        cp "$SUM_TEMP" "$module_dir/go.sum"
    fi
    rm -f -- "$SUM_TEMP"
    SUM_TEMP=""
}

# init_openlist must copy the unmodified upstream module first. These paths are
# relative to each module, not this script; copying the overlaid src/go.mod to
# the build root would give the build root the wrong replacement depth.
apply_overlay "$OPENLIST_ROOT" ../../shared/encryptcore
apply_overlay "$OPENLIST_ROOT/src" ../../../shared/encryptcore
