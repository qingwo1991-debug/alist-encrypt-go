#!/bin/bash
#
# install_openlist_web.sh — fetch and install the OpenList file-manager
# frontend into public/dist/ so the embedded OpenList server (5244) serves it
# at the root path instead of falling back to the enc-webui management console.
#
# This aligns the APK with the docker build: root "/" shows the file listing
# (proxied to the embedded OpenList), while the enc-webui management console is
# served separately at /index and /public by the encrypt proxy (5344).
#
# The enc/ subdirectory (enc-webui) is preserved untouched. Run this BEFORE
# install_enc_web.sh so a fresh enc-webui build always wins.
#
# Override defaults with:
#   OPENLIST_WEB_VERSION  — frontend release tag (default: v4.2.4)
#   OPENLIST_WEB_VARIANT  — "lite" or "full" (default: lite)
#   GITHUB_TOKEN          — optional, raises GitHub API rate limit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENLIST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

VERSION="${OPENLIST_WEB_VERSION:-v4.2.4}"
VARIANT="${OPENLIST_WEB_VARIANT:-lite}"
DIST_DIR="$OPENLIST_ROOT/public/dist"

# The lite build omits the admin panel (handled by enc-webui) and is roughly
# half the size of the full build, which is the right trade-off for mobile.
if [ "$VARIANT" = "full" ]; then
    ASSET="openlist-frontend-dist-${VERSION}.tar.gz"
else
    ASSET="openlist-frontend-dist-lite-${VERSION}.tar.gz"
fi

DOWNLOAD_URL="https://github.com/OpenListTeam/OpenList-Frontend/releases/download/${VERSION}/${ASSET}"
PROXY_URL="https://ghproxy.lvedong.eu.org/${DOWNLOAD_URL}"

echo "Installing OpenList frontend (${VARIANT} ${VERSION}) into ${DIST_DIR}"

mkdir -p "$DIST_DIR"

# --- Download ---------------------------------------------------------------
TARBALL="$(mktemp "$DIST_DIR/.openlist-web.XXXXXX.tar.gz")"
cleanup() { rm -f -- "$TARBALL"; }
trap cleanup EXIT

download() {
    local url="$1"
    local label="$2"
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fsSL --max-time 60 -H "Authorization: Bearer $GITHUB_TOKEN" -o "$TARBALL" "$url"
    else
        curl -fsSL --max-time 60 -o "$TARBALL" "$url"
    fi
    echo "Downloaded via ${label}"
}

echo "Trying direct download..."
if download "$DOWNLOAD_URL" "direct" 2>/dev/null; then
    : # success
else
    echo "Direct download failed, trying proxy..."
    download "$PROXY_URL" "proxy"
fi

# --- Extract + install (atomic, preserves enc/) ----------------------------
STAGING="$(mktemp -d "$DIST_DIR/.openlist-web.XXXXXX")"
cleanup_staging() { rm -rf -- "$STAGING" "$TARBALL"; }
trap cleanup_staging EXIT

tar -xzf "$TARBALL" -C "$STAGING"

if [ ! -s "$STAGING/index.html" ]; then
    echo "Refusing to install: extracted frontend has no index.html" >&2
    exit 1
fi

# Remove previous frontend artefacts (but never enc/ or README.md).
for item in index.html assets images static streamer VERSION; do
    rm -rf -- "$DIST_DIR/$item"
done

# Move new frontend files into place.
shopt -s dotglob nullglob
for item in "$STAGING"/*; do
    mv -- "$item" "$DIST_DIR/"
done
shopt -u dotglob nullglob

# Sanity: the installed index.html must not be the dev placeholder, otherwise
# pickEmbeddedDist skips dist/ and falls back to enc-webui at root.
if grep -q "OpenList Encrypt Proxy is running." "$DIST_DIR/index.html" 2>/dev/null; then
    echo "Installed index.html looks like the dev placeholder — aborting" >&2
    exit 1
fi

echo "Installed OpenList frontend ${VERSION} (${VARIANT}) into $DIST_DIR"
echo "Contents:"
ls -1 "$DIST_DIR" | sed 's/^/  /'
