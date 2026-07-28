#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENLIST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
cd "$OPENLIST_ROOT"

echo "Installing gomobile and dependencies..."

MOBILE_VERSION="$(go list -mod=readonly -m -f '{{.Version}}' golang.org/x/mobile)"
if [ -z "$MOBILE_VERSION" ] || [ "$MOBILE_VERSION" = "<no value>" ]; then
    echo "Failed to resolve golang.org/x/mobile version from go.mod"
    exit 1
fi

GO_BIN_DIR="$(go env GOBIN)"
if [ -z "$GO_BIN_DIR" ]; then
    GO_BIN_DIR="$(go env GOPATH)/bin"
fi
export PATH="$GO_BIN_DIR:$PATH"

# Install gomobile command
echo "Installing gomobile command..."
go install "golang.org/x/mobile/cmd/gomobile@${MOBILE_VERSION}" || {
    echo "Failed to install gomobile"
    exit 1
}

# Install gobind command (needed for iOS)
echo "Installing gobind command..."
go install "golang.org/x/mobile/cmd/gobind@${MOBILE_VERSION}" || {
    echo "Failed to install gobind"
    exit 1
}

# Initialize gomobile
echo "Initializing gomobile..."
gomobile init || {
    echo "Failed to initialize gomobile"
    exit 1
}

echo "Gomobile initialization completed successfully"

# Verify installation
echo "Verifying installation..."
echo "gomobile version: $(gomobile version 2>/dev/null || echo 'version command failed')"
echo "gobind available: $(command -v gobind >/dev/null && echo 'yes' || echo 'no')"
