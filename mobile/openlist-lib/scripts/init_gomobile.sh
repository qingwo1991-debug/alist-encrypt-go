#!/bin/bash

echo "Installing gomobile and dependencies..."

# Install gomobile command
echo "Installing gomobile command..."
go install golang.org/x/mobile/cmd/gomobile@latest || {
    echo "Failed to install gomobile"
    exit 1
}

# Install gobind command (needed for iOS)
echo "Installing gobind command..."
go install golang.org/x/mobile/cmd/gobind@latest || {
    echo "Failed to install gobind"
    exit 1
}

# Install bind packages
echo "Installing bind packages..."
go get golang.org/x/mobile/bind@latest || {
    echo "Failed to install golang.org/x/mobile/bind"
    exit 1
}

go get golang.org/x/mobile/bind/objc@latest || {
    echo "Failed to install golang.org/x/mobile/bind/objc"
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