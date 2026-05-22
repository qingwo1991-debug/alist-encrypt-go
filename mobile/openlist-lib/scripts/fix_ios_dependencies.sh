#!/bin/bash

echo "Fixing iOS incompatible dependencies by patching rclone source..."

# Find the module root
if [ -f go.mod ]; then
    MODULE_ROOT="."
elif [ -f ../go.mod ]; then
    MODULE_ROOT=".."
    cd ..
else
    echo "Error: Cannot find go.mod"
    exit 1
fi

echo "Working in module root: $(pwd)"

# Check for rclone dependency
echo "Checking for rclone dependency..."
RCLONE_VERSION=$(go list -m all | grep "github.com/rclone/rclone" | awk '{print $2}' || echo "")

if [ -z "$RCLONE_VERSION" ]; then
    echo "No rclone dependency found, skipping patch"
    exit 0
fi

echo "Found rclone version: $RCLONE_VERSION"

# Function to create minimal local rclone (backup method)
create_minimal_rclone() {
    echo "Using backup method: creating minimal local rclone module..."
    
    LOCAL_RCLONE_DIR="./local_rclone"
    rm -rf "$LOCAL_RCLONE_DIR" 2>/dev/null || true
    
    # Create the directory structure
    mkdir -p "$LOCAL_RCLONE_DIR/lib/buildinfo"
    
    # Create a minimal go.mod for the local rclone
    cat > "$LOCAL_RCLONE_DIR/go.mod" << 'GOMOD_EOF'
module github.com/rclone/rclone

go 1.19
GOMOD_EOF
    
    # Create the patched osversion.go file
    cat > "$LOCAL_RCLONE_DIR/lib/buildinfo/osversion.go" << 'OSVERSION_EOF'
//go:build !windows

package buildinfo

// GetOSVersion returns OS version, kernel and bitness
func GetOSVersion() (osVersion, osKernel string) {
	return
}
OSVERSION_EOF
    
    # Add replace directive to use local copy
    echo "Adding replace directive to use local rclone copy..."
    go mod edit -replace github.com/rclone/rclone="./local_rclone"
    
    return 0
}

# Try primary method first
echo "Attempting primary method: patching existing rclone..."

# Download dependencies to get the source
echo "Downloading dependencies..."
go mod download

# Find the rclone module path
RCLONE_PATH=$(go list -m -f '{{.Dir}}' github.com/rclone/rclone 2>/dev/null)

if [ -z "$RCLONE_PATH" ]; then
    echo "Could not find rclone module path, trying alternative method..."
    # Try to find it in GOPATH/pkg/mod
    GOPATH_MOD=$(go env GOPATH)/pkg/mod
    RCLONE_PATH=$(find "$GOPATH_MOD" -name "rclone@$RCLONE_VERSION" -type d 2>/dev/null | head -1)
fi

if [ -z "$RCLONE_PATH" ]; then
    echo "Could not locate rclone source directory, using backup method..."
    create_minimal_rclone
else
    echo "Found rclone source at: $RCLONE_PATH"
    
    # Path to the problematic file
    OSVERSION_FILE="$RCLONE_PATH/lib/buildinfo/osversion.go"
    
    if [ ! -f "$OSVERSION_FILE" ]; then
        echo "osversion.go file not found, using backup method..."
        create_minimal_rclone
    else
        echo "Found osversion.go at: $OSVERSION_FILE"
        
        # Try to patch the existing file
        LOCAL_RCLONE_DIR="./local_rclone"
        rm -rf "$LOCAL_RCLONE_DIR" 2>/dev/null || true
        mkdir -p "$LOCAL_RCLONE_DIR"
        
        echo "Copying rclone source to local directory..."
        if cp -r "$RCLONE_PATH"/* "$LOCAL_RCLONE_DIR/" 2>/dev/null; then
            # Fix permissions on the copied files
            echo "Fixing permissions on copied files..."
            find "$LOCAL_RCLONE_DIR" -type f -exec chmod u+w {} \; 2>/dev/null || true
            find "$LOCAL_RCLONE_DIR" -type d -exec chmod u+w {} \; 2>/dev/null || true
            
            # Update the file path to local copy
            OSVERSION_FILE="$LOCAL_RCLONE_DIR/lib/buildinfo/osversion.go"
            
            # Try to patch the file
            if [ -f "$OSVERSION_FILE" ] && [ -w "$OSVERSION_FILE" ]; then
                echo "Patching osversion.go for iOS compatibility..."
                
                # Create the patch content
                cat > "$OSVERSION_FILE" << 'PATCH_EOF'
//go:build !windows

package buildinfo

// GetOSVersion returns OS version, kernel and bitness
func GetOSVersion() (osVersion, osKernel string) {
	return
}
PATCH_EOF
                
                # Add replace directive to use local copy
                echo "Adding replace directive to use local rclone copy..."
                go mod edit -replace github.com/rclone/rclone="./local_rclone"
            else
                echo "Cannot write to copied file, using backup method..."
                create_minimal_rclone
            fi
        else
            echo "Failed to copy rclone source, using backup method..."
            create_minimal_rclone
        fi
    fi
fi

# Verify the patch
echo "Verifying patch..."
FINAL_OSVERSION_FILE="./local_rclone/lib/buildinfo/osversion.go"

if [ -f "$FINAL_OSVERSION_FILE" ]; then
    echo "✅ Patched osversion.go found"
    echo "Content:"
    cat "$FINAL_OSVERSION_FILE"
    echo ""
    
    # Check if the patch was applied correctly
    if grep -q "host.PlatformInformation\|host.KernelVersion\|host.KernelArch" "$FINAL_OSVERSION_FILE"; then
        echo "❌ WARNING: File still contains problematic host function calls!"
        echo "Patch may not have been applied correctly."
        exit 1
    else
        echo "✅ Patch applied successfully - no problematic host function calls found"
    fi
else
    echo "❌ Failed to create patched osversion.go"
    exit 1
fi

# Clean and rebuild to apply changes
echo "Cleaning and rebuilding module with patched rclone..."
go mod tidy
go mod download

echo "✅ iOS dependency fix completed by patching rclone source"
echo "The problematic gopsutil calls in rclone have been disabled for iOS builds"