#!/bin/bash

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENLIST_LIB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Working in: $OPENLIST_LIB_DIR"

GIT_REPO="https://github.com/OpenListTeam/OpenList.git"
TAG_NAME=$(git -c 'versionsort.suffix=-' ls-remote --exit-code --refs --sort='version:refname' --tags $GIT_REPO | tail -n 1 | cut -d'/' -f3)

echo "OpenList - ${TAG_NAME}"

cd "$OPENLIST_LIB_DIR"

# Clean up any previous source
rm -rf ./src

unset GIT_WORK_TREE
git clone --branch "$TAG_NAME" https://github.com/OpenListTeam/OpenList.git ./src
rm -rf ./src/.git

echo "Checking cloned source structure:"
ls -la ./src/

# Copy go.mod and go.sum from OpenList source
if [ -f ./src/go.mod ]; then
    cp ./src/go.mod ./go.mod
    cp ./src/go.sum ./go.sum 2>/dev/null || true
    
    # Keep module name as OpenList but add our openlistlib as local package
    # The openlistlib directory already exists in this repo
    go mod edit -replace github.com/djherbis/times@v1.6.0=github.com/jing332/times@latest
    
    # Copy ALL required packages from OpenList source
    echo "Copying required packages from OpenList source..."
    
    # 复制所有必需的目录（包括 public）
    for dir in internal pkg cmd drivers server public; do
        if [ -d "./src/$dir" ]; then
            echo "Copying $dir..."
            mkdir -p "./$dir"
            cp -r "./src/$dir"/* "./$dir/" 2>/dev/null || true
        else
            echo "Warning: $dir not found in source"
        fi
    done
    
    # Copy openlistlib from source if exists, then merge our custom code
    if [ -d ./src/openlistlib ]; then
        echo "Found openlistlib in OpenList source, merging..."
        # Backup our custom openlistlib
        if [ -d ./openlistlib ]; then
            cp -r ./openlistlib ./openlistlib_custom
        fi
        # Copy source openlistlib
        mkdir -p ./openlistlib
        cp -r ./src/openlistlib/* ./openlistlib/ 2>/dev/null || true
        # Restore custom files (our encrypt module, etc.)
        if [ -d ./openlistlib_custom ]; then
            # 复制我们自定义的 encrypt 模块
            if [ -d ./openlistlib_custom/encrypt ]; then
                echo "Restoring custom encrypt module..."
                cp -r ./openlistlib_custom/encrypt ./openlistlib/
            fi
            # 复制我们自定义的 encrypt_server.go
            if [ -f ./openlistlib_custom/encrypt_server.go ]; then
                echo "Restoring custom encrypt_server.go..."
                cp ./openlistlib_custom/encrypt_server.go ./openlistlib/
            fi
            rm -rf ./openlistlib_custom
        fi
    fi
    
    # 显示复制后的目录结构
    echo ""
    echo "Directory structure after copy:"
    ls -la
    
    echo "OpenList source initialization completed"
    echo "go.mod location: $(pwd)/go.mod"
    
    # Show the module name
    echo "Module name:"
    head -1 ./go.mod
    
    # Show openlistlib structure
    echo ""
    echo "openlistlib structure:"
    ls -la ./openlistlib/ 2>/dev/null || echo "openlistlib not found"
else
    echo "Error: go.mod not found in cloned source"
    exit 1
fi

# Download dependencies
echo "Downloading Go dependencies..."
go mod download || true

# Add golang.org/x/mobile dependency for gomobile
echo "Adding gomobile dependencies..."
# 使用 go get 在模块内添加依赖
echo "Getting golang.org/x/mobile/bind..."
go get golang.org/x/mobile/bind@latest
echo "Getting golang.org/x/mobile/cmd/gomobile..."
go get golang.org/x/mobile/cmd/gomobile@latest

echo "Running go mod tidy..."
go mod tidy

echo "Initialization complete!"
echo ""
echo "Directory structure:"
ls -la
