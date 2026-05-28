#!/bin/bash

set -euo pipefail

# Build version information
builtAt="${OPENLIST_BUILT_AT:-$(date +'%F %T %z')}"
gitAuthor="${OPENLIST_GIT_AUTHOR:-The OpenList Projects Contributors <noreply@openlist.team>}"
gitCommit="${OPENLIST_GIT_COMMIT:-$(git log --pretty=format:'%h' -1 2>/dev/null || echo 'unknown')}"
version="${OPENLIST_VERSION:-dev}"
webVersion="${OPENLIST_WEB_VERSION:-rolling}"

echo "Building with version info:"
echo "  Version: $version"
echo "  WebVersion: $webVersion"
echo "  GitCommit: $gitCommit"
echo "  BuiltAt: $builtAt"

# Construct ldflags
ldflags="-s -w"
ldflags="$ldflags -X 'github.com/OpenListTeam/OpenList/v4/internal/conf.BuiltAt=$builtAt'"
ldflags="$ldflags -X 'github.com/OpenListTeam/OpenList/v4/internal/conf.GitAuthor=$gitAuthor'"
ldflags="$ldflags -X 'github.com/OpenListTeam/OpenList/v4/internal/conf.GitCommit=$gitCommit'"
ldflags="$ldflags -X 'github.com/OpenListTeam/OpenList/v4/internal/conf.Version=$version'"
ldflags="$ldflags -X 'github.com/OpenListTeam/OpenList/v4/internal/conf.WebVersion=$webVersion'"

# First check if we're in the right place
echo "Starting Android build from: $(pwd)"

# For Android, we need to find the bindable package directory, not just go.mod
# The original approach was correct - look for openlistlib directory
if [ -d ../openlistlib ]; then
    echo "Found openlistlib directory, using that for Android build"
    cd ../openlistlib || exit
else
    echo "Searching for bindable package directory..."
    cd ../ || exit
    
    # Look for directories that might contain bindable packages
    if [ -d openlistlib ]; then
        echo "Found openlistlib in current directory"
        cd openlistlib || exit
    elif [ -d cmd/openlistlib ]; then
        echo "Found openlistlib in cmd directory"
        cd cmd/openlistlib || exit
    else
        echo "Error: Cannot find openlistlib directory for Android binding"
        echo "Current directory: $(pwd)"
        echo "Directory contents:"
        ls -la
        echo "Looking for Go files that might be bindable..."
        find . -name "*.go" -type f | head -10
        exit 1
    fi
fi

echo "Current directory: $(pwd)"
echo "Building OpenList for Android..."

# Check if this directory has Go files suitable for binding
if ! ls *.go >/dev/null 2>&1; then
    echo "Warning: No Go files found in current directory"
    echo "Directory contents:"
    ls -la
fi

build_mode="${1:-release}"
target_abi="${2:-all}"

gomobile_target=""
artifact_suffix=""
case "$target_abi" in
  arm64-v8a|android/arm64)
    gomobile_target="android/arm64"
    artifact_suffix="arm64-v8a"
    ;;
  armeabi-v7a|android/arm)
    gomobile_target="android/arm"
    artifact_suffix="armeabi-v7a"
    ;;
  x86_64|android/amd64)
    gomobile_target="android/amd64"
    artifact_suffix="x86_64"
    ;;
  all|"")
    gomobile_target=""
    artifact_suffix="all"
    ;;
  *)
    echo "Unsupported ABI target: $target_abi"
    exit 1
    ;;
esac

bind_args=(-ldflags "$ldflags" -v -androidapi 21)
if [ "$build_mode" == "debug" ] && [ -z "$gomobile_target" ]; then
  gomobile_target="android/arm64"
  artifact_suffix="arm64-v8a"
fi

if [ -n "$gomobile_target" ]; then
  bind_args+=(-target="$gomobile_target")
fi

gomobile bind "${bind_args[@]}"

echo "Moving aar and jar files to android/app/libs"
mkdir -p ../../android/app/libs
rm -f ../../android/app/libs/*.aar ../../android/app/libs/*.jar
for aar in ./*.aar; do
  [ -e "$aar" ] || continue
  mv -f "$aar" "../../android/app/libs/openlistlib-${artifact_suffix}.aar"
done
for jar in ./*.jar; do
  [ -e "$jar" ] || continue
  mv -f "$jar" "../../android/app/libs/openlistlib-${artifact_suffix}.jar"
done
