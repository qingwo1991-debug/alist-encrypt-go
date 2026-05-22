#!/bin/bash

echo "Initializing Web assets for iOS build..."

# Create dist directory
mkdir -p dist

# Use a more reliable approach for iOS with retry mechanism
# First, try to get the latest release info with better error handling
echo "Fetching latest release information..."

# Function to fetch release info with retries and proxy fallback
fetch_release_info() {
    local attempt=1
    local max_attempts=3
    local api_url="https://api.github.com/repos/OpenListTeam/OpenList-Frontend/releases/latest"
    local proxy_url="https://ghproxy.lvedong.eu.org/https://api.github.com/repos/OpenListTeam/OpenList-Frontend/releases/latest"
    
    # First try direct API
    echo "Trying direct GitHub API..."
    while [ $attempt -le $max_attempts ]; do
        echo "Direct API attempt $attempt/$max_attempts..."
        
        RELEASE_INFO=$(curl -fsSL --max-time 10 \
            -H "Accept: application/vnd.github.v3+json" \
            -H "User-Agent: OpenList-iOS-Builder" \
            "$api_url" 2>/dev/null)
        
        local curl_exit_code=$?
        
        if [ $curl_exit_code -eq 0 ] && [ -n "$RELEASE_INFO" ]; then
            echo "Successfully fetched release info via direct API on attempt $attempt"
            return 0
        else
            echo "Direct API attempt $attempt failed (exit code: $curl_exit_code)"
            if [ $attempt -lt $max_attempts ]; then
                echo "Waiting 3 seconds before retry..."
                sleep 3
            fi
        fi
        
        attempt=$((attempt + 1))
    done
    
    echo "Direct API failed after $max_attempts attempts, trying proxy..."
    
    # Try proxy API
    attempt=1
    while [ $attempt -le $max_attempts ]; do
        echo "Proxy API attempt $attempt/$max_attempts..."
        
        RELEASE_INFO=$(curl -fsSL --max-time 15 \
            -H "Accept: application/vnd.github.v3+json" \
            -H "User-Agent: OpenList-iOS-Builder" \
            "$proxy_url" 2>/dev/null)
        
        local curl_exit_code=$?
        
        if [ $curl_exit_code -eq 0 ] && [ -n "$RELEASE_INFO" ]; then
            echo "Successfully fetched release info via proxy on attempt $attempt"
            return 0
        else
            echo "Proxy attempt $attempt failed (exit code: $curl_exit_code)"
            if [ $attempt -lt $max_attempts ]; then
                echo "Waiting 5 seconds before retry..."
                sleep 5
            fi
        fi
        
        attempt=$((attempt + 1))
    done
    
    echo "Failed to fetch release info via both direct API and proxy"
    return 1
}

# Try to fetch release info with retries
if ! fetch_release_info; then
    echo "Cannot proceed without API access"
    exit 1
else
    echo "Successfully fetched release info, parsing download URL..."
    
    # Check if jq is available
    if command -v jq >/dev/null 2>&1; then
        echo "Using jq to parse JSON..."
        DOWNLOAD_URL=$(echo "$RELEASE_INFO" | jq -r '.assets[] | select(.browser_download_url | test("openlist-frontend-dist.*\\.tar\\.gz$") and (test("openlist-frontend-dist-lite") | not)) | .browser_download_url')
        echo "jq found URL: $DOWNLOAD_URL"
    else
        echo "jq not available, using grep/sed to parse JSON..."
        # More robust fallback parsing without jq
        # Look for openlist-frontend-dist-v*.tar.gz but not lite version
        DOWNLOAD_URL=$(echo "$RELEASE_INFO" | grep -o '"browser_download_url":"[^"]*openlist-frontend-dist-v[^"]*\.tar\.gz"' | grep -v 'lite' | head -1 | sed 's/.*"browser_download_url":"\([^"]*\)".*/\1/')
        echo "grep/sed found URL: $DOWNLOAD_URL"
        
        # If the above doesn't work, try a more general pattern
        if [ -z "$DOWNLOAD_URL" ] || [ "$DOWNLOAD_URL" = "null" ]; then
            echo "Trying more general pattern..."
            DOWNLOAD_URL=$(echo "$RELEASE_INFO" | grep -o '"browser_download_url":"[^"]*openlist-frontend-dist[^"]*\.tar\.gz"' | grep -v 'lite' | head -1 | sed 's/.*"browser_download_url":"\([^"]*\)".*/\1/')
            echo "General pattern found URL: $DOWNLOAD_URL"
        fi
    fi
fi

# Validate download URL
if [ -z "$DOWNLOAD_URL" ] || [ "$DOWNLOAD_URL" = "null" ]; then
    echo "Error: Could not determine download URL from API response"
    echo "API response preview:"
    echo "$RELEASE_INFO" | head -20
    exit 1
fi

echo "Download URL: $DOWNLOAD_URL"

# Function to download file with retries and proxy fallback
download_file() {
    local url="$1"
    local output="$2"
    local attempt=1
    local max_attempts=3
    
    # First try direct download
    echo "Trying direct download..."
    while [ $attempt -le $max_attempts ]; do
        echo "Direct download attempt $attempt/$max_attempts..."
        
        # Try download
        if curl -fsSL --max-time 30 -o "$output" "$url"; then
            echo "Direct download successful on attempt $attempt"
            return 0
        else
            local curl_exit_code=$?
            echo "Direct download attempt $attempt failed (exit code: $curl_exit_code)"
            
            # Remove partial file if it exists
            rm -f "$output"
            
            if [ $attempt -lt $max_attempts ]; then
                echo "Waiting 3 seconds before retry..."
                sleep 3
            fi
        fi
        
        attempt=$((attempt + 1))
    done
    
    # Try proxy download if direct failed
    echo "Direct download failed, trying proxy download..."
    local proxy_url="https://ghproxy.lvedong.eu.org/$url"
    attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        echo "Proxy download attempt $attempt/$max_attempts..."
        
        # Try proxy download
        if curl -fsSL --max-time 45 -o "$output" "$proxy_url"; then
            echo "Proxy download successful on attempt $attempt"
            return 0
        else
            local curl_exit_code=$?
            echo "Proxy download attempt $attempt failed (exit code: $curl_exit_code)"
            
            # Remove partial file if it exists
            rm -f "$output"
            
            if [ $attempt -lt $max_attempts ]; then
                echo "Waiting 5 seconds before retry..."
                sleep 5
            fi
        fi
        
        attempt=$((attempt + 1))
    done
    
    echo "Failed to download via both direct and proxy methods"
    return 1
}

# Download the file with retries
echo "Downloading web assets..."
if ! download_file "$DOWNLOAD_URL" "dist.tar.gz"; then
    echo "Error: Failed to download web assets after multiple attempts"
    exit 1
fi

# Verify the downloaded file
if [ ! -f dist.tar.gz ] || [ ! -s dist.tar.gz ]; then
    echo "Error: Downloaded file is empty or missing"
    exit 1
fi

echo "Downloaded file size: $(ls -lh dist.tar.gz | awk '{print $5}')"

# Extract the archive
echo "Extracting web assets..."
if tar -zxf dist.tar.gz -C dist 2>/dev/null; then
    echo "Extraction successful"
else
    echo "Error: Failed to extract archive"
    echo "File info:"
    file dist.tar.gz 2>/dev/null || echo "file command not available"
    ls -la dist.tar.gz
    exit 1
fi

# Move to final location
echo "Installing web assets..."
rm -rf ../public/dist
if [ -d dist ]; then
    mv dist ../public/
    echo "Web assets installed successfully"
else
    echo "Error: Extracted directory not found"
    exit 1
fi

# Cleanup
rm -f dist.tar.gz

echo "Web assets initialization completed"