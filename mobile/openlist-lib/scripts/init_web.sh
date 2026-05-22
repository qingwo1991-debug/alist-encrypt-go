#!/bin/bash

echo "Initializing Web assets..."

mkdir -p dist

# Function to fetch release info with retries and proxy fallback
fetch_release_info() {
    local attempt=1
    local max_attempts=3
    local api_url="https://api.github.com/repos/OpenListTeam/OpenList-Frontend/releases/latest"
    local proxy_url="https://ghproxy.lvedong.eu.org/https://api.github.com/repos/OpenListTeam/OpenList-Frontend/releases/latest"
    
    # Build auth header if GITHUB_TOKEN is available (increases rate limit from 60 to 5000 per hour)
    local auth_header=""
    if [ -n "$GITHUB_TOKEN" ]; then
        auth_header="Authorization: Bearer $GITHUB_TOKEN"
        echo "Using GITHUB_TOKEN for API authentication"
    fi
    
    # First try direct API
    echo "Trying direct GitHub API..."
    while [ $attempt -le $max_attempts ]; do
        echo "Direct API attempt $attempt/$max_attempts..."
        
        if [ -n "$auth_header" ]; then
            RELEASE_INFO=$(curl -fsSL --max-time 10 \
                -H "Accept: application/vnd.github.v3+json" \
                -H "$auth_header" \
                "$api_url" 2>/dev/null)
        else
            RELEASE_INFO=$(curl -fsSL --max-time 10 \
                -H "Accept: application/vnd.github.v3+json" \
                "$api_url" 2>/dev/null)
        fi
        
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

# Get release info from GitHub API with retries
echo "Fetching latest release information..."
if ! fetch_release_info; then
    echo "Error: Failed to fetch release info from GitHub API"
    exit 1
fi

# Parse download URL with better pattern matching
echo "Parsing download URL..."
if command -v jq >/dev/null 2>&1; then
    DOWNLOAD_URL=$(echo "$RELEASE_INFO" | jq -r '.assets[] | select(.browser_download_url | test("openlist-frontend-dist.*\\.tar\\.gz$") and (test("openlist-frontend-dist-lite") | not)) | .browser_download_url')
else
    # Fallback without jq - look for versioned filename
    DOWNLOAD_URL=$(echo "$RELEASE_INFO" | grep -o '"browser_download_url":"[^"]*openlist-frontend-dist-v[^"]*\.tar\.gz"' | grep -v 'lite' | head -1 | sed 's/.*"browser_download_url":"\([^"]*\)".*/\1/')
    
    # If versioned pattern doesn't work, try general pattern
    if [ -z "$DOWNLOAD_URL" ]; then
        DOWNLOAD_URL=$(echo "$RELEASE_INFO" | grep -o '"browser_download_url":"[^"]*openlist-frontend-dist[^"]*\.tar\.gz"' | grep -v 'lite' | head -1 | sed 's/.*"browser_download_url":"\([^"]*\)".*/\1/')
    fi
fi

if [ -z "$DOWNLOAD_URL" ] || [ "$DOWNLOAD_URL" = "null" ]; then
    echo "Error: Could not determine download URL"
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

# Extract and install
echo "Extracting web assets..."
tar -zxf dist.tar.gz -C dist || {
    echo "Error: Failed to extract archive"
    exit 1
}

echo "Installing web assets..."
rm -rf ../public/dist
mv -f dist ../public
rm -f dist.tar.gz

echo "Web assets initialization completed"