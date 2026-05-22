package encrypt

import (
	"crypto/md5"
	"encoding/hex"
	"net/url"
	"strings"
)

func buildLocalKey(providerHost, originalPath string) string {
	if providerHost == "" || originalPath == "" {
		return ""
	}
	src := providerHost + "::" + originalPath
	sum := md5.Sum([]byte(src))
	return hex.EncodeToString(sum[:])
}

func parseProviderAndPath(providerURL, originalURL string) (string, string, bool) {
	providerHost := ""
	originalPath := ""

	if providerURL != "" {
		if u, err := url.Parse(providerURL); err == nil {
			providerHost = u.Host
		}
	}

	if originalURL != "" {
		if u, err := url.Parse(originalURL); err == nil {
			if u.Path != "" {
				originalPath = u.Path
			}
		} else {
			originalPath = originalURL
		}
	}

	if originalPath != "" {
		if decoded, err := url.PathUnescape(originalPath); err == nil {
			originalPath = decoded
		}
	}

	if providerHost == "" || originalPath == "" {
		return "", "", false
	}
	return providerHost, originalPath, true
}

func isValidMediaResponse(statusCode int, contentType string, size int64) bool {
	if statusCode != 200 && statusCode != 206 {
		return false
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "html") || strings.Contains(ct, "json") || strings.Contains(ct, "xml") {
		return false
	}
	if strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") {
		return true
	}
	if strings.HasPrefix(ct, "application/octet-stream") && size > 0 {
		return true
	}
	return false
}
