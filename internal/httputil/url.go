package httputil

import (
	"net/http"
	"strings"
)

// BuildTargetURL constructs the target URL from base URL, path, and query string
func BuildTargetURL(baseURL, path string, r *http.Request) string {
	url := baseURL + path
	if r != nil && r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}
	return url
}

// BuildTargetURLWithQuery constructs the target URL with explicit query string
func BuildTargetURLWithQuery(baseURL, path, query string) string {
	url := baseURL + path
	if query != "" {
		url += "?" + query
	}
	return url
}

// JoinPath safely joins path segments, handling slashes
func JoinPath(base string, paths ...string) string {
	result := strings.TrimSuffix(base, "/")
	for _, p := range paths {
		p = strings.TrimPrefix(p, "/")
		if p != "" {
			result = result + "/" + p
		}
	}
	return result
}

// StripPrefix removes a prefix from the path
func StripPrefix(path, prefix string) string {
	return strings.TrimPrefix(path, prefix)
}

// EnsureLeadingSlash ensures the path starts with a slash
func EnsureLeadingSlash(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

// CleanPath normalizes a path by removing double slashes
func CleanPath(path string) string {
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return path
}
