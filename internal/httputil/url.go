package httputil

import (
	"net/http"
	"net/url"
	"strings"
)

// BuildTargetURL constructs the target URL from base URL, path, and query string
func BuildTargetURL(baseURL, path string, r *http.Request) string {
	// path is a decoded, literal storage/route path, not a URL reference.
	// Escape once so '%' cannot be reinterpreted by NewRequest downstream.
	u := baseURL + (&url.URL{Path: path}).EscapedPath()
	if r != nil && r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery
	}
	return u
}

// BuildTargetURLWithQuery constructs the target URL with explicit query string
func BuildTargetURLWithQuery(baseURL, path, query string) string {
	// path is a decoded, literal storage/route path, not a URL reference.
	// Escape once so '%' cannot be reinterpreted by NewRequest downstream.
	u := baseURL + (&url.URL{Path: path}).EscapedPath()
	if query != "" {
		u += "?" + query
	}
	return u
}

// BuildTargetURLStripped constructs the target URL WITHOUT query parameters.
// Use this when the path has been modified (e.g. filename encryption) and the
// original query parameters (like ?sign=xxx) are invalid for the new path.
func BuildTargetURLStripped(baseURL, path string) string {
	return BuildTargetURLWithQuery(baseURL, path, "")
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
