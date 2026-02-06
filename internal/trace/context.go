package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
)

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	pathTagKey   contextKey = "path_tag"
)

// GenerateRequestID generates a unique request ID in format "req-XXXXXX"
func GenerateRequestID() string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "req-000000"
	}
	return "req-" + hex.EncodeToString(b)
}

// ExtractPathTag extracts a path tag like "baidu:/电影" from a URL path
// For /dav/baidu/movies/file.mp4 -> "baidu:/movies"
// For /d/local/files/doc.pdf -> "local:/files"
func ExtractPathTag(urlPath string) string {
	// Remove common prefixes
	path := urlPath
	for _, prefix := range []string{"/dav", "/d", "/p", "/api/fs"} {
		if strings.HasPrefix(path, prefix) {
			path = strings.TrimPrefix(path, prefix)
			break
		}
	}

	// Split into parts and extract storage + first directory
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "/"
	}

	storage := parts[0]
	if len(parts) > 1 {
		return storage + ":/" + parts[1]
	}
	return storage + ":/"
}

// WithRequestID adds request ID to context
func WithRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, requestIDKey, reqID)
}

// GetRequestID retrieves request ID from context
func GetRequestID(ctx context.Context) string {
	if v := ctx.Value(requestIDKey); v != nil {
		return v.(string)
	}
	return ""
}

// WithPathTag adds path tag to context
func WithPathTag(ctx context.Context, pathTag string) context.Context {
	return context.WithValue(ctx, pathTagKey, pathTag)
}

// GetPathTag retrieves path tag from context
func GetPathTag(ctx context.Context) string {
	if v := ctx.Value(pathTagKey); v != nil {
		return v.(string)
	}
	return ""
}

// LogPrefix returns a formatted log prefix: "[req-xxx] [path] [op]"
func LogPrefix(ctx context.Context, operation string) string {
	reqID := GetRequestID(ctx)
	pathTag := GetPathTag(ctx)
	if reqID == "" {
		reqID = "req-??????"
	}
	if pathTag == "" {
		pathTag = "/"
	}
	return "[" + reqID + "] [" + pathTag + "] [" + operation + "]"
}
