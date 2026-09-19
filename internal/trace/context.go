package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

// logEvent builds a zerolog event carrying the request context (req_id,
// path_tag) plus the operation, so request-scoped diagnostics stay correlated.
func logEvent(ctx context.Context, operation string) *zerolog.Event {
	ev := log.Info()
	if reqID := GetRequestID(ctx); reqID != "" {
		ev = ev.Str("req_id", reqID)
	}
	if pathTag := GetPathTag(ctx); pathTag != "" {
		ev = ev.Str("path_tag", pathTag)
	}
	if operation != "" {
		ev = ev.Str("operation", operation)
	}
	return ev
}

// Log 输出一条带请求上下文的服务端日志（走 zerolog）。
func Log(ctx context.Context, operation, message string) {
	logEvent(ctx, operation).Msg(message)
}

// Logf 输出一条格式化服务端日志（走 zerolog）。
func Logf(ctx context.Context, operation, format string, args ...interface{}) {
	logEvent(ctx, operation).Msgf(format, args...)
}

// ServerLog 输出一条服务器级分类日志（走 zerolog）。
func ServerLog(category, message string) {
	ev := log.Info()
	if category != "" {
		ev = ev.Str("category", category)
	}
	ev.Msg(message)
}
