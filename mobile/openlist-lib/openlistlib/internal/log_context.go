package internal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// 操作标签常量
const (
	TagEncrypt  = "encrypt"   // 加密操作
	TagDecrypt  = "decrypt"   // 解密操作
	TagDownload = "download"  // 下载操作
	TagUpload   = "upload"    // 上传操作
	TagFileSize = "filesize"  // 文件大小探测
	TagList     = "list"      // 目录列表
	TagProxy    = "proxy"     // 代理通用
	TagCache    = "cache"     // 缓存操作
	TagConfig   = "config"    // 配置操作
	TagServer   = "server"    // 服务器启停
)

// LogContext 日志上下文，用于全链路追踪
type LogContext struct {
	RequestID string // 请求ID，如 "req-a1b2c3"
	PathTag   string // 路径标识，如 "baidu:/电影"
}

type contextKey string

const logContextKey contextKey = "logContext"

// NewLogContext 创建新的日志上下文
func NewLogContext(pathTag string) *LogContext {
	id := make([]byte, 3)
	rand.Read(id)
	return &LogContext{
		RequestID: "req-" + hex.EncodeToString(id),
		PathTag:   pathTag,
	}
}

// WithLogContext 将日志上下文注入 context
func WithLogContext(ctx context.Context, lc *LogContext) context.Context {
	return context.WithValue(ctx, logContextKey, lc)
}

// GetLogContext 从 context 获取日志上下文
func GetLogContext(ctx context.Context) *LogContext {
	if ctx == nil {
		return nil
	}
	if lc, ok := ctx.Value(logContextKey).(*LogContext); ok {
		return lc
	}
	return nil
}

// Prefix 生成日志前缀
func (lc *LogContext) Prefix(tag string) string {
	if lc == nil {
		return fmt.Sprintf("[%s]", tag)
	}
	if lc.PathTag != "" {
		return fmt.Sprintf("[%s] [%s] [%s]", lc.RequestID, lc.PathTag, tag)
	}
	return fmt.Sprintf("[%s] [%s]", lc.RequestID, tag)
}

// LogPrefix 从 context 获取日志前缀的便捷函数
func LogPrefix(ctx context.Context, tag string) string {
	lc := GetLogContext(ctx)
	if lc == nil {
		return fmt.Sprintf("[%s]", tag)
	}
	return lc.Prefix(tag)
}

// ExtractPathTag 从 URL 路径提取路径标识
// 例如: "/d/baidu/电影/test.mp4" -> "baidu:/电影"
// 例如: "/api/fs/list" with path="/baidu/电影" -> "baidu:/电影"
func ExtractPathTag(urlPath string, bodyPath string) string {
	// 优先使用 body 中的路径（API 请求）
	targetPath := bodyPath
	if targetPath == "" {
		// 从 URL 提取路径（下载/WebDAV 请求）
		targetPath = urlPath
		// 移除前缀 /d/, /p/, /dav/
		for _, prefix := range []string{"/d/", "/p/", "/dav/"} {
			if strings.HasPrefix(targetPath, prefix) {
				targetPath = targetPath[len(prefix)-1:]
				break
			}
		}
	}

	// 清理路径
	targetPath = strings.TrimPrefix(targetPath, "/")
	if targetPath == "" {
		return ""
	}

	// 提取前两级作为标识
	parts := strings.SplitN(targetPath, "/", 3)
	if len(parts) >= 2 {
		return parts[0] + ":/" + parts[1]
	} else if len(parts) == 1 {
		return parts[0]
	}
	return ""
}

// WrapHandler 包装 HTTP handler，注入日志上下文
func WrapHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pathTag := ExtractPathTag(r.URL.Path, "")
		lc := NewLogContext(pathTag)
		ctx := WithLogContext(r.Context(), lc)
		handler(w, r.WithContext(ctx))
	}
}

// TraceMiddleware wraps an http.Handler to add request tracing to all requests.
// Logs: [timestamp] [req-xxx] [path] [request] METHOD /path status=200 duration=1ms
func TraceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathTag := ExtractPathTag(r.URL.Path, "")
		lc := NewLogContext(pathTag)
		ctx := WithLogContext(r.Context(), lc)
		start := time.Now()

		// Capture status code
		wr := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wr, r.WithContext(ctx))

		dur := time.Since(start)
		log.Infof("[%s] [%s] [request] %s %s status=%d duration=%s",
			lc.RequestID, lc.PathTag, r.Method, r.URL.Path, wr.statusCode, dur)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

