package server

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/trace"
)

// TraceMiddleware adds request tracing context to each request
func TraceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := trace.GenerateRequestID()
		pathTag := trace.ExtractPathTag(c.Request.URL.Path)

		ctx := trace.WithRequestID(c.Request.Context(), reqID)
		ctx = trace.WithPathTag(ctx, pathTag)
		c.Request = c.Request.WithContext(ctx)

		c.Header("X-Request-ID", reqID)
		c.Next()
	}
}

// 访问日志采样：成功请求按 1/50 记录；慢请求（>=1s）与 4xx/5xx 全量记录，
// 避免高频成功请求（磁盘/文件列表/医学请求）刷屏磁盘日志。
const (
	accessLogSuccessSampleRate = 50
	accessLogSlowThreshold     = time.Second
)

// LoggerMiddleware logs HTTP requests via zerolog with sampling.
func LoggerMiddleware() gin.HandlerFunc {
	var sampled uint64
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()
		slow := duration >= accessLogSlowThreshold

		// 成功且不慢的请求按固定比例采样；慢/错误全量。
		if status < 400 && !slow {
			if (atomic.AddUint64(&sampled, 1)-1)%accessLogSuccessSampleRate != 0 {
				return
			}
		}

		var ev *zerolog.Event
		switch {
		case status >= 500:
			ev = log.Error()
		case status >= 400 || slow:
			ev = log.Warn()
		default:
			ev = log.Info()
		}
		ev.Str("req_id", trace.GetRequestID(c.Request.Context()))
		ev.Str("path_tag", trace.GetPathTag(c.Request.Context()))
		ev.Str("method", c.Request.Method)
		ev.Str("path", c.Request.URL.Path)
		ev.Int("status", status)
		ev.Int64("bytes_out", int64(c.Writer.Size()))
		ev.Float64("duration_ms", float64(duration.Microseconds())/1000.0)
		ev.Msg("request")
	}
}

// CORSMiddleware handles CORS headers
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		isEncAPI := strings.HasPrefix(c.Request.URL.Path, "/enc-api")
		if isEncAPI {
			if origin != "" && isSameOriginHost(origin, c.Request.Host) {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Credentials", "true")
				c.Header("Vary", "Origin")
			}
		} else if origin != "" {
			// Public routes (WebDAV, downloads) can use wildcard and do not need credentials.
			c.Header("Access-Control-Allow-Origin", "*")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK")
		c.Header("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token, Depth, Destination, Overwrite, File-Path, Authorizetoken, AUTHORIZETOKEN")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Content-Disposition")

		if c.Request.Method == "OPTIONS" && !strings.HasPrefix(c.Request.URL.Path, "/dav") {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

func isSameOriginHost(origin, requestHost string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return normalizeOriginHost(u.Host) == normalizeOriginHost(requestHost)
}

func normalizeOriginHost(hostport string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(hostport)), "[]")
}

// ForceHTTPSMiddleware redirects HTTP to HTTPS
func ForceHTTPSMiddleware(httpsPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS == nil && c.GetHeader("X-Forwarded-Proto") != "https" {
			host := httpsRedirectHost(c.Request.Host, httpsPort)
			target := fmt.Sprintf("https://%s%s", host, c.Request.URL.RequestURI())
			c.Redirect(http.StatusMovedPermanently, target)
			c.Abort()
			return
		}
		c.Next()
	}
}

func httpsRedirectHost(requestHost string, httpsPort int) string {
	hostname := (&url.URL{Host: requestHost}).Hostname()
	if hostname == "" {
		hostname = strings.Trim(requestHost, "[]")
	}
	if httpsPort == 443 {
		if strings.Contains(hostname, ":") {
			return "[" + strings.Trim(hostname, "[]") + "]"
		}
		return hostname
	}
	return net.JoinHostPort(strings.Trim(hostname, "[]"), strconv.Itoa(httpsPort))
}

// AuthMiddleware validates JWT tokens
func AuthMiddleware(jwtSecret string, expireHours int) gin.HandlerFunc {
	if expireHours <= 0 {
		expireHours = 48
	}
	jwtAuth := auth.NewJWTAuth(jwtSecret, time.Duration(expireHours)*time.Hour)

	extractToken := func(c *gin.Context) string {
		if token := strings.TrimSpace(c.GetHeader("Authorizetoken")); token != "" {
			return token
		}
		if authz := strings.TrimSpace(c.GetHeader("Authorization")); authz != "" {
			if len(authz) >= 7 && strings.EqualFold(authz[:7], "Bearer ") {
				return strings.TrimSpace(authz[7:])
			}
			return authz
		}
		// Query parameter tokens removed for security — URLs leak into logs, browser history, and referrer headers
		return ""
	}

	return func(c *gin.Context) {
		// Skip auth for login endpoint
		if c.Request.URL.Path == "/enc-api/login" {
			c.Next()
			return
		}

		token := extractToken(c)

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "user unlogin"})
			c.Abort()
			return
		}

		if _, err := jwtAuth.ValidateToken(token); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "user unlogin"})
			c.Abort()
			return
		}

		// Store token in Gin context without mutating request headers that may be proxied upstream.
		c.Set("user_token", token)
		c.Next()
	}
}
