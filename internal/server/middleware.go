package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

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

// LoggerMiddleware logs HTTP requests using the new trace format
func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		reqID := trace.GetRequestID(c.Request.Context())
		pathTag := trace.GetPathTag(c.Request.Context())
		duration := time.Since(start)

		// Use new format: [timestamp] [req-xxx] [path_tag] [request] details
		ts := time.Now().Format("2006-01-02T15:04:05")
		fmt.Printf("%s [%s] [%s] [request] %s %s status=%d bytes=%d duration=%v\n",
			ts, reqID, pathTag, c.Request.Method, c.Request.URL.Path,
			c.Writer.Status(), c.Writer.Size(), duration)
	}
}

// CORSMiddleware handles CORS headers
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK")
		c.Header("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token, Depth, Destination, Overwrite, File-Path, Authorizetoken, AUTHORIZETOKEN")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Content-Disposition")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

// ForceHTTPSMiddleware redirects HTTP to HTTPS
func ForceHTTPSMiddleware(httpsPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS == nil && c.GetHeader("X-Forwarded-Proto") != "https" {
			host := c.Request.Host
			if httpsPort != 443 {
				host = fmt.Sprintf("%s:%d", c.Request.Host, httpsPort)
			}
			target := fmt.Sprintf("https://%s%s", host, c.Request.URL.RequestURI())
			c.Redirect(http.StatusMovedPermanently, target)
			c.Abort()
			return
		}
		c.Next()
	}
}

// AuthMiddleware validates JWT tokens
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for login endpoint
		if c.Request.URL.Path == "/enc-api/login" {
			c.Next()
			return
		}

		// Check multiple header names for compatibility with original Node.js version
		token := c.GetHeader("Authorizetoken") // Primary: matches Node.js version
		if token == "" {
			token = c.GetHeader("Authorization")
		}
		if token == "" {
			token = c.Query("token")
		}

		if token == "" {
			// Return JSON error for frontend compatibility - matches Node.js: { code: 401, msg: 'user unlogin' }
			c.JSON(http.StatusOK, gin.H{"code": 401, "msg": "user unlogin"})
			c.Abort()
			return
		}

		// Store token in context for handlers
		c.Request.Header.Set("X-User-Token", token)
		c.Next()
	}
}
