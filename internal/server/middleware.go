package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// LoggerMiddleware logs HTTP requests using zerolog
func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		log.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			Int("bytes", c.Writer.Size()).
			Dur("duration", time.Since(start)).
			Str("remote", c.ClientIP()).
			Str("proto", c.Request.Proto).
			Msg("request")
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
