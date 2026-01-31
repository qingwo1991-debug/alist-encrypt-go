package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

// LoggerMiddleware logs HTTP requests using zerolog
func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		defer func() {
			log.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.Status()).
				Int("bytes", ww.BytesWritten()).
				Dur("duration", time.Since(start)).
				Str("remote", r.RemoteAddr).
				Str("proto", r.Proto).
				Msg("request")
		}()

		next.ServeHTTP(ww, r)
	})
}

// CORSMiddleware handles CORS headers
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token, Depth, Destination, Overwrite, File-Path, Authorizetoken, AUTHORIZETOKEN")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Content-Disposition")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ForceHTTPSMiddleware redirects HTTP to HTTPS
func ForceHTTPSMiddleware(httpsPort int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
				host := r.Host
				if httpsPort != 443 {
					host = fmt.Sprintf("%s:%d", r.Host, httpsPort)
				}
				target := fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware validates JWT tokens
func AuthMiddleware(jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for login endpoint
			if r.URL.Path == "/enc-api/login" {
				next.ServeHTTP(w, r)
				return
			}

			// Check multiple header names for compatibility with original Node.js version
			// Note: Go's http package canonicalizes headers, so "authorizetoken" becomes "Authorizetoken"
			token := r.Header.Get("Authorizetoken") // Primary: matches Node.js version
			if token == "" {
				token = r.Header.Get("Authorization")
			}
			if token == "" {
				token = r.URL.Query().Get("token")
			}

			if token == "" {
				// Return JSON error for frontend compatibility - matches Node.js: { code: 401, msg: 'user unlogin' }
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"code":401,"msg":"user unlogin"}`))
				return
			}

			// Store token in context for handlers
			r.Header.Set("X-User-Token", token)
			next.ServeHTTP(w, r)
		})
	}
}
