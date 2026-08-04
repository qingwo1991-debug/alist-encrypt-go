package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
	"golang.org/x/sync/singleflight"
)

const (
	probeJWTCacheTTL         = 2 * time.Hour
	probeJWTNegativeCacheTTL = 30 * time.Second
	probeJWTCacheMax         = 64
)

type probeJWTCacheEntry struct {
	token     string
	expiresAt time.Time
	lastUsed  time.Time
}

var probeJWTState = struct {
	sync.Mutex
	entries map[[sha256.Size]byte]probeJWTCacheEntry
	flights singleflight.Group
}{
	entries: make(map[[sha256.Size]byte]probeJWTCacheEntry),
}

func buildProbeAuthVariants(cfg *config.Config, requestHeaders http.Header) []http.Header {
	var variants []http.Header
	seen := make(map[string]struct{})

	add := func(h http.Header) {
		if h == nil {
			h = make(http.Header)
		}
		auth := strings.TrimSpace(h.Get("Authorization"))
		cookie := strings.TrimSpace(h.Get("Cookie"))
		key := auth + "\n" + cookie
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		cp := make(http.Header, len(h))
		for k, values := range h {
			cloned := make([]string, len(values))
			copy(cloned, values)
			cp[k] = cloned
		}
		variants = append(variants, cp)
	}

	requestAuth := make(http.Header)
	if requestHeaders != nil {
		if auth := strings.TrimSpace(requestHeaders.Get("Authorization")); auth != "" {
			requestAuth.Set("Authorization", auth)
		}
		if cookie := strings.TrimSpace(requestHeaders.Get("Cookie")); cookie != "" {
			requestAuth.Set("Cookie", cookie)
		}
	}
	add(requestAuth)

	if cfg != nil {
		alist := cfg.AlistServerSnapshot()
		if raw := strings.TrimSpace(alist.ScanAuthHeader); raw != "" {
			h := make(http.Header)
			h.Set("Authorization", extractAuthorizationValue(raw))
			add(h)
		}
		username := strings.TrimSpace(alist.ScanUsername)
		password := strings.TrimSpace(alist.ScanPassword)
		if username != "" && password != "" {
			basic := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			h := make(http.Header)
			h.Set("Authorization", "Basic "+basic)
			add(h)
		}
	}

	if len(variants) == 0 {
		variants = append(variants, make(http.Header))
	}
	return variants
}

// injectProbeAuthFallback sets the configured scan credential (Basic auth or
// raw Authorization header) on a request that carries none of its own. Used by
// size-resolution HEAD/Range probes that must reach Alist's protected /d/ and
// /dav/ endpoints even when the client request was unauthenticated.
func injectProbeAuthFallback(req *http.Request, cfg *config.Config) {
	if req == nil || cfg == nil {
		return
	}
	alist := cfg.AlistServerSnapshot()
	if raw := strings.TrimSpace(alist.ScanAuthHeader); raw != "" {
		req.Header.Set("Authorization", extractAuthorizationValue(raw))
		return
	}
	username := strings.TrimSpace(alist.ScanUsername)
	password := strings.TrimSpace(alist.ScanPassword)
	if username != "" && password != "" {
		basic := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Authorization", "Basic "+basic)
	}
}

func probeJWTCacheKey(alistURL, username, password string) [sha256.Size]byte {
	alistURL = strings.TrimRight(strings.TrimSpace(alistURL), "/")
	return sha256.Sum256([]byte(alistURL + "\x00" + username + "\x00" + password))
}

func configuredProbeJWTCredentials(cfg *config.Config) (alistURL, username, password string, ok bool) {
	if cfg == nil {
		return "", "", "", false
	}
	alist := cfg.AlistServerSnapshot()
	alistURL = strings.TrimRight(strings.TrimSpace(cfg.GetAlistURL()), "/")
	username = strings.TrimSpace(alist.ScanUsername)
	password = strings.TrimSpace(alist.ScanPassword)
	return alistURL, username, password, alistURL != "" && username != "" && password != ""
}

func lookupCachedProbeJWTForCredentials(alistURL, username, password string) (string, bool) {
	key := probeJWTCacheKey(alistURL, username, password)
	now := time.Now()
	probeJWTState.Lock()
	defer probeJWTState.Unlock()
	entry, ok := probeJWTState.entries[key]
	if !ok {
		return "", false
	}
	if !now.Before(entry.expiresAt) {
		delete(probeJWTState.entries, key)
		return "", false
	}
	entry.lastUsed = now
	probeJWTState.entries[key] = entry
	return entry.token, true
}

func cachedProbeJWTForCredentials(alistURL, username, password string) string {
	token, _ := lookupCachedProbeJWTForCredentials(alistURL, username, password)
	return token
}

func probeJWTForCredentials(alistURL, username, password string, fetcher func(string, string, string) string) string {
	if strings.TrimSpace(alistURL) == "" || strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" || fetcher == nil {
		return ""
	}
	key := probeJWTCacheKey(alistURL, username, password)
	if token, ok := lookupCachedProbeJWTForCredentials(alistURL, username, password); ok {
		return token
	}

	value, _, _ := probeJWTState.flights.Do(string(key[:]), func() (interface{}, error) {
		if token, ok := lookupCachedProbeJWTForCredentials(alistURL, username, password); ok {
			return token, nil
		}

		token := strings.TrimSpace(fetcher(alistURL, username, password))
		now := time.Now()
		ttl := probeJWTCacheTTL
		if token == "" {
			ttl = probeJWTNegativeCacheTTL
		}
		probeJWTState.Lock()
		for cachedKey, entry := range probeJWTState.entries {
			if !now.Before(entry.expiresAt) {
				delete(probeJWTState.entries, cachedKey)
			}
		}
		if _, exists := probeJWTState.entries[key]; !exists && len(probeJWTState.entries) >= probeJWTCacheMax {
			var oldestKey [sha256.Size]byte
			var oldestAt time.Time
			for cachedKey, entry := range probeJWTState.entries {
				if oldestAt.IsZero() || entry.lastUsed.Before(oldestAt) {
					oldestKey = cachedKey
					oldestAt = entry.lastUsed
				}
			}
			delete(probeJWTState.entries, oldestKey)
		}
		probeJWTState.entries[key] = probeJWTCacheEntry{
			token:     token,
			expiresAt: now.Add(ttl),
			lastUsed:  now,
		}
		probeJWTState.Unlock()
		return token, nil
	})
	if value == nil {
		return ""
	}
	token, _ := value.(string)
	return token
}

func lazyProbeJWTHeader(cfg *config.Config) http.Header {
	alistURL, username, password, ok := configuredProbeJWTCredentials(cfg)
	if !ok {
		return nil
	}
	token := probeJWTForCredentials(alistURL, username, password, fetchAlistJWT)
	if token == "" {
		return nil
	}
	headers := make(http.Header)
	headers.Set("Authorization", token)
	return headers
}

func cachedProbeJWTHeader(cfg *config.Config) http.Header {
	alistURL, username, password, ok := configuredProbeJWTCredentials(cfg)
	if !ok {
		return nil
	}
	token := cachedProbeJWTForCredentials(alistURL, username, password)
	if token == "" {
		return nil
	}
	headers := make(http.Header)
	headers.Set("Authorization", token)
	return headers
}

func invalidateProbeJWT(cfg *config.Config, rejectedToken string) {
	alistURL, username, password, ok := configuredProbeJWTCredentials(cfg)
	if !ok {
		return
	}
	key := probeJWTCacheKey(alistURL, username, password)
	probeJWTState.Lock()
	if entry, exists := probeJWTState.entries[key]; exists && (rejectedToken == "" || entry.token == rejectedToken) {
		delete(probeJWTState.entries, key)
	}
	probeJWTState.Unlock()
}

func isAlistProbeTarget(cfg *config.Config, target string) bool {
	if cfg == nil {
		return false
	}
	alistURL, err := url.Parse(strings.TrimSpace(cfg.GetAlistURL()))
	if err != nil || alistURL.Host == "" {
		return false
	}
	targetURL, err := url.Parse(strings.TrimSpace(target))
	if err != nil || targetURL.Host == "" {
		return false
	}
	return strings.EqualFold(alistURL.Scheme, targetURL.Scheme) && strings.EqualFold(alistURL.Host, targetURL.Host)
}

func isProbeAuthFailure(statusCode int) bool {
	return statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
}

func probeCandidateWithAuth(cfg *config.Config, candidate string, authVariants []http.Header, inspect func(http.Header) proxy.ContentInspectionResult) proxy.ContentInspectionResult {
	if inspect == nil {
		return proxy.ContentInspectionResult{}
	}
	var last proxy.ContentInspectionResult
	unauthorized := false
	triedCachedJWT := false
	seenAuth := make(map[string]struct{}, len(authVariants)+1)
	probe := func(headers http.Header) (proxy.ContentInspectionResult, bool) {
		authKey := strings.TrimSpace(headers.Get("Authorization")) + "\n" + strings.TrimSpace(headers.Get("Cookie"))
		if _, exists := seenAuth[authKey]; exists {
			return proxy.ContentInspectionResult{}, false
		}
		seenAuth[authKey] = struct{}{}
		return inspect(headers), true
	}

	for _, headers := range authVariants {
		result, attempted := probe(headers)
		if !attempted {
			continue
		}
		last = result
		if result.Confirmed {
			return result
		}
		if isProbeAuthFailure(result.StatusCode) {
			unauthorized = true
			if !triedCachedJWT && isAlistProbeTarget(cfg, candidate) {
				triedCachedJWT = true
				if jwtHeaders := cachedProbeJWTHeader(cfg); jwtHeaders != nil {
					cachedResult, attempted := probe(jwtHeaders)
					if !attempted {
						// The request/scan header itself may be the cached JWT.
						// Invalidate it after an explicit rejection so the final
						// lazy retry can refresh rather than reuse it.
						if strings.TrimSpace(jwtHeaders.Get("Authorization")) == strings.TrimSpace(headers.Get("Authorization")) {
							invalidateProbeJWT(cfg, jwtHeaders.Get("Authorization"))
						}
					} else {
						last = cachedResult
						if cachedResult.Confirmed {
							return cachedResult
						}
						if isProbeAuthFailure(cachedResult.StatusCode) {
							invalidateProbeJWT(cfg, jwtHeaders.Get("Authorization"))
						} else {
							return cachedResult
						}
					}
				}
			}
			continue
		}
		// Authentication variants cannot repair transport failures, short
		// successful responses, not-found responses, or server failures. Only
		// an explicit 401/403 justifies another authentication RTT.
		return result
	}
	if !unauthorized || !isAlistProbeTarget(cfg, candidate) {
		return last
	}
	jwtHeaders := lazyProbeJWTHeader(cfg)
	if jwtHeaders == nil {
		return last
	}
	result, attempted := probe(jwtHeaders)
	if !attempted {
		return last
	}
	if isProbeAuthFailure(result.StatusCode) {
		invalidateProbeJWT(cfg, jwtHeaders.Get("Authorization"))
	}
	return result
}
