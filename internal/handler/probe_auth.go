package handler

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
)

func buildProbeAuthVariants(cfg *config.Config, requestHeaders http.Header) []http.Header {
	var variants []http.Header
	seen := make(map[string]struct{})

	add := func(h http.Header) {
		if h == nil {
			return
		}
		auth := strings.TrimSpace(h.Get("Authorization"))
		cookie := strings.TrimSpace(h.Get("Cookie"))
		if auth == "" && cookie == "" {
			return
		}
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
		if raw := strings.TrimSpace(cfg.AlistServer.ScanAuthHeader); raw != "" {
			h := make(http.Header)
			h.Set("Authorization", extractAuthorizationValue(raw))
			add(h)
		}
		username := strings.TrimSpace(cfg.AlistServer.ScanUsername)
		password := strings.TrimSpace(cfg.AlistServer.ScanPassword)
		if username != "" && password != "" {
			if token := fetchAlistJWT(cfg.GetAlistURL(), username, password); token != "" {
				h := make(http.Header)
				h.Set("Authorization", token)
				add(h)
			}
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
