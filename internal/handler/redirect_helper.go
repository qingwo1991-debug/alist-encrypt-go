package handler

import (
	"net/http"
	"net/url"
	"strings"
)

func buildRedirectPath(key, lastURL string, decode bool) string {
	path := "/redirect/" + key
	values := url.Values{}
	if decode {
		values.Set("decode", "1")
	}
	if lastURL != "" {
		values.Set("lastUrl", lastURL)
	}
	if len(values) == 0 {
		return path
	}
	return path + "?" + values.Encode()
}

func buildRedirectURL(r *http.Request, redirectPath string) string {
	if r == nil {
		return redirectPath
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		return strings.TrimRight(origin, "/") + redirectPath
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return redirectPath
	}
	return proto + "://" + host + redirectPath
}
