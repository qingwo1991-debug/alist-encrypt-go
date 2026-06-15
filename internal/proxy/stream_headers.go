package proxy

import (
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
)

// Pre-compiled regex for Content-Disposition rewriting (avoids per-request compilation)
var contentDispositionRe = regexp.MustCompile(`(?i)filename\*?=[^;]*;?`)

func decodeNameFromRequest(passwdInfo *config.PasswdInfo, urlPath string, allowLoose bool) string {
	if passwdInfo == nil {
		return ""
	}
	name := path.Base(urlPath)
	decoded, err := url.PathUnescape(name)
	if err == nil {
		name = decoded
	}
	ext := path.Ext(name)
	base := strings.TrimSuffix(name, ext)
	decodedName := encryption.DecodeName(passwdInfo.Password, passwdInfo.EncType, base)
	if decodedName == "" && allowLoose {
		return encryption.DecodeNameLoose(passwdInfo.Password, passwdInfo.EncType, base)
	}
	return decodedName
}

func rewriteContentDisposition(w http.ResponseWriter, showName string) {
	cd := w.Header().Get("Content-Disposition")
	if cd != "" {
		cd = contentDispositionRe.ReplaceAllString(cd, "")
		cd = strings.TrimSpace(cd)
		if cd != "" && !strings.HasSuffix(cd, ";") {
			cd += ";"
		}
	}
	w.Header().Set("Content-Disposition", cd+"filename*=UTF-8''"+url.PathEscape(showName)+";")
}

// StripForeignHeaders removes WebDAV-specific headers that confuse CDN targets.
func (s *StreamProxy) StripForeignHeaders(req *http.Request) {
	if req == nil || req.URL == nil {
		return
	}
	stripWebDAVHeaders(req)
	if s.shouldPreserveUpstreamAuth(req.URL) {
		req.Header.Del("Referer")
		req.Header.Del("Host")
		return
	}
	// Raw CDN targets reject WebDAV auth/referrer style headers.
	req.Header.Del("Authorization")
	req.Header.Del("Referer")
	req.Header.Del("Host")
}

// StripWebDAVHeaders removes WebDAV-specific request headers that confuse CDNs.
func StripWebDAVHeaders(r *http.Request) {
	stripWebDAVHeaders(r)
	// Old encrypt proxy also stripped these for CDN compatibility:
	// - Authorization: CDNs don't understand alist/WebDAV auth tokens
	// - Referer: Aliyun CDN returns 403 with certain referrers
	// - Host: prevent host header mismatch with CDN
	r.Header.Del("Authorization")
	r.Header.Del("Referer")
	r.Header.Del("Host")
}

func stripWebDAVHeaders(r *http.Request) {
	if r == nil {
		return
	}
	webdavHeaders := []string{
		"Depth", "Translate", "Destination", "If", "If-Match",
		"If-None-Match", "If-Modified-Since", "If-Unmodified-Since",
		"Lock-Token", "Overwrite", "Timeout",
	}
	for _, h := range webdavHeaders {
		r.Header.Del(h)
	}
}

func (s *StreamProxy) shouldPreserveUpstreamAuth(target *url.URL) bool {
	if s == nil || s.cfg == nil || target == nil {
		return false
	}
	targetHost := parseHostOnly(target.Host)
	if targetHost == "" {
		return false
	}
	alistHost := parseHostOnly(s.cfg.AlistServer.ServerHost)
	if alistHost != "" && strings.EqualFold(targetHost, alistHost) {
		return true
	}
	return false
}
