package encrypt

import (
	"net/http"
	"strings"
)

// Metadata proves geometry, never permission. Local V3 HEAD/empty responses
// still issue the real authorized origin operation, without another header probe.
func (p *ProxyServer) authorizeLocalWebDAVMetadata(w http.ResponseWriter, r *http.Request, encryptedPath string, meta ContentMeta) bool {
	if confirmedMetadataRequestFromContext(r.Context()) == nil || (r.Method != http.MethodHead && !(r.Method == http.MethodGet && meta.PlainSize == 0)) {
		return true
	}
	targetPath := encryptedPath
	if !strings.HasPrefix(targetPath, "/dav/") {
		targetPath = "/dav/" + strings.TrimPrefix(targetPath, "/")
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, p.getAlistURL()+targetPath, nil)
	if err != nil {
		http.Error(w, "invalid origin request", http.StatusBadGateway)
		return false
	}
	req.Header = r.Header.Clone()
	req.Header.Del("Range")
	for _, key := range []string{"If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
		req.Header.Del(key)
	}
	req.Header.Set("Accept-Encoding", "identity")
	if r.Method == http.MethodGet {
		req.Header.Set("Range", "bytes=0-0")
	}
	configured := p.streamClientSnapshot()
	if configured == nil {
		http.Error(w, "origin transport unavailable", http.StatusBadGateway)
		return false
	}
	client := *configured
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "origin authorization unavailable", http.StatusBadGateway)
		return false
	}
	defer resp.Body.Close()
	// A redirect is an origin authorization response too; verify its actual
	// target through the existing credential-isolating stream request helper.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		info := &RedirectInfo{RedirectURL: req.URL.String(), Headers: r.Header.Clone()}
		redirected, redirectErr := p.v3PlaybackRequest(r, info, "bytes=0-0")
		if redirectErr != nil {
			http.Error(w, "origin authorization unavailable", http.StatusBadGateway)
			return false
		}
		defer redirected.Body.Close()
		resp = redirected
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := resp.StatusCode
		if status < 400 {
			status = http.StatusBadGateway
		}
		http.Error(w, http.StatusText(status), status)
		return false
	}
	if !p.validateConfirmedMetadataResponse(r.Context(), resp) {
		http.Error(w, "encrypted representation changed; retry required", http.StatusBadGateway)
		return false
	}
	return true
}
