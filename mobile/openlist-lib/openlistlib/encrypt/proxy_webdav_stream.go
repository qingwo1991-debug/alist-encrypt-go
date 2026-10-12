package encrypt

import (
	"fmt"
	"net/http"
	"strconv"
)

// writeWebDAVPlainHeaders is shared by direct and resolved HEAD responses.
// Geometry comes only from inspected metadata, never a directory cache size.
func writeWebDAVPlainHeaders(w http.ResponseWriter, r *http.Request, meta ContentMeta, status int) {
	w.Header().Del("Location")
	w.Header().Del("Content-Range")
	w.Header().Del("Content-Length")
	w.Header().Del("Transfer-Encoding")
	w.Header().Del("Content-Encoding")
	w.Header().Del("ETag")
	w.Header().Del("Content-MD5")
	w.Header().Del("Digest")
	if meta.PlainSize < 0 {
		http.Error(w, "plaintext size unavailable", http.StatusBadGateway)
		return
	}
	start, end, ranged, err := parseSingleRange(r.Header.Get("Range"), meta.PlainSize)
	if err != nil {
		writeRangeNotSatisfiable(w, meta.PlainSize)
		return
	}
	length := meta.PlainSize
	if ranged {
		status = http.StatusPartialContent
		length = end - start + 1
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, meta.PlainSize))
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.WriteHeader(status)
}

// serveWebDAVResolvedLegacy uses the existing playback orchestrator, including
// routing hints, signed URL refresh, redirect credentials and bounded fallback.
// Dispatch explicitly even with the old engine setting: V2 must never reach the
// legacy redirect reader, which has V1-only cipher geometry.
func (p *ProxyServer) serveWebDAVResolvedLegacy(w http.ResponseWriter, r *http.Request, target string, enc *EncryptPath, meta ContentMeta, encryptedPath string) {
	for _, key := range []string{"Location", "Content-Length", "Content-Range", "Content-Encoding", "Transfer-Encoding", "ETag", "Content-MD5", "Digest"} {
		w.Header().Del(key)
	}
	if r.Method == http.MethodHead {
		writeWebDAVPlainHeaders(w, r, meta, http.StatusOK)
		return
	}
	key := generateRedirectKey()
	driver := p.inferDriverFromPath(r.Context(), r.URL.Path, r.Header)
	p.noteDriverCandidate(driver)
	info := &RedirectInfo{
		RedirectURL: target, PasswdInfo: enc, FileSize: meta.PlainSize,
		OriginalURL: r.URL.String(), EncryptedPath: encryptedPath, Headers: r.Header.Clone(), Driver: driver,
		ContentVersion: meta.Version, HeaderLen: meta.HeaderLen,
		NonceField: cloneNonceField(meta.NonceField), CiphertextSize: meta.TotalCiphertextSize(),
	}
	p.storeRedirectCache(key, info)
	next := r.Clone(r.Context())
	u := *r.URL
	u.Path = "/redirect/" + key
	u.RawPath = ""
	query := u.Query()
	query.Set("decode", "1")
	query.Set("lastUrl", r.URL.Path)
	u.RawQuery = query.Encode()
	next.URL = &u
	newPlayOrchestrator(p).ServeRedirect(w, next)
}
