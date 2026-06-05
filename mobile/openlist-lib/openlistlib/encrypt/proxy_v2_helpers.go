package encrypt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func uploadMetaKey(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func cloneNonceField(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func (p *ProxyServer) getUploadMeta(target string) (ContentMeta, bool) {
	if p == nil {
		return ContentMeta{}, false
	}
	key := uploadMetaKey(target)
	p.uploadMetaMu.Lock()
	defer p.uploadMetaMu.Unlock()
	entry, ok := p.uploadMeta[key]
	if !ok {
		return ContentMeta{}, false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(p.uploadMeta, key)
		return ContentMeta{}, false
	}
	return entry.Meta, true
}

func (p *ProxyServer) putUploadMeta(target string, meta ContentMeta) {
	if p == nil || !meta.IsV2() {
		return
	}
	key := uploadMetaKey(target)
	p.uploadMetaMu.Lock()
	defer p.uploadMetaMu.Unlock()
	p.uploadMeta[key] = uploadMetaEntry{
		Meta:      meta,
		ExpiresAt: time.Now().Add(time.Duration(uploadMetaTTLSeconds) * time.Second),
	}
}

func (p *ProxyServer) inspectEncryptedContent(ctx context.Context, target string, authHeaders http.Header, encPath *EncryptPath, ciphertextSize int64) ContentMeta {
	encType := EncryptionType("")
	if encPath != nil {
		encType = EncryptionType(encPath.EncType)
	}
	meta := LegacyContentMeta(encType, ciphertextSize)
	if p == nil || encPath == nil || !encPath.Enable || strings.TrimSpace(target) == "" {
		log.Infof("[v2-inspect] skipped: p=%v encPath=%v enable=%v target=%q", p != nil, encPath != nil, encPath != nil && encPath.Enable, target)
		return meta
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		log.Infof("[v2-inspect] request creation failed: err=%v", err)
		return meta
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", ContentHeaderSize()-1))
	req.Header.Set("Accept-Encoding", "identity")
	if auth := authHeaders.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if cookie := authHeaders.Get("Cookie"); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if ua := authHeaders.Get("User-Agent"); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := p.streamClient.Do(req)
	if err != nil {
		log.Infof("[v2-inspect] upstream request failed: target=%.120s err=%v", target, err)
		return meta
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		log.Infof("[v2-inspect] upstream returned error status: target=%.120s status=%d", target, resp.StatusCode)
		return meta
	}
	prefix, err := io.ReadAll(io.LimitReader(resp.Body, ContentHeaderSize()))
	if err != nil {
		log.Infof("[v2-inspect] failed to read prefix bytes: target=%.120s err=%v", target, err)
		return meta
	}
	if total := parseContentRangeTotal(resp.Header.Get("Content-Range")); total > 0 {
		meta.CiphertextSize = total
		meta.PlainSize = total
	}
	if parsed, ok, err := ParseContentHeader(encType, prefix, meta.CiphertextSize); err == nil && ok {
		log.Infof("[v2] detected content header target=%s encType=%s headerLen=%d cipherSize=%d plainSize=%d",
			target, parsed.EncType, parsed.HeaderLen, parsed.CiphertextSize, parsed.PlainSize)
		return parsed
	} else {
		log.Infof("[v2-inspect] header not detected: target=%.120s encType=%q prefixLen=%d status=%d contentRange=%q ok=%v parseErr=%v first6=%x",
			target, encType, len(prefix), resp.StatusCode, resp.Header.Get("Content-Range"), ok, err, prefix[:min(len(prefix), 6)])
	}
	return meta
}

func (p *ProxyServer) inspectEncryptedContentWithFallback(ctx context.Context, target string, authHeaders http.Header, encPath *EncryptPath, ciphertextSize int64, encryptedPath string) ContentMeta {
	meta := p.inspectEncryptedContent(ctx, target, authHeaders, encPath, ciphertextSize)
	if meta.IsV2() && meta.PlainSize > 0 {
		return meta
	}
	if p == nil || encPath == nil || strings.TrimSpace(encryptedPath) == "" {
		return meta
	}
	// Defensive: strip any leading /dav or /d prefix so candidates don't double up
	if strings.HasPrefix(encryptedPath, "/dav") {
		encryptedPath = strings.TrimPrefix(encryptedPath, "/dav")
	} else if strings.HasPrefix(encryptedPath, "/d") {
		encryptedPath = strings.TrimPrefix(encryptedPath, "/d")
	}
	if encryptedPath == "" {
		return meta
	}
	alistURL := strings.TrimSpace(p.getAlistURL())
	if alistURL == "" {
		return meta
	}
	candidates := []string{
		alistURL + "/dav" + encryptedPath,
		alistURL + "/d" + encryptedPath,
	}
	seen := map[string]struct{}{}
	if trimmed := strings.TrimSpace(target); trimmed != "" {
		seen[trimmed] = struct{}{}
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		fallback := p.inspectEncryptedContent(ctx, candidate, authHeaders, encPath, ciphertextSize)
		if fallback.IsV2() && fallback.PlainSize > 0 {
			log.Infof("[v2] detected content header via fallback target=%s encType=%s headerLen=%d cipherSize=%d plainSize=%d",
				candidate, fallback.EncType, fallback.HeaderLen, fallback.CiphertextSize, fallback.PlainSize)
			return fallback
		}
	}
	return meta
}

func parseUploadStartOffset(contentRange string) int64 {
	contentRange = strings.TrimSpace(contentRange)
	if contentRange == "" {
		return 0
	}
	if !strings.HasPrefix(strings.ToLower(contentRange), "bytes ") {
		return 0
	}
	spec := strings.TrimSpace(contentRange[len("bytes "):])
	slash := strings.Index(spec, "/")
	if slash <= 0 {
		return 0
	}
	rangePart := strings.TrimSpace(spec[:slash])
	parts := strings.SplitN(rangePart, "-", 2)
	if len(parts) != 2 {
		return 0
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil || start < 0 {
		return 0
	}
	return start
}
