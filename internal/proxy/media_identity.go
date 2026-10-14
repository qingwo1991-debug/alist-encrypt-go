package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// MediaIdentityResult is evidence from a bounded decrypted prefix, not a claim
// that the complete file is valid. ValidatorScope excludes URL query tokens.
type MediaIdentityResult struct {
	Meta                                          encryption.ContentMeta
	Ext, MIME, ETag, LastModified, ValidatorScope string
	UpstreamStatus                                int
	Reusable                                      bool
	V3Layout, Reason                              string
	BytesRead, RecordBytes                        int64
	RecordAuthenticated                           bool
}

// StopMediaRecognition closes the instance admission fence and joins recognition
// operations only. It does not stop playback or the global KDF service.
func (s *StreamProxy) StopMediaRecognition() {
	s.mediaRecognitionMu.Lock()
	if s.mediaRecognition == nil {
		s.mediaRecognition = encryption.NewMediaRecognizer(encryption.MediaRecognitionConfig{})
	}
	owner := s.mediaRecognition
	s.mediaRecognitionMu.Unlock()
	owner.Stop()
}

// InspectDecryptedMediaPrefix is optional and deliberately not part of proxy
// ports. V3 must authenticate a complete record, under instance-owned admission.
func (s *StreamProxy) InspectDecryptedMediaPrefix(ctx context.Context, targetURL string, authHeaders http.Header, passwdInfo *config.PasswdInfo, ciphertextSize int64) (MediaIdentityResult, error) {
	var out MediaIdentityResult
	if s == nil || s.client == nil || s.client.Client == nil || passwdInfo == nil || !passwdInfo.Enable {
		return out, fmt.Errorf("media identity: disabled inspector")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := 8 * time.Second
	if s.cfg != nil && s.cfg.AlistServerSnapshot().MediaRecognitionLargeRecordOptIn {
		deadline = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	// Metadata and payload probes both use explicit redirects, even when a
	// caller installed an automatically redirecting HTTP client.
	client := *s.client.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	probe := &StreamProxy{cfg: s.cfg, client: &Client{Client: &client}}
	// Try the strictly bounded shared header/record path first, so V3 never
	// inherits permissive legacy parsing or a separate unaccounted tail probe.
	if ciphertextSize >= encryption.V3HeaderSize {
		s.mediaRecognitionMu.Lock()
		if s.mediaRecognition == nil {
			large := false
			if s.cfg != nil {
				large = s.cfg.AlistServerSnapshot().MediaRecognitionLargeRecordOptIn
			}
			s.mediaRecognition = encryption.NewMediaRecognizer(encryption.MediaRecognitionConfig{LargeRecordOptIn: large})
		}
		owner := s.mediaRecognition
		large := false
		if s.cfg != nil {
			large = s.cfg.AlistServerSnapshot().MediaRecognitionLargeRecordOptIn
		}
		owner.SetConfig(encryption.MediaRecognitionConfig{LargeRecordOptIn: large})
		s.mediaRecognitionMu.Unlock()
		v3, err := owner.RecognizeV3(ctx, &client, targetURL, passwdInfo.Password, authHeaders, ciphertextSize)
		out.Meta, out.UpstreamStatus = v3.Meta, v3.Status
		out.Meta.EncType = encryption.EncType(passwdInfo.EncType)
		out.V3Layout, out.Reason = v3.Layout, v3.Reason
		out.Ext, out.MIME = v3.Ext, v3.MIME
		out.ETag, out.LastModified, out.ValidatorScope = v3.ETag, v3.LastModified, v3.ValidatorScope
		out.BytesRead, out.RecordBytes, out.RecordAuthenticated = v3.BytesRead, v3.RecordBytes, v3.RecordAuthenticated
		out.Reusable = err == nil && v3.RecordAuthenticated && v3.ETag != "" && !strings.HasPrefix(strings.TrimSpace(v3.ETag), "W/")
		if v3.Meta.Version == encryption.ContentVersionV3 || v3.Reason != "invalid_header" {
			return out, err
		}
	}
	inspection := probe.InspectEncryptedContentResult(ctx, targetURL, authHeaders, passwdInfo, ciphertextSize)
	out = MediaIdentityResult{Meta: inspection.Meta, UpstreamStatus: inspection.StatusCode}
	meta := inspection.Meta
	if !inspection.Confirmed || meta.CiphertextSize <= 0 || meta.PlainSize <= 0 {
		return out, fmt.Errorf("media identity: unconfirmed geometry")
	}
	if ciphertextSize > 0 && ciphertextSize != meta.CiphertextSize {
		return out, fmt.Errorf("media identity: observed ciphertext size changed")
	}
	if meta.HeaderLen < 0 || meta.HeaderLen > 32 || meta.CiphertextSize != meta.HeaderLen+meta.PlainSize {
		return out, fmt.Errorf("media identity: invalid geometry")
	}
	count := int64(4096)
	if meta.PlainSize < count {
		count = meta.PlainSize
	}
	// Include the V2 header in the payload response, so a same-size replacement
	// between the metadata probe and this response cannot reuse the old nonce.
	start := int64(0)
	end := meta.HeaderLen + count - 1
	current := targetURL
	headers := authHeaders
	for hop := 0; hop <= 2; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
		req.Header.Set("Accept-Encoding", "identity")
		copyProbeAuthHeaders(req, headers)
		resp, err := client.Do(req)
		if err != nil {
			return out, err
		}
		out.UpstreamStatus = resp.StatusCode
		if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308 {
			location := resp.Header.Get("Location")
			resp.Body.Close()
			next, err := resolveRedirectTarget(current, location)
			if err != nil || location == "" {
				return out, fmt.Errorf("media identity: invalid redirect")
			}
			previous, _ := url.Parse(current)
			u, _ := url.Parse(next)
			if previous == nil || u == nil || !sameRedirectOrigin(previous, u) {
				headers = make(http.Header)
			}
			current = next
			continue
		}
		if resp.StatusCode != 200 && resp.StatusCode != 206 {
			resp.Body.Close()
			return out, fmt.Errorf("media identity: upstream status %d", resp.StatusCode)
		}
		if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
			resp.Body.Close()
			return out, fmt.Errorf("media identity: encoded representation")
		}
		offset := meta.HeaderLen
		readCount := count + offset
		if resp.StatusCode == 206 {
			cr, valid := parseContentRange(resp.Header.Get("Content-Range"))
			if !valid || !cr.TotalKnown || cr.Total != meta.CiphertextSize || cr.Start != start || cr.End != end || resp.ContentLength != readCount {
				resp.Body.Close()
				return out, fmt.Errorf("media identity: inconsistent range geometry")
			}
		} else {
			if resp.ContentLength != meta.CiphertextSize {
				resp.Body.Close()
				return out, fmt.Errorf("media identity: inconsistent full response size")
			}
		}
		// This bound is independent of the full object size, including Range-ignoring origins.
		if readCount > 8192 {
			resp.Body.Close()
			return out, fmt.Errorf("media identity: prefix budget exceeded")
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, readCount))
		resp.Body.Close()
		if err != nil {
			return out, err
		}
		if int64(len(b)) != readCount {
			return out, fmt.Errorf("media identity: truncated prefix")
		}
		if offset > 0 {
			parsed, recognized, err := encryption.ParseFrontMatter(encryption.EncType(passwdInfo.EncType), b, meta.CiphertextSize)
			if err != nil || !recognized || parsed.Version != meta.Version || parsed.EncType != meta.EncType || parsed.HeaderLen != meta.HeaderLen || parsed.PlainSize != meta.PlainSize || parsed.CiphertextSize != meta.CiphertextSize || string(parsed.NonceField) != string(meta.NonceField) {
				return out, fmt.Errorf("media identity: representation header changed")
			}
		}
		var cipher encryption.Cipher
		if meta.Version == encryption.ContentVersionV2 {
			cipher, err = encryption.NewCipherV2(encryption.EncType(passwdInfo.EncType), passwdInfo.Password, meta.PlainSize, meta.NonceField)
		} else {
			cipher, err = encryption.NewCipher(encryption.EncType(passwdInfo.EncType), passwdInfo.Password, meta.PlainSize)
		}
		if err != nil {
			return out, err
		}
		plain := b[offset:]
		cipher.Decrypt(plain)
		out.Ext, out.MIME, _ = encryption.DetectVideoFormat(plain)
		out.ETag, out.LastModified = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
		u, err := url.Parse(current)
		if err == nil {
			u.RawQuery = ""
			u.Fragment = ""
			u.User = nil
			out.ValidatorScope = strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.EscapedPath()
		}
		out.Reusable = true
		for _, vary := range resp.Header.Values("Vary") {
			for _, field := range strings.Split(vary, ",") {
				switch strings.ToLower(strings.TrimSpace(field)) {
				case "", "accept-encoding", "authorization", "cookie", "user-agent":
				default:
					out.Reusable = false
				}
			}
		}
		if out.Ext == "" {
			return out, fmt.Errorf("media identity: unknown video format")
		}
		return out, nil
	}
	return out, fmt.Errorf("media identity: redirect limit exceeded")
}
