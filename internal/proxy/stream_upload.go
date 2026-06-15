package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
)

// ProxyUploadEncrypt uploads with encryption.
// startOffset should be the absolute file offset for chunked/resume uploads.
func (s *StreamProxy) ProxyUploadEncrypt(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, startOffset int64) error {
	var (
		encryptedBody io.Reader
		contentMeta   encryption.ContentMeta
		err           error
	)
	if startOffset > 0 {
		meta, ok := s.getUploadMeta(targetURL)
		if !ok {
			meta = encryption.LegacyContentMeta(encryption.EncType(passwdInfo.EncType), fileSize)
		}
		if !meta.IsV2() && (strings.Contains(targetURL, "/dav/") || strings.HasSuffix(targetURL, "/dav")) {
			meta = s.inspectEncryptedContent(r.Context(), targetURL, r.Header, passwdInfo, fileSize)
		}
		if meta.IsV2() {
			cipherImpl, cipherErr := encryption.NewCipherV2(encryption.EncType(passwdInfo.EncType), passwdInfo.Password, meta.PlainSize, meta.NonceField)
			if cipherErr != nil {
				return errors.NewEncryptionErrorWithCause("failed to create v2 cipher", cipherErr)
			}
			if err := cipherImpl.SetPosition(startOffset); err != nil {
				return errors.NewEncryptionErrorWithCause("failed to set upload offset", err)
			}
			encryptedBody = cipherImpl.EncryptReader(r.Body)
			contentMeta = meta
		} else {
			flowEnc, cipherErr := encryption.NewFlowEnc(passwdInfo.Password, passwdInfo.EncType, fileSize)
			if cipherErr != nil {
				return errors.NewEncryptionErrorWithCause("failed to create cipher", cipherErr)
			}
			if err := flowEnc.SetPosition(startOffset); err != nil {
				return errors.NewEncryptionErrorWithCause("failed to set upload offset", err)
			}
			encryptedBody = flowEnc.EncryptReader(r.Body)
			contentMeta = meta
		}
	} else {
		contentEnc, cipherErr := encryption.NewLatestContentEncryptor(passwdInfo.Password, passwdInfo.EncType, fileSize)
		if cipherErr != nil {
			return errors.NewEncryptionErrorWithCause("failed to create cipher", cipherErr)
		}
		encryptedBody, err = contentEnc.EncryptReader(r.Body, startOffset)
		if err != nil {
			return errors.NewEncryptionErrorWithCause("failed to create encrypt reader", err)
		}
		contentMeta = contentEnc.Meta
		s.putUploadMeta(targetURL, contentMeta)
	}

	req, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(encryptedBody).
		CopyHeaders(r).
		Build()
	if err != nil {
		return errors.NewInternalWithCause("failed to create request", err)
	}
	rewriteUploadHeadersForV2(req, contentMeta, startOffset, r.Header.Get("Content-Range"))

	resp, err := s.client.Do(req)
	if err != nil {
		return errors.NewProxyErrorWithCause("failed to upload", err)
	}
	defer resp.Body.Close()

	// Copy response headers and write status
	httputil.CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	// Stream response with large buffer
	buf := getBuffer()
	defer putBuffer(buf)
	_, err = io.CopyBuffer(w, resp.Body, *buf)
	return err
}
func rewriteUploadHeadersForV2(req *http.Request, meta encryption.ContentMeta, startOffset int64, originalContentRange string) {
	if req == nil || !meta.IsV2() {
		return
	}
	ciphertextSize := meta.TotalCiphertextSize()
	if rewritten, ok := rewritePlainContentRangeToCiphertext(originalContentRange, meta.HeaderLen); ok {
		req.Header.Set("Content-Range", rewritten)
	}
	if req.ContentLength > 0 {
		if startOffset == 0 {
			req.ContentLength += meta.HeaderLen
		}
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}
	if ciphertextSize > 0 {
		sizeStr := strconv.FormatInt(ciphertextSize, 10)
		req.Header.Set("X-File-Size", sizeStr)
		req.Header.Set("File-Size", sizeStr)
		req.Header.Set("X-Upload-Content-Length", sizeStr)
		req.Header.Set("X-Expected-Entity-Length", sizeStr)
	}
}

func rewritePlainContentRangeToCiphertext(contentRange string, headerLen int64) (string, bool) {
	contentRange = strings.TrimSpace(contentRange)
	if contentRange == "" || headerLen <= 0 {
		return "", false
	}
	if !strings.HasPrefix(strings.ToLower(contentRange), "bytes ") {
		return "", false
	}
	spec := strings.TrimSpace(contentRange[len("bytes "):])
	slash := strings.Index(spec, "/")
	if slash <= 0 {
		return "", false
	}
	rangePart := strings.TrimSpace(spec[:slash])
	totalPart := strings.TrimSpace(spec[slash+1:])
	parts := strings.SplitN(rangePart, "-", 2)
	if len(parts) != 2 {
		return "", false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil || start < 0 {
		return "", false
	}
	end, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil || end < start {
		return "", false
	}
	total, err := strconv.ParseInt(totalPart, 10, 64)
	if err != nil || total <= 0 {
		return "", false
	}
	return fmt.Sprintf("bytes %d-%d/%d", start+headerLen, end+headerLen, total+headerLen), true
}
