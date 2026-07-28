package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	uploadFilePath := r.Header.Get("File-Path")
	originalContentRange := strings.TrimSpace(r.Header.Get("Content-Range"))
	parsedRange, hasContentRange := parsePlainUploadContentRange(originalContentRange)
	if originalContentRange != "" && !hasContentRange {
		return errors.NewEncryptionError("invalid Content-Range for encrypted upload")
	}
	if hasContentRange {
		if parsedRange.start != startOffset || parsedRange.total != fileSize {
			return errors.NewEncryptionError("Content-Range does not match encrypted upload offsets")
		}
		if r.ContentLength >= 0 && r.ContentLength != parsedRange.end-parsedRange.start+1 {
			return errors.NewEncryptionError("Content-Range length does not match upload body")
		}
	}
	var (
		encryptedBody io.Reader
		contentMeta   encryption.ContentMeta
		err           error
	)
	if startOffset > 0 {
		meta, ok := s.getUploadMeta(targetURL, uploadFilePath)
		if !ok {
			if !isWebDAVUploadTarget(targetURL) {
				return errors.NewEncryptionError("missing V2 upload metadata for resumed upload; restart from the first chunk")
			}
			var confirmed bool
			meta, confirmed = s.inspectEncryptedContentConfirmed(r.Context(), targetURL, r.Header, passwdInfo, fileSize)
			if !confirmed {
				return errors.NewEncryptionError("cannot determine encryption metadata for resumed WebDAV upload; restart from the first chunk")
			}
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
	}

	req, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(encryptedBody).
		CopyHeaders(r).
		Build()
	if err != nil {
		return errors.NewInternalWithCause("failed to create request", err)
	}
	plainContentLength := r.ContentLength
	if plainContentLength <= 0 {
		if parsed, parseErr := strconv.ParseInt(strings.TrimSpace(r.Header.Get("Content-Length")), 10, 64); parseErr == nil && parsed > 0 {
			plainContentLength = parsed
		}
	}
	rewriteUploadHeadersForV2(req, contentMeta, startOffset, originalContentRange, plainContentLength)

	resp, err := s.client.Do(req)
	if err != nil {
		return errors.NewProxyErrorWithCause("failed to upload", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		// The caller turns transport/upstream failures into its own error response.
		// Do not commit the upstream response here, otherwise the caller cannot
		// report the failure cleanly and may mistake it for a successful upload.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		return errors.NewProxyError(fmt.Sprintf("upstream upload status %d", resp.StatusCode))
	}
	if contentMeta.IsV2() {
		uploadComplete := (!hasContentRange && startOffset == 0) || (hasContentRange && parsedRange.end+1 == parsedRange.total)
		if uploadComplete {
			s.deleteUploadMeta(targetURL, uploadFilePath)
		} else {
			s.putUploadMeta(targetURL, uploadFilePath, contentMeta)
		}
	}

	// Copy response headers and write status
	httputil.CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	// Stream response with large buffer
	buf := getBuffer()
	defer putBuffer(buf)
	_, err = io.CopyBuffer(w, resp.Body, *buf)
	return err
}

func isWebDAVUploadTarget(targetURL string) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	targetPath := strings.TrimRight(parsed.Path, "/")
	return targetPath == "/dav" || strings.HasPrefix(targetPath, "/dav/")
}

type plainUploadContentRange struct {
	start int64
	end   int64
	total int64
}

func parsePlainUploadContentRange(contentRange string) (plainUploadContentRange, bool) {
	var result plainUploadContentRange
	contentRange = strings.TrimSpace(contentRange)
	if !strings.HasPrefix(strings.ToLower(contentRange), "bytes ") {
		return result, false
	}
	spec := strings.TrimSpace(contentRange[len("bytes "):])
	slash := strings.Index(spec, "/")
	if slash <= 0 || strings.Contains(spec[slash+1:], "/") {
		return result, false
	}
	parts := strings.SplitN(strings.TrimSpace(spec[:slash]), "-", 2)
	if len(parts) != 2 {
		return result, false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil || start < 0 {
		return result, false
	}
	end, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil || end < start {
		return result, false
	}
	total, err := strconv.ParseInt(strings.TrimSpace(spec[slash+1:]), 10, 64)
	if err != nil || total <= 0 || end >= total {
		return result, false
	}
	return plainUploadContentRange{start: start, end: end, total: total}, true
}

func rewriteUploadHeadersForV2(req *http.Request, meta encryption.ContentMeta, startOffset int64, originalContentRange string, plainContentLength int64) {
	if req == nil || !meta.IsV2() {
		return
	}
	ciphertextSize := meta.TotalCiphertextSize()
	if rewritten, ok := rewritePlainContentRangeToCiphertext(originalContentRange, meta.HeaderLen); ok {
		req.Header.Set("Content-Range", rewritten)
	}
	if plainContentLength > 0 {
		req.ContentLength = plainContentLength
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
	if headerLen <= 0 {
		return "", false
	}
	parsed, ok := parsePlainUploadContentRange(contentRange)
	if !ok {
		return "", false
	}
	ciphertextStart := parsed.start + headerLen
	if parsed.start == 0 {
		ciphertextStart = 0
	}
	return fmt.Sprintf("bytes %d-%d/%d", ciphertextStart, parsed.end+headerLen, parsed.total+headerLen), true
}
