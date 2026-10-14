package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

type filenameReservationRepository interface {
	ReserveFilename(storage.FilenameRecord) (storage.FilenameRecord, error)
	FinishFilenameReservation(string, string, string, string) error
}

func protectedFilenameLimit(cfg *config.Config, displayPath string) int {
	if cfg == nil {
		return 0
	}
	best, limit := 0, 0
	for prefix, n := range cfg.AlistServerSnapshot().FilenameWriteLimits {
		prefix = strings.TrimSuffix(prefix, "/")
		if prefix != "" && n > 0 && (displayPath == prefix || strings.HasPrefix(displayPath, prefix+"/")) && len(prefix) > best {
			best, limit = len(prefix), n
		}
	}
	return limit
}
func filenameScopeDigest(parts ...string) string {
	h := sha256.New()
	for _, s := range parts {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
func filenameAuthScope(headers http.Header) string {
	return filenameScopeDigest(strings.Join(headers.Values("Authorization"), "\x00"), strings.Join(headers.Values("Cookie"), "\x00"), strings.Join(headers.Values("Proxy-Authorization"), "\x00"))
}
func filenameRequestScope(r *http.Request) string { return filenameAuthScope(r.Header) }
func filenameRuleFingerprint(p *config.PasswdInfo) string {
	return filenameScopeDigest(p.Password, p.EncType, p.EncSuffix, strings.Join(p.EncPath, "\x00"))
}
func filenameRuleScope(p *config.PasswdInfo) string { return filenameRuleFingerprint(p) }
func filenameWriteLimit(cfg *config.Config, displayPath string) int {
	return protectedFilenameLimit(cfg, displayPath)
}

type protectedFilenameWrite struct {
	repo         filenameReservationRepository
	record       storage.FilenameRecord
	expectedSize int64
}

// Reserve before any upstream body write. Even failed reservations remain
// claimed: a failed upload can have created a partial remote object.
func prepareFilenameWrite(cfg *config.Config, repository interface{}, r *http.Request, info *config.PasswdInfo, displayPath, legacyRawPath string, plainSize int64, hasRange bool, client *http.Client) (*protectedFilenameWrite, string, error) {
	limit := protectedFilenameLimit(cfg, displayPath)
	if limit == 0 || info == nil || !info.EncName {
		return nil, legacyRawPath, nil
	}
	if hasRange {
		return nil, "", fmt.Errorf("protected filename upload requires a complete non-resumed file")
	}
	suffix := info.EncSuffix
	if suffix == "" {
		suffix = path.Ext(displayPath)
	}
	encoded, short, err := encryption.BoundEncryptedFilename(info.Password, info.EncType, path.Base(displayPath), suffix, limit)
	if err != nil {
		return nil, "", err
	}
	raw := path.Join(path.Dir(displayPath), encoded)
	repo, ok := repository.(filenameReservationRepository)
	if !ok {
		return nil, "", fmt.Errorf("filename reservation store unavailable")
	}
	rec, err := repo.ReserveFilename(storage.FilenameRecord{Origin: cfg.GetAlistURL(), EncryptedPath: raw, OriginalPath: displayPath, DisplayName: short, RuleFingerprint: filenameRuleScope(info), AuthScope: filenameRequestScope(r), CiphertextSize: plainSize + 32})
	if err != nil {
		return nil, "", fmt.Errorf("filename destination cannot be reserved: %w", err)
	}
	write := &protectedFilenameWrite{repo: repo, record: rec, expectedSize: plainSize + 32}
	status, size, err := filenameRemoteHead(r, cfg.GetAlistURL(), raw, client)
	_ = size
	if err != nil || status != http.StatusNotFound {
		_ = write.finish(storage.FilenameFailed)
		return nil, "", fmt.Errorf("filename destination must be verified absent (status %d): %v", status, err)
	}
	return write, raw, nil
}
func (w *protectedFilenameWrite) finish(status string) error {
	return w.repo.FinishFilenameReservation(w.record.Origin, w.record.EncryptedPath, w.record.Token, status)
}
func (w *protectedFilenameWrite) verify(r *http.Request, client *http.Client) error {
	status, size, err := filenameRemoteHead(r, w.record.Origin, w.record.EncryptedPath, client)
	if err == nil && ((status >= 300 && status < 400) || (status >= 200 && status < 300 && size < 0)) {
		size, err = filenameRemotePropfind(r, w.record.Origin, w.record.EncryptedPath, client)
		if err == nil {
			status = http.StatusOK
		}
	}
	if err != nil || status < 200 || status >= 300 || size != w.expectedSize {
		_ = w.finish(storage.FilenameFailed)
		return fmt.Errorf("saved filename/size verification failed (status %d, size %d, expected %d): %v", status, size, w.expectedSize, err)
	}
	return w.finish(storage.FilenameComplete)
}
func filenameRemoteHead(r *http.Request, origin, raw string, client *http.Client) (int, int64, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	u, err := url.Parse(origin)
	if err != nil {
		return 0, 0, err
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/dav" + raw
	u.RawPath = ""
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header = r.Header.Clone()
	req.Header.Del("Range")
	req.Header.Del("Content-Length")
	req.Header.Del("File-Path")
	req.Header.Del("If-Match")
	req.Header.Del("If-None-Match")
	req.Header.Set("Accept-Encoding", "identity")
	if client == nil {
		client = http.DefaultClient
	}
	snapshot := *client
	snapshot.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := snapshot.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.ContentLength, nil
}

// Verify the canonical DAV resource without following a signed CDN redirect.
// Depth-zero successful properties must refer to precisely the requested path.
func filenameRemotePropfind(r *http.Request, origin, raw string, client *http.Client) (int64, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	u, err := url.Parse(origin)
	if err != nil {
		return 0, err
	}
	u.Path = "/dav" + raw
	u.RawPath = ""
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", u.String(), strings.NewReader(`<d:propfind xmlns:d="DAV:"><d:prop><d:getcontentlength/></d:prop></d:propfind>`))
	if err != nil {
		return 0, err
	}
	req.Header = r.Header.Clone()
	for _, k := range []string{"Range", "Content-Length", "File-Path", "If-Match", "If-None-Match", "If", "Destination", "Overwrite", "Lock-Token"} {
		req.Header.Del(k)
	}
	req.Header.Set("Depth", "0")
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept-Encoding", "identity")
	if client == nil {
		client = http.DefaultClient
	}
	snapshot := *client
	snapshot.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := snapshot.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMultiStatus {
		return 0, fmt.Errorf("canonical DAV verification status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return 0, err
	}
	if len(body) > 64*1024 {
		return 0, fmt.Errorf("canonical DAV verification response too large")
	}
	var ms struct {
		Responses []struct {
			Href  string `xml:"DAV: href"`
			Props []struct {
				Status string `xml:"DAV: status"`
				Prop   struct {
					Length string `xml:"DAV: getcontentlength"`
				} `xml:"DAV: prop"`
			} `xml:"DAV: propstat"`
		} `xml:"DAV: response"`
	}
	if err := xml.Unmarshal(body, &ms); err != nil {
		return 0, err
	}
	for _, entry := range ms.Responses {
		href, err := url.Parse(entry.Href)
		if err != nil {
			continue
		}
		if href.Host != "" && href.Host != u.Host || href.Scheme != "" && href.Scheme != u.Scheme || href.User != nil {
			continue
		}
		if href.Path != u.Path || href.RawQuery != "" || href.Fragment != "" {
			continue
		}
		for _, ps := range entry.Props {
			fields := strings.Fields(ps.Status)
			if len(fields) < 2 || fields[1] != "200" {
				continue
			}
			n, err := strconv.ParseInt(strings.TrimSpace(ps.Prop.Length), 10, 64)
			if err == nil && n >= 0 {
				return n, nil
			}
		}
	}
	return 0, fmt.Errorf("canonical DAV verification lacks matching successful size")
}

// Keep successful upstream headers private until physical name and durable
// completion are verified. This buffers only the small response, not the file.
type filenameWriteResponse struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func newFilenameWriteResponse() *filenameWriteResponse {
	return &filenameWriteResponse{header: make(http.Header)}
}
func (w *filenameWriteResponse) Header() http.Header { return w.header }
func (w *filenameWriteResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *filenameWriteResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if w.body.Len()+len(b) > 64*1024 {
		w.overflow = true
		return 0, fmt.Errorf("protected upload response exceeds limit")
	}
	return w.body.Write(b)
}
func (w *filenameWriteResponse) publish(dst http.ResponseWriter) {
	for k, v := range w.header {
		dst.Header()[k] = append([]string(nil), v...)
	}
	status := w.status
	if status == 0 {
		status = 200
	}
	dst.WriteHeader(status)
	_, _ = io.Copy(dst, &w.body)
}
