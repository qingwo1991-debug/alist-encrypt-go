package handler

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

type mediaAliasRepository interface {
	PutVerifiedMediaAlias(storage.VerifiedMediaAlias) error
	GetVerifiedMediaAlias(string, string, string, string, int64) (storage.VerifiedMediaAlias, bool, error)
	GetVerifiedMediaAliasByDisplay(string, string, string, string, int64) (storage.VerifiedMediaAlias, bool, error)
}
type mediaPrefixInspector interface {
	InspectDecryptedMediaPrefix(context.Context, string, http.Header, *config.PasswdInfo, int64) (proxy.MediaIdentityResult, error)
}
type mediaRecoveryFlight struct {
	done   chan struct{}
	record storage.VerifiedMediaAlias
	ok     bool
}
type mediaRecoveryState struct {
	// mu serializes admission/Add, Stop's fence, and publication. Never hold it
	// while joining workers: their completion also needs this lock.
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	stopped  bool
	workers  sync.WaitGroup
	flights  map[string]*mediaRecoveryFlight
	failures map[string]time.Time
	sem      chan struct{}
}

func (s *mediaRecoveryState) initLocked() {
	if s.ctx == nil {
		s.ctx, s.cancel = context.WithCancel(context.Background())
	}
	if s.flights == nil {
		s.flights = make(map[string]*mediaRecoveryFlight)
		s.failures = make(map[string]time.Time)
		s.sem = make(chan struct{}, 2)
	}
}

func (s *mediaRecoveryState) stop() {
	s.mu.Lock()
	s.stopped = true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	// All positive Add calls occur under mu after checking stopped, so no
	// admission can race with Wait, including on a zero-value handler.
	s.workers.Wait()
}

type verifiedFilenameRawPathKey struct{}
type verifiedFilenameRawPath struct{ display, raw string }

func rememberVerifiedFilenamePath(r *http.Request, display, raw string) {
	*r = *r.WithContext(context.WithValue(r.Context(), verifiedFilenameRawPathKey{}, verifiedFilenameRawPath{display, raw}))
}
func (h *WebDAVHandler) resolveRealPathForRequest(r *http.Request, display string, ep *config.PasswdInfo) (string, string) {
	if bound, ok := r.Context().Value(verifiedFilenameRawPathKey{}).(verifiedFilenameRawPath); ok && bound.display == display {
		return bound.raw, pathModeCacheMapping
	}
	return h.resolveRealPathWithMode(display, ep)
}
func (h *WebDAVHandler) hasInvalidProtectedFilenameScope(r *http.Request, display string) bool {
	getter, ok := h.fileDAO.(interface {
		GetFilenameReservation(string, string) (storage.FilenameRecord, bool, error)
	})
	if !ok || h.cfg == nil || h.passwdDAO == nil {
		return false
	}
	raw, ok := h.fileDAO.GetEncPath(display)
	if !ok {
		return false
	}
	saved, found, err := getter.GetFilenameReservation(h.cfg.GetAlistURL(), raw)
	if err != nil || !found || saved.OriginalPath != display {
		return false
	}
	ep, found := h.passwdDAO.FindByPath(display)
	return !found || ep == nil || saved.Status != storage.FilenameComplete || saved.AuthScope != filenameRequestScope(r) || saved.RuleFingerprint != filenameRuleScope(ep)
}

// Alias restoration is credential/rule scoped and precedes generic orig_ passthrough.
// Ordinary upstream authorization remains mandatory for GET/HEAD.
func (h *WebDAVHandler) restoreVerifiedAliasMapping(r *http.Request, display string) (storage.VerifiedMediaAlias, bool) {
	repo, ok := h.fileDAO.(mediaAliasRepository)
	if !ok || h.passwdDAO == nil || h.cfg == nil {
		return storage.VerifiedMediaAlias{}, false
	}
	ep, found := h.passwdDAO.FindByPath(display)
	if !found || ep == nil {
		return storage.VerifiedMediaAlias{}, false
	}
	if reservations, ok := h.fileDAO.(interface {
		GetFilenameReservationByOriginal(string, string, string, string) (storage.FilenameRecord, bool, error)
	}); ok {
		saved, present, err := reservations.GetFilenameReservationByOriginal(h.cfg.GetAlistURL(), display, filenameRequestScope(r), filenameRuleScope(ep))
		if err == nil && present && saved.Status == storage.FilenameComplete {
			rememberVerifiedFilenamePath(r, display, saved.EncryptedPath)
		}
	}
	rec, found, err := repo.GetVerifiedMediaAliasByDisplay(h.cfg.GetAlistURL(), display, filenameRequestScope(r), filenameRuleScope(ep), 0)
	if err != nil || !found {
		return storage.VerifiedMediaAlias{}, false
	}
	rememberVerifiedFilenamePath(r, display, rec.EncryptedPath)
	return rec, true
}

type mediaAliasResponseWriter struct {
	http.ResponseWriter
	mime    string
	display string
	wrote   bool
}

func (w *mediaAliasResponseWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if status >= 200 && status < 300 {
		w.Header().Set("Content-Type", w.mime)
		w.Header().Set("Content-Disposition", "inline; filename*=UTF-8''"+url.PathEscape(path.Base(w.display)))
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *mediaAliasResponseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func isRecoveredMediaAliasPath(display string) bool {
	base := path.Base(display)
	if !strings.HasPrefix(base, encryption.OrigPrefix) {
		return false
	}
	ext := strings.ToLower(path.Ext(base))
	switch ext {
	case ".mp4", ".mkv", ".webm", ".mov", ".avi", ".flv", ".ts":
	default:
		return false
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(base, encryption.OrigPrefix), path.Ext(base))
	if len(payload) < 4 {
		return false
	}
	for _, c := range payload {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~+", c) {
			return false
		}
	}
	return true
}

var mediaResponseRE = regexp.MustCompile(`(?s)<(?:D:|d:)?response>.*?</(?:D:|d:)?response>`)
var mediaDisplayRE = regexp.MustCompile(`(?s)<((?:D:|d:)?displayname)>.*?</(?:D:|d:)?displayname>`)
var mediaHrefRE = regexp.MustCompile(`(?s)<((?:D:|d:)?href)>.*?</(?:D:|d:)?href>`)
var mediaTypeRE = regexp.MustCompile(`(?s)<((?:D:|d:)?getcontenttype)>.*?</(?:D:|d:)?getcontenttype>`)
var mediaLengthRE = regexp.MustCompile(`(?s)<((?:D:|d:)?getcontentlength)>.*?</(?:D:|d:)?getcontentlength>`)

func escapedMediaText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func replaceMediaProperty(block []byte, re *regexp.Regexp, value string) []byte {
	return re.ReplaceAllFunc(block, func(old []byte) []byte {
		m := re.FindSubmatch(old)
		tag := string(m[1])
		return []byte("<" + tag + ">" + escapedMediaText(value) + "</" + tag + ">")
	})
}

// Recovery is opt-in per mount. At most four unconfirmed candidates are awaited
// per listing, under one eight-second budget. Persisted positive results cost no
// network operation; failures have a five-minute bounded negative cache.
func (h *WebDAVHandler) recoverMediaNames(r *http.Request, body []byte, snapshot bool, originalBody ...[]byte) []byte {
	if h == nil || h.cfg == nil || h.passwdDAO == nil {
		return body
	}
	repo, ok := h.fileDAO.(mediaAliasRepository)
	if !ok {
		return body
	}
	inspector, ok := h.streamProxy.(mediaPrefixInspector)
	if !ok {
		return body
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	attempts := 0
	// The generic rewrite may already turn ciphertext length into plaintext.
	// Only untouched live XML is authoritative evidence for admission.
	actualSizes := make(map[string]int64)
	if !snapshot && len(originalBody) > 0 {
		for _, entry := range h.parsePropfindEntries(originalBody[0]) {
			actualSizes[entry.Path] = entry.Size
		}
	}
	return mediaResponseRE.ReplaceAllFunc(body, func(block []byte) []byte {
		var response struct {
			Href  string `xml:"href"`
			Props []struct {
				Status string `xml:"status"`
				Prop   struct {
					Name     string `xml:"displayname"`
					Size     int64  `xml:"getcontentlength"`
					Resource struct {
						Collection *struct{} `xml:"collection"`
					} `xml:"resourcetype"`
				} `xml:"prop"`
			} `xml:"propstat"`
		}
		if xml.Unmarshal(block, &response) != nil || !strings.HasPrefix(response.Href, "/dav/") {
			return block
		}
		u, err := url.Parse(response.Href)
		if err != nil || u.Host != "" || u.RawQuery != "" || u.Fragment != "" {
			return block
		}
		raw := strings.TrimPrefix(u.Path, "/dav")
		var name string
		var size int64
		isDir := false
		for _, p := range response.Props {
			if !strings.Contains(p.Status, " 200 ") {
				continue
			}
			if p.Prop.Name != "" {
				name = p.Prop.Name
			}
			if p.Prop.Size > 0 {
				size = p.Prop.Size
			}
			if p.Prop.Resource.Collection != nil {
				isDir = true
			}
		}
		if isDir || !strings.HasSuffix(raw, ".bin") || path.Clean(raw) != raw {
			return block
		}
		requestPath := strings.TrimPrefix(r.URL.Path, "/dav")
		expectedDir := strings.TrimSuffix(requestPath, "/")
		if strings.TrimSpace(r.Header.Get("Depth")) == "0" {
			expectedDir = path.Dir(requestPath)
			if raw != requestPath {
				return block
			}
		}
		if path.Dir(raw) != expectedDir {
			return block
		}
		base := path.Base(raw)
		if strings.HasPrefix(base, encryption.OrigPrefix) {
			raw = path.Join(path.Dir(raw), strings.TrimPrefix(base, encryption.OrigPrefix))
			base = path.Base(raw)
		}
		if protectedFilenameLimit(h.cfg, raw) == 0 {
			return block
		}
		ep, found := h.passwdDAO.FindByPath(raw)
		if !found || ep == nil || !ep.Enable || !ep.EncName {
			return block
		}
		decoded := encryption.ConvertShowNameWithSuffixOptions(ep.Password, ep.EncType, base, ep.EncSuffix, false)
		if !encryption.IsOriginalFile(decoded) {
			return block
		}
		if name != "" && !encryption.IsOriginalFile(name) && name != base {
			return block
		}
		observed := size
		if actual, ok := actualSizes[raw]; ok {
			observed = actual
		}
		if snapshot {
			observed = 0
		}
		auth, rule := filenameRequestScope(r), filenameRuleScope(ep)
		rec, found, err := repo.GetVerifiedMediaAlias(h.cfg.GetAlistURL(), raw, auth, rule, observed)
		if err != nil {
			return block
		}
		if !found && attempts < 4 && ctx.Err() == nil && !h.mediaRecoveryCoolingDown(raw, auth, rule, observed) {
			attempts++
			rec, found = h.resolveMediaRecovery(ctx, r, repo, inspector, ep, raw, auth, rule, observed)
		}
		if !found {
			return block
		}
		block = replaceMediaProperty(block, mediaDisplayRE, path.Base(rec.DisplayPath))
		block = replaceMediaProperty(block, mediaHrefRE, (&url.URL{Path: "/dav" + rec.DisplayPath}).EscapedPath())
		block = replaceMediaProperty(block, mediaTypeRE, rec.MIME)
		block = replaceMediaProperty(block, mediaLengthRE, strconv.FormatInt(rec.PlainSize, 10))
		return block
	})
}

func (h *WebDAVHandler) mediaRecoveryCoolingDown(raw, auth, rule string, size int64) bool {
	key := filenameScopeDigest(h.cfg.GetAlistURL(), raw, auth, rule, strconv.FormatInt(size, 10))
	h.mediaRecovery.mu.Lock()
	defer h.mediaRecovery.mu.Unlock()
	return time.Now().Before(h.mediaRecovery.failures[key])
}

func (h *WebDAVHandler) resolveMediaRecovery(ctx context.Context, r *http.Request, repo mediaAliasRepository, inspector mediaPrefixInspector, ep *config.PasswdInfo, raw, auth, rule string, size int64) (storage.VerifiedMediaAlias, bool) {
	revision := h.cfg.RuntimeRevision()
	origin := h.cfg.GetAlistURL()
	// A caller may hold a rule cached before the latest management update.
	// Bind the flight to a fresh rule snapshot, not merely a new generation
	// number paired with an old credential/rule.
	if fresh, ok := h.passwdDAO.(interface {
		FindByPathFresh(string) (*config.PasswdInfo, bool)
	}); ok {
		current, found := fresh.FindByPathFresh(raw)
		if !found || current == nil || filenameRuleScope(current) != rule {
			return storage.VerifiedMediaAlias{}, false
		}
		ep = current
	}
	if h.cfg.RuntimeRevision() != revision {
		return storage.VerifiedMediaAlias{}, false
	}
	key := filenameScopeDigest(origin, raw, auth, rule, strconv.FormatInt(size, 10))
	s := &h.mediaRecovery
	s.mu.Lock()
	if s.stopped || ctx.Err() != nil {
		s.mu.Unlock()
		return storage.VerifiedMediaAlias{}, false
	}
	s.initLocked()
	if rec, ok, err := repo.GetVerifiedMediaAlias(origin, raw, auth, rule, size); err == nil && ok {
		s.mu.Unlock()
		return rec, true
	}
	if until := s.failures[key]; time.Now().Before(until) {
		s.mu.Unlock()
		return storage.VerifiedMediaAlias{}, false
	}
	flight := s.flights[key]
	if flight == nil {
		if len(s.flights) >= 32 {
			s.mu.Unlock()
			return storage.VerifiedMediaAlias{}, false
		}
		flight = &mediaRecoveryFlight{done: make(chan struct{})}
		s.flights[key] = flight
		headers := r.Header.Clone()
		info := *ep
		info.EncPath = append([]string(nil), ep.EncPath...)
		limit := protectedFilenameLimit(h.cfg, raw)
		worker, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		s.workers.Add(1)
		go func() {
			// Five-minute cooldown is reserved for inspected-but-unknown format.
			// Transient transport/storage failures retry after a short backoff;
			// authorization refusal and cancellation are not format evidence.
			cooldown := 15 * time.Second
			defer s.workers.Done()
			defer cancel()
			defer func() {
				s.mu.Lock()
				delete(s.flights, key)
				// Lifecycle cancellation and stale configuration are not format
				// evidence. Preserve the bounded cooldown for other failures.
				if !flight.ok && cooldown > 0 && !s.stopped && worker.Err() == nil && h.cfg.RuntimeRevision() == revision {
					if len(s.failures) >= 2048 {
						clear(s.failures)
					}
					s.failures[key] = time.Now().Add(cooldown)
				}
				close(flight.done)
				s.mu.Unlock()
			}()
			select {
			case s.sem <- struct{}{}:
				defer func() { <-s.sem }()
			case <-worker.Done():
				return
			}
			if worker.Err() != nil {
				return
			}
			target := origin + (&url.URL{Path: "/dav" + raw}).EscapedPath()
			out, err := inspector.InspectDecryptedMediaPrefix(worker, target, headers, &info, size)
			if err != nil {
				if out.UpstreamStatus == http.StatusUnauthorized || out.UpstreamStatus == http.StatusForbidden {
					cooldown = 0
				}
				return
			}
			if !out.Reusable || !strings.HasPrefix(out.MIME, "video/") || out.Ext == "" {
				cooldown = 5 * time.Minute
				return
			}
			// Serialize publication against Stop; cancellation-ignoring readers
			// must not write after the admission fence has closed.
			s.mu.Lock()
			defer s.mu.Unlock()
			current, ok := h.passwdDAO.FindByPath(raw)
			if fresh, supported := h.passwdDAO.(interface {
				FindByPathFresh(string) (*config.PasswdInfo, bool)
			}); supported {
				current, ok = fresh.FindByPathFresh(raw)
			}
			if s.stopped || worker.Err() != nil || !ok || current == nil || h.cfg.RuntimeRevision() != revision || h.cfg.GetAlistURL() != origin || filenameRuleScope(current) != rule || protectedFilenameLimit(h.cfg, raw) != limit {
				return
			}
			m := out.Meta
			rec := storage.VerifiedMediaAlias{Origin: origin, EncryptedPath: raw, DisplayPath: path.Join(path.Dir(raw), encryption.OrigPrefix+strings.TrimSuffix(path.Base(raw), path.Ext(raw))+out.Ext), AuthScope: auth, RuleFingerprint: rule, CiphertextSize: m.CiphertextSize, PlainSize: m.PlainSize, ContentVersion: m.Version, HeaderLen: m.HeaderLen, NonceField: append([]byte(nil), m.NonceField...), ChunkSize: uint32(m.ChunkSize), KDFIterations: m.KDFIterations, EncType: m.EncType, ETag: out.ETag, LastModified: out.LastModified, ValidatorScope: out.ValidatorScope, VerifiedAt: time.Now().UTC(), MIME: out.MIME, Ext: out.Ext, Provenance: storage.VerifiedMediaAliasProvenance}
			published, err := h.cfg.PublishIfRevision(revision, func() error {
				return repo.PutVerifiedMediaAlias(rec)
			})
			if err != nil || !published {
				return
			}
			flight.record, flight.ok = rec, true
		}()
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return storage.VerifiedMediaAlias{}, false
	case <-flight.done:
		return flight.record, flight.ok
	}
}
