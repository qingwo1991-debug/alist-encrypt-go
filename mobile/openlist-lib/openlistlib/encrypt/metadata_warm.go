package encrypt

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	metadataWarmCandidates      = 128
	metadataWarmDirectories     = 32
	metadataWarmPending         = 2
	metadataWarmTimeout         = 5 * time.Second
	metadataWarmSuccessCooldown = 24 * time.Hour
	metadataWarmErrorCooldown   = 5 * time.Minute
)

// Only unambiguous, single numeric episode names are eligible. Multiple numeric
// groups (years, seasons, versions) deliberately do not get ordinal guesses.
var metadataWarmNumber = regexp.MustCompile(`[0-9]+`)

type metadataWarmCandidate struct {
	davPath, objectPath, series, extension string
	episode                                uint64
	cipherSize                             int64
}

type metadataWarmDirectory struct {
	key        string
	candidates []metadataWarmCandidate
	truncated  bool
}

type metadataWarmTask struct {
	key, origin string
	candidate   metadataWarmCandidate
	headers     http.Header // Caller credentials exist only while a bounded task lives.
	enc         EncryptPath
}

// Zero-value usable. Parent owns one state per ProxyServer; never a global map
// retaining server/config/crypto pointers. All persistent keys are scoped hashes.
type metadataWarmState struct {
	mu                              sync.Mutex
	directories                     []metadataWarmDirectory // MRU first, at most 32.
	cooldown                        map[string]time.Time    // At most 128 keys; no raw credentials.
	running                         bool
	pending                         []metadataWarmTask // One running task plus at most two pending.
	successes, hits, drops, backoff atomic.Uint64
}

// Collector consumes an already fetched listing; it must never enumerate fs/list
// or fetch another directory. r.URL.Path must be the actual encrypted DAV parent.
type metadataWarmListing struct {
	p                    *ProxyServer
	key, parent          string
	candidates           []metadataWarmCandidate
	truncated, committed bool
}

func metadataWarmHash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func metadataWarmScope(origin string, headers http.Header, ep *EncryptPath) string {
	if ep == nil {
		return ""
	}
	return metadataWarmHash(origin, strings.Join(headers.Values("Authorization"), "\x00"),
		strings.Join(headers.Values("Cookie"), "\x00"), ep.Path, ep.Password,
		string(ep.EncType), strconv.FormatBool(ep.EncName), ep.EncSuffix,
		strconv.FormatBool(ep.Enable))
}

func (p *ProxyServer) metadataWarmEnabled() bool {
	if p == nil {
		return false
	}
	cfg := p.runtimeSnapshot().config
	return cfg != nil && cfg.MetadataNextWarmEnabled
}

func newMetadataWarmListing(p *ProxyServer, r *http.Request, ep *EncryptPath) *metadataWarmListing {
	if !p.metadataWarmEnabled() || r == nil || r.URL == nil || ep == nil {
		return nil
	}
	parent := strings.TrimRight(r.URL.Path, "/")
	if parent != "/dav" && !strings.HasPrefix(parent, "/dav/") {
		return nil
	}
	if path.Clean(parent) != parent {
		return nil
	}
	scope := metadataWarmScope(p.getAlistURL(), r.Header, ep)
	return &metadataWarmListing{p: p, parent: parent, key: metadataWarmHash(scope, parent)}
}

func metadataWarmEpisode(displayPath string) (series, extension string, episode uint64, ok bool) {
	name := path.Base(displayPath)
	extension = strings.ToLower(path.Ext(name))
	switch extension {
	case ".mp4", ".mkv", ".avi", ".mov", ".webm", ".m4v", ".ts", ".m2ts", ".wmv", ".flv":
	default:
		return "", "", 0, false
	}
	stem := strings.TrimSuffix(name, path.Ext(name))
	matches := metadataWarmNumber.FindAllStringIndex(stem, 2)
	if len(matches) != 1 {
		return "", "", 0, false
	}
	i, j := matches[0][0], matches[0][1]
	episode, err := strconv.ParseUint(stem[i:j], 10, 64)
	if err != nil || episode == ^uint64(0) {
		return "", "", 0, false
	}
	series = strings.ToLower(stem[:i]) + "\x00" + strings.ToLower(stem[j:])
	return series, extension, episode, true
}

// Only root-relative, direct-child, original XML hrefs are accepted. URI hosts,
// queries, fragments, traversal and escaped slash tricks cannot become targets.
func metadataWarmDAVChild(rawhref, parent string) (davPath, objectPath string, ok bool) {
	if len(rawhref) > 4096 || !strings.HasPrefix(rawhref, "/") || strings.HasPrefix(rawhref, "//") {
		return "", "", false
	}
	u, err := url.Parse(rawhref)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(rawhref, "#") {
		return "", "", false
	}
	if strings.ContainsAny(u.Path, "\\\x00\r\n") || path.Clean(u.Path) != u.Path || path.Dir(u.Path) != parent || u.Path == parent {
		return "", "", false
	}
	// A percent-encoded separator changes hierarchy after additional decoding.
	lower := strings.ToLower(u.EscapedPath())
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%25") {
		return "", "", false
	}
	return u.EscapedPath(), u.Path, true
}

func (l *metadataWarmListing) Observe(rawhref, displayPath string, cipherSize int64, collection bool) {
	if l == nil || l.committed || l.truncated || collection || cipherSize <= 0 || len(displayPath) > 4096 {
		return
	}
	davPath, objectPath, ok := metadataWarmDAVChild(rawhref, l.parent)
	if !ok {
		return
	}
	series, ext, episode, ok := metadataWarmEpisode(displayPath)
	if !ok {
		return
	}
	if len(l.candidates) == metadataWarmCandidates {
		l.truncated = true
		return
	}
	l.candidates = append(l.candidates, metadataWarmCandidate{davPath: davPath, objectPath: objectPath, series: series, extension: ext, episode: episode, cipherSize: cipherSize})
}

func (l *metadataWarmListing) Commit(success bool) {
	if l == nil || l.committed {
		return
	}
	l.committed = true
	if !success {
		return
	}
	state := &l.p.metadataWarm
	state.mu.Lock()
	defer state.mu.Unlock()
	state.rememberDirectory(metadataWarmDirectory{key: l.key, candidates: l.candidates, truncated: l.truncated})
}

// Called under mu. Replacing a listing never merges stale/partial candidates.
func (s *metadataWarmState) rememberDirectory(dir metadataWarmDirectory) {
	for i := range s.directories {
		if s.directories[i].key == dir.key {
			s.directories = append(s.directories[:i], s.directories[i+1:]...)
			break
		}
	}
	s.directories = append([]metadataWarmDirectory{dir}, s.directories...)
	if len(s.directories) > metadataWarmDirectories {
		s.directories = s.directories[:metadataWarmDirectories]
	}
}

func metadataWarmNext(dir metadataWarmDirectory, currentPath string) (metadataWarmCandidate, bool) {
	if dir.truncated {
		return metadataWarmCandidate{}, false
	}
	var current metadataWarmCandidate
	found := 0
	for _, c := range dir.candidates {
		if c.objectPath == currentPath {
			current = c
			found++
		}
	}
	if found != 1 {
		return metadataWarmCandidate{}, false
	}
	var next metadataWarmCandidate
	found = 0
	currentEpisodes := 0
	for _, c := range dir.candidates {
		if c.series != current.series || c.extension != current.extension {
			continue
		}
		if c.episode == current.episode {
			currentEpisodes++
		}
		if c.episode == current.episode+1 {
			next = c
			found++
		}
	}
	if found != 1 || currentEpisodes != 1 {
		return metadataWarmCandidate{}, false
	}
	return next, true
}

// The parent calls this only after the current GET actually wrote downstream
// bytes successfully, never on HEAD, metadata probing or before the first frame.
func (p *ProxyServer) maybeWarmNextMetadata(r *http.Request, encryptedPath string, enc *EncryptPath) {
	if !p.metadataWarmEnabled() || r == nil || r.Method != http.MethodGet || enc == nil {
		return
	}
	if GetNetworkState() == NetworkStateOffline || p.shouldFastFailUpstream() {
		p.metadataWarm.backoff.Add(1)
		return
	}
	// Accept an object path or an already prefixed DAV path, never a URL.
	if !strings.HasPrefix(encryptedPath, "/dav/") {
		encryptedPath = "/dav/" + strings.TrimPrefix(encryptedPath, "/")
	}
	if path.Clean(encryptedPath) != encryptedPath {
		return
	}
	origin := p.getAlistURL()
	scope := metadataWarmScope(origin, r.Header, enc)
	key := metadataWarmHash(scope, path.Dir(encryptedPath))
	state := &p.metadataWarm
	state.mu.Lock()
	var next metadataWarmCandidate
	ok := false
	for i, dir := range state.directories {
		if dir.key == key {
			next, ok = metadataWarmNext(dir, encryptedPath)
			copy(state.directories[1:i+1], state.directories[:i])
			state.directories[0] = dir
			break
		}
	}
	if !ok {
		state.mu.Unlock()
		return
	}
	taskKey := metadataWarmHash(scope, next.objectPath)
	now := time.Now()
	if until := state.cooldown[taskKey]; now.Before(until) {
		state.mu.Unlock()
		state.hits.Add(1)
		return
	}
	if state.running && len(state.pending) >= metadataWarmPending {
		state.mu.Unlock()
		state.drops.Add(1)
		return
	}
	if state.cooldown == nil {
		state.cooldown = make(map[string]time.Time)
	}
	if len(state.cooldown) >= metadataWarmCandidates {
		var oldestKey string
		var oldest time.Time
		for k, until := range state.cooldown {
			if oldestKey == "" || until.Before(oldest) {
				oldestKey, oldest = k, until
			}
		}
		delete(state.cooldown, oldestKey)
	}
	state.cooldown[taskKey] = now.Add(metadataWarmErrorCooldown)
	task := metadataWarmTask{key: taskKey, origin: origin, candidate: next, headers: r.Header.Clone(), enc: *enc}
	if state.running {
		state.pending = append(state.pending, task)
		state.mu.Unlock()
		return
	}
	state.running = true
	state.mu.Unlock()
	if !p.goBackground(func(ctx context.Context) { p.metadataWarmLoop(ctx, task) }) {
		state.mu.Lock()
		state.running = false
		state.pending = nil
		state.mu.Unlock()
		state.drops.Add(1)
	}
}

// Pending tasks are snapshots, not authority to probe a newly configured
// backend or publish old-rule evidence under the current object's identity.
func (p *ProxyServer) metadataWarmTaskCurrent(task metadataWarmTask) bool {
	if p == nil || task.origin != p.getAlistURL() {
		return false
	}
	if p.runtimeSnapshot().config == nil {
		return false
	}
	current := p.findEncryptPath(strings.TrimPrefix(task.candidate.objectPath, "/dav"))
	return current != nil && current.Enable && confirmedMetadataCryptoFingerprint(current) == confirmedMetadataCryptoFingerprint(&task.enc)
}

func (p *ProxyServer) metadataWarmLoop(lifetime context.Context, task metadataWarmTask) {
	state := &p.metadataWarm
	for {
		if lifetime.Err() == nil && p.metadataWarmEnabled() && GetNetworkState() != NetworkStateOffline && !p.shouldFastFailUpstream() && p.metadataWarmTaskCurrent(task) {
			ctx, cancel := context.WithTimeout(lifetime, metadataWarmTimeout)
			ctx = withConfirmedMetadataWarmBudget(ctx)
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, task.origin+task.candidate.davPath, nil)
			ok := false
			if err == nil {
				r.Header = task.headers
				r = p.withConfirmedMetadataIdentity(r, task.candidate.davPath, &task.enc)
				meta, recognized := p.resolveConfirmedMetadata(r.Context(), task.origin+task.candidate.davPath, r.Header, &task.enc, task.candidate.cipherSize)
				ok = metadataWarmConfirmedComplete(r.Context(), meta, recognized)
			}
			cancel()
			state.mu.Lock()
			if ok {
				state.cooldown[task.key] = time.Now().Add(metadataWarmSuccessCooldown)
			} else {
				state.cooldown[task.key] = time.Now().Add(metadataWarmErrorCooldown)
			}
			state.mu.Unlock()
			if ok {
				state.successes.Add(1)
			}
		} else {
			state.backoff.Add(1)
		}
		// Clear short-lived credential/rule references before acquiring next work.
		task = metadataWarmTask{}
		state.mu.Lock()
		if lifetime.Err() != nil || len(state.pending) == 0 {
			state.pending = nil
			state.running = false
			state.mu.Unlock()
			return
		}
		task = state.pending[0]
		state.pending[0] = metadataWarmTask{}
		state.pending = state.pending[1:]
		state.mu.Unlock()
	}
}

// Recognition alone includes malformed V3 and non-reusable Vary responses.
// Only a fully validated, attached cache record earns the 24h cooldown.
func metadataWarmConfirmedComplete(ctx context.Context, meta ContentMeta, recognized bool) bool {
	if !recognized {
		return false
	}
	holder := confirmedMetadataRequestFromContext(ctx)
	if holder == nil {
		return false
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	rec := holder.record
	rec.Meta = meta
	return holder.attached && rec.Identity == holder.identity && validConfirmedMetadataRecord(rec)
}

// Exportable by the parent's diagnostics endpoint, without secrets or paths.
func (p *ProxyServer) metadataWarmStats() map[string]uint64 {
	s := &p.metadataWarm
	return map[string]uint64{"successes": s.successes.Load(), "hits": s.hits.Load(), "drops": s.drops.Load(), "backoff": s.backoff.Load()}
}

type metadataWarmWriter struct {
	http.ResponseWriter
	onFirstWrite func()
	once         sync.Once
}

func metadataWarmFirstWriter(w http.ResponseWriter, onFirstWrite func()) http.ResponseWriter {
	return &metadataWarmWriter{ResponseWriter: w, onFirstWrite: onFirstWrite}
}

func (w *metadataWarmWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if n > 0 && err == nil {
		w.once.Do(func() {
			if w.onFirstWrite != nil {
				w.onFirstWrite()
			}
		})
	}
	return n, err
}

// Preserve streaming flushes used by direct http.Flusher assertions. A flush
// alone does not trigger warming; only a successful Write above does.
func (w *metadataWarmWriter) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }

// ResponseController can still reach the original writer's optional interfaces.
func (w *metadataWarmWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
