package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

// WarmKind distinguishes explicit current-target metadata work from cancellable
// speculation. This is not a media-request priority or an inferred session.
type WarmKind uint8

const (
	WarmForeground WarmKind = iota
	WarmSpeculative
)

var (
	ErrPlaybackInterestInvalid  = errors.New("invalid playback interest")
	ErrPlaybackInterestStale    = errors.New("stale playback interest")
	ErrPlaybackInterestCapacity = errors.New("playback interest capacity exhausted")
	ErrPlaybackInterestStopped  = errors.New("playback interest scheduler stopped")
)

const playbackInterestTTL = 5 * time.Minute
const playbackInterestSessions = 256
const playbackInterestPerSession = 32

type playbackSessionKey struct{ scope, session, provider string }
type playbackSession struct {
	generation uint64
	target     string
	touched    time.Time
	refs       map[string]*playbackInterestTask
}
type playbackTaskReference struct {
	generation uint64
	kind       WarmKind
}
type playbackInterestTask struct {
	key        string
	ctx        context.Context
	cancel     context.CancelFunc
	refs       map[playbackSessionKey]playbackTaskReference
	foreground bool // Metadata priority only; all trusted warm tasks remain speculative relative to live HTTP.
	finished   bool
	alist      config.AlistServer // Immutable origin/credential/routing snapshot at admission.
}

func validPlaybackSession(scope, session, provider string, generation uint64, target string) bool {
	return strings.TrimSpace(scope) != "" && len(scope) <= 1024 && strings.TrimSpace(session) != "" && len(session) <= 128 && strings.TrimSpace(provider) != "" && len(provider) <= 2048 && generation > 0 && strings.TrimSpace(target) != "" && len(target) <= 4096
}

// AdvancePlaybackInterest accepts only an opaque, already-authorized scope supplied
// by the caller. A client header, source IP, HEAD or Range is never session proof.
// The boolean reports a new generation; identical retries do not advance it.
func (ps *ProbeScheduler) AdvancePlaybackInterest(scope, session, provider string, generation uint64, target string) (bool, error) {
	return ps.advancePlaybackInterest(scope, session, provider, generation, target, false)
}

// ClearPlaybackInterest retains the monotonic generation tombstone. Delayed old
// withdraws cannot erase a new launch, and a cleared generation cannot re-enqueue.
func (ps *ProbeScheduler) ClearPlaybackInterest(scope, session, provider string, generation uint64) (bool, error) {
	return ps.advancePlaybackInterest(scope, session, provider, generation, "", true)
}

func (ps *ProbeScheduler) PlaybackInterestAvailable() bool {
	if ps == nil || !ps.enabled || ps.queue == nil {
		return false
	}
	select {
	case <-ps.done():
		return false
	default:
		return true
	}
}

func (ps *ProbeScheduler) advancePlaybackInterest(scope, session, provider string, generation uint64, target string, clear bool) (bool, error) {
	if ps == nil || !ps.enabled || ps.queue == nil {
		return false, ErrPlaybackInterestStopped
	}
	validationTarget := target
	if clear {
		validationTarget = "clear"
	}
	if !validPlaybackSession(scope, session, provider, generation, validationTarget) {
		return false, ErrPlaybackInterestInvalid
	}
	ps.queueMu.Lock()
	defer ps.queueMu.Unlock()
	select {
	case <-ps.done():
		return false, ErrPlaybackInterestStopped
	default:
	}
	now := time.Now()
	ps.prunePlaybackInterestsLocked(now)
	if ps.interests == nil {
		ps.interests = make(map[playbackSessionKey]*playbackSession)
	}
	k := playbackSessionKey{scope, session, provider}
	s := ps.interests[k]
	if s != nil {
		if generation < s.generation {
			return false, ErrPlaybackInterestStale
		}
		if generation == s.generation {
			if target != s.target {
				return false, ErrPlaybackInterestInvalid
			}
			s.touched = now
			return false, nil
		}
		ps.withdrawPlaybackSessionLocked(k, s)
	} else if len(ps.interests) >= playbackInterestSessions {
		return false, ErrPlaybackInterestCapacity
	}
	ps.interests[k] = &playbackSession{generation: generation, target: target, touched: now, refs: make(map[string]*playbackInterestTask)}
	ps.notifyDispatchLocked()
	return true, nil
}

func playbackInterestTaskKey(scope, provider string, file FileItem, auth http.Header, snapshots ...config.AlistServer) string {
	if len(snapshots) == 0 {
		snapshots = []config.AlistServer{{}}
	}
	// JSON map keys are sorted; all headers are conservatively scope-bound, including
	// custom provider credentials. No plaintext credential appears in registry keys.
	b, _ := json.Marshal(struct {
		Scope, Provider, Path, URL, Encrypted, Compat string
		Auth                                          http.Header
		Config                                        []config.AlistServer
	}{scope, provider, file.DisplayPath, file.TargetURL, file.EncryptedPath, file.CompatStorageKey, auth, snapshots})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// EnqueuePlaybackInterest joins an existing same-scope task without duplicating
// its transfer. Every admitted task uses the scheduler's fixed workers and real
// cancellable request context, not a detached goroutine or media-request context.
func (ps *ProbeScheduler) EnqueuePlaybackInterest(scope, session, provider string, generation uint64, file FileItem, auth http.Header, reportedSize int64, kind WarmKind) error {
	var alist config.AlistServer
	if ps != nil && ps.cfg != nil {
		alist = ps.cfg.AlistServerSnapshot()
	}
	return ps.EnqueuePlaybackInterestWithConfig(scope, session, provider, generation, file, auth, reportedSize, kind, alist)
}

// EnqueuePlaybackInterestWithConfig binds execution to the exact configuration
// snapshot used by the authenticated caller to validate the intent's origin.
func (ps *ProbeScheduler) EnqueuePlaybackInterestWithConfig(scope, session, provider string, generation uint64, file FileItem, auth http.Header, reportedSize int64, kind WarmKind, alist config.AlistServer) error {
	// Detach nested slices/maps too: the caller may reuse or mutate its snapshot.
	encoded, err := json.Marshal(alist)
	if err != nil {
		return ErrPlaybackInterestInvalid
	}
	var bound config.AlistServer
	if json.Unmarshal(encoded, &bound) != nil {
		return ErrPlaybackInterestInvalid
	}
	if ps == nil || !ps.enabled || ps.queue == nil {
		return ErrPlaybackInterestStopped
	}
	if !validPlaybackSession(scope, session, provider, generation, file.DisplayPath) || file.TargetURL == "" || (kind != WarmForeground && kind != WarmSpeculative) {
		return ErrPlaybackInterestInvalid
	}
	ps.queueMu.Lock()
	defer ps.queueMu.Unlock()
	select {
	case <-ps.done():
		return ErrPlaybackInterestStopped
	default:
	}
	ps.prunePlaybackInterestsLocked(time.Now())
	sk := playbackSessionKey{scope, session, provider}
	s := ps.interests[sk]
	if s == nil || generation != s.generation || s.target == "" {
		return ErrPlaybackInterestStale
	}
	if kind == WarmForeground && file.DisplayPath != s.target {
		return ErrPlaybackInterestInvalid
	}
	key := playbackInterestTaskKey(scope, provider, file, auth, bound)
	if existing, ok := s.refs[key]; ok {
		s.touched = time.Now()
		if kind == WarmForeground {
			existing.refs[sk] = playbackTaskReference{generation, kind}
			existing.foreground = true
			ps.notifyDispatchLocked()
		}
		return nil
	}
	if len(s.refs) >= playbackInterestPerSession {
		return ErrPlaybackInterestCapacity
	}
	if ps.interestTasks == nil {
		ps.interestTasks = make(map[string]*playbackInterestTask)
	}
	task := ps.interestTasks[key]
	if task != nil && task.ctx.Err() == nil && !task.finished {
		task.refs[sk] = playbackTaskReference{generation, kind}
		s.refs[key] = task
		s.touched = time.Now()
		if kind == WarmForeground {
			task.foreground = true
			ps.notifyDispatchLocked()
		}
		return nil
	}
	if task != nil {
		return ErrPlaybackInterestCapacity
	} // canceled transfer must actually drain before replacement
	if len(ps.queue)+len(ps.waiting) >= cap(ps.queue) {
		return ErrPlaybackInterestCapacity
	}
	// Active orphan transfers are still counted until their actual worker returns.
	// Bound their registry too; queue capacity alone doesn't include active tasks.
	limit := cap(ps.queue) + ps.workers
	if limit < cap(ps.queue) {
		limit = cap(ps.queue)
	}
	if len(ps.interestTasks) >= limit {
		return ErrPlaybackInterestCapacity
	}
	ctx, cancel := context.WithTimeout(ps.probeContext(), playbackInterestTTL)
	task = &playbackInterestTask{key: key, ctx: ctx, cancel: cancel, refs: map[playbackSessionKey]playbackTaskReference{sk: {generation, kind}}, foreground: kind == WarmForeground, alist: bound}
	ps.interestTasks[key] = task
	s.refs[key] = task
	s.touched = time.Now()
	if reportedSize > 0 {
		file.PropfindSize = reportedSize
	}
	ps.queue <- probeItem{file: file, authHeaders: auth.Clone(), source: probeSourceFirstFrame, queuedAt: time.Now(), interest: task}
	ps.notifyDispatchLocked()
	return nil
}

func (ps *ProbeScheduler) withdrawPlaybackSessionLocked(k playbackSessionKey, s *playbackSession) {
	for _, task := range s.refs {
		delete(task.refs, k)
		task.foreground = false
		for _, ref := range task.refs {
			if ref.kind == WarmForeground {
				task.foreground = true
				break
			}
		}
		if len(task.refs) == 0 {
			task.cancel()
		}
	}
	s.refs = nil
}
func (ps *ProbeScheduler) prunePlaybackInterestsLocked(now time.Time) {
	for k, s := range ps.interests {
		if now.Sub(s.touched) >= playbackInterestTTL {
			ps.withdrawPlaybackSessionLocked(k, s)
			delete(ps.interests, k)
		}
	}
}
func (ps *ProbeScheduler) finishPlaybackInterestLocked(task *playbackInterestTask) {
	if task == nil || task.finished {
		return
	}
	task.finished = true
	task.cancel()
	if ps.interestTasks[task.key] == task {
		delete(ps.interestTasks, task.key)
	}
	for k := range task.refs {
		if s := ps.interests[k]; s != nil && s.refs[task.key] == task {
			delete(s.refs, task.key)
		}
	}
	task.refs = nil
}
func (ps *ProbeScheduler) finishPlaybackInterest(task *playbackInterestTask) {
	ps.queueMu.Lock()
	defer ps.queueMu.Unlock()
	ps.finishPlaybackInterestLocked(task)
}
func (ps *ProbeScheduler) playbackItemPriorityLocked(item probeItem) int {
	if item.interest != nil {
		if item.interest.foreground {
			return 0
		}
		return 2
	}
	if item.source == probeSourceFirstFrame {
		return 0
	}
	return 1
}
func (ps *ProbeScheduler) playbackItemContext(item probeItem) context.Context {
	if item.interest != nil {
		return item.interest.ctx
	}
	return ps.probeContext()
}

// ensurePlaybackInterestAuth uses configured provider credentials, never the
// enc-api JWT. Login is a real task-context HTTP request, not an abandoned call.
func (ps *ProbeScheduler) ensurePlaybackInterestAuth(ctx context.Context, headers http.Header, snapshots ...config.AlistServer) (http.Header, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	headers = headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	if headers.Get("Authorization") != "" || headers.Get("Cookie") != "" {
		return headers, "request", nil
	}
	var alist config.AlistServer
	if len(snapshots) > 0 {
		alist = snapshots[0]
	} else if ps.cfg != nil {
		alist = ps.cfg.AlistServerSnapshot()
	}
	if raw := strings.TrimSpace(alist.ScanAuthHeader); raw != "" {
		headers.Set("Authorization", raw)
		return headers, "scan_header", nil
	}
	username, password := alist.ScanUsername, alist.ScanPassword
	if username == "" || password == "" {
		return headers, "none", nil
	}
	origin := config.BuildAlistURL(alist)
	scope := sha256.Sum256([]byte(origin + "\x00" + username + "\x00" + password))
	ps.jwtMu.Lock()
	token := ""
	if ps.cachedJWTScope == scope && time.Now().Before(ps.cachedJWTExpiry) {
		token = ps.cachedJWT
	}
	ps.jwtMu.Unlock()
	if token != "" {
		headers.Set("Authorization", token)
		return headers, "scan_jwt_cached", nil
	}
	token = fetchAlistJWTContext(ctx, origin, username, password)
	if err := ctx.Err(); err != nil {
		return nil, "", fmt.Errorf("interest login canceled: %w", err)
	}
	if token != "" {
		ps.jwtMu.Lock()
		ps.cachedJWT = token
		ps.cachedJWTScope = scope
		ps.cachedJWTExpiry = time.Now().Add(2 * time.Hour)
		ps.jwtMu.Unlock()
		headers.Set("Authorization", token)
		return headers, "scan_jwt", nil
	}
	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	return headers, "scan_basic", nil
}
