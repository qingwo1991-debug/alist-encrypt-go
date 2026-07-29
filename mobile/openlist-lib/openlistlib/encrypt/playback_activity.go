package encrypt

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const playbackBackupIdleGrace = 12 * time.Second

// playbackActivityTracker keeps media backup traffic from competing with an
// active playback stream. The grace window deliberately remains active after a
// stream closes because players commonly close and reopen requests while
// seeking.
type playbackActivityTracker struct {
	activeStreams atomic.Int64
	lastActiveNS  atomic.Int64
	idleGrace     time.Duration
}

type playbackActivitySnapshot struct {
	Active        bool  `json:"active"`
	ActiveStreams int64 `json:"active_streams"`
	IdleForMS     int64 `json:"idle_for_ms"`
	ResumeAfterMS int64 `json:"resume_after_ms"`
	IdleGraceMS   int64 `json:"idle_grace_ms"`
}

func newPlaybackActivityTracker(idleGrace time.Duration) *playbackActivityTracker {
	if idleGrace < 0 {
		idleGrace = 0
	}
	return &playbackActivityTracker{idleGrace: idleGrace}
}

func (t *playbackActivityTracker) begin(now time.Time) func() {
	if t == nil {
		return func() {}
	}
	t.lastActiveNS.Store(now.UnixNano())
	t.activeStreams.Add(1)

	var once sync.Once
	return func() {
		once.Do(func() {
			t.lastActiveNS.Store(time.Now().UnixNano())
			t.activeStreams.Add(-1)
		})
	}
}

func (t *playbackActivityTracker) snapshot(now time.Time) playbackActivitySnapshot {
	if t == nil {
		return playbackActivitySnapshot{}
	}
	activeStreams := t.activeStreams.Load()
	graceMS := t.idleGrace.Milliseconds()
	if activeStreams > 0 {
		return playbackActivitySnapshot{
			Active:        true,
			ActiveStreams: activeStreams,
			ResumeAfterMS: graceMS,
			IdleGraceMS:   graceMS,
		}
	}

	lastActiveNS := t.lastActiveNS.Load()
	if lastActiveNS <= 0 {
		return playbackActivitySnapshot{IdleGraceMS: graceMS}
	}
	idleFor := now.Sub(time.Unix(0, lastActiveNS))
	if idleFor < 0 {
		idleFor = 0
	}
	resumeAfter := t.idleGrace - idleFor
	if resumeAfter < 0 {
		resumeAfter = 0
	}
	return playbackActivitySnapshot{
		Active:        resumeAfter > 0,
		IdleForMS:     idleFor.Milliseconds(),
		ResumeAfterMS: resumeAfter.Milliseconds(),
		IdleGraceMS:   graceMS,
	}
}

func (p *ProxyServer) ensurePlaybackActivityTracker() *playbackActivityTracker {
	if p == nil {
		return nil
	}
	p.playbackActivityOnce.Do(func() {
		p.playbackActivity = newPlaybackActivityTracker(playbackBackupIdleGrace)
	})
	return p.playbackActivity
}

func (p *ProxyServer) withPlaybackActivity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isPlaybackActivityRequest(r) {
			next(w, r)
			return
		}
		done := p.ensurePlaybackActivityTracker().begin(time.Now())
		defer done()
		next(w, r)
	}
}

func isPlaybackActivityRequest(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet || r.URL == nil {
		return false
	}
	requestPath := r.URL.Path
	return strings.HasPrefix(requestPath, "/redirect/") ||
		strings.HasPrefix(requestPath, "/api/play/stream/") ||
		strings.HasPrefix(requestPath, "/d/") ||
		strings.HasPrefix(requestPath, "/p/") ||
		requestPath == "/dav" ||
		strings.HasPrefix(requestPath, "/dav/") ||
		requestPath == "/dav2" ||
		strings.HasPrefix(requestPath, "/dav2/")
}

func (p *ProxyServer) handlePlaybackActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p.ensurePlaybackActivityTracker().snapshot(time.Now()))
}
