package encrypt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPlaybackActivityTrackerGraceWindow(t *testing.T) {
	tracker := newPlaybackActivityTracker(12 * time.Second)
	startedAt := time.Unix(1_000, 0)
	doneFirst := tracker.begin(startedAt)
	doneSecond := tracker.begin(startedAt.Add(time.Millisecond))

	active := tracker.snapshot(startedAt.Add(time.Second))
	if !active.Active || active.ActiveStreams != 2 {
		t.Fatalf("active snapshot = %+v", active)
	}

	doneFirst()
	doneFirst()
	if got := tracker.activeStreams.Load(); got != 1 {
		t.Fatalf("active streams after duplicate completion = %d, want 1", got)
	}
	doneSecond()
	lastActive := time.Unix(0, tracker.lastActiveNS.Load())
	coolingDown := tracker.snapshot(lastActive.Add(5 * time.Second))
	if !coolingDown.Active || coolingDown.ActiveStreams != 0 {
		t.Fatalf("cooldown snapshot = %+v", coolingDown)
	}
	if coolingDown.ResumeAfterMS != 7_000 {
		t.Fatalf("cooldown resume_after_ms = %d, want 7000", coolingDown.ResumeAfterMS)
	}

	idle := tracker.snapshot(lastActive.Add(13 * time.Second))
	if idle.Active || idle.ResumeAfterMS != 0 {
		t.Fatalf("idle snapshot = %+v", idle)
	}
}

func TestPlaybackActivityHandlerTracksOnlyGet(t *testing.T) {
	server := &ProxyServer{}
	started := make(chan struct{})
	release := make(chan struct{})
	handler := server.withPlaybackActivity(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/redirect/token", nil))
	}()
	<-started

	active := server.ensurePlaybackActivityTracker().snapshot(time.Now())
	if !active.Active || active.ActiveStreams != 1 {
		t.Fatalf("active GET snapshot = %+v", active)
	}
	close(release)
	<-done

	// The completion callback is idempotent, so request teardown cannot drive
	// the concurrent count below zero.
	completion := server.ensurePlaybackActivityTracker().begin(time.Now())
	completion()
	completion()
	if got := server.ensurePlaybackActivityTracker().activeStreams.Load(); got != 0 {
		t.Fatalf("active streams after duplicate completion = %d, want 0", got)
	}

	for _, testCase := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "head playback", method: http.MethodHead, path: "/redirect/token"},
		{name: "post playback", method: http.MethodPost, path: "/redirect/token"},
		{name: "non media API", method: http.MethodGet, path: "/api/fs/get"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			untrackedHandler := server.withPlaybackActivity(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			untrackedHandler(recorder, httptest.NewRequest(testCase.method, testCase.path, nil))
			if got := server.ensurePlaybackActivityTracker().activeStreams.Load(); got != 0 {
				t.Fatalf("active streams = %d, want 0", got)
			}
		})
	}
}

func TestHandlePlaybackActivity(t *testing.T) {
	server := &ProxyServer{}
	recorder := httptest.NewRecorder()
	server.handlePlaybackActivity(recorder, httptest.NewRequest(http.MethodGet, "/api/play/activity", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var snapshot playbackActivitySnapshot
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &fields); err != nil {
		t.Fatalf("decode response fields: %v", err)
	}
	for _, field := range []string{"active", "active_streams", "idle_for_ms", "resume_after_ms", "idle_grace_ms"} {
		if _, ok := fields[field]; !ok {
			t.Errorf("response missing JSON field %q: %s", field, recorder.Body.String())
		}
	}
	if snapshot.Active || snapshot.IdleGraceMS != playbackBackupIdleGrace.Milliseconds() {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}
