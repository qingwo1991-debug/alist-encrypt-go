package encrypt

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type firstByteTestWriter struct {
	header http.Header
	n      int
	err    error
}

func (w *firstByteTestWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *firstByteTestWriter) WriteHeader(int)           {}
func (w *firstByteTestWriter) Write([]byte) (int, error) { return w.n, w.err }

func TestPlaybackTimingSuccessfulBodyOnly(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status, n int
		err       error
		measured  bool
	}{
		{"implicit", 0, 1, nil, true}, {"partial_error", 206, 1, errors.New("disconnect"), true},
		{"zero", 200, 0, nil, false}, {"failure", 502, 1, nil, false}, {"redirect", 302, 1, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := &firstByteTestWriter{n: tc.n, err: tc.err}
			w, r, timing := withPlaybackTiming(dst, httptest.NewRequest("GET", "http://local/redirect/x", nil))
			timing.started = time.Now().Add(-25 * time.Millisecond)
			if _, ok := w.(http.Flusher); ok {
				t.Fatal("invented Flusher")
			}
			w2, _, same := withPlaybackTiming(w, r)
			if w2 != w || same != timing {
				t.Fatal("nested wrapper")
			}
			if tc.status != 0 {
				w.WriteHeader(tc.status)
			}
			_, _ = w.Write([]byte("x"))
			if (timing.firstByteLatencyMs > 0) != tc.measured {
				t.Fatalf("timing=%+v", timing)
			}
			if tc.measured && timing.firstByteLatencyMs < 25 {
				t.Fatal("prework excluded")
			}
			first := timing.firstByteLatencyMs
			_, _ = w.Write([]byte("x"))
			if timing.firstByteLatencyMs != first {
				t.Fatal("first measurement replaced")
			}
			if timing.headerLatencyMs != 0 {
				t.Fatal("body wrapper changed legacy header metric")
			}
		})
	}
	rec := httptest.NewRecorder()
	w, _, timing := withPlaybackTiming(rec, httptest.NewRequest("GET", "http://local/", nil))
	w.(http.Flusher).Flush()
	if timing.firstByteLatencyMs != 0 {
		t.Fatal("flush measured body")
	}
	if w.(interface{ Unwrap() http.ResponseWriter }).Unwrap() != rec {
		t.Fatal("unwrap lost")
	}
}

func TestPlaybackFirstByteSQLiteMigrationRestartExport(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "stats.db")
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE playback_stats (id TEXT PRIMARY KEY,path TEXT NOT NULL,provider TEXT NOT NULL DEFAULT '',bytes_served INTEGER NOT NULL DEFAULT 0,total_bytes INTEGER NOT NULL DEFAULT 0,duration_secs REAL NOT NULL DEFAULT 0,played_at INTEGER NOT NULL,completed INTEGER NOT NULL DEFAULT 0,content_type TEXT NOT NULL DEFAULT '')`)
	if err != nil {
		t.Fatal(err)
	}
	if err = initLocalSchema(db); err != nil {
		t.Fatal(err)
	}
	store := &localStore{db: db}
	if err = store.AppendPlayback(PlaybackStatsRecord{ID: "real", Path: "/real.mp4", PlayedAt: 1, FirstByteLatencyMs: 0.125, HeaderLatencyMs: 8}); err != nil {
		t.Fatal(err)
	}
	if err = store.AppendPlayback(PlaybackStatsRecord{ID: "legacy", Path: "/old.mp4", PlayedAt: 2}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite3", filename)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store.db = db
	records, err := store.ListPlaybackStats(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].FirstByteLatencyMs != 0.125 || records[0].HeaderLatencyMs != 8 {
		t.Fatalf("records=%+v", records)
	}
	raw, err := json.Marshal(records[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"first_byte_latency_ms":0.125`) {
		t.Fatalf("export=%s", raw)
	}
	raw, _ = json.Marshal(records[1])
	if strings.Contains(string(raw), "first_byte_latency_ms") {
		t.Fatal("invented old measurement")
	}
	var decoded PlaybackStatsRecord
	if err = json.Unmarshal([]byte(`{"path":"/old.mp4","header_latency_ms":9}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.FirstByteLatencyMs != 0 {
		t.Fatal("header fallback")
	}
}

func TestPlaybackSessionFirstByteRetention(t *testing.T) {
	tr, store := newTestSessionTracker()
	tr.record("/video", "cdn", "", 1, 10, 1, true, 0, 7, 0)
	tr.record("/video", "cdn", "", 1, 10, 1, true, 0, 8, 0, 0.125)
	tr.record("/video", "cdn", "", 1, 10, 1, true, 0, 9, 0, 200)
	tr.flushAll()
	if len(store.records) != 1 || store.records[0].FirstByteLatencyMs != 0.125 || store.records[0].HeaderLatencyMs != 7 {
		t.Fatalf("records=%+v", store.records)
	}
}

type firstByteBlockingStore struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *firstByteBlockingStore) AppendPlayback(PlaybackStatsRecord) error {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return nil
}

func TestPlaybackSessionPersistenceDoesNotHoldMapLock(t *testing.T) {
	for _, mode := range []string{"record", "stale", "all"} {
		t.Run(mode, func(t *testing.T) {
			store := &firstByteBlockingStore{entered: make(chan struct{}), release: make(chan struct{})}
			tr := newPlaybackSessionTracker(store)
			tr.record("/old", "", "", 1, 10, 0, true, 0, 0, 0)
			tr.mu.Lock()
			tr.sessions["/old"].lastAt = time.Now().Add(-time.Hour)
			tr.mu.Unlock()
			done := make(chan struct{})
			var flushed, recorded chan struct{}
			defer func() {
				close(store.release)
				for _, ch := range []chan struct{}{done, flushed, recorded} {
					if ch != nil {
						select {
						case <-ch:
						case <-time.After(time.Second):
							t.Error("worker cleanup timed out")
						}
					}
				}
			}()
			go func() {
				defer close(done)
				switch mode {
				case "record":
					tr.record("/new", "", "", 1, 10, 0, true, 0, 0, 0)
				case "stale":
					tr.flushStale(time.Now())
				default:
					tr.flushAll()
				}
			}()
			select {
			case <-store.entered:
			case <-time.After(time.Second):
				t.Fatal("append not entered")
			}
			recorded = make(chan struct{})
			go func() { tr.record("/old", "", "", 2, 10, 0, true, 0, 0, 0, 5); close(recorded) }()
			select {
			case <-recorded:
			case <-time.After(time.Second):
				t.Fatal("session map blocked by persistence")
			}
			tr.mu.Lock()
			sess := tr.sessions["/old"]
			tr.mu.Unlock()
			if sess == nil || sess.bytesServed != 2 {
				t.Fatal("new session lost")
			}
			// An export must wait even if another caller already detached everything.
			tr.mu.Lock()
			tr.sessions = make(map[string]*playbackSession)
			tr.mu.Unlock()
			flushed = make(chan struct{})
			go func() { tr.flushAll(); close(flushed) }()
			select {
			case <-flushed:
				t.Fatal("flushAll returned before inflight persistence")
			case <-time.After(20 * time.Millisecond):
			}
		})
	}
}
