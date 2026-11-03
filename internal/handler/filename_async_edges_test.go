package handler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func newFilenameAsyncEdgeHandler(t *testing.T, origin string) (*AlistHandler, *dao.FileDAO, *config.PasswdInfo) {
	t.Helper()
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
	h, d := newTestAlistHandler(t, origin, ep)
	// The shared fixture owns stores, but its callers must stop cache workers.
	t.Cleanup(d.Stop)
	t.Cleanup(h.passwdDAO.(*dao.PasswdDAO).Stop)
	t.Cleanup(h.Stop)
	return h, d, ep
}

func reserveFilenameAsyncEdge(t *testing.T, h *AlistHandler, d *dao.FileDAO, ep *config.PasswdInfo) storage.FilenameRecord {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/task/upload/info?tid=edge-task", nil)
	r.Header.Set("Authorization", "Bearer owner")
	rec, err := d.ReserveFilename(storage.FilenameRecord{
		Origin: h.cfg.GetAlistURL(), EncryptedPath: "/limited/raw.bin", OriginalPath: "/limited/original.mp4", DisplayName: "raw.bin",
		AuthScope: filenameRequestScope(r), RuleFingerprint: filenameRuleFingerprint(ep), CiphertextSize: 37,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.BindFilenameUploadTask(storage.FilenameUploadTask{
		Origin: rec.Origin, TaskID: "edge-task", EncryptedPath: rec.EncryptedPath, Token: rec.Token, AuthScope: rec.AuthScope, RuleFingerprint: rec.RuleFingerprint,
	}); err != nil {
		t.Fatal(err)
	}
	return rec
}

func assertFilenameAsyncEdgePending(t *testing.T, d *dao.FileDAO, rec storage.FilenameRecord) {
	t.Helper()
	got, found, err := d.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	if err != nil || !found || got.Status != storage.FilenamePending {
		t.Fatalf("reservation status=%q found=%v err=%v", got.Status, found, err)
	}
	if raw, found := d.GetEncPath(rec.OriginalPath); found {
		t.Fatalf("pending reservation published mapping %q", raw)
	}
}

func TestFilenameAsyncOversizedTaskResponsePassthrough(t *testing.T) {
	h, d, ep := newFilenameAsyncEdgeHandler(t, "http://127.0.0.1:1")
	rec := reserveFilenameAsyncEdge(t, h, d, ep)
	// Valid JSON with a successful task near the beginning catches both truncation
	// and accidental reconciliation of an oversized (but parseable) response.
	body := `{"code":200,"data":{"id":"edge-task","state":2},"padding":"` + strings.Repeat("x", filenameTaskResponseLimit) + `"}`
	listCalls := 0
	h.httpClient = newHTTPClientFromHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/task/upload/info":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Upstream-Receipt", "unchanged")
			_, _ = io.WriteString(w, body)
		case "/api/fs/list":
			listCalls++
			_, _ = io.WriteString(w, `{"code":200,"data":{"total":1,"content":[{"name":"raw.bin","size":37,"is_dir":false}]}}`)
		default:
			t.Errorf("unexpected upstream path %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/task/upload/info?tid=edge-task", nil)
	r.Header.Set("Authorization", "Bearer owner")
	out := httptest.NewRecorder()
	h.HandleUploadTasks(out, r)
	if out.Code != http.StatusOK || out.Body.String() != body || out.Header().Get("X-Upstream-Receipt") != "unchanged" {
		t.Fatalf("upstream response changed: status=%d bytes=%d want=%d", out.Code, out.Body.Len(), len(body))
	}
	if listCalls != 0 {
		t.Fatalf("oversized task response triggered %d verification requests", listCalls)
	}
	assertFilenameAsyncEdgePending(t, d, rec)
}

func TestFilenameAsyncAcceptedUploadUnpublishedAndStopCancelsPoll(t *testing.T) {
	type uploadObservation struct {
		raw  string
		size int
	}
	uploaded := make(chan uploadObservation, 1)
	pollStarted := make(chan struct{})
	pollCanceled := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var uploadAccepted atomic.Bool
	var postUploadLists atomic.Int32
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/list":
			if uploadAccepted.Load() {
				postUploadLists.Add(1)
			}
			_, _ = io.WriteString(w, `{"code":200,"data":{"total":0,"content":[]}}`)
		case "/api/fs/put":
			if r.Header.Get("As-Task") != "true" {
				t.Errorf("As-Task rewritten to %q", r.Header.Get("As-Task"))
			}
			raw, err := url.QueryUnescape(r.Header.Get("File-Path"))
			if err != nil {
				t.Errorf("decode upload path: %v", err)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read upload: %v", err)
			}
			uploadAccepted.Store(true)
			uploaded <- uploadObservation{raw, len(body)}
			_, _ = io.WriteString(w, `{"code":200,"data":{"task":{"id":"edge-task","state":0}}}`)
		case "/api/task/upload/info":
			if r.Header.Get("Authorization") != "Bearer owner" || r.URL.Query().Get("tid") != "edge-task" {
				t.Errorf("poll lost caller credentials or task ID")
			}
			close(pollStarted)
			// No response headers: cancellation must interrupt the actual HTTP
			// round trip, not merely an interval timer or a fake request context.
			select {
			case <-r.Context().Done():
				close(pollCanceled)
			case <-release:
			}
		default:
			t.Errorf("unexpected upstream path %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer upstream.Close()
	// Unblock server handlers even if an assertion fails before Stop runs.
	defer unblock()
	h, d, _ := newFilenameAsyncEdgeHandler(t, upstream.URL)
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100}
	meta := &protocolMetaStore{}
	h.metaStore = meta
	original := "/limited/" + strings.Repeat("long-filename-", 30) + ".mp4"
	r := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader("plain"))
	r.Header.Set("Authorization", "Bearer owner")
	r.Header.Set("File-Path", url.QueryEscape(original))
	r.Header.Set("As-Task", "true")
	r.Header.Set("Content-Length", "5")
	out := httptest.NewRecorder()
	h.HandleFsPut(out, r)
	if out.Code != http.StatusOK || out.Body.String() != `{"code":200,"data":{"task":{"id":"edge-task","state":0}}}` {
		t.Fatalf("task acceptance changed: %d %s", out.Code, out.Body)
	}
	observation := <-uploaded
	rec, found, err := d.GetFilenameReservation(h.cfg.GetAlistURL(), observation.raw)
	if err != nil || !found || rec.OriginalPath != original || rec.CiphertextSize != int64(observation.size) {
		t.Fatalf("missing upload reservation: %+v found=%v err=%v", rec, found, err)
	}
	assertFilenameAsyncEdgePending(t, d, rec)
	if len(meta.writes) != 0 {
		t.Fatalf("accepted task published metadata: %+v", meta.writes)
	}
	if got := postUploadLists.Load(); got != 0 {
		t.Fatalf("accepted task performed premature destination verification: lists=%d", got)
	}
	select {
	case <-pollStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("background poll did not start")
	}
	stopped := make(chan struct{})
	go func() { h.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		unblock()
		t.Fatal("Stop did not cancel and join blocked poll")
	}
	select {
	case <-pollCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream request was not canceled")
	}
	h.filenameTaskMu.Lock()
	pending, active := len(h.filenameTaskPending), len(h.filenameTaskSem)
	h.filenameTaskMu.Unlock()
	if pending != 0 || active != 0 {
		t.Fatalf("Stop leaked task admission: pending=%d active=%d", pending, active)
	}
	assertFilenameAsyncEdgePending(t, d, rec)
}

func TestFilenameAsyncFinalizeRequiresCurrentRuleAndScope(t *testing.T) {
	for _, mismatch := range []string{"encryption-rule", "auth-scope"} {
		t.Run(mismatch, func(t *testing.T) {
			h, d, ep := newFilenameAsyncEdgeHandler(t, "http://127.0.0.1:1")
			rec := reserveFilenameAsyncEdge(t, h, d, ep)
			listCalls := 0
			h.httpClient = newHTTPClientFromHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/fs/list" {
					t.Errorf("unexpected upstream path %s", r.URL.Path)
				}
				listCalls++
				_, _ = fmt.Fprintf(w, `{"code":200,"data":{"total":1,"content":[{"name":"raw.bin","size":%d,"is_dir":false}]}}`, rec.CiphertextSize)
			}))
			r := httptest.NewRequest(http.MethodPost, "/api/task/upload/info?tid=edge-task", nil)
			r.Header.Set("Authorization", "Bearer owner")
			if mismatch == "encryption-rule" {
				h.cfg.AlistServer.PasswdList[0].Password = "changed-password"
				h.passwdDAO.(*dao.PasswdDAO).Reload()
			} else {
				r.Header.Set("Authorization", "Bearer other")
			}
			state := filenameTaskSucceeded
			task := filenameTaskInfo{ID: "edge-task", State: &state}
			if err := h.reconcileFilenameTask(r, rec.Origin, task); err == nil {
				t.Fatal("mismatched rule/scope finalized task")
			}
			assertFilenameAsyncEdgePending(t, d, rec)
			if listCalls != 0 {
				t.Fatalf("mismatch still probed destination %d times", listCalls)
			}
			// Positive control: the same durable receipt and physical object are
			// sufficient once the original rule and caller identity are restored.
			h.cfg.AlistServer.PasswdList[0].Password = ep.Password
			h.passwdDAO.(*dao.PasswdDAO).Reload()
			r.Header.Set("Authorization", "Bearer owner")
			if err := h.reconcileFilenameTask(r, rec.Origin, task); err != nil {
				t.Fatalf("valid task failed to finalize: %v", err)
			}
			got, found, err := d.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
			if err != nil || !found || got.Status != storage.FilenameComplete || listCalls != 1 {
				t.Fatalf("valid reservation=%+v found=%v lists=%d err=%v", got, found, listCalls, err)
			}
			if raw, found := d.GetEncPath(rec.OriginalPath); !found || raw != rec.EncryptedPath {
				t.Fatalf("verified mapping=%q found=%v", raw, found)
			}
		})
	}
}
