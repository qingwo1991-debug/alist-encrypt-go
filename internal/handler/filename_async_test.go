package handler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// Exercise the real encrypting proxy, real durable DAO and real upstream task
// responses together. Stopping background work simulates lost in-memory polling
// credentials; authenticated task queries must still reconcile durable receipts.
func TestProtectedLongFilenameAsyncTaskLifecycle(t *testing.T) {
	var mu sync.Mutex
	var raw string
	var stored []byte
	state := 0
	listAllowed := true
	const taskID = "real-task/with+special?characters"
	taskBody := func() string {
		return fmt.Sprintf(`{"code":200,"data":{"id":%q,"state":%d,"progress":100}}`, taskID, state)
	}
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer owner" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"code":401}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/fs/list":
			if !listAllowed {
				_, _ = io.WriteString(w, `{"code":401}`)
				return
			}
			if len(stored) == 0 || state != 2 {
				_, _ = io.WriteString(w, `{"code":200,"data":{"total":0,"content":[]}}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"code":200,"data":{"total":1,"content":[{"name":%q,"size":%d,"is_dir":false}]}}`, pathBase(raw), len(stored))
		case "/api/fs/put":
			if r.Header.Get("As-Task") != "true" {
				t.Errorf("async request silently changed: %q", r.Header.Get("As-Task"))
			}
			raw, _ = url.QueryUnescape(r.Header.Get("File-Path"))
			stored, _ = io.ReadAll(r.Body)
			_, _ = fmt.Fprintf(w, `{"code":200,"data":{"task":{"id":%q,"state":0}}}`, taskID)
		case "/api/task/upload/info":
			if r.URL.Query().Get("tid") != taskID {
				t.Errorf("wrong query task ID: %q", r.URL.Query().Get("tid"))
			}
			_, _ = io.WriteString(w, taskBody())
		case "/api/task/upload/undone":
			_, _ = fmt.Fprintf(w, `{"code":200,"data":[{"id":%q,"state":%d}]}`, taskID, state)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer upstream.Close()
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
	h, d := newTestAlistHandler(t, upstream.URL, ep)
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100}
	h.Stop()
	original := "/limited/" + strings.Repeat("很长的视频文件名", 30) + ".mp4"
	r := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader("plain"))
	r.Header.Set("Authorization", "Bearer owner")
	r.Header.Set("File-Path", url.QueryEscape(original))
	r.Header.Set("As-Task", "true")
	r.Header.Set("Content-Length", "5")
	w := httptest.NewRecorder()
	h.HandleFsPut(w, r)
	want := fmt.Sprintf(`{"code":200,"data":{"task":{"id":%q,"state":0}}}`, taskID)
	if w.Code != 200 || w.Body.String() != want {
		t.Fatalf("task receipt changed: %d %s", w.Code, w.Body)
	}
	if len(pathBase(raw)) > 100 {
		t.Fatalf("filename remains too long: %d", len(pathBase(raw)))
	}
	if got := encryption.ConvertShowNameWithSuffixOptions(ep.Password, ep.EncType, pathBase(raw), ep.EncSuffix, false); !strings.HasSuffix(got, ".mp4") {
		t.Fatalf("bounded filename no longer decrypts: %q", got)
	}
	assertStatus := func(want string) {
		t.Helper()
		rec, found, err := d.GetFilenameReservation(h.cfg.GetAlistURL(), raw)
		if err != nil || !found || rec.Status != want || rec.OriginalPath != original {
			t.Fatalf("reservation status=%q found=%v err=%v", rec.Status, found, err)
		}
	}
	assertStatus(storage.FilenamePending)
	query := func(endpoint, auth string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, endpoint, nil)
		req.Header.Set("Authorization", auth)
		out := httptest.NewRecorder()
		h.HandleUploadTasks(out, req)
		return out
	}
	undoneReq := httptest.NewRequest(http.MethodGet, "/api/task/upload/undone", nil)
	undoneReq.Header.Set("Authorization", "Bearer owner")
	undoneOut := httptest.NewRecorder()
	h.HandleUploadTasks(undoneOut, undoneReq)
	if undoneOut.Code != 200 || !strings.Contains(undoneOut.Body.String(), taskID) {
		t.Fatalf("real upload task missing from undone: %d %s", undoneOut.Code, undoneOut.Body)
	}
	assertStatus(storage.FilenamePending)
	info := "/api/task/upload/info?tid=" + url.QueryEscape(taskID)
	// Failed, canceled, errored, retry wait, and even progress=100 do not complete
	// the claim or prevent a later successful retry of the same real task ID.
	for _, s := range []int{7, 4, 5, 6, 0, 1} {
		mu.Lock()
		state = s
		mu.Unlock()
		out := query(info, "Bearer owner")
		if out.Code != 200 {
			t.Fatalf("task query: %d %s", out.Code, out.Body)
		}
		assertStatus(storage.FilenamePending)
	}
	mu.Lock()
	state = 2
	listAllowed = false
	mu.Unlock()
	out := query(info, "Bearer owner")
	if out.Code != 200 {
		t.Fatalf("local verification changed upstream task response: %d", out.Code)
	}
	assertStatus(storage.FilenamePending)
	mu.Lock()
	listAllowed = true
	mu.Unlock()
	out = query(info, "Bearer other")
	if out.Code != 401 {
		t.Fatalf("unauthorized query changed: %d", out.Code)
	}
	assertStatus(storage.FilenamePending)
	out = query(info, "Bearer owner")
	if out.Code != 200 {
		t.Fatalf("success response: %d %s", out.Code, out.Body)
	}
	assertStatus(storage.FilenameComplete)
}

// A definite no-task failure must mark the claim failed (management can release
// it), while a malformed/ambiguous result keeps it pending because an upstream
// task may already be running and cannot be guessed successful or failed.
func TestProtectedAsyncDefiniteNoTaskFailureMarksFailed(t *testing.T) {
	for _, mode := range []string{"reject", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/fs/list" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"code":200,"data":{"total":0,"content":[]}}`)
					return
				}
				if r.URL.Path == "/api/fs/put" {
					if mode == "reject" {
						w.WriteHeader(http.StatusBadGateway)
						_, _ = io.WriteString(w, `{"code":502}`)
					} else {
						w.WriteHeader(http.StatusOK)
						_, _ = io.WriteString(w, `not-json`)
					}
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer upstream.Close()
			ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
			h, d := newTestAlistHandler(t, upstream.URL, ep)
			h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100}
			h.Stop()
			original := "/limited/" + strings.Repeat("很长的视频文件名", 30) + ".mp4"
			r := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader("plain"))
			r.Header.Set("Authorization", "Bearer owner")
			r.Header.Set("File-Path", url.QueryEscape(original))
			r.Header.Set("As-Task", "true")
			r.Header.Set("Content-Length", "5")
			w := httptest.NewRecorder()
			h.HandleFsPut(w, r)
			if w.Code < 500 {
				t.Fatalf("mode=%s status=%d", mode, w.Code)
			}
			// Look up the durable reservation by its original path, auth scope and
			// rule fingerprint (the encrypted path is shortened internally).
			rec, found, err := d.GetFilenameReservationByOriginal(h.cfg.GetAlistURL(), original, filenameRequestScope(r), filenameRuleScope(ep))
			if err != nil || !found {
				t.Fatalf("mode=%s reservation not found: %v %v", mode, found, err)
			}
			want := storage.FilenameFailed
			if mode == "malformed" {
				want = storage.FilenamePending
			}
			if rec.Status != want {
				t.Fatalf("mode=%s status=%q want=%q", mode, rec.Status, want)
			}
		})
	}
}
