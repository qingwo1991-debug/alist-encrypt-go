package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestProtectedMutationAPIRejectsBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200}`))
	}))
	defer upstream.Close()
	h, _ := newTestAlistHandler(t, upstream.URL, &config.PasswdInfo{Enable: true, EncName: true, Password: "secret", EncType: "aesctr", EncPath: []string{"/mount/*"}})
	defer h.Stop()
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/mount/protected": 100, "/other/protected": 80}
	cases := []struct {
		name, operation, body string
		status                int
	}{
		{"orig source move", "move", `{"src_dir":"/mount","dst_dir":"/outside","names":["orig_protected"]}`, 501},
		{"orig source rename", "rename", `{"path":"/mount/orig_protected","name":"new"}`, 501},
		{"orig dot batch", "copy", `{"src_dir":"/mount","dst_dir":"/outside","names":["orig_."]}`, 400},
		{"orig dotdot batch", "move", `{"src_dir":"/mount","dst_dir":"/outside","names":["orig_.."]}`, 400},
		{"orig dot rename", "rename", `{"path":"/mount/orig_.","name":"new"}`, 400},
		{"short rename", "rename", `{"path":"/mount/protected/a","name":"b"}`, 501},
		{"long rename", "rename", `{"path":"/mount/protected/a","name":"` + strings.Repeat("长", 150) + `"}`, 501},
		{"directory ancestor rename", "rename", `{"path":"/mount","name":"new"}`, 501},
		{"destination rename", "rename", `{"path":"/mount/outside","name":"protected"}`, 501},
		{"normalized rename", "rename", `{"path":"/outside/../mount//protected/a","name":"b"}`, 501},
		{"source move", "move", `{"src_dir":"/mount/protected","dst_dir":"/outside","names":["a"]}`, 501},
		{"destination copy", "copy", `{"src_dir":"/outside","dst_dir":"/mount/protected","names":["a"]}`, 501},
		{"cross rule move", "move", `{"src_dir":"/mount/protected","dst_dir":"/other/protected","names":["a"]}`, 501},
		{"ancestor batch", "move", `{"src_dir":"/","dst_dir":"/outside","names":["mount"]}`, 501},
		{"mixed batch", "copy", `{"src_dir":"/mount","dst_dir":"/outside","names":["safe","protected"]}`, 501},
		{"unknown source", "move", `{"dst_dir":"/outside","names":["a"]}`, 400},
		{"unknown destination", "copy", `{"src_dir":"/outside","names":["a"]}`, 400},
		{"relative source", "move", `{"src_dir":"mount/protected","dst_dir":"/outside","names":["a"]}`, 400},
		{"URL source", "copy", `{"src_dir":"https://host/mount/protected","dst_dir":"/outside","names":["a"]}`, 400},
		{"empty batch", "move", `{"src_dir":"/outside","dst_dir":"/outside2","names":[]}`, 400},
		{"null batch", "copy", `{"src_dir":"/outside","dst_dir":"/outside2","names":null}`, 400},
		{"nested batch name", "move", `{"src_dir":"/outside","dst_dir":"/outside2","names":["../mount"]}`, 400},
		{"control", "rename", `{"path":"/outside/\u0000","name":"a"}`, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/fs/"+tc.operation, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "caller-not-admin")
			rec := httptest.NewRecorder()
			switch tc.operation {
			case "rename":
				h.HandleFsRename(rec, req)
			case "move":
				h.HandleFsMove(rec, req)
			case "copy":
				h.HandleFsCopy(rec, req)
			}
			if rec.Code != tc.status {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var response struct {
				Data map[string]string `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			expected := "protected_operation_unsupported"
			if tc.status == 400 {
				expected = "invalid_mutation_path"
			}
			if response.Data["reason"] != expected {
				t.Fatalf("reason=%v", response.Data)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("unsafe upstream requests=%d", got)
			}
		})
	}
}

func TestProtectedMutationAPIUnrelatedAndUnconfiguredPassThrough(t *testing.T) {
	var calls atomic.Int64
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200}`))
	}))
	defer upstream.Close()
	h, _ := newTestAlistHandler(t, upstream.URL, &config.PasswdInfo{})
	defer h.Stop()
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/mount/protected": 100}
	// A source parent is not itself the moved object. Unrelated siblings must work.
	for _, op := range []string{"move", "copy", "rename"} {
		body := `{"src_dir":"/mount","dst_dir":"/outside","names":["safe"]}`
		if op == "rename" {
			body = `{"path":"/mount/safe","name":"safe2"}`
		}
		req := httptest.NewRequest("POST", "/api/fs/"+op, strings.NewReader(body))
		rec := httptest.NewRecorder()
		switch op {
		case "move":
			h.HandleFsMove(rec, req)
		case "copy":
			h.HandleFsCopy(rec, req)
		case "rename":
			h.HandleFsRename(rec, req)
		}
		if rec.Code != 200 {
			t.Fatalf("%s status=%d body=%s", op, rec.Code, rec.Body.String())
		}
	}
	for _, body := range []string{
		`{"src_dir":"/mount","dst_dir":"/outside","names":["%2570rotected","%2fmount","100%"]}`,
		`{"src_dir":"/outside%GG","dst_dir":"/outside2","names":["a"]}`,
	} {
		req := httptest.NewRequest("POST", "/api/fs/copy", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.HandleFsCopy(rec, req)
		if rec.Code != 200 {
			t.Fatalf("literal API path status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
	h.cfg.AlistServer.FilenameWriteLimits = nil
	req := httptest.NewRequest("POST", "/api/fs/copy", strings.NewReader(`{"src_dir":"/mount/protected","dst_dir":"/outside","names":["a"]}`))
	rec := httptest.NewRecorder()
	h.HandleFsCopy(rec, req)
	if rec.Code != 200 || calls.Load() != 6 {
		t.Fatalf("status=%d upstream=%d", rec.Code, calls.Load())
	}
}

func TestProtectedMutationProxyFallbackRejectsUnknownWithoutReadingBody(t *testing.T) {
	var calls atomic.Int64
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200}`))
	}))
	defer upstream.Close()
	h, _ := newTestAlistHandler(t, upstream.URL, &config.PasswdInfo{})
	defer h.Stop()
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/protected": 100}
	for _, tc := range []struct{ method, endpoint string }{
		{"PUT", "/api/fs/form"}, {"GET", "/api/fs/rename"}, {"POST", "/api/fs/put"},
		{"GET", "/api/fs/batch_rename"}, {"POST", "/api/fs/regex_rename"},
		{"POST", "/api/fs/recursive_move"}, {"POST", "/api/fs/mkdir"},
		{"POST", "/api/fs/get_direct_upload_info"}, {"POST", "/api/fs/add_offline_download"},
		{"POST", "/api/fs/other"}, {"DELETE", "/api/fs/list"},
		{"GET", "/api/fs/future_mutation"}, {"POST", "/api/fs/archive/decompress"},
		{"POST", "/api/fs//list"}, {"GET", "/api/%66s/rename"},
	} {
		t.Run(tc.method+tc.endpoint, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.endpoint, nil)
			body := &mutationUnreadBody{}
			req.Body = body
			req.Header.Set("File-Path", "/unrelated/file")
			rec := httptest.NewRecorder()
			h.proxyHandler.HandleProxy(rec, req)
			if rec.Code != 501 || !strings.Contains(rec.Body.String(), "proxy_fs_unclassified") {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if body.reads != 0 || calls.Load() != 0 {
				t.Fatalf("reads=%d calls=%d", body.reads, calls.Load())
			}
		})
	}
}

type mutationUnreadBody struct{ reads int }

func (b *mutationUnreadBody) Read(p []byte) (int, error) {
	b.reads++
	panic("unclassified mutation body must not be read")
}
func (b *mutationUnreadBody) Close() error { return nil }

func TestProtectedMutationProxyReadAllowlistAndUnconfigured(t *testing.T) {
	cfg := &config.Config{}
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/protected": 100}
	for _, endpoint := range []string{"get", "list", "search", "dirs", "archive/meta", "archive/list"} {
		for _, method := range []string{"GET", "HEAD", "POST"} {
			req := httptest.NewRequest(method, "/api/fs/"+endpoint, strings.NewReader("read payload"))
			original := req.Body
			if err := guardProtectedProxyMutation(cfg, req); err != nil {
				t.Fatalf("%s %s: %v", method, endpoint, err)
			}
			if req.Body != original {
				t.Fatal("read body was replaced")
			}
		}
	}
	for _, endpoint := range []string{"/api/fs/link", "/api/auth/login", "/api/me", "/assets/app.js"} {
		if err := guardProtectedProxyMutation(cfg, httptest.NewRequest("POST", endpoint, nil)); err != nil {
			t.Fatal(err)
		}
	}
	cfg.AlistServer.FilenameWriteLimits = nil
	if err := guardProtectedProxyMutation(cfg, httptest.NewRequest("PUT", "/api/fs/form", nil)); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedMutationSubtreeAndEncodingBoundaries(t *testing.T) {
	cfg := &config.Config{}
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/mount/protected": 100}
	for _, p := range []string{"/", "/mount", "/mount/protected", "/mount/protected/raw.bin", "/mount/protected/../protected/a"} {
		if err := guardProtectedMutation(cfg, "MOVE", p, "/outside/a"); err == nil {
			t.Fatalf("allowed %q", p)
		}
	}
	for _, p := range []string{"/mount/protected-sibling", "/mount/other", "/outside/a+b", "/%256dount/protected/a", "/mount/%70rotected/a", "/outside%GG/a", "/outside/100%"} {
		if err := guardProtectedMutation(cfg, "COPY", p, "/outside/new"); err != nil {
			t.Fatalf("rejected %q: %v", p, err)
		}
	}
	if err := guardProtectedMutation(cfg, "COPY"); err == nil {
		t.Fatal("unknown paths allowed")
	}
	for _, name := range []string{"%70rotected", "%2570rotected", "%2fmount", "100%", "%GG"} {
		if err := guardProtectedBatchMutation(cfg, "copy", "/mount", "/outside", []string{name}); err != nil {
			t.Fatalf("literal basename %q rejected: %v", name, err)
		}
	}
	// HTTP URL escaping is decoded once by net/url, before the DAV guard.
	req := httptest.NewRequest("MOVE", "/%6dount/protected/a", nil)
	if err := guardProtectedMutation(cfg, "MOVE", req.URL.Path); err == nil {
		t.Fatal("actual decoded HTTP path was allowed")
	}
	cfg.AlistServer.FilenameWriteLimits = nil
	if err := guardProtectedMutation(cfg, "COPY", ""); err != nil {
		t.Fatal(err)
	}
}
