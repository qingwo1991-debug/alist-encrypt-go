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
	h, _ := newTestAlistHandler(t, upstream.URL, &config.PasswdInfo{Enable: true, EncName: true, Password: "secret", EncType: "aesctr", EncPath: []string{"/mount/protected/*"}})
	defer h.Stop()
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/mount/protected": 100, "/other/protected": 80}
	cases := []struct {
		name, operation, body string
		status                int
	}{
		{"short rename", "rename", `{"path":"/mount/protected/a","name":"b"}`, 501},
		{"long rename", "rename", `{"path":"/mount/protected/a","name":"` + strings.Repeat("长", 150) + `"}`, 501},
		{"directory ancestor rename", "rename", `{"path":"/mount","name":"new"}`, 501},
		{"destination rename", "rename", `{"path":"/mount/outside","name":"protected"}`, 501},
		{"encoded rename", "rename", `{"path":"/%6dount/%70rotected/a","name":"b"}`, 501},
		{"normalized rename", "rename", `{"path":"/outside/../mount//protected/a","name":"b"}`, 501},
		{"source move", "move", `{"src_dir":"/mount/protected","dst_dir":"/outside","names":["a"]}`, 501},
		{"destination copy", "copy", `{"src_dir":"/outside","dst_dir":"/mount/protected","names":["a"]}`, 501},
		{"cross rule move", "move", `{"src_dir":"/mount/protected","dst_dir":"/other/protected","names":["a"]}`, 501},
		{"ancestor batch", "move", `{"src_dir":"/","dst_dir":"/outside","names":["mount"]}`, 501},
		{"mixed batch", "copy", `{"src_dir":"/mount","dst_dir":"/outside","names":["safe","protected"]}`, 501},
		{"encoded batch", "copy", `{"src_dir":"/mount","dst_dir":"/outside","names":["%2570rotected"]}`, 501},
		{"unknown source", "move", `{"dst_dir":"/outside","names":["a"]}`, 400},
		{"unknown destination", "copy", `{"src_dir":"/outside","names":["a"]}`, 400},
		{"relative source", "move", `{"src_dir":"mount/protected","dst_dir":"/outside","names":["a"]}`, 400},
		{"URL source", "copy", `{"src_dir":"https://host/mount/protected","dst_dir":"/outside","names":["a"]}`, 400},
		{"empty batch", "move", `{"src_dir":"/outside","dst_dir":"/outside2","names":[]}`, 400},
		{"null batch", "copy", `{"src_dir":"/outside","dst_dir":"/outside2","names":null}`, 400},
		{"nested batch name", "move", `{"src_dir":"/outside","dst_dir":"/outside2","names":["../mount"]}`, 400},
		{"encoded slash", "copy", `{"src_dir":"/outside","dst_dir":"/outside2","names":["%2fmount"]}`, 400},
		{"bad percent", "copy", `{"src_dir":"/outside%GG","dst_dir":"/outside2","names":["a"]}`, 400},
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
	h.cfg.AlistServer.FilenameWriteLimits = nil
	req := httptest.NewRequest("POST", "/api/fs/copy", strings.NewReader(`{"src_dir":"/mount/protected","dst_dir":"/outside","names":["a"]}`))
	rec := httptest.NewRecorder()
	h.HandleFsCopy(rec, req)
	if rec.Code != 200 || calls.Load() != 4 {
		t.Fatalf("status=%d upstream=%d", rec.Code, calls.Load())
	}
}

func TestProtectedMutationSubtreeAndEncodingBoundaries(t *testing.T) {
	cfg := &config.Config{}
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/mount/protected": 100}
	for _, p := range []string{"/", "/mount", "/mount/protected", "/mount/protected/raw.bin", "/%256dount/protected/a", "/mount/protected/../protected/a"} {
		if err := guardProtectedMutation(cfg, "MOVE", p, "/outside/a"); err == nil {
			t.Fatalf("allowed %q", p)
		}
	}
	for _, p := range []string{"/mount/protected-sibling", "/mount/other", "/outside/a+b"} {
		if err := guardProtectedMutation(cfg, "COPY", p, "/outside/new"); err != nil {
			t.Fatalf("rejected %q: %v", p, err)
		}
	}
	if err := guardProtectedMutation(cfg, "COPY"); err == nil {
		t.Fatal("unknown paths allowed")
	}
	cfg.AlistServer.FilenameWriteLimits = nil
	if err := guardProtectedMutation(cfg, "COPY", ""); err != nil {
		t.Fatal(err)
	}
}
