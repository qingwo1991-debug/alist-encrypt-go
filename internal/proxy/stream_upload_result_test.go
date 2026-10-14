package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestSynchronousUploadVerificationBeforePublication(t *testing.T) {
	for _, tc := range []struct {
		name, body                string
		protected, dav, wantError bool
	}{
		{"json-success", `{"code":200,"data":null}`, true, false, false},
		{"application-failure", `{"code":500,"message":"secret upstream error"}`, true, false, true},
		{"malformed", `not-json`, true, false, true},
		{"missing-code", `{}`, true, false, true},
		{"trailing-json", `{"code":200}{"code":500}`, true, false, true},
		{"oversize", strings.Repeat(" ", 64*1024) + `{"code":200}`, true, false, true},
		{"legacy-unmarked", `ok`, false, false, false},
		{"dav-empty", ``, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
				if tc.protected && !tc.dav && r.Header.Get("As-Task") != "false" {
					t.Errorf("As-Task=%q, want false", r.Header.Get("As-Task"))
				}
				if (!tc.protected || tc.dav) && r.Header.Get("As-Task") != "true" {
					t.Errorf("legacy/DAV As-Task changed: %q", r.Header.Get("As-Task"))
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}, "Content-Length": {"999999"}, "X-Test": {"preserved"}}, Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			})
			req := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader("upload-body"))
			req.Header.Set("As-Task", "true")
			if tc.protected {
				req = req.WithContext(WithSynchronousUploadVerification(req.Context()))
			}
			target := "http://upstream.local/api/fs/put"
			if tc.dav {
				target = "http://upstream.local/dav/file"
			}
			rr := httptest.NewRecorder()
			err := sp.ProxyUploadEncrypt(rr, req, target, &config.PasswdInfo{Password: "test-password", EncType: "aesctr", Enable: true}, 11, 0)
			if (err != nil) != tc.wantError {
				t.Fatalf("err=%v wantError=%v", err, tc.wantError)
			}
			if tc.wantError {
				if rr.Body.Len() != 0 || rr.Header().Get("X-Test") != "" || rr.Flushed {
					t.Fatalf("failure committed response: body=%q headers=%v", rr.Body.String(), rr.Header())
				}
				if strings.Contains(err.Error(), "secret upstream error") {
					t.Fatal("upstream message leaked in error")
				}
				return
			}
			if rr.Body.String() != tc.body || rr.Header().Get("X-Test") != "preserved" {
				t.Fatalf("successful response not preserved: %q %v", rr.Body.String(), rr.Header())
			}
			if tc.protected && !tc.dav && rr.Header().Get("Content-Length") != strconv.Itoa(len(tc.body)) {
				t.Fatalf("verified response length=%q", rr.Header().Get("Content-Length"))
			}
		})
	}
}
