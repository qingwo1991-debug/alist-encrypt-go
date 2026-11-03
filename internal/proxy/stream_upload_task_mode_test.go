package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestProtectedUploadKeepsExplicitTaskMode(t *testing.T) {
	for _, tc := range []struct{ header, want string }{{"true", "true"}, {"false", "false"}, {"", "false"}, {"TRUE", "false"}} {
		t.Run(tc.header, func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
				if got := r.Header.Get("As-Task"); got != tc.want {
					t.Errorf("As-Task=%q want=%q", got, tc.want)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":200,"data":null}`)), Request: r}, nil
			})
			r := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader("plain"))
			r.Header.Set("As-Task", tc.header)
			r = r.WithContext(WithSynchronousUploadVerification(r.Context()))
			out := httptest.NewRecorder()
			if err := sp.ProxyUploadEncrypt(out, r, "http://upstream.local/api/fs/put", &config.PasswdInfo{Password: "test", EncType: "aesctr", Enable: true}, 5, 0); err != nil {
				t.Fatal(err)
			}
		})
	}
}
