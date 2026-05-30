package encrypt

import (
	"net/http/httptest"
	"testing"
)

func TestRewriteLoopbackRawURLForRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "http://192.168.1.7:5344/api/fs/get", nil)
	req.Host = "192.168.1.7:5344"

	got := rewriteLoopbackRawURLForRequest(req, "http://127.0.0.1:5244/p/local/test.jpg?sign=abc")
	want := "http://192.168.1.7:5244/p/local/test.jpg?sign=abc"
	if got != want {
		t.Fatalf("rewriteLoopbackRawURLForRequest() = %q, want %q", got, want)
	}
}

func TestRewriteLoopbackRawURLForRequestKeepsExternalHost(t *testing.T) {
	req := httptest.NewRequest("GET", "http://192.168.1.7:5344/api/fs/get", nil)
	req.Host = "192.168.1.7:5344"

	raw := "https://example.com/p/local/test.jpg?sign=abc"
	if got := rewriteLoopbackRawURLForRequest(req, raw); got != raw {
		t.Fatalf("rewriteLoopbackRawURLForRequest() changed external url: got %q want %q", got, raw)
	}
}
