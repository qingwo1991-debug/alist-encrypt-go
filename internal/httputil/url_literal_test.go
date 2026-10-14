package httputil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTargetURLLiteralPathAtActualUpstream(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "sign=keep" {
			t.Errorf("query changed: %q", r.URL.RawQuery)
		}
		seen <- r.URL.Path
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	for _, p := range []string{"/api/%66s/form", "/dav/mount/%70rotected/a", "/dav/100%done", "/dav/literal?part#fragment", "/dav/中文+空 格"} {
		target := BuildTargetURLWithQuery(upstream.URL, p, "sign=keep")
		req, err := http.NewRequestWithContext(context.Background(), "GET", target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := upstream.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := <-seen; got != p {
			t.Fatalf("actual path=%q want=%q", got, p)
		}
	}
}
