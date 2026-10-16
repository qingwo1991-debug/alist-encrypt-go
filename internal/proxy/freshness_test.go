package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestStrictFreshnessResponsePublicationAfterUpdate(t *testing.T) {
	cfg := config.LoadFromBaseDir(t.TempDir())
	current := cfg.AlistServerSnapshot()
	current.StrictFreshness = true
	if err := cfg.UpdateAlistServer(current); err != nil {
		t.Fatal(err)
	}
	sp := NewStreamProxy(cfg)
	target := "https://provider.test/object"
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		r := httptest.NewRequest(method, "http://local/file", nil)
		r = r.WithContext(WithStrictFreshnessCheck(r.Context(), cfg.RuntimeRevision(), target))
		recorder := httptest.NewRecorder()
		w := sp.guardStrictFreshnessWriter(recorder, r, target)
		w.Header().Set("Content-Length", "123")
		w.Header().Set("Content-Range", "bytes 0-122/123")
		w.Header().Set("X-Encrypt-Freshness-Evidence", "confirmed_metadata")
		// Models a KDF/sniff/record read completing after the managed update.
		next := cfg.AlistServerSnapshot()
		next.ServerHost = "updated.example"
		if err := cfg.UpdateAlistServer(next); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusPartialContent)
		if n, err := w.Write([]byte("old plaintext")); n != 0 || err == nil {
			t.Fatalf("late write n=%d err=%v", n, err)
		}
		if recorder.Header().Get("Content-Range") != "" || recorder.Header().Get("Content-Length") != "0" || recorder.Header().Get("X-Encrypt-Freshness-Evidence") != "" {
			t.Fatalf("stale HEAD geometry/evidence: %v", recorder.Header())
		}
		out := finishStrictFreshnessOutcome(w, &StreamOutcome{ResponseStarted: true, StatusCode: http.StatusPartialContent})
		if out.Err == nil || !out.NoLearning || !out.ResponseStarted || out.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("success escaped stale response: %+v", out)
		}
		if recorder.Body.Len() != 0 || recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("old publication escaped method=%s status=%d bytes=%d", method, recorder.Code, recorder.Body.Len())
		}
	}
}

func TestStrictFreshnessHeadFailureIsExplicitOverHTTP(t *testing.T) {
	cfg := config.LoadFromBaseDir(t.TempDir())
	current := cfg.AlistServerSnapshot()
	current.StrictFreshness = true
	if err := cfg.UpdateAlistServer(current); err != nil {
		t.Fatal(err)
	}
	sp := NewStreamProxy(cfg)
	target := "https://provider.test/object"
	ready, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(WithStrictFreshnessCheck(r.Context(), cfg.RuntimeRevision(), target))
		guard := sp.guardStrictFreshnessWriter(w, r, target)
		guard.Header().Set("Content-Length", "123")
		guard.Header().Set("Content-Range", "bytes 0-122/123")
		guard.Header().Set("X-Encrypt-Freshness-Evidence", "confirmed_metadata")
		close(ready)
		<-release
		guard.WriteHeader(http.StatusPartialContent)
	}))
	defer server.Close()
	result := make(chan *http.Response, 1)
	failed := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodHead, server.URL, nil)
		resp, err := server.Client().Do(req)
		if err != nil {
			failed <- err
			return
		}
		result <- resp
	}()
	<-ready
	next := cfg.AlistServerSnapshot()
	next.ServerHost = "changed.example"
	err := cfg.UpdateAlistServer(next)
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-failed:
		t.Fatal(err)
	case resp := <-result:
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Content-Length") != "0" || resp.Header.Get("Content-Range") != "" || resp.Header.Get("X-Encrypt-Freshness-Evidence") != "" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("stale HEAD implicit success: status=%d headers=%v", resp.StatusCode, resp.Header)
		}
	}
}

func TestStrictFreshnessActualStreamRejectsUncheckedAndOldEpoch(t *testing.T) {
	cfg := &config.Config{AlistServer: config.AlistServer{StrictFreshness: true}}
	sp := NewStreamProxy(cfg)
	r := httptest.NewRequest(http.MethodHead, "http://local/d/file", nil)
	target := "http://upstream/file?token=new"
	if out := sp.ProxyDownloadDecryptWithStrategyForStorage(httptest.NewRecorder(), r, target, &config.PasswdInfo{Enable: true}, 1, StreamStrategyRange, ""); out.FailureReason != "strict_freshness_unconfirmed" {
		t.Fatalf("unchecked actual path: %+v", out)
	}
	for _, tc := range []struct {
		revision uint64
		target   string
	}{{cfg.RuntimeRevision() + 1, target}, {cfg.RuntimeRevision(), "http://upstream/file?token=old"}} {
		checked := r.WithContext(WithStrictFreshnessCheck(context.Background(), tc.revision, tc.target))
		if sp.strictFreshnessFailure(checked, target) == nil {
			t.Fatal("old epoch/token accepted")
		}
	}
	if key := sp.decryptedCacheBaseKey(target, &config.PasswdInfo{Enable: true}, 32, encryption.ContentMeta{}, "object"); key != "" {
		t.Fatal("strict plaintext cache enabled without revision")
	}
}
