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
		if recorder.Body.Len() != 0 || recorder.Code == http.StatusPartialContent {
			t.Fatalf("old publication escaped method=%s status=%d bytes=%d", method, recorder.Code, recorder.Body.Len())
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
