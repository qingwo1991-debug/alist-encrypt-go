package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

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
