package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestV3PlaybackMemoryBudgetTerminalAndRelease(t *testing.T) {
	payload := []byte("memory-budget")
	container, meta := buildV3Container(t, "pw", 64, payload)
	passwd := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}
	for _, mode := range []string{"oversized", "exhausted", "success", "decrypt-error"} {
		t.Run(mode, func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			sp.client = newTestClient(rangeAwareRoundTripper(container))
			requestMeta := meta
			var release func()
			switch mode {
			case "oversized":
				requestMeta.ChunkSize = uint32(v3RecordBudgetBytes)
			case "exhausted":
				var ok bool
				release, ok = sp.acquireV3Memory(v3RecordBudgetBytes)
				if !ok {
					t.Fatal("failed to reserve empty budget")
				}
				defer release()
			case "decrypt-error":
				bad := append([]byte(nil), container...)
				bad[meta.HeaderLen] ^= 1
				sp.client = newTestClient(rangeAwareRoundTripper(bad))
			}
			req := httptest.NewRequest(http.MethodGet, "/file", nil)
			req = req.WithContext(WithContentMeta(req.Context(), requestMeta))
			rr := httptest.NewRecorder()
			outcome := sp.ProxyDownloadDecryptWithStrategy(rr, req, "http://upstream.test/file", passwd, meta.PlainSize, StreamStrategyFull)
			if mode == "oversized" || mode == "exhausted" {
				if rr.Code != 503 || outcome.StatusCode != 503 || !outcome.ResponseStarted || outcome.Retryable || !outcome.NoLearning {
					t.Fatalf("memory rejection=%+v", outcome)
				}
				want := "bad_v3_metadata"
				if mode == "exhausted" {
					want = "resource_exhausted"
					release()
					release()
				}
				if string(outcome.FailureReason) != want {
					t.Fatalf("memory reason=%+v", outcome)
				}
			} else if mode == "success" && (outcome.Err != nil || !bytes.Equal(rr.Body.Bytes(), payload)) {
				t.Fatalf("stream=%+v", outcome)
			} else if mode == "decrypt-error" && outcome.Err == nil {
				t.Fatal("corrupted chunk unexpectedly decrypted")
			}
			if sp.v3Memory.used.Load() != 0 {
				t.Fatal("stream leaked V3 memory reservation")
			}
		})
	}
}
