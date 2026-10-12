package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/errors"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestV3KDFPlaybackBusyIsTerminalBeforeSuccess(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/file", nil)
	rr := httptest.NewRecorder()
	rr.Header().Set("Content-Range", "bytes 0-1/100")
	rr.Header().Set("Content-Length", "2")
	rr.Header().Set("ETag", "ciphertext-etag")
	out := v3KDFPlaybackFailure(rr, req, fmt.Errorf("admission: %w", encryption.ErrV3KDFBusy))
	if out.Err == nil || out.Retryable || !out.NoLearning || !out.ResponseStarted || out.FailureReason != "v3_kdf_busy" || out.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("busy outcome: %+v", out)
	}
	if rr.Code != http.StatusServiceUnavailable || rr.Body.Len() != 0 || rr.Header().Get("Content-Range") != "" || rr.Header().Get("ETag") != "" || rr.Header().Get("Content-Length") != "0" || rr.Header().Get("Retry-After") == "" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("busy headers/body: %v %q", rr.Header(), rr.Body.String())
	}
}

func TestV3KDFPlaybackCancellationNeverCommitsOrRetries(t *testing.T) {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, fmt.Errorf("wait: %w", context.Canceled)} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/file", nil)
		out := v3KDFPlaybackFailure(rr, req, err)
		if out.Err != err || out.ResponseStarted || out.Retryable || !out.NoLearning || out.FailureReason != errors.ReasonClientDisconnect || rr.Body.Len() != 0 {
			t.Fatalf("cancellation: %+v", out)
		}
	}
	// The request cancellation wins if busy admission and disconnect race.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/file", nil).WithContext(ctx)
	out := v3KDFPlaybackFailure(rr, req, encryption.ErrV3KDFBusy)
	if out.Err != context.Canceled || out.ResponseStarted || out.Retryable || !out.NoLearning || out.FailureReason != errors.ReasonClientDisconnect {
		t.Fatalf("cancel/busy race: %+v", out)
	}
}

func TestV3KDFPlaybackPreCanceledPhaseDoesNotReadOrLease(t *testing.T) {
	meta := encryption.ContentMeta{Version: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, ChunkSize: 64, NonceField: make([]byte, 16), PlainSize: 1024}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/file", nil).WithContext(ctx)
	sp := NewStreamProxy(config.DefaultConfig())
	body := &v3BudgetCountingBody{}
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}
	rr := httptest.NewRecorder()
	// A nil password proves the pre-canceled phase never attempts to enter KDF.
	out := sp.streamV3Response(rr, req, resp, nil, meta.PlainSize, meta, "", StreamStrategyFull, nil, nil, "http://upstream.test/file", "")
	if out.Err != context.Canceled || out.ResponseStarted || out.Retryable || !out.NoLearning || rr.Body.Len() != 0 || body.reads != 0 || sp.v3Memory.used.Load() != 0 {
		t.Fatalf("canceled phase: %+v bodyReads=%d recordOwned=%d", out, body.reads, sp.v3Memory.used.Load())
	}
}
