package encrypt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	core "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestV3PlaybackKDFBusyIsTerminalResourceFailure(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Content-Range", "bytes 0-1/8")
	w.Header().Set("Content-Length", "2")
	w.Header().Set("ETag", "stale-success")
	err := v3PlaybackKDFFailure(w, fmt.Errorf("admission: %w", core.ErrV3KDFBusy))
	var failure *V3PlaybackError
	if !errors.As(err, &failure) || !errors.Is(err, core.ErrV3KDFBusy) || !failure.ResponseStarted || !failure.NoLearning || failure.UpstreamStatus != 0 || w.Code != http.StatusServiceUnavailable || w.Body.Len() != 0 {
		t.Fatalf("err=%v status=%d body=%q", err, w.Code, w.Body.Bytes())
	}
	if w.Header().Get("Retry-After") == "" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Range") != "" || w.Header().Get("ETag") != "" || w.Header().Get("Content-Length") != "0" {
		t.Fatalf("headers=%v", w.Header())
	}
}

func TestV3PlaybackCanceledAfterHeadersBeforeKDFClosesBody(t *testing.T) {
	_, meta := v3PlaybackFixture(t, []byte("abcdefgh"), 8, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var reads, closes, calls atomic.Int64
	p := &ProxyServer{streamClient: &http.Client{Transport: v3PlaybackRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		// No record reservation may be held while preparing provider headers or
		// waiting for CPU admission. Acquire the entire existing memory semaphore.
		if !v3PlaybackMemory.TryAcquire(v3PlaybackMemoryBytes) {
			t.Error("record reservation held before KDF")
		} else {
			v3PlaybackMemory.Release(v3PlaybackMemoryBytes)
		}
		cancel()
		return &http.Response{StatusCode: http.StatusPartialContent, Header: http.Header{"Content-Range": []string{"bytes 48-71/72"}}, ContentLength: 24, Body: v3PlaybackCountingBody{&reads, &closes}}, nil
	})}}
	request := httptest.NewRequest("GET", "http://client/", nil).WithContext(ctx)
	request.Header.Set("Range", "bytes=0-1")
	w := httptest.NewRecorder()
	err := p.serveV3Playback(w, request, v3PlaybackInfo("http://cancel-before-kdf.invalid/object"), meta)
	var failure *V3PlaybackError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &failure) || !failure.NoLearning || failure.UpstreamStatus != 0 || w.Code != http.StatusBadGateway || w.Body.Len() != 0 || calls.Load() != 1 || reads.Load() != 0 || closes.Load() != 1 {
		t.Fatalf("err=%v status=%d reads=%d closes=%d calls=%d", err, w.Code, reads.Load(), closes.Load(), calls.Load())
	}
	if !v3PlaybackMemory.TryAcquire(v3PlaybackMemoryBytes) {
		t.Fatal("record admission leaked on cancellation")
	}
	v3PlaybackMemory.Release(v3PlaybackMemoryBytes)
}

func TestV3PlaybackKDFFailureCanceledDoesNotRefresh(t *testing.T) {
	w := httptest.NewRecorder()
	err := v3PlaybackKDFFailure(w, context.Canceled)
	var failure *V3PlaybackError
	if !errors.As(err, &failure) || !failure.NoLearning || !failure.ResponseStarted || failure.UpstreamStatus != 0 || w.Code != http.StatusBadGateway || w.Body.Len() != 0 {
		t.Fatalf("err=%v status=%d", err, w.Code)
	}
}
