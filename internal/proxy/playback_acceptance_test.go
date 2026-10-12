package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/playbacktest"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

type acceptanceContainer struct {
	name string
	body []byte
	meta encryption.ContentMeta
}

// Reuse the existing V3 builder and the same V1/V2 encryptors as legacy tests.
func acceptanceContainers(t *testing.T, plain []byte) []acceptanceContainer {
	t.Helper()
	v1 := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("pw", "aesctr", int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	flow.Encrypt(v1)
	enc, err := encryption.NewLatestContentEncryptor("pw", "aesctr", int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := enc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	v3, meta := buildV3Container(t, "pw", 64, plain)
	return []acceptanceContainer{
		{"V1", v1, encryption.ContentMeta{EncType: encryption.EncTypeAESCTR, Version: 1, PlainSize: int64(len(plain)), CiphertextSize: int64(len(v1))}},
		{"V2", v2, enc.Meta}, {"V3", v3, meta},
	}
}

func acceptanceProxy(u *playbacktest.Upstream) *StreamProxy {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableSniff = false
	cfg.AlistServer.FollowRedirectForDecrypt = true
	cfg.AlistServer.CircuitBreakerThreshold = 1
	sp := NewStreamProxy(cfg)
	client := u.Server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	sp.client = &Client{Client: client}
	sp.retrier.MaxRetries = 0
	return sp
}

// These are transport/decryption acceptance metrics, NOT decoder readiness or
// rendered-frame measurements. Server BodyBytes is a write-side download proxy,
// including bytes discarded by fallback, not TCP traffic or client-consumed bytes.
type acceptanceMetric struct {
	Case                  string                `json:"case"`
	PlaintextBytes        int                   `json:"plaintext_bytes"`
	Upstream              playbacktest.Snapshot `json:"upstream"`
	DownloadAmplification float64               `json:"download_amplification"`
}

func TestPlaybackAcceptanceExactPlaintextMatrix(t *testing.T) {
	plain := bytes.Repeat([]byte("playback-exact-plaintext-0123456789"), 32)
	var metrics []acceptanceMetric
	for _, container := range acceptanceContainers(t, plain) {
		for _, mode := range []playbacktest.RangeMode{playbacktest.RangeAccept, playbacktest.RangeIgnore, playbacktest.RangeReject} {
			for _, interval := range []struct {
				name, header string
				start, end   int
			}{
				{"full", "", 0, len(plain)}, {"initial", "bytes=0-31", 0, 32}, {"seek", "bytes=127-190", 127, 191}, {"suffix", "bytes=-19", len(plain) - 19, len(plain)},
			} {
				name := container.name + "/" + string(mode) + "/" + interval.name
				t.Run(name, func(t *testing.T) {
					u := playbacktest.New(container.body, playbacktest.Behavior{Range: mode}, nil)
					defer u.Close()
					sp := acceptanceProxy(u)
					req := httptest.NewRequest(http.MethodGet, "/d/acceptance.mp4", nil)
					req.Header.Set("Range", interval.header)
					req = req.WithContext(WithContentMeta(req.Context(), container.meta))
					rr := httptest.NewRecorder()
					passwd := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}
					outcome := sp.ProxyDownloadDecryptWithStrategy(rr, req, u.URL("/object"), passwd, int64(len(plain)), StreamStrategyRange)
					fallback := mode != playbacktest.RangeAccept && interval.header != ""
					if fallback {
						if outcome.Err == nil || outcome.ResponseStarted {
							t.Fatalf("range failure should be uncommitted: %+v", outcome)
						}
						rr = httptest.NewRecorder()
						outcome = sp.ProxyDownloadDecryptWithStrategy(rr, req, u.URL("/object"), passwd, int64(len(plain)), StreamStrategyFull)
					}
					want := plain[interval.start:interval.end]
					if outcome.Err != nil || !bytes.Equal(rr.Body.Bytes(), want) {
						t.Fatalf("outcome=%+v bytes=%d want=%d", outcome, rr.Body.Len(), len(want))
					}
					status := http.StatusOK
					if interval.header != "" {
						status = http.StatusPartialContent
						expected := fmt.Sprintf("bytes %d-%d/%d", interval.start, interval.end-1, len(plain))
						if rr.Header().Get("Content-Range") != expected {
							t.Fatalf("Content-Range=%q want %q", rr.Header().Get("Content-Range"), expected)
						}
					}
					if rr.Code != status {
						t.Fatalf("status=%d want %d", rr.Code, status)
					}
					u.Close()
					snap := u.Snapshot()
					calls := 1
					if fallback {
						calls = 2
					}
					if snap.RequestCount != calls {
						t.Fatalf("requests=%d want %d", snap.RequestCount, calls)
					}
					// Small fixtures are flushed in one write, so healthy and fallback write
					// counts are exact and reproducible, not race-dependent streaming estimates.
					expectedBytes := int64(len(container.body))
					if !fallback && interval.header != "" {
						expectedBytes = int64(len(want))
						if container.meta.IsV3() {
							a, b := encryption.V3ChunkWindow(int64(interval.start), int64(interval.end-1), 64)
							expectedBytes = b - a + 1
						}
					}
					if fallback && mode == playbacktest.RangeIgnore {
						expectedBytes *= 2
					}
					if snap.BodyBytes != expectedBytes {
						t.Fatalf("upstream bytes=%d want %d", snap.BodyBytes, expectedBytes)
					}
					m := acceptanceMetric{Case: name, PlaintextBytes: len(want), Upstream: snap, DownloadAmplification: float64(snap.BodyBytes) / float64(len(want))}
					metrics = append(metrics, m)
					t.Logf("requests=%d upstream_body_bytes=%d plaintext_bytes=%d amplification=%.3f", calls, snap.BodyBytes, len(want), m.DownloadAmplification)
				})
			}
		}
	}
	if path := os.Getenv("PLAYBACK_ACCEPTANCE_REPORT"); path != "" {
		artifact := struct {
			Schema  int                `json:"schema"`
			Scope   string             `json:"scope"`
			Metrics []acceptanceMetric `json:"metrics"`
		}{1, "HTTP plaintext and upstream write-side bytes; no rendered-frame claims", metrics}
		if err := playbacktest.WriteJSON(path, artifact); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPlaybackAcceptanceCancellationMatrix(t *testing.T) {
	plain := bytes.Repeat([]byte("cancel-plaintext"), 64)
	for _, container := range acceptanceContainers(t, plain) {
		for _, stall := range []string{"headers", "body"} {
			t.Run(container.name+"/"+stall, func(t *testing.T) {
				b := playbacktest.Behavior{Range: playbacktest.RangeAccept, StallHeaders: stall == "headers", StallBody: stall == "body"}
				u := playbacktest.New(container.body, b, nil)
				defer u.Close()
				sp := acceptanceProxy(u)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				req := httptest.NewRequest(http.MethodGet, "/d/cancel.mp4", nil)
				req.Header.Set("Range", "bytes=127-190")
				req = req.WithContext(WithContentMeta(ctx, container.meta))
				rr := httptest.NewRecorder()
				done := make(chan *StreamOutcome, 1)
				go func() {
					done <- sp.ProxyDownloadDecryptWithStrategy(rr, req, u.URL("/object"), &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}, int64(len(plain)), StreamStrategyRange)
				}()
				event := u.Started
				if stall == "body" {
					event = u.HeadersSent
				}
				select {
				case <-event:
				case <-ctx.Done():
					t.Fatal("request never reached fixture")
				}
				cancel()
				select {
				case result := <-done:
					if result.Err == nil || result.Retryable || rr.Body.Len() != 0 {
						t.Fatalf("cancel result=%+v bytes=%d", result, rr.Body.Len())
					}
				case <-time.After(3 * time.Second):
					t.Fatal("proxy cancellation failed to unblock")
				}
				u.Close()
				snap := u.Snapshot()
				if snap.RequestCount != 1 || snap.BodyBytes != 0 {
					t.Fatalf("cancel snapshot=%+v", snap)
				}
				if !sp.circuitBreakerFor(u.URL("/object")).Allow() {
					t.Fatal("seek cancellation poisoned circuit breaker")
				}
			})
		}
	}
}

func TestPlaybackAcceptanceRedirectAndFaults(t *testing.T) {
	plain := bytes.Repeat([]byte("fault-plaintext-"), 64)
	for _, container := range acceptanceContainers(t, plain) {
		for _, scenario := range []string{"redirect", "expired", "unavailable", "truncate"} {
			t.Run(container.name+"/"+scenario, func(t *testing.T) {
				route := playbacktest.Behavior{Range: playbacktest.RangeAccept}
				switch scenario {
				case "redirect":
					route.Redirect = "/object"
				case "expired":
					route.Status = 403
				case "unavailable":
					route.Status = 503
				case "truncate":
					route.TruncateAfter = 1
				}
				u := playbacktest.New(container.body, playbacktest.Behavior{Range: playbacktest.RangeAccept}, map[string]playbacktest.Behavior{"/entry": route})
				defer u.Close()
				sp := acceptanceProxy(u)
				req := httptest.NewRequest(http.MethodGet, "/d/fault.mp4", nil)
				req.Header.Set("Range", "bytes=127-190")
				req = req.WithContext(WithContentMeta(req.Context(), container.meta))
				rr := httptest.NewRecorder()
				result := sp.ProxyDownloadDecryptWithStrategy(rr, req, u.URL("/entry"), &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}, int64(len(plain)), StreamStrategyRange)
				if scenario == "redirect" {
					if result.Err != nil || !bytes.Equal(rr.Body.Bytes(), plain[127:191]) {
						t.Fatalf("redirect result=%+v body=%d", result, rr.Body.Len())
					}
				} else {
					if result.Err == nil || bytes.Equal(rr.Body.Bytes(), plain[127:191]) {
						t.Fatalf("fault accepted as complete: %+v", result)
					}
					if scenario == "expired" && result.StatusCode != 403 {
						t.Fatalf("expired=%+v", result)
					}
					if scenario == "unavailable" && result.StatusCode != 503 {
						t.Fatalf("unavailable=%+v", result)
					}
				}
				u.Close()
				wantCalls := 1
				if scenario == "redirect" {
					wantCalls = 2
				}
				if u.Snapshot().RequestCount != wantCalls {
					t.Fatalf("snapshot=%+v", u.Snapshot())
				}
			})
		}
	}
}
