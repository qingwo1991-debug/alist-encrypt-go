package playbacktest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestUpstreamRangeMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		mode         RangeMode
		status       int
		body         string
	}{
		{"bounded", "bytes=2-4", RangeAccept, 206, "234"}, {"open", "bytes=7-", RangeAccept, 206, "789"},
		{"suffix", "bytes=-3", RangeAccept, 206, "789"}, {"clamp", "bytes=8-99", RangeAccept, 206, "89"},
		{"invalid", "bytes=20-", RangeAccept, 416, ""}, {"multi", "bytes=1-2,4-5", RangeAccept, 416, ""},
		{"reject", "bytes=2-4", RangeReject, 416, ""}, {"ignore", "bytes=2-4", RangeIgnore, 200, "0123456789"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := New([]byte("0123456789"), Behavior{Range: tc.mode}, nil)
			defer u.Close()
			req, _ := http.NewRequest(http.MethodGet, u.URL("/object"), nil)
			req.Header.Set("Range", tc.header)
			resp, err := u.Server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			u.Close()
			s := u.Snapshot()
			if resp.StatusCode != tc.status || string(body) != tc.body || s.RequestCount != 1 || s.BodyBytes != int64(len(tc.body)) {
				t.Fatalf("status=%d body=%q snapshot=%+v", resp.StatusCode, body, s)
			}
		})
	}
}

func TestUpstreamRedirectStatusAndTruncate(t *testing.T) {
	u := New([]byte("payload"), Behavior{}, map[string]Behavior{
		"/redirect": {Redirect: "/object"}, "/expired": {Status: 403, Headers: http.Header{"X-Fixture-Reason": {"expired"}}},
		"/unavailable": {Status: 503}, "/truncate": {TruncateAfter: 3},
	})
	defer u.Close()
	for _, tc := range []struct {
		path      string
		status    int
		body      string
		truncated bool
	}{
		{"/redirect", 200, "payload", false}, {"/expired", 403, "", false}, {"/unavailable", 503, "", false}, {"/truncate", 200, "pay", true},
	} {
		resp, err := u.Server.Client().Get(u.URL(tc.path))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if tc.truncated {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncate err=%v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != tc.status || string(body) != tc.body {
			t.Fatalf("%s status=%d body=%q", tc.path, resp.StatusCode, body)
		}
	}
	u.Close()
	if u.Snapshot().RequestCount != 5 {
		t.Fatalf("snapshot=%+v", u.Snapshot())
	}
}

func TestUpstreamCancellationAndSafeShutdown(t *testing.T) {
	gate := make(chan struct{})
	for _, tc := range []struct {
		name         string
		b            Behavior
		afterHeaders bool
	}{
		{"header-stall", Behavior{StallHeaders: true}, false}, {"body-stall", Behavior{StallBody: true}, true},
		{"header-gate", Behavior{HeaderGate: gate}, false}, {"body-gate", Behavior{BodyGate: gate}, true},
		{"latency", Behavior{HeaderLatency: time.Hour}, false},
		{"bandwidth", Behavior{ChunkBytes: 1, BytesPerSecond: 1, ChunkLatency: time.Hour}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, shutdown := range []bool{false, true} {
				func() {
					u := New([]byte("data"), tc.b, nil)
					defer u.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.URL("/object"), nil)
					done := make(chan error, 1)
					go func() {
						resp, err := u.Server.Client().Do(req)
						if err == nil {
							_, err = io.ReadAll(resp.Body)
							resp.Body.Close()
						}
						done <- err
					}()
					event := u.Started
					if tc.afterHeaders {
						event = u.HeadersSent
					}
					select {
					case <-event:
					case <-ctx.Done():
						t.Fatal("fixture did not start")
					}
					if shutdown {
						u.Close()
					} else {
						cancel()
					}
					select {
					case err := <-done:
						if err == nil {
							t.Fatal("blocked transfer unexpectedly succeeded")
						}
					case <-time.After(2 * time.Second):
						t.Fatal("cancellation/shutdown hung")
					}
					cancel()
					u.Close()
					u.Close()
					if u.Snapshot().RequestCount != 1 {
						t.Fatalf("snapshot=%+v", u.Snapshot())
					}
				}()
			}
		})
	}
}

// Isolate the first phase of Close: cancel the fixture without closing sockets.
// This deterministically exercises the handler-abort path, rather than relying
// on CloseClientConnections winning the race against an implicit HTTP 200.
func TestUpstreamHeaderShutdownNeverSynthesizesSuccess(t *testing.T) {
	for iteration := 0; iteration < 32; iteration++ {
		func() {
			u := New([]byte("data"), Behavior{StallHeaders: true}, nil)
			defer u.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL("/object"), nil)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				resp, err := u.Server.Client().Do(req)
				if resp != nil {
					resp.Body.Close()
				}
				done <- err
			}()
			select {
			case <-u.Started:
			case <-ctx.Done():
				t.Fatalf("iteration %d: fixture did not start", iteration)
			}
			u.cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("iteration %d: header shutdown synthesized success", iteration)
				}
			case <-ctx.Done():
				t.Fatalf("iteration %d: handler abort failed to unblock client", iteration)
			}
			u.Close()
			snapshot := u.Snapshot()
			if snapshot.RequestCount != 1 || snapshot.BodyBytes != 0 || snapshot.Requests[0].Status != 0 || !snapshot.Requests[0].Canceled {
				t.Fatalf("iteration %d: shutdown snapshot=%+v", iteration, snapshot)
			}
		}()
	}
}

func TestWriteJSONExplicitPath(t *testing.T) {
	if err := WriteJSON("artifact.json", Snapshot{}); err == nil {
		t.Fatal("relative artifact path accepted")
	}
	if err := WriteJSON(filepath.Join(t.TempDir(), "artifact.json"), Snapshot{}); err != nil {
		t.Fatal(err)
	}
}
