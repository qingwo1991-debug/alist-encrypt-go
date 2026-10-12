package mega

import (
	"context"
	"crypto/aes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func stalledServer(t *testing.T) (*httptest.Server, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	stop := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
			canceled <- struct{}{}
		case <-stop:
		}
	}))
	t.Cleanup(func() { close(stop); s.CloseClientConnections(); s.Close() })
	return s, entered, canceled
}
func awaitSignal(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("actual request/session did not settle")
	}
}
func TestContextLoginCancelsActualHTTP(t *testing.T) {
	s, entered, canceled := stalledServer(t)
	m := New()
	defer m.Close()
	m.SetAPIUrl(s.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.LoginContext(ctx, "test@example.invalid", "not-a-secret") }()
	awaitSignal(t, entered)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("login not canceled")
	}
	awaitSignal(t, canceled)
	if m.pollStarted {
		t.Fatal("failed login leaked event poller")
	}
}
func TestContextAPIWaiterCancelsWithoutCPUOrNetwork(t *testing.T) {
	m := New()
	defer m.Close()
	m.apiMu <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.apiRequestContext(ctx, []byte("[]"))
	<-m.apiMu
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestContextDownloadChunkCancelsActualHTTP(t *testing.T) {
	s, entered, canceled := stalledServer(t)
	m := New()
	defer m.Close()
	block, _ := aes.NewCipher(make([]byte, 16))
	d := &Download{m: m, src: &Node{name: "fixture"}, resourceUrl: s.URL, aes_block: block, chunks: []chunkSize{{size: 16}}, chunk_macs: make([][]byte, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := d.DownloadChunkContext(ctx, 0); done <- err }()
	awaitSignal(t, entered)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("chunk did not cancel")
	}
	awaitSignal(t, canceled)
	if d.chunk_macs[0] != nil {
		t.Fatal("canceled chunk published MAC")
	}
}
func TestCloseCancelsAndJoinsActualPoller(t *testing.T) {
	s, entered, canceled := stalledServer(t)
	m := New()
	m.SetLogger(nil)
	m.SetAPIUrl(s.URL)
	defer m.Close()
	m.startPoller()
	m.startPoller()
	awaitSignal(t, entered)
	done := make(chan error, 1)
	go func() { done <- m.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join poller")
	}
	awaitSignal(t, canceled)
	if m.lifeCtx.Err() == nil {
		t.Fatal("session still alive")
	}
}
func TestBackoffPollerFailuresDoNotHotLoop(t *testing.T) {
	for _, response := range []struct {
		name   string
		status int
		body   string
	}{
		{"http500", 500, ""}, {"badJSON", 200, "not-json"},
	} {
		t.Run(response.name, func(t *testing.T) {
			stamps := make(chan time.Time, 16)
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
				// Timestamp before sending the failure; the next request must include
				// the cancellable retry delay even on a fast local upstream.
				select {
				case stamps <- time.Now():
				default:
				}
				w.WriteHeader(response.status)
				_, _ = io.WriteString(w, response.body)
			}))
			defer s.Close()
			m := New()
			m.SetLogger(nil)
			m.SetAPIUrl(s.URL)
			defer m.Close()
			m.startPoller()
			var previous time.Time
			for i := 0; i < 3; i++ {
				select {
				case stamp := <-stamps:
					if !previous.IsZero() && stamp.Sub(previous) < minSleepTime {
						t.Fatalf("failure hot loop: retry gap %s below %s", stamp.Sub(previous), minSleepTime)
					}
					previous = stamp
				case <-time.After(2 * time.Second):
					t.Fatal("poller failed to retry")
				}
			}
			done := make(chan error, 1)
			go func() { done <- m.Close() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Close failed to interrupt poller backoff")
			}
		})
	}
}

func TestBackoffContextCanceledTimerAndNoFurtherRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	delay := time.Hour
	if err := backOffContext(ctx, &delay); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var calls atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(503)
	}))
	defer s.Close()
	m := New()
	defer m.Close()
	m.SetAPIUrl(s.URL)
	_, err := m.apiRequestContext(ctx, []byte("[]"))
	if !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}
