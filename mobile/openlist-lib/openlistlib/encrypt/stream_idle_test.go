package encrypt

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type idleTestTransport func(*http.Request) (*http.Response, error)

func (f idleTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type idleBlockingBody struct{ ctx context.Context }

func (b idleBlockingBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (b idleBlockingBody) Close() error             { return nil }

func TestStreamIdlePendingReadCancellation(t *testing.T) {
	rt := &streamIdleRoundTripper{timeout: 20 * time.Millisecond, base: idleTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{Body: idleBlockingBody{r.Context()}}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "http://example/file", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = resp.Body.Read(make([]byte, 1))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want idle timeout, got %v", err)
	}
}

func TestStreamIdleBackpressureAndLongProgress(t *testing.T) {
	var upstream context.Context
	rt := &streamIdleRoundTripper{timeout: 10 * time.Millisecond, base: idleTestTransport(func(r *http.Request) (*http.Response, error) {
		upstream = r.Context()
		return &http.Response{Body: io.NopCloser(strings.NewReader("abcdef"))}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "http://example/file", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		// Playback pauses / slow downstream writes must not cancel the upstream.
		time.Sleep(20 * time.Millisecond)
		if upstream.Err() != nil {
			t.Fatal("body canceled between reads")
		}
		n, err := resp.Body.Read(make([]byte, 1))
		if n != 1 || err != nil {
			t.Fatalf("progress %d: %d %v", i, n, err)
		}
	}
	resp.Body.Close()
	if !errors.Is(upstream.Err(), context.Canceled) {
		t.Fatal("Close did not preserve cancel")
	}
}

func TestStreamIdleParentCancellation(t *testing.T) {
	rt := &streamIdleRoundTripper{timeout: time.Second, base: idleTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{Body: idleBlockingBody{r.Context()}}, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example/file", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = resp.Body.Read(make([]byte, 1))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancel lost: %v", err)
	}
	resp.Body.Close()
}
