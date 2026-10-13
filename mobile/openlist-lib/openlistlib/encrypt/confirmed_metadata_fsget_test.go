package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// FsGet requires proof for a new download target, but simultaneous requests for
// that same target must join one owned inspection, not invalidate each other's
// flights. Ordinary stable-object playback may still reuse metadata across URLs.
func TestConfirmedMetadataFsGetConcurrentFreshTarget(t *testing.T) {
	const callers = 12
	plain := bytes.Repeat([]byte("confirmed-fsget-media"), 16)
	fixture := func(nonceByte byte) []byte {
		nonce := bytes.Repeat([]byte{nonceByte}, 16)
		header, err := BuildV2Header(EncTypeAESCTR, int64(len(plain)), nonce)
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := NewCipherV2(EncTypeAESCTR, "legacy-test-password", int64(len(plain)), nonce)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(NewEncryptReader(bytes.NewReader(plain), cipher))
		if err != nil {
			t.Fatal(err)
		}
		return append(header, body...)
	}
	cipherA, cipherB := fixture(3), fixture(9)
	type waveState struct {
		signature    string
		cipher       []byte
		controls     atomic.Int32
		probes       atomic.Int32
		allControls  chan struct{}
		probeStarted chan struct{}
		release      chan struct{}
		releaseOnce  sync.Once
	}
	var stateMu sync.RWMutex
	var state *waveState
	upstreamErrors := make(chan error, 100)
	report := func(format string, args ...interface{}) {
		select {
		case upstreamErrors <- fmt.Errorf(format, args...):
		default:
		}
	}
	var origin string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stateMu.RLock()
		current := state
		stateMu.RUnlock()
		if r.URL.Path == "/api/admin/storage/list" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"code":200,"data":{"content":[]}}`)
			return
		}
		if current == nil {
			report("unexpected request before wave: %s %s", r.Method, r.URL)
			http.Error(w, "no wave", 500)
			return
		}
		if r.Header.Get("Authorization") != "Bearer fsget-test" || r.Header.Get("Cookie") != "session=fsget-test" {
			report("missing same-origin credentials: %s %s", r.Method, r.URL)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/fs/get":
			var input struct {
				Path string `json:"path"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Path != "/enc/movie" {
				report("fs/get input path=%q err=%v", input.Path, err)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{
				"name": "movie", "size": len(current.cipher), "raw_url": origin + "/object?sig=" + current.signature, "is_dir": false,
			}})
			if current.controls.Add(1) == callers {
				close(current.allControls)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/object":
			if r.URL.Query().Get("sig") != current.signature || r.Header.Get("Range") != "bytes=0-47" {
				report("unexpected content probe target/range: %s %q", r.URL, r.Header.Get("Range"))
			}
			if current.probes.Add(1) == 1 {
				close(current.probeStarted)
			}
			select {
			case <-current.release:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeContent(w, r, "cipher", time.Time{}, bytes.NewReader(current.cipher))
		default:
			report("unexpected upstream request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	origin = upstream.URL
	p := confirmedWebDAVProxy(t, upstream)
	proxy := httptest.NewServer(http.HandlerFunc(p.handleFsGet))
	defer proxy.Close()
	proxy.Client().Timeout = 5 * time.Second

	for _, tc := range []struct {
		name, signature string
		cipher          []byte
		nonceByte       byte
		wantProbes      int32
	}{
		{"cold-target-a", "a", cipherA, 3, 1},
		{"warm-target-a", "a", cipherA, 3, 0},
		{"new-target-b-same-size-new-nonce", "b", cipherB, 9, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := &waveState{signature: tc.signature, cipher: tc.cipher, allControls: make(chan struct{}), probeStarted: make(chan struct{}), release: make(chan struct{})}
			release := func() { current.releaseOnce.Do(func() { close(current.release) }) }
			defer release()
			stateMu.Lock()
			state = current
			stateMu.Unlock()
			results := make(chan error, callers)
			start := make(chan struct{})
			for i := 0; i < callers; i++ {
				go func() {
					<-start
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					r, err := http.NewRequestWithContext(ctx, http.MethodPost, proxy.URL+"/api/fs/get", strings.NewReader(`{"path":"/enc/movie"}`))
					if err != nil {
						results <- err
						return
					}
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Authorization", "Bearer fsget-test")
					r.Header.Set("Cookie", "session=fsget-test")
					resp, err := proxy.Client().Do(r)
					if err != nil {
						results <- err
						return
					}
					defer resp.Body.Close()
					var result struct {
						Code int `json:"code"`
						Data struct {
							Size   int64  `json:"size"`
							RawURL string `json:"raw_url"`
						} `json:"data"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
						results <- err
						return
					}
					if resp.StatusCode != 200 || result.Code != 200 || result.Data.Size != int64(len(plain)) || result.Data.RawURL == "" {
						results <- fmt.Errorf("fs/get status=%d code=%d plainSize=%d rawURL=%q", resp.StatusCode, result.Code, result.Data.Size, result.Data.RawURL)
						return
					}
					results <- nil
				}()
			}
			close(start)
			await := func(ch <-chan struct{}, description string) {
				t.Helper()
				select {
				case <-ch:
				case <-time.After(6 * time.Second):
					t.Fatalf("timed out waiting for %s", description)
				}
			}
			await(current.allControls, "all concurrent fs/get control responses")
			if tc.wantProbes > 0 {
				await(current.probeStarted, "first owned content probe")
			}
			release()
			for i := 0; i < callers; i++ {
				select {
				case err := <-results:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(6 * time.Second):
					t.Fatal("timed out collecting fs/get handlers")
				}
			}
			if got := current.controls.Load(); got != callers {
				t.Errorf("control requests=%d want=%d", got, callers)
			}
			if got := current.probes.Load(); got != tc.wantProbes {
				t.Errorf("content probes=%d want=%d", got, tc.wantProbes)
			}
			r := httptest.NewRequest(http.MethodPost, "http://proxy/api/fs/get", nil)
			r.Header.Set("Authorization", "Bearer fsget-test")
			r.Header.Set("Cookie", "session=fsget-test")
			ep := p.config.EncryptPaths[0]
			r = p.withConfirmedMetadataIdentity(r, canonicalMetadataDAVPath("/enc/movie"), ep)
			meta, ok := p.confirmedMetadataForObject(r.Context(), canonicalMetadataDAVPath("/enc/movie"), int64(len(tc.cipher)))
			if !ok || meta.Version != ContentVersionV2 || meta.PlainSize != int64(len(plain)) || !bytes.Equal(meta.NonceField, bytes.Repeat([]byte{tc.nonceByte}, 16)) {
				t.Errorf("confirmed metadata after wave: ok=%v version=%d plain=%d nonce=%x", ok, meta.Version, meta.PlainSize, meta.NonceField)
			}
		})
	}
	for {
		select {
		case err := <-upstreamErrors:
			t.Error(err)
		default:
			return
		}
	}
}
