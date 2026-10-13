package encrypt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func confirmedMetadataTestServer(t *testing.T, gate <-chan struct{}, started chan<- struct{}) (*ProxyServer, *EncryptPath, string, *atomic.Int32) {
	t.Helper()
	nonce := bytes.Repeat([]byte{7}, 16)
	header, err := BuildV2Header(EncTypeAESCTR, 4096, nonce)
	if err != nil {
		t.Fatal(err)
	}
	prefix := append(header, bytes.Repeat([]byte{0x61}, int(V3HeaderSize)-len(header))...)
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if started != nil {
			select {
			case started <- struct{}{}:
			default:
			}
		}
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", V3HeaderSize-1, 4096+len(header)))
		w.Header().Set("Content-Length", strconv.Itoa(len(prefix)))
		w.Header().Set("ETag", "\"object-a\"")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(prefix)
	}))
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	p := &ProxyServer{config: &ProxyConfig{AlistHost: u.Hostname(), AlistPort: port}, streamClient: server.Client()}
	t.Cleanup(func() { p.sealLifetime(); p.lifetime().background.Wait() })
	return p, &EncryptPath{Enable: true, EncType: EncTypeAESCTR, Password: "fixture-only"}, server.URL + "/object", calls
}
func confirmedMetadataTestRequest(p *ProxyServer, enc *EncryptPath, auth string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://proxy.local/video", nil)
	r.Header.Set("Authorization", auth)
	return p.withConfirmedMetadataIdentity(r, "/mount/video.bin", enc)
}
func TestConfirmedMetadataFreshTargetCoalesces(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	p, enc, target, calls := confirmedMetadataTestServer(t, gate, started)
	results := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		r := confirmedMetadataTestRequest(p, enc, "one")
		go func() {
			_, ok := p.resolveConfirmedMetadata(withConfirmedMetadataFreshTarget(r.Context()), target, r.Header, enc, 0)
			results <- ok
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("cold probe did not start")
	}
	close(gate)
	for i := 0; i < 100; i++ {
		select {
		case ok := <-results:
			if !ok {
				t.Fatal("fresh target coalesced result failed")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("fresh target waiter blocked")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("same-target cold calls=%d", calls.Load())
	}
	r := confirmedMetadataTestRequest(p, enc, "one")
	// Model old complete geometry with a different nonce: a new target must
	// replace that record with the real fixture's newly inspected nonce.
	p.confirmedMetadata.mu.Lock()
	entry := p.confirmedMetadata.entries[confirmedMetadataRequestFromContext(r.Context()).identity]
	entry.record.Meta.NonceField[0] = 99
	p.confirmedMetadata.mu.Unlock()
	ctx := withConfirmedMetadataFreshTarget(r.Context())
	meta, ok := p.resolveConfirmedMetadata(ctx, target+"?sig=b", r.Header, enc, 0)
	if !ok || meta.NonceField[0] != 7 || calls.Load() != 2 {
		t.Fatalf("new target meta=%+v ok=%v calls=%d", meta, ok, calls.Load())
	}
	_, _ = p.resolveConfirmedMetadata(ctx, target+"?sig=b", r.Header, enc, 0)
	if calls.Load() != 2 {
		t.Fatal("same fresh target re-probed")
	}
	// Ordinary playback retains stable cross-target reuse.
	_, _ = p.resolveConfirmedMetadata(r.Context(), target+"?sig=c", r.Header, enc, 0)
	if calls.Load() != 2 {
		t.Fatal("normal playback adopted fresh-target policy")
	}
}

func TestConfirmedMetadataFreshTargetWaitsForDifferentOwnedFlight(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	p, enc, target, calls := confirmedMetadataTestServer(t, gate, started)
	first := confirmedMetadataTestRequest(p, enc, "one")
	second := confirmedMetadataTestRequest(p, enc, "one")
	firstDone, secondDone := make(chan bool, 1), make(chan bool, 1)
	go func() {
		_, ok := p.resolveConfirmedMetadata(first.Context(), target+"?sig=a", first.Header, enc, 0)
		firstDone <- ok
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first probe did not start")
	}
	go func() {
		_, ok := p.resolveConfirmedMetadata(withConfirmedMetadataFreshTarget(second.Context()), target+"?sig=b", second.Header, enc, 0)
		secondDone <- ok
	}()
	close(gate)
	for _, done := range []chan bool{firstDone, secondDone} {
		select {
		case ok := <-done:
			if !ok {
				t.Fatal("target flight failed")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("different target waiter blocked")
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("different-target probes=%d", calls.Load())
	}
}

func TestConfirmedMetadataFallbackOptInAndEscapedDAVPath(t *testing.T) {
	p, enc, _, calls := confirmedMetadataTestServer(t, nil, nil)
	original := p.streamClientSnapshot().Transport
	if original == nil {
		original = http.DefaultTransport
	}
	var externalCalls atomic.Int32
	var pathMatches, authMatches atomic.Bool
	objectPath := "/docs/video #?%.bin"
	p.streamClient = &http.Client{Transport: v2ProbeRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "expired-cdn.local" {
			externalCalls.Add(1)
			if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
				return nil, fmt.Errorf("external target leaked credentials")
			}
			return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)), Request: req}, nil
		}
		pathMatches.Store(req.URL.Path == "/dav"+objectPath && req.URL.RawQuery == "" && req.URL.Fragment == "")
		authMatches.Store(req.Header.Get("Authorization") == "Bearer one" && req.Header.Get("Cookie") == "session=one")
		return original.RoundTrip(req)
	})}
	r := httptest.NewRequest(http.MethodGet, "http://proxy.local/play", nil)
	r.Header.Set("Authorization", "Bearer one")
	r.Header.Set("Cookie", "session=one")
	r = p.withConfirmedMetadataIdentity(r, objectPath, enc)
	target := "https://expired-cdn.local/object?expired=yes"
	if _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); ok {
		t.Fatal("ordinary resolution unexpectedly fell back")
	}
	if externalCalls.Load() != 1 || calls.Load() != 0 {
		t.Fatal("non-opted resolution added fallback requests")
	}
	ctx := withConfirmedMetadataFallback(r.Context())
	meta, ok := p.resolveConfirmedMetadata(ctx, target, r.Header, enc, 0)
	if !ok || meta.PlainSize != 4096 || externalCalls.Load() != 2 || calls.Load() != 1 || !pathMatches.Load() || !authMatches.Load() {
		t.Fatalf("fallback meta=%+v ok=%v external=%d DAV=%d path=%v auth=%v", meta, ok, externalCalls.Load(), calls.Load(), pathMatches.Load(), authMatches.Load())
	}
	_, _ = p.resolveConfirmedMetadata(ctx, "https://new-cdn.local/signed?new=yes", r.Header, enc, 0)
	if externalCalls.Load() != 2 || calls.Load() != 1 {
		t.Fatal("fallback-confirmed stable object did not reuse across signed URLs")
	}
	// The parent passes an already-canonical /dav route. It must not produce
	// /dav/dav/... during fallback, including escaped special-name objects.
	prefixed := p.withConfirmedMetadataIdentity(r, "/dav"+objectPath, enc)
	_, ok = p.resolveConfirmedMetadata(withConfirmedMetadataFallback(prefixed.Context()), target, prefixed.Header, enc, 0)
	if !ok || !pathMatches.Load() || externalCalls.Load() != 3 || calls.Load() != 2 {
		t.Fatalf("prefixed DAV fallback ok=%v path=%v external=%d DAV=%d", ok, pathMatches.Load(), externalCalls.Load(), calls.Load())
	}
}

func TestConfirmedMetadataGoexitReleasesFlight(t *testing.T) {
	p, enc, target, calls := confirmedMetadataTestServer(t, nil, nil)
	original := p.streamClientSnapshot().Transport
	if original == nil {
		original = http.DefaultTransport
	}
	var attempts atomic.Int32
	p.streamClient = &http.Client{Transport: v2ProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
		if attempts.Add(1) == 1 {
			runtime.Goexit()
		}
		return original.RoundTrip(r)
	})}
	r := confirmedMetadataTestRequest(p, enc, "one")
	done := make(chan bool, 1)
	go func() { _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); done <- ok }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("Goexit inspection was confirmed")
		}
	case <-time.After(time.Second):
		t.Fatal("Goexit stranded shared flight")
	}
	// Failed worker cleanup must release the entry for a new cold inspection.
	go func() { _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); done <- ok }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("fresh inspection after Goexit failed")
		}
	case <-time.After(time.Second):
		t.Fatal("Goexit retained failed flight")
	}
	if attempts.Load() != 2 || calls.Load() != 1 {
		t.Fatalf("attempts=%d HTTP calls=%d", attempts.Load(), calls.Load())
	}
}

func TestConfirmedMetadataMemoryOnlyObjectLookup(t *testing.T) {
	p, enc, target, calls := confirmedMetadataTestServer(t, nil, nil)
	child := confirmedMetadataTestRequest(p, enc, "one")
	_, _ = p.resolveConfirmedMetadata(child.Context(), target, child.Header, enc, 0)
	listing := httptest.NewRequest("PROPFIND", "http://proxy.local/mount", nil)
	listing.Header.Set("Authorization", "one")
	listing = p.withConfirmedMetadataIdentity(listing, "/mount", enc)
	size := int64(4096) + ContentHeaderSize()
	meta, ok := p.confirmedMetadataForObject(listing.Context(), "/mount/video.bin", size)
	if !ok || meta.PlainSize != 4096 {
		t.Fatalf("lookup=%+v ok=%v", meta, ok)
	}
	meta.NonceField[0] = 99
	for _, test := range []struct {
		ctx  context.Context
		path string
		size int64
	}{
		{context.Background(), "/mount/video.bin", size},
		{listing.Context(), "/mount/video.bin", 0},
		{listing.Context(), "/mount/video.bin", size + 1},
		{listing.Context(), "/mount/missing.bin", size},
		{confirmedMetadataTestRequest(p, enc, "two").Context(), "/mount/video.bin", size},
	} {
		if _, ok := p.confirmedMetadataForObject(test.ctx, test.path, test.size); ok {
			t.Fatal("unscoped/mismatching lookup reused metadata")
		}
	}
	alternate := *enc
	alternate.Password = "another-key"
	if _, ok := p.confirmedMetadataForObject(confirmedMetadataTestRequest(p, &alternate, "one").Context(), "/mount/video.bin", size); ok {
		t.Fatal("crypto scope reused metadata")
	}
	if calls.Load() != 1 {
		t.Fatal("memory lookup probed")
	}
	p.invalidateConfirmedMetadataObject("/mount/video.bin")
	if _, ok := p.confirmedMetadataForObject(listing.Context(), "/mount/video.bin", size); ok {
		t.Fatal("invalidated lookup survived")
	}
}

func TestConfirmedMetadataInvalidateAllFencesFlight(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	p, enc, target, calls := confirmedMetadataTestServer(t, gate, started)
	r := confirmedMetadataTestRequest(p, enc, "one")
	done := make(chan bool, 1)
	go func() { _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); done <- ok }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("inspection did not start")
	}
	p.invalidateAllConfirmedMetadata()
	close(gate)
	select {
	case ok := <-done:
		if ok {
			t.Fatal("all-invalidated flight confirmed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("flight blocked")
	}
	if _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); !ok || calls.Load() != 2 {
		t.Fatal("fresh inspection failed")
	}
}

func TestConfirmedMetadataObjectInvalidationVariantsAndFlight(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{}, 2)
	p, enc, target, calls := confirmedMetadataTestServer(t, gate, started)
	first := confirmedMetadataTestRequest(p, enc, "one")
	second := confirmedMetadataTestRequest(p, enc, "two")
	done := make(chan bool, 2)
	for _, r := range []*http.Request{first, second} {
		go func(r *http.Request) {
			_, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0)
			done <- ok
		}(r)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("variant flight did not start")
		}
	}
	p.invalidateConfirmedMetadataObject("/mount/video.bin")
	close(gate)
	for i := 0; i < 2; i++ {
		select {
		case ok := <-done:
			if ok {
				t.Fatal("object-invalidated flight was confirmed")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("invalidated flight blocked")
		}
	}
	for _, r := range []*http.Request{first, second} {
		if _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); !ok {
			t.Fatal("variant fresh inspection failed")
		}
	}
	p.invalidateConfirmedMetadataObject("/mount/video.bin")
	for _, r := range []*http.Request{first, second} {
		_, _ = p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0)
	}
	if calls.Load() != 6 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestConfirmedMetadataObjectInvalidationDeletesPersistedVariants(t *testing.T) {
	p, enc, target, calls := confirmedMetadataTestServer(t, nil, nil)
	store, err := newLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	p.localStore = store
	requests := []*http.Request{confirmedMetadataTestRequest(p, enc, "one"), confirmedMetadataTestRequest(p, enc, "two")}
	for _, r := range requests {
		_, _ = p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0)
	}
	p.invalidateConfirmedMetadataObject("/mount/video.bin")
	for _, r := range requests {
		id := confirmedMetadataRequestFromContext(r.Context()).identity
		if _, ok := store.GetConfirmedMetadata(id); ok {
			t.Fatal("persisted auth variant survived object invalidation")
		}
		_, _ = p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0)
	}
	if calls.Load() != 4 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestConfirmedMetadataObservedCiphertextSize(t *testing.T) {
	p, enc, target, calls := confirmedMetadataTestServer(t, nil, nil)
	r := confirmedMetadataTestRequest(p, enc, "one")
	_, _ = p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 123) // Generic size is untrusted.
	_, _ = p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 999)
	if calls.Load() != 1 {
		t.Fatalf("generic hints invalidated cache: %d", calls.Load())
	}
	holder := confirmedMetadataRequestFromContext(r.Context())
	// Model a previously inspected old object: its cached V2 geometry remains
	// complete, but the authoritative DAV ciphertext total now proves a change.
	p.confirmedMetadata.mu.Lock()
	entry := p.confirmedMetadata.entries[holder.identity]
	entry.record.Meta.PlainSize = 8192
	entry.record.Meta.CiphertextSize = 8192 + ContentHeaderSize()
	p.confirmedMetadata.mu.Unlock()
	ctx := withConfirmedMetadataObservedSize(r.Context(), 4096+ContentHeaderSize())
	meta, ok := p.resolveConfirmedMetadata(ctx, target, r.Header, enc, 0)
	if !ok || meta.PlainSize != 4096 || calls.Load() != 2 {
		t.Fatalf("changed size meta=%+v ok=%v calls=%d", meta, ok, calls.Load())
	}
	_, _ = p.resolveConfirmedMetadata(ctx, target, r.Header, enc, 0)
	if calls.Load() != 2 {
		t.Fatal("matching authoritative size did not reuse fresh result")
	}
}

func TestConfirmedMetadataResolverReuseAndIsolation(t *testing.T) {
	p, enc, target, calls := confirmedMetadataTestServer(t, nil, nil)
	for i := 0; i < 3; i++ {
		r := confirmedMetadataTestRequest(p, enc, "Bearer one")
		meta, ok := p.resolveConfirmedMetadata(r.Context(), target+"?signature="+strconv.Itoa(i), r.Header, enc, 0)
		if !ok || meta.Version != ContentVersionV2 || meta.PlainSize != 4096 || len(meta.NonceField) != 16 {
			t.Fatalf("meta=%+v confirmed=%v", meta, ok)
		}
		// Mutating the returned nonce must not corrupt the cache.
		meta.NonceField[0] = 99
	}
	if calls.Load() != 1 {
		t.Fatalf("repeat calls=%d", calls.Load())
	}
	r := confirmedMetadataTestRequest(p, enc, "Bearer two")
	if _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); !ok {
		t.Fatal("isolated inspection failed")
	}
	if calls.Load() != 2 {
		t.Fatalf("auth calls=%d", calls.Load())
	}
	cookie := confirmedMetadataTestRequest(p, enc, "Bearer two")
	cookie.Header.Set("Cookie", "session=another")
	cookie = p.withConfirmedMetadataIdentity(cookie, "/mount/video.bin", enc)
	_, _ = p.resolveConfirmedMetadata(cookie.Context(), target, cookie.Header, enc, 0)
	if calls.Load() != 3 {
		t.Fatalf("cookie calls=%d", calls.Load())
	}
	alternate := *enc
	alternate.Password = "different-key"
	r = confirmedMetadataTestRequest(p, &alternate, "Bearer one")
	_, _ = p.resolveConfirmedMetadata(r.Context(), target, r.Header, &alternate, 0)
	if calls.Load() != 4 {
		t.Fatalf("crypto calls=%d", calls.Load())
	}
}
func TestConfirmedMetadataWithoutIdentityDoesNotReuse(t *testing.T) {
	p, enc, target, calls := confirmedMetadataTestServer(t, nil, nil)
	for i := 0; i < 2; i++ {
		if _, ok := p.resolveConfirmedMetadata(context.Background(), target, nil, enc, 0); !ok {
			t.Fatal("inspection failed")
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
}
func TestConfirmedMetadataCancellationDoesNotKillSharedInspection(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	p, enc, target, calls := confirmedMetadataTestServer(t, gate, started)
	first := confirmedMetadataTestRequest(p, enc, "Bearer one")
	ctx, cancel := context.WithCancel(first.Context())
	firstDone := make(chan bool, 1)
	go func() { _, ok := p.resolveConfirmedMetadata(ctx, target, first.Header, enc, 0); firstDone <- ok }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("inspection did not start")
	}
	cancel()
	select {
	case ok := <-firstDone:
		if ok {
			t.Fatal("canceled waiter succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not cancel")
	}
	second := confirmedMetadataTestRequest(p, enc, "Bearer one")
	secondDone := make(chan bool, 1)
	go func() {
		_, ok := p.resolveConfirmedMetadata(second.Context(), target, second.Header, enc, 0)
		secondDone <- ok
	}()
	close(gate)
	select {
	case ok := <-secondDone:
		if !ok {
			t.Fatal("other waiter lost inspection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shared inspection blocked")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}
func TestConfirmedMetadataInvalidationFencesInflight(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	p, enc, target, calls := confirmedMetadataTestServer(t, gate, started)
	r := confirmedMetadataTestRequest(p, enc, "one")
	done := make(chan bool, 1)
	go func() { _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); done <- ok }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("inspection did not start")
	}
	p.invalidateConfirmedMetadata(r.Context())
	close(gate)
	select {
	case ok := <-done:
		if ok {
			t.Fatal("invalidated flight returned confirmed metadata")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("invalidated flight blocked")
	}
	if _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); !ok {
		t.Fatal("fresh generation failed")
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
}
func TestConfirmedMetadataResponseValidators(t *testing.T) {
	p, enc, target, calls := confirmedMetadataTestServer(t, nil, nil)
	r := confirmedMetadataTestRequest(p, enc, "one")
	meta, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0)
	if !ok {
		t.Fatal("inspection failed")
	}
	response := func(raw, etag, total string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, raw, nil)
		return &http.Response{StatusCode: http.StatusPartialContent, Request: req, Header: http.Header{"Etag": []string{etag}, "Content-Range": []string{"bytes 32-47/" + total}}, ContentLength: 16}
	}
	total := strconv.FormatInt(meta.CiphertextSize, 10)
	if !p.validateConfirmedMetadataResponse(r.Context(), response("https://other-cdn.local/object", "\"other-namespace\"", total)) {
		t.Fatal("cross-CDN validator compared")
	}
	if p.validateConfirmedMetadataResponse(r.Context(), response(target+"?new-signature=yes", "\"changed\"", total)) {
		t.Fatal("same scope strong ETag conflict accepted")
	}
	if _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); !ok {
		t.Fatal("re-inspect failed")
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
	if p.validateConfirmedMetadataResponse(r.Context(), response("https://another.local/object", "\"a\"", "99999")) {
		t.Fatal("ciphertext total conflict accepted")
	}
}
func TestConfirmedMetadataPersistAcrossResolverRestart(t *testing.T) {
	p, enc, target, calls := confirmedMetadataTestServer(t, nil, nil)
	dir := t.TempDir()
	store, err := newLocalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p.localStore = store
	r := confirmedMetadataTestRequest(p, enc, "one")
	if _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); !ok {
		t.Fatal("inspection failed")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := newLocalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted := &ProxyServer{config: p.configSnapshot(), streamClient: p.streamClientSnapshot(), localStore: reopened}
	t.Cleanup(func() { restarted.sealLifetime(); restarted.lifetime().background.Wait() })
	r = confirmedMetadataTestRequest(restarted, enc, "one")
	meta, ok := restarted.resolveConfirmedMetadata(r.Context(), target+"?rotated=yes", r.Header, enc, 0)
	if !ok || meta.Version != ContentVersionV2 || meta.PlainSize != 4096 || len(meta.NonceField) != 16 {
		t.Fatalf("restart meta=%+v ok=%v", meta, ok)
	}
	if calls.Load() != 1 {
		t.Fatalf("restart probed calls=%d", calls.Load())
	}
}
func TestConfirmedMetadataBoundsAndExpiry(t *testing.T) {
	state := &confirmedMetadataState{}
	state.mu.Lock()
	for i := 0; i < confirmedMetadataLimit+10; i++ {
		state.ensureEntry(confirmedMetadataIdentity{ObjectID: strconv.Itoa(i)}, time.Now())
	}
	if len(state.entries) != confirmedMetadataLimit {
		t.Fatalf("entries=%d", len(state.entries))
	}
	state.mu.Unlock()
	p, enc, target, calls := confirmedMetadataTestServer(t, nil, nil)
	r := confirmedMetadataTestRequest(p, enc, "one")
	_, _ = p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0)
	p.confirmedMetadata.mu.Lock()
	entry := p.confirmedMetadata.entries[confirmedMetadataRequestFromContext(r.Context()).identity]
	entry.record.ConfirmedAt = time.Now().Add(-25 * time.Hour).Unix()
	p.confirmedMetadata.mu.Unlock()
	_, _ = p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0)
	if calls.Load() != 2 {
		t.Fatalf("expired record reused, calls=%d", calls.Load())
	}
}
func TestConfirmedMetadataShutdownCompletesWaiters(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	p, enc, target, _ := confirmedMetadataTestServer(t, gate, started)
	r := confirmedMetadataTestRequest(p, enc, "one")
	done := make(chan bool, 1)
	go func() { _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); done <- ok }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("inspection did not start")
	}
	p.sealLifetime()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("shutdown inspection succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown stranded waiter")
	}
	if _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); ok {
		t.Fatal("sealed lifecycle admitted cold probe")
	}
	close(gate)
}

func TestConfirmedMetadataProofVaryPolicy(t *testing.T) {
	for _, test := range []struct {
		vary  string
		reuse bool
	}{{"", true}, {"Accept-Encoding", true}, {"User-Agent", false}, {"*", false}, {"Accept-Encoding, Cookie", false}} {
		collector := &confirmedMetadataCollector{}
		ctx := context.WithValue(context.Background(), confirmedMetadataCollectorKey{}, collector)
		captureConfirmedMetadataProof(ctx, &http.Response{StatusCode: http.StatusOK, ContentLength: 100, Header: http.Header{"Vary": []string{test.vary}}}, "https://cdn.local/object?signature=secret")
		if collector.proof.reusable != test.reuse || collector.proof.scope != "https://cdn.local/object" {
			t.Fatalf("vary=%q proof=%+v", test.vary, collector.proof)
		}
	}
}
