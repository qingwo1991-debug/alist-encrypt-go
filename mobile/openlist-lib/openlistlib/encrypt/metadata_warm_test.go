package encrypt

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func warmTestServer() *ProxyServer {
	return &ProxyServer{config: &ProxyConfig{MetadataNextWarmEnabled: true, AlistHost: "127.0.0.1", AlistPort: 5244}}
}

func TestMetadataWarmTaskRejectsStaleOriginAndCrypto(t *testing.T) {
	p := warmTestServer()
	ep := &EncryptPath{Path: "^/series/", Password: "test-old", Enable: true, regex: regexp.MustCompile("^/series/")}
	p.config.EncryptPaths = []*EncryptPath{ep}
	task := metadataWarmTask{origin: p.getAlistURL(), candidate: metadataWarmCandidate{objectPath: "/dav/series/opaque.bin", davPath: "/dav/series/opaque.bin"}, enc: *ep}
	if !p.metadataWarmTaskCurrent(task) {
		t.Fatal("current backend/rule task should be eligible")
	}
	p.config.AlistPort++
	if p.metadataWarmTaskCurrent(task) {
		t.Fatal("stale origin task must not probe or publish")
	}
	p.config.AlistPort--
	ep.Password = "test-new"
	if p.metadataWarmTaskCurrent(task) {
		t.Fatal("stale crypto fingerprint must not probe or publish")
	}
	task.enc = *ep
	if !p.metadataWarmTaskCurrent(task) {
		t.Fatal("new current rule snapshot should be eligible")
	}
	ep.Enable = false
	if p.metadataWarmTaskCurrent(task) {
		t.Fatal("disabled/no-match rule task must be skipped")
	}
}

func TestMetadataWarmIdentityMatchesActualDAVAndRequiresReusableRecord(t *testing.T) {
	p := warmTestServer()
	ep := &EncryptPath{Path: "/series", Enable: true}
	davPath, _, ok := metadataWarmDAVChild("/dav/series/%E4%B8%AD.bin", "/dav/series")
	if !ok {
		t.Fatal("expected valid candidate")
	}
	r := httptest.NewRequest(http.MethodGet, p.getAlistURL()+davPath, nil)
	warm := p.withConfirmedMetadataIdentity(r, davPath, ep)
	actual := p.withConfirmedMetadataIdentity(r, "/dav/series/%E4%B8%AD.bin", ep)
	holder := confirmedMetadataRequestFromContext(warm.Context())
	if holder.identity != confirmedMetadataRequestFromContext(actual.Context()).identity {
		t.Fatal("warm and actual DAV identity must match, including /dav prefix and escaped path")
	}
	meta := ContentMeta{Version: ContentVersionV1, PlainSize: 64, CiphertextSize: 64}
	if metadataWarmConfirmedComplete(warm.Context(), meta, true) {
		t.Fatal("recognized but unattached metadata is not reusable")
	}
	holder.attach(confirmedMetadataRecord{Identity: holder.identity, Meta: meta, Provenance: confirmedMetadataProvenanceInspection, ConfirmedAt: 1, ValidatedAt: 1})
	if !metadataWarmConfirmedComplete(warm.Context(), meta, true) {
		t.Fatal("valid attached record should earn success cooldown")
	}
	if metadataWarmConfirmedComplete(warm.Context(), meta, false) {
		t.Fatal("unrecognized metadata cannot be successful")
	}
	meta.Version = ContentVersionV3
	if metadataWarmConfirmedComplete(warm.Context(), meta, true) {
		t.Fatal("recognized invalid V3 cannot be successful")
	}
}

func TestMetadataWarmEpisodeConservative(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ok      bool
		episode uint64
	}{
		{"Show EP009.MKV", true, 9}, {"show e10.mkv", true, 10}, {"01.mp4", true, 1},
		{"Show S01E02.mkv", false, 0}, {"Show 2024 ep01.mkv", false, 0},
		{"Show final.mp4", false, 0}, {"Show ep01.txt", false, 0},
		{"Show 18446744073709551615.mp4", false, 0},
	} {
		_, _, episode, ok := metadataWarmEpisode(tc.name)
		if ok != tc.ok || (ok && episode != tc.episode) {
			t.Errorf("%q: got %d/%v", tc.name, episode, ok)
		}
	}
}

func TestMetadataWarmDAVOriginalChildOnly(t *testing.T) {
	for _, tc := range []struct {
		href string
		ok   bool
	}{
		{"/dav/series/opaque.bin", true}, {"/dav/series/%E4%B8%AD.bin", true},
		{"https://evil.example/dav/series/ep02.mp4", false}, {"//evil.example/dav/series/ep02.mp4", false},
		{"ep02.mp4", false}, {"/dav/other/ep02.mp4", false}, {"/dav/series/sub/ep02.mp4", false},
		{"/dav/series/../series/ep02.mp4", false}, {"/dav/series/%2e%2e/ep02.mp4", false},
		{"/dav/series/x%2fy.mp4", false}, {"/dav/series/x%252fy.mp4", false},
		{"/dav/series/ep02.mp4?token=secret", false}, {"/dav/series/ep02.mp4#frag", false},
	} {
		_, _, ok := metadataWarmDAVChild(tc.href, "/dav/series")
		if ok != tc.ok {
			t.Errorf("href %q: got %v", tc.href, ok)
		}
	}
}

func TestMetadataWarmListingBoundAndUniqueNumericNext(t *testing.T) {
	p := warmTestServer()
	r := httptest.NewRequest("PROPFIND", "/dav/series/", nil)
	ep := &EncryptPath{Path: "/series", Password: "test-only", Enable: true}
	l := newMetadataWarmListing(p, r, ep)
	l.Observe("/dav/series/opaque-a.bin", "show EP01.mkv", 64, false)
	l.Observe("/dav/series/opaque-b.bin", "SHOW ep02.MKV", 64, false)
	l.Observe("/dav/series/ignored.bin", "show EP02.txt", 64, false)
	l.Commit(true)
	dir := p.metadataWarm.directories[0]
	next, ok := metadataWarmNext(dir, "/dav/series/opaque-a.bin")
	if !ok || next.davPath != "/dav/series/opaque-b.bin" {
		t.Fatalf("numeric display next: %+v %v", next, ok)
	}
	dir.candidates = append(dir.candidates, next)
	if _, ok := metadataWarmNext(dir, "/dav/series/opaque-a.bin"); ok {
		t.Fatal("ambiguous next must skip")
	}
	l = newMetadataWarmListing(p, r, ep)
	for i := 0; i < metadataWarmCandidates+1; i++ {
		l.Observe(fmt.Sprintf("/dav/series/%d.bin", i), fmt.Sprintf("show EP%d.mkv", i), 64, false)
	}
	if len(l.candidates) != metadataWarmCandidates || !l.truncated {
		t.Fatal("collector must truncate without allocating more candidates")
	}
	l.Commit(true)
	if _, ok := metadataWarmNext(p.metadataWarm.directories[0], "/dav/series/0.bin"); ok {
		t.Fatal("truncated listings cannot prove uniqueness")
	}
}

func TestMetadataWarmListingCommitFailureAndLRU(t *testing.T) {
	p := warmTestServer()
	ep := &EncryptPath{Enable: true}
	l := newMetadataWarmListing(p, httptest.NewRequest("PROPFIND", "/dav/series/", nil), ep)
	l.Observe("/dav/series/a.bin", "show 1.mp4", 64, false)
	l.Commit(false)
	l.Commit(true)
	if len(p.metadataWarm.directories) != 0 {
		t.Fatal("failed/incomplete listing was committed")
	}
	var state metadataWarmState
	for i := 0; i < metadataWarmDirectories+1; i++ {
		state.rememberDirectory(metadataWarmDirectory{key: fmt.Sprint(i)})
	}
	if len(state.directories) != metadataWarmDirectories || state.directories[0].key != "32" || state.directories[31].key != "1" {
		t.Fatal("directory LRU not bounded")
	}
	state.rememberDirectory(metadataWarmDirectory{key: "1"})
	if state.directories[0].key != "1" || len(state.directories) != metadataWarmDirectories {
		t.Fatal("replacement should promote, not duplicate")
	}
}

func TestMetadataWarmDefaultOffAndScopeIsolation(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{}}
	ep := &EncryptPath{Path: "/series", Password: "one", Enable: true}
	r := httptest.NewRequest("PROPFIND", "/dav/series/", nil)
	if newMetadataWarmListing(p, r, ep) != nil {
		t.Fatal("warming must default off")
	}
	headers := http.Header{"Authorization": []string{"Basic test"}, "Cookie": []string{"session=test"}}
	a := metadataWarmScope("http://localhost", headers, ep)
	copyEP := *ep
	if a != metadataWarmScope("http://localhost", headers, &copyEP) {
		t.Fatal("scope must use crypto values, not pointer identity")
	}
	copyEP.Password = "two"
	if a == metadataWarmScope("http://localhost", headers, &copyEP) {
		t.Fatal("crypto scopes collided")
	}
	headers = headers.Clone()
	headers.Set("Cookie", "session=other")
	if a == metadataWarmScope("http://localhost", headers, ep) {
		t.Fatal("credential scopes collided")
	}
}

type metadataWarmFailWriter struct {
	http.ResponseWriter
	n   int
	err error
}

func (w *metadataWarmFailWriter) Write([]byte) (int, error) { return w.n, w.err }

func TestMetadataWarmQueueAndCooldownBounds(t *testing.T) {
	p := warmTestServer()
	ep := &EncryptPath{Path: "/series", Enable: true}
	r := httptest.NewRequest(http.MethodGet, "/dav/series/opaque-0.bin", nil)
	r.Header.Set("Authorization", "Basic caller-test")
	listingRequest := r.Clone(r.Context())
	listingURL := *r.URL
	listingURL.Path = "/dav/series/"
	listingRequest.URL = &listingURL
	l := newMetadataWarmListing(p, listingRequest, ep)
	for i := 0; i < 6; i++ {
		l.Observe(fmt.Sprintf("/dav/series/opaque-%d.bin", i), fmt.Sprintf("show EP%d.mkv", i), 64, false)
	}
	l.Commit(true)
	// Simulate one running worker without launching any network or goroutine.
	p.metadataWarm.running = true
	p.maybeWarmNextMetadata(r, "/series/opaque-0.bin", ep)
	p.maybeWarmNextMetadata(r, "/series/opaque-0.bin", ep)
	if len(p.metadataWarm.pending) != 1 || p.metadataWarm.hits.Load() != 1 {
		t.Fatal("duplicate task was not suppressed by cooldown")
	}
	p.maybeWarmNextMetadata(r, "/series/opaque-1.bin", ep)
	p.maybeWarmNextMetadata(r, "/series/opaque-2.bin", ep)
	if len(p.metadataWarm.pending) != metadataWarmPending || p.metadataWarm.drops.Load() != 1 {
		t.Fatal("queue must nonblock-drop beyond two pending tasks")
	}
	r.Header.Set("Authorization", "Basic changed-test")
	if p.metadataWarm.pending[0].headers.Get("Authorization") != "Basic caller-test" {
		t.Fatal("queued caller headers were not cloned")
	}
}

func TestMetadataWarmFirstSuccessfulActualWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	base := &metadataWarmFailWriter{ResponseWriter: rec}
	calls := 0
	w := metadataWarmFirstWriter(base, func() { calls++ })
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(nil)
	base.n = 1
	base.err = errors.New("downstream failed")
	_, _ = w.Write([]byte("x"))
	if calls != 0 {
		t.Fatal("headers, zero bytes, or failed writes scheduled warming")
	}
	base.err = nil
	_, _ = w.Write([]byte("x"))
	_, _ = w.Write([]byte("y"))
	if calls != 1 {
		t.Fatalf("callback count %d, want exactly one", calls)
	}
}
