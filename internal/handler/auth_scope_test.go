package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
)

var testJWTNonce int

func testJWT(t *testing.T, username string) string {
	t.Helper()
	testJWTNonce++
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]interface{}{"username": username, "exp": 1893456000, "iat": testJWTNonce})
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".fakesig"
}

func bearerHeaders(token string) http.Header {
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+token)
	return h
}

func TestRequestScopeHashUnvalidatedTokenKeepsLegacyScope(t *testing.T) {
	h := &AlistHandler{authScope: newAuthScopeValidator()}
	tok := testJWT(t, "admin")
	got := h.requestScopeHash(bearerHeaders(tok))
	want := scopeHashLegacy(bearerHeaders(tok))
	if got != want {
		t.Fatalf("unvalidated token must keep legacy scope: got %q want %q", got, want)
	}
	if strings.HasPrefix(got, "u:") {
		t.Fatalf("unvalidated token leaked stable scope %q", got)
	}
}

func TestRequestScopeHashValidatedTokenIsStableAcrossRotation(t *testing.T) {
	h := &AlistHandler{authScope: newAuthScopeValidator()}
	tok1 := testJWT(t, "admin")
	tok2 := testJWT(t, "admin") // same user, different iat/exp -> different token
	if tok1 == tok2 {
		t.Fatal("test tokens must differ")
	}
	h.noteUpstreamAuthOK(bearerHeaders(tok1))
	h.noteUpstreamAuthOK(bearerHeaders(tok2))
	s1 := h.requestScopeHash(bearerHeaders(tok1))
	s2 := h.requestScopeHash(bearerHeaders(tok2))
	if s1 != s2 || !strings.HasPrefix(s1, "u:") {
		t.Fatalf("rotated tokens for same user must share stable scope: %q vs %q", s1, s2)
	}
	// A different account must NOT share the scope.
	tok3 := testJWT(t, "other")
	h.noteUpstreamAuthOK(bearerHeaders(tok3))
	if s3 := h.requestScopeHash(bearerHeaders(tok3)); s3 == s1 {
		t.Fatal("different users must not share a scope")
	}
}

func TestRequestScopeHashForgedTokenStaysLegacy(t *testing.T) {
	h := &AlistHandler{authScope: newAuthScopeValidator()}
	// Attacker forges a JWT claiming username=admin; signature is fake and
	// upstream never validated it, so noteUpstreamAuthOK must never have run.
	forged := testJWT(t, "admin")
	got := h.requestScopeHash(bearerHeaders(forged))
	if strings.HasPrefix(got, "u:") {
		t.Fatalf("forged token must not reach stable scope, got %q", got)
	}
}

func TestRequestScopeHashAuthorizetokenIgnoredForScope(t *testing.T) {
	h := &AlistHandler{authScope: newAuthScopeValidator()}
	// Authorizetoken is a per-request auxiliary credential: it must NOT
	// participate in the scope hash or every poll mints a new scope.
	hdr := make(http.Header)
	hdr.Set("Authorizetoken", "nonce-"+testJWT(t, "admin"))
	if got := h.requestScopeHash(hdr); strings.HasPrefix(got, "u:") {
		t.Fatalf("Authorizetoken-only client must keep legacy scope, got %q", got)
	}
	// Authorization is the stable credential: a rotating Authorizetoken or
	// Cookie must not change the scope.
	tok := testJWT(t, "admin")
	stable := make(http.Header)
	stable.Set("Authorization", "Bearer "+tok)
	withNoise := stable.Clone()
	withNoise.Set("Authorizetoken", "nonce-1")
	withNoise.Set("Cookie", "session=abc")
	if got, want := h.requestScopeHash(withNoise), h.requestScopeHash(stable); got != want {
		t.Fatalf("auxiliary headers changed scope: %q vs %q", got, want)
	}
}

func TestRequestScopeHashNonJWTAndAnon(t *testing.T) {
	h := &AlistHandler{authScope: newAuthScopeValidator()}
	if got := h.requestScopeHash(nil); got != "anon" {
		t.Fatalf("nil headers should be anon, got %q", got)
	}
	hdr := make(http.Header)
	hdr.Set("Authorization", "Bearer not-a-jwt")
	if got := h.requestScopeHash(hdr); strings.HasPrefix(got, "u:") {
		t.Fatalf("non-JWT token must keep legacy scope, got %q", got)
	}
}

func TestScopeHashFromScopeKey(t *testing.T) {
	if got := scopeHashFromScopeKey("/dir/sub::abc123"); got != "abc123" {
		t.Fatalf("got %q", got)
	}
	if got := scopeHashFromScopeKey("/dir::u:deadbeef"); got != "u:deadbeef" {
		t.Fatalf("got %q", got)
	}
	if got := scopeHashFromScopeKey("noscope"); got != "noscope" {
		t.Fatalf("got %q", got)
	}
}

func TestAuthScopeValidatorEvictsOldest(t *testing.T) {
	v := newAuthScopeValidator()
	// Fill beyond cap with distinct tokens.
	for i := 0; i < authScopeValidatedCap+10; i++ {
		v.note("fp"+strings.Repeat("x", i)+string(rune('a'+i%26)), "user"+string(rune('a'+i%26)))
	}
	v.mu.Lock()
	n := len(v.validated)
	v.mu.Unlock()
	if n > authScopeValidatedCap {
		t.Fatalf("validator exceeded cap: %d", n)
	}
}

// TestHandleFsListRotatedJWTsShareSnapshot is the end-to-end proof: two
// different upstream JWTs for the SAME account must converge on one stable
// "u:" scope after upstream validation, so the second token is served from
// the snapshot the first one persisted.
func TestHandleFsListRotatedJWTsShareSnapshot(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password: "testpass", EncType: "aesctr", Enable: true, EncName: true,
		EncPath: []string{"/cloud/encrypt/*"},
	}
	mux := http.NewServeMux()
	upstreamCalls := 0
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		writeJSONResponse(w, map[string]interface{}{
			"code": 200, "message": "success",
			"data": map[string]interface{}{
				"content": []interface{}{map[string]interface{}{
					"name": "f1.bin", "path": "/cloud/encrypt/f1.bin", "is_dir": false, "size": float64(1), "type": float64(0)}},
				"total": float64(1),
			},
		})
	})
	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	handler.dirSyncStart.Do(func() {})
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create snapshot store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	handler.SetDirSyncStore(NewBoltDirSyncStore(store))

	tokA := testJWT(t, "admin")
	tokB := testJWT(t, "admin") // rotated token, same account

	request := func(token string) string {
		req := httptest.NewRequest(http.MethodPost, "/api/fs/list", strings.NewReader(`{"path":"/cloud/encrypt","page":1,"per_page":1000}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.HandleFsList(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	request(tokA)         // live fetch; validates tokA and persists under its scope
	request(tokB)         // different token: miss -> live -> persists under u: scope (if bound)
	body := request(tokB) // should now hit the shared u: snapshot
	if !strings.Contains(body, `"cache_hit":true`) && !strings.Contains(body, `"cache_hit": true`) {
		t.Fatalf("expected snapshot hit for rotated token, body=%s", body)
	}
	if upstreamCalls > 2 {
		t.Fatalf("rotated token caused extra upstream calls: %d", upstreamCalls)
	}
}

// TestResolveScopeViaMe proves the /api/me probe path: an unvalidated
// credential resolves to the stable "u:" scope using the username upstream
// reports, and a forged/unknown credential stays legacy.
func TestResolveScopeViaMe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer good-token" {
			writeJSONResponse(w, map[string]interface{}{
				"code": 200, "message": "success",
				"data": map[string]interface{}{"username": "admin"},
			})
			return
		}
		writeJSONResponse(w, map[string]interface{}{"code": 401, "message": "token is invalidated", "data": nil})
	})
	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, &config.PasswdInfo{
		Password: "p", EncType: "aesctr", Enable: true, EncName: true,
		EncPath: []string{"/cloud/encrypt/*"},
	})

	good := bearerHeaders("good-token")
	if got := handler.requestScopeHash(good); strings.HasPrefix(got, "u:") {
		t.Fatalf("unvalidated credential must not start in u: scope, got %q", got)
	}
	if !handler.resolveScopeViaMe(t.Context(), good) {
		t.Fatal("resolveScopeViaMe failed for valid credential")
	}
	got := handler.requestScopeHash(good)
	if !strings.HasPrefix(got, "u:") {
		t.Fatalf("expected stable u: scope after /api/me, got %q", got)
	}

	bad := bearerHeaders("forged-token")
	if handler.resolveScopeViaMe(t.Context(), bad) {
		t.Fatal("forged credential must not resolve")
	}
	if got := handler.requestScopeHash(bad); strings.HasPrefix(got, "u:") {
		t.Fatalf("forged credential leaked u: scope %q", got)
	}
	// Second forged attempt is negative-cached: still legacy, no panic.
	if handler.resolveScopeViaMe(t.Context(), bad) {
		t.Fatal("negative cache should suppress re-probe")
	}
}
