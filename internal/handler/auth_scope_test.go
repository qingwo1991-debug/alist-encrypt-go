package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
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

func TestRequestScopeHashAuthorizetokenHeader(t *testing.T) {
	h := &AlistHandler{authScope: newAuthScopeValidator()}
	tok := testJWT(t, "admin")
	hdr := make(http.Header)
	hdr.Set("Authorizetoken", tok)
	// Authorizetoken is the middleware's preferred credential; it must feed
	// both the legacy hash and the stable-scope path.
	legacy := scopeHashLegacy(hdr)
	if legacy == "anon" || legacy == authScopeHash(make(http.Header)) {
		t.Fatalf("Authorizetoken must participate in scope hash, got %q", legacy)
	}
	h.noteUpstreamAuthOK(hdr)
	if got := h.requestScopeHash(hdr); !strings.HasPrefix(got, "u:") {
		t.Fatalf("Authorizetoken JWT should reach stable scope after validation, got %q", got)
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
		v.note(testJWT(t, "u"+strings.Repeat("x", 1)+string(rune('a'+i%26))+strings.Repeat("y", i)))
	}
	v.mu.Lock()
	n := len(v.validated)
	v.mu.Unlock()
	if n > authScopeValidatedCap {
		t.Fatalf("validator exceeded cap: %d", n)
	}
}
