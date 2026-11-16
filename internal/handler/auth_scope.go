package handler

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

// authScopeValidatedCap bounds the in-memory set of upstream credentials that
// have already produced a successful upstream response. Entries only gate the
// stable "u:<user>" scope hash; evicting one merely costs a single live
// upstream fetch to re-validate.
const authScopeValidatedCap = 8192

// authScopeValidator tracks bearer tokens that upstream has accepted at least
// once. A token earns entry only after a live upstream call returns success,
// which means its JWT claims are authentic (the upstream verified the
// signature). Until then the token keeps the legacy raw-material scope hash,
// so a self-signed forged token can never reach another user's snapshots.
type authScopeValidator struct {
	mu        sync.Mutex
	validated map[string]struct{}
	order     []string
	head      int
}

func newAuthScopeValidator() *authScopeValidator {
	return &authScopeValidator{validated: make(map[string]struct{})}
}

func (v *authScopeValidator) note(token string) {
	if v == nil || token == "" {
		return
	}
	sum := sha1.Sum([]byte(token))
	key := hex.EncodeToString(sum[:])
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.validated[key]; ok {
		return
	}
	v.validated[key] = struct{}{}
	v.order = append(v.order, key)
	for len(v.order)-v.head > authScopeValidatedCap {
		delete(v.validated, v.order[v.head])
		v.head++
	}
	if v.head > 1024 && v.head*2 > len(v.order) {
		v.order = append([]string(nil), v.order[v.head:]...)
		v.head = 0
	}
}

func (v *authScopeValidator) has(token string) bool {
	if v == nil || token == "" {
		return false
	}
	sum := sha1.Sum([]byte(token))
	key := hex.EncodeToString(sum[:])
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.validated[key]
	return ok
}

// effectiveBearerToken extracts the credential the UPSTREAM validates:
// Authorization wins (upstream alist/openlist reads it), Authorizetoken is
// only a fallback for clients that send no Authorization at all.
func effectiveBearerToken(headers http.Header) string {
	if headers == nil {
		return ""
	}
	if a := strings.TrimSpace(headers.Get("Authorization")); a != "" {
		if len(a) >= 7 && strings.EqualFold(a[:7], "Bearer ") {
			return strings.TrimSpace(a[7:])
		}
		return a
	}
	return strings.TrimSpace(headers.Get("Authorizetoken"))
}

// jwtUsernameClaim decodes the username claim WITHOUT verifying the signature.
// The result is only trusted for scope hashing after the token has produced a
// successful upstream response (see authScopeValidator); callers must not use
// it for authorization decisions.
func jwtUsernameClaim(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return strings.TrimSpace(claims.Username)
}

// scopeHashLegacy hashes only the STABLE credential material. Authorization
// is the primary credential and fully determines the scope when present;
// Cookie is consulted only for cookie-only clients. Auxiliary per-request
// headers (Authorizetoken, and Cookie when Authorization exists) are
// deliberately excluded: clients that rotate them every request would
// otherwise mint a new snapshot scope per poll and the cache could never
// warm.
func scopeHashLegacy(headers http.Header) string {
	if headers == nil {
		return authScopeHash(nil)
	}
	if strings.TrimSpace(headers.Get("Authorization")) != "" {
		clone := headers.Clone()
		clone.Del("Cookie")
		clone.Del("Authorizetoken")
		return authScopeHash(clone)
	}
	clone := headers.Clone()
	clone.Del("Authorizetoken")
	return authScopeHash(clone)
}

// requestScopeHash returns the snapshot-scope discriminator for a request.
// Once a JWT-bearing credential has been validated by a successful upstream
// response, the scope collapses to a stable per-account hash so token rotation
// (re-login, refreshed JWT) no longer invalidates every cached snapshot.
// Unvalidated or non-JWT credentials keep the legacy raw-material hash.
func (h *AlistHandler) requestScopeHash(headers http.Header) string {
	if h == nil {
		return scopeHashLegacy(headers)
	}
	token := effectiveBearerToken(headers)
	if token == "" {
		return scopeHashLegacy(headers)
	}
	user := jwtUsernameClaim(token)
	if user == "" {
		return scopeHashLegacy(headers)
	}
	if h.authScope != nil && h.authScope.has(token) {
		sum := sha1.Sum([]byte("user:" + user))
		return "u:" + hex.EncodeToString(sum[:8])
	}
	return scopeHashLegacy(headers)
}

// noteUpstreamAuthOK records a credential as upstream-validated. Call only
// after the upstream accepted the request (e.g. a 200 listing), never before.
func (h *AlistHandler) noteUpstreamAuthOK(headers http.Header) {
	if h == nil || h.authScope == nil {
		return
	}
	token := effectiveBearerToken(headers)
	if token == "" || jwtUsernameClaim(token) == "" {
		return
	}
	h.authScope.note(token)
}

// RequestScopeHash exposes requestScopeHash to sibling handlers (WebDAV).
func (h *AlistHandler) RequestScopeHash(headers http.Header) string {
	return h.requestScopeHash(headers)
}

// NoteUpstreamAuthOK exposes noteUpstreamAuthOK to sibling handlers (WebDAV).
func (h *AlistHandler) NoteUpstreamAuthOK(headers http.Header) {
	h.noteUpstreamAuthOK(headers)
}

// scopeHashFromScopeKey extracts the auth-hash segment embedded in a
// buildDirScopeKey result so persisted rows always carry the same
// discriminator as their scope key.
func scopeHashFromScopeKey(scopeKey string) string {
	if i := strings.LastIndex(scopeKey, "::"); i >= 0 {
		return scopeKey[i+2:]
	}
	return scopeKey
}
