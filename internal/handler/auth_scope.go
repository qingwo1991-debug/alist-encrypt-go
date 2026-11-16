package handler

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// authScopeValidatedCap bounds the in-memory set of upstream credentials that
// have already produced a successful upstream response. Entries only gate the
// stable "u:<user>" scope hash; evicting one merely costs a single live
// upstream fetch (or /api/me probe) to re-validate.
const authScopeValidatedCap = 8192

// authScopeMeFailTTL is how long a failed /api/me credential probe suppresses
// retries for the same credential fingerprint.
const authScopeMeFailTTL = 60 * time.Second

// authScopeMeFailCap bounds the negative-cache map; on overflow it is reset.
const authScopeMeFailCap = 4096

// authScopeValidator tracks credentials that upstream has accepted at least
// once, mapped to the account username upstream reported. A credential earns
// entry only after a live upstream call returns success (or /api/me confirms
// it), which means its identity is authentic — a self-signed forged token can
// never reach another user's snapshots. The fingerprint covers the whole
// credential (bearer token preferred, Cookie as fallback) so rotating JWTs of
// the same account each re-validate once and then share the stable scope.
type authScopeValidator struct {
	mu        sync.Mutex
	validated map[string]string // credFP -> username
	order     []string
	head      int
	meFails   map[string]time.Time
}

func newAuthScopeValidator() *authScopeValidator {
	return &authScopeValidator{
		validated: make(map[string]string),
		meFails:   make(map[string]time.Time),
	}
}

func (v *authScopeValidator) note(fp, username string) {
	if v == nil || fp == "" || username == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.validated[fp]; ok {
		return
	}
	v.validated[fp] = username
	v.order = append(v.order, fp)
	for len(v.order)-v.head > authScopeValidatedCap {
		delete(v.validated, v.order[v.head])
		v.head++
	}
	if v.head > 1024 && v.head*2 > len(v.order) {
		v.order = append([]string(nil), v.order[v.head:]...)
		v.head = 0
	}
}

func (v *authScopeValidator) lookup(fp string) (string, bool) {
	if v == nil || fp == "" {
		return "", false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	user, ok := v.validated[fp]
	return user, ok
}

func (v *authScopeValidator) noteMeFail(fp string) {
	if v == nil || fp == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.meFails) >= authScopeMeFailCap {
		v.meFails = make(map[string]time.Time)
	}
	v.meFails[fp] = time.Now()
}

func (v *authScopeValidator) meFailed(fp string) bool {
	if v == nil || fp == "" {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	t, ok := v.meFails[fp]
	return ok && time.Since(t) < authScopeMeFailTTL
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

// credFingerprint returns a stable per-credential key: the bearer token when
// present (auxiliary headers like Cookie/Authorizetoken rotate independently
// and must not fragment it), otherwise the Cookie material for cookie-only
// clients. Empty when the request carries no usable credential.
func credFingerprint(headers http.Header) string {
	if headers == nil {
		return ""
	}
	material := effectiveBearerToken(headers)
	if material == "" {
		material = strings.TrimSpace(headers.Get("Cookie"))
	}
	if material == "" {
		return ""
	}
	sum := sha1.Sum([]byte(material))
	return hex.EncodeToString(sum[:])
}

// jwtUsernameClaim decodes the username claim WITHOUT verifying the signature.
// The result is only trusted for scope hashing after the credential has
// produced a successful upstream response (see authScopeValidator); callers
// must not use it for authorization decisions.
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

func stableUserScopeHash(user string) string {
	sum := sha1.Sum([]byte("user:" + user))
	return "u:" + hex.EncodeToString(sum[:8])
}

// requestScopeHash returns the snapshot-scope discriminator for a request.
// Once a credential has been validated by a successful upstream response (or
// an /api/me probe), the scope collapses to a stable per-account hash so
// token rotation no longer invalidates every cached snapshot. Unvalidated
// credentials keep the legacy raw-material hash.
func (h *AlistHandler) requestScopeHash(headers http.Header) string {
	if h == nil {
		return scopeHashLegacy(headers)
	}
	if user, ok := h.authScope.lookup(credFingerprint(headers)); ok {
		return stableUserScopeHash(user)
	}
	return scopeHashLegacy(headers)
}

// noteUpstreamAuthOK records a credential as upstream-validated. Call only
// after the upstream accepted the request (e.g. a 200 listing), never before.
// The username comes from the JWT claim, which is trustworthy at this point
// because upstream verified the signature.
func (h *AlistHandler) noteUpstreamAuthOK(headers http.Header) {
	if h == nil || h.authScope == nil {
		return
	}
	token := effectiveBearerToken(headers)
	user := jwtUsernameClaim(token)
	if user == "" {
		return
	}
	h.authScope.note(credFingerprint(headers), user)
}

// resolveScopeViaMe probes upstream GET /api/me with the request's own auth
// headers. On success the credential is recorded with the username upstream
// reports — authoritative identity, independent of token format or JWT
// claims — and requestScopeHash starts returning the stable "u:" scope.
// Failures are negative-cached briefly so a broken endpoint cannot add
// latency to every request.
func (h *AlistHandler) resolveScopeViaMe(ctx context.Context, headers http.Header) bool {
	if h == nil || h.authScope == nil || h.cfg == nil || h.httpClient == nil {
		return false
	}
	fp := credFingerprint(headers)
	if fp == "" || h.authScope.meFailed(fp) {
		return false
	}
	if _, ok := h.authScope.lookup(fp); ok {
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet,
		strings.TrimRight(h.cfg.GetAlistURL(), "/")+"/api/me", nil)
	if err != nil {
		return false
	}
	for k, vs := range headers {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "cookie" {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		h.authScope.noteMeFail(fp)
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		h.authScope.noteMeFail(fp)
		return false
	}
	var me struct {
		Code int `json:"code"`
		Data struct {
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &me); err != nil || me.Code != 200 {
		h.authScope.noteMeFail(fp)
		return false
	}
	user := strings.TrimSpace(me.Data.Username)
	if user == "" {
		h.authScope.noteMeFail(fp)
		return false
	}
	h.authScope.note(fp, user)
	return true
}

// RequestScopeHash exposes requestScopeHash to sibling handlers (WebDAV).
func (h *AlistHandler) RequestScopeHash(headers http.Header) string {
	return h.requestScopeHash(headers)
}

// ResolveScopeViaMe exposes resolveScopeViaMe to sibling handlers (WebDAV).
func (h *AlistHandler) ResolveScopeViaMe(ctx context.Context, headers http.Header) bool {
	return h.resolveScopeViaMe(ctx, headers)
}

// NoteUpstreamAuthOK exposes noteUpstreamAuthOK to sibling handlers (WebDAV).
func (h *AlistHandler) NoteUpstreamAuthOK(headers http.Header) {
	h.noteUpstreamAuthOK(headers)
}

// DebugScopeInfo returns non-sensitive fingerprint diagnostics for logging.
func (h *AlistHandler) DebugScopeInfo(headers http.Header) (fp string, validated bool, user string) {
	fp = credFingerprint(headers)
	user, validated = h.authScope.lookup(fp)
	return fp, validated, user
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
