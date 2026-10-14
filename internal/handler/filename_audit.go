package handler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/storage"
)

type filenameAuditCursor struct {
	After   string `json:"after"`
	Binding string `json:"binding"`
	Expires int64  `json:"expires"`
}

func auditCipher(secret string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte("filename-audit-cursor-v1\x00" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func encodeAuditCursor(secret, after, binding string) (string, error) {
	a, err := auditCipher(secret)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	raw, err := json.Marshal(filenameAuditCursor{after, binding, time.Now().Add(15 * time.Minute).Unix()})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(a.Seal(nonce, nonce, raw, []byte("filename-audit-v1"))), nil
}
func decodeAuditCursor(secret, token, binding string) (string, error) {
	if len(token) > 2048 {
		return "", errors.New("invalid cursor")
	}
	a, err := auditCipher(secret)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) < a.NonceSize() {
		return "", errors.New("invalid cursor")
	}
	raw, err = a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], []byte("filename-audit-v1"))
	if err != nil {
		return "", errors.New("invalid cursor")
	}
	var c filenameAuditCursor
	if json.Unmarshal(raw, &c) != nil || c.Binding != binding || c.Expires <= time.Now().Unix() {
		return "", errors.New("invalid cursor")
	}
	return c.After, nil
}

// FilenameAudit is management-only. This user model has no Role: every extant
// management user can explicitly request sensitive audit access. It does NOT
// establish that user as an upstream principal or impersonate scan credentials.
func (h *APIHandler) FilenameAudit(w http.ResponseWriter, r *http.Request) {
	h.filenameAudit(w, r, false)
}
func (h *APIHandler) FilenameReconcileDryRun(w http.ResponseWriter, r *http.Request) {
	h.filenameAudit(w, r, true)
}
func (h *APIHandler) filenameAudit(w http.ResponseWriter, r *http.Request, dry bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(code int, msg string) { http.Error(w, msg, code) }
	if (!dry && r.Method != http.MethodGet) || (dry && r.Method != http.MethodPost) {
		fail(405, "method not allowed")
		return
	}
	// Header JWT only: never accept stats passwords, cookies or query tokens.
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || h.userDAO == nil {
		fail(401, "management authentication required")
		return
	}
	claims, err := auth.NewJWTAuth(h.cfg.JWTSecret, time.Hour).ValidateToken(strings.TrimPrefix(header, "Bearer "))
	if err != nil || claims.Username == "" || claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.Issuer != "alist-encrypt" {
		fail(401, "invalid management authentication")
		return
	}
	user, err := h.userDAO.Get(claims.Username)
	if err != nil || user.Username != claims.Username || user.PasswordHash == "" {
		fail(403, "current management user required")
		return
	}
	if len(r.URL.RawQuery) > 8192 {
		fail(400, "query too large")
		return
	}
	qv, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(400, "invalid query")
		return
	}
	allowed := map[string]bool{"version": true, "sensitive": true, "include_names": true, "from": true, "until": true, "path_prefix": true, "limit": true, "cursor": true}
	for key, v := range qv {
		if !allowed[key] || len(v) != 1 {
			fail(400, "unknown or duplicate query field")
			return
		}
	}
	if qv.Get("version") != "1" || qv.Get("sensitive") != "true" {
		fail(400, "version=1 and sensitive=true required")
		return
	}
	if v := qv.Get("include_names"); v != "" && v != "true" && v != "false" {
		fail(400, "invalid include_names")
		return
	}
	from, e1 := time.Parse(time.RFC3339Nano, qv.Get("from"))
	until, e2 := time.Parse(time.RFC3339Nano, qv.Get("until"))
	limit, e3 := strconv.Atoi(qv.Get("limit"))
	prefix := qv.Get("path_prefix")
	if e1 != nil || e2 != nil || e3 != nil || from.IsZero() || !until.After(from) || until.Sub(from) > 31*24*time.Hour || limit < 1 || limit > 100 || !strings.HasPrefix(prefix, "/") || path.Clean(prefix) != prefix || strings.ContainsAny(prefix, "\x00\r\n\\") {
		fail(400, "explicit canonical path, time bounds (maximum 31 days) and limit (1..100) required")
		return
	}
	query := storage.FilenameAuditQuery{Origin: h.cfg.GetAlistURL(), Prefix: prefix, From: from, Until: until, Limit: limit, Names: qv.Get("include_names") == "true"}
	bindingValues := url.Values{}
	for k, v := range qv {
		if k != "cursor" {
			bindingValues[k] = v
		}
	}
	canonical := bindingValues.Encode()
	binding := filenameScopeDigest("v1", user.Username, user.PasswordHash, query.Origin, canonical, strconv.FormatBool(dry))
	if token := qv.Get("cursor"); token != "" {
		query.After, err = decodeAuditCursor(h.cfg.JWTSecret, token, binding)
		if err != nil {
			fail(400, "invalid or scope-mismatched cursor")
			return
		}
	}
	page, err := h.fileDAO.FilenameAudit(query)
	if err != nil {
		fail(503, "audit store unavailable or inconsistent")
		return
	}
	next := ""
	if page.After != "" {
		next, err = encodeAuditCursor(h.cfg.JWTSecret, page.After, binding)
		if err != nil {
			fail(503, "cursor unavailable")
			return
		}
	}
	result := map[string]interface{}{"version": 1, "consistency": "live_bounded_bolt_view", "records": page.Records, "scanned": page.Scanned, "next_cursor": next, "include_names": query.Names}
	if dry {
		op := make([]byte, 16)
		if _, err = rand.Read(op); err != nil {
			fail(503, "operation ID unavailable")
			return
		}
		violations := 0
		for _, row := range page.Records {
			if row.LocalInvariant != "ok" {
				violations++
			}
		}
		check := storage.FilenameCheck{OpID: hex.EncodeToString(op), At: time.Now().UTC(), CallerDigest: filenameScopeDigest(user.Username), QueryDigest: filenameScopeDigest(binding, query.After), Checked: len(page.Records), Violations: violations, Remote: "unknown"}
		if err = h.fileDAO.AppendFilenameCheck(check); err != nil {
			fail(503, "check audit unavailable")
			return
		}
		result["op_id"] = check.OpID
		result["dry_run"] = true
		result["remote"] = "unknown"
		result["actual_remote_check"] = false
		result["runtime_blocked"] = "authorized upstream caller resolver and verified safe backup capability not available"
		result["local_scope"] = "selected reservation primary/reverse links only; not exhaustive orphan or alias validation"
		result["mutations_enabled"] = false
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
