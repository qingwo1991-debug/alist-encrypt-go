package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/wopan"
	"github.com/rs/zerolog/log"
)

const (
	wopanConfirmationPhrase = "清空个人账号全部回收站"
	wopanChallengeTTL       = 2 * time.Minute
	wopanStateLimit         = 128
	wopanOperationTimeout   = 15 * time.Second
	wopanUpstreamBodyLimit  = 256 << 10
)

// The narrow interface keeps every destructive test independent of the real
// provider. Neither the local JWT nor refresh tokens are passed to this client.
type wopanAdminProvider interface {
	Account(context.Context, string) (wopan.Account, error)
	Quota(context.Context, string, string) (wopan.Quota, error)
	EmptyRecycle(context.Context, string) error
}

type wopanAdminError struct {
	status int
	code   string
}

func (e *wopanAdminError) Error() string       { return e.code }
func wopanError(status int, code string) error { return &wopanAdminError{status, code} }

// WopanAdminHandler owns process-local, bounded, single-use confirmations.
// Construct it once when registering routes: rebuilding it per request would
// invalidate confirmations, while persisting them would defeat restart expiry.
type WopanAdminHandler struct {
	cfg      *config.Config
	userDAO  *dao.UserDAO
	jwtAuth  *auth.JWTAuth
	upstream *http.Client
	provider wopanAdminProvider
	now      func() time.Time
	mu       sync.Mutex
	pending  map[[32]byte]wopanChallenge
	inflight map[[32]byte]bool
}

func NewWopanAdminHandler(cfg *config.Config, userDAO *dao.UserDAO) *WopanAdminHandler {
	expire := cfg.JWTExpire
	if expire <= 0 {
		expire = 48
	}
	// Do not follow redirects with upstream credentials, and do not inherit a
	// browser session or environment-proxy authentication.
	newClient := func() *http.Client {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		return &http.Client{
			Transport: transport, Timeout: wopanOperationTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &WopanAdminHandler{
		cfg: cfg, userDAO: userDAO,
		jwtAuth:  auth.NewJWTAuth(cfg.JWTSecret, time.Duration(expire)*time.Hour),
		upstream: newClient(), provider: wopan.NewClient(newClient()), now: time.Now,
		pending: make(map[[32]byte]wopanChallenge), inflight: make(map[[32]byte]bool),
	}
}

type wopanLocalAdmin struct {
	username string
	session  [32]byte
	jwt      string
}

type wopanUpstreamSession struct {
	origin     string
	revision   uint64
	configHash [32]byte
	auth       string
	settings   config.AlistServer
}

type wopanStorage struct {
	ID        int    `json:"id"`
	MountPath string `json:"mount_path"`
	Driver    string `json:"driver"`
	Disabled  bool   `json:"disabled"`
	Status    string `json:"status"`
	Addition  string `json:"addition"`
}

type wopanAddition struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	FamilyID     string `json:"family_id"`
	RootFolderID string `json:"root_folder_id"`
}

type wopanStorageView struct {
	StorageID         int    `json:"storage_id"`
	MountPath         string `json:"mount_path"`
	Scope             string `json:"scope"`
	Available         bool   `json:"available"`
	ClearSupported    bool   `json:"clear_supported"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
}

type wopanChallenge struct {
	username    string
	session     [32]byte
	origin      string
	revision    uint64
	configHash  [32]byte
	storageID   int
	storageHash [32]byte
	accountID   string // Private identity, never emitted in responses or logs.
	expires     time.Time
}

func (h *WopanAdminHandler) localAdmin(r *http.Request) (wopanLocalAdmin, error) {
	token := strings.TrimSpace(r.Header.Get("Authorizetoken"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("Authorization"))
		if len(token) >= 7 && strings.EqualFold(token[:7], "Bearer ") {
			token = strings.TrimSpace(token[7:])
		}
	}
	claims, err := h.jwtAuth.ValidateToken(token)
	if err != nil || claims.Username == "" {
		return wopanLocalAdmin{}, wopanError(http.StatusUnauthorized, "local_auth_required")
	}
	// UserInfo's role is cosmetic in this single-admin application. A signed
	// token alone is insufficient after deletion/rename of the actual user.
	if h.userDAO == nil {
		return wopanLocalAdmin{}, wopanError(http.StatusForbidden, "local_admin_required")
	}
	user, err := h.userDAO.Get(claims.Username)
	if err != nil || user == nil || user.Username != claims.Username {
		return wopanLocalAdmin{}, wopanError(http.StatusForbidden, "local_admin_required")
	}
	return wopanLocalAdmin{claims.Username, sha256.Sum256([]byte(token)), token}, nil
}

func wopanCSRF(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return wopanError(http.StatusForbidden, "origin_not_allowed")
	}
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		// CLI clients use an explicit non-cookie JWT header; no ambient cookie
		// credentials are accepted. Browser origins, when present, must match.
		return nil
	}
	if len(origins) != 1 {
		return wopanError(http.StatusForbidden, "origin_not_allowed")
	}
	u, err := url.Parse(origins[0])
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// Deliberately ignore untrusted Forwarded / X-Forwarded-Proto headers.
	if err != nil || origins[0] != scheme+"://"+r.Host || u.Scheme != scheme || u.Host != r.Host || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return wopanError(http.StatusForbidden, "origin_not_allowed")
	}
	return nil
}

func (h *WopanAdminHandler) snapshot() (wopanUpstreamSession, error) {
	revision := h.cfg.RuntimeRevision()
	settings := h.cfg.AlistServerSnapshot()
	origin := config.BuildAlistURL(settings)
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || h.cfg.RuntimeRevision() != revision {
		return wopanUpstreamSession{}, wopanError(http.StatusConflict, "configuration_changed")
	}
	encoded, _ := json.Marshal(settings)
	return wopanUpstreamSession{origin: origin, revision: revision, configHash: sha256.Sum256(encoded), settings: settings}, nil
}

func (h *WopanAdminHandler) unchanged(s wopanUpstreamSession) bool {
	current, err := h.snapshot()
	return err == nil && current.origin == s.origin && current.revision == s.revision && current.configHash == s.configHash
}

func (h *WopanAdminHandler) upstreamAdmin(ctx context.Context, s *wopanUpstreamSession, local wopanLocalAdmin) error {
	raw := strings.TrimSpace(s.settings.ScanAuthHeader)
	if raw != "" && !strings.EqualFold(strings.Fields(raw)[0], "Basic") {
		s.auth = raw
	} else {
		// Basic credentials are not an AList API token. Only explicitly
		// configured scan username/password may be exchanged; no privileged
		// account fallback is allowed if the configured reader is not admin.
		if strings.TrimSpace(s.settings.ScanUsername) == "" || s.settings.ScanPassword == "" {
			return wopanError(http.StatusForbidden, "upstream_admin_required")
		}
		var login struct {
			Token string `json:"token"`
		}
		body, _ := json.Marshal(map[string]string{"username": s.settings.ScanUsername, "password": s.settings.ScanPassword})
		if err := h.upstreamJSON(ctx, *s, http.MethodPost, "/api/auth/login", body, &login); err != nil {
			return err
		}
		if !wopanValidCredential(login.Token) {
			return wopanError(http.StatusForbidden, "upstream_admin_required")
		}
		s.auth = login.Token
	}
	comparison := s.auth
	if len(comparison) >= 7 && strings.EqualFold(comparison[:7], "Bearer ") {
		comparison = strings.TrimSpace(comparison[7:])
	}
	_, localTokenErr := h.jwtAuth.ValidateToken(comparison)
	if comparison == local.jwt || localTokenErr == nil {
		return wopanError(http.StatusForbidden, "upstream_admin_required")
	}
	var me struct {
		Role *int `json:"role"`
	}
	if err := h.upstreamJSON(ctx, *s, http.MethodGet, "/api/me", nil, &me); err != nil {
		return err
	}
	if me.Role == nil || *me.Role != 2 {
		return wopanError(http.StatusForbidden, "upstream_admin_required")
	}
	if !h.unchanged(*s) {
		return wopanError(http.StatusConflict, "configuration_changed")
	}
	return nil
}

// upstreamJSON accepts only internal constant paths on the captured config
// origin. Every error is translated to a fixed code, never an upstream body,
// transport error (which can include URLs), or credential-bearing message.
func (h *WopanAdminHandler) upstreamJSON(ctx context.Context, s wopanUpstreamSession, method, path string, body []byte, dst interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, s.origin+path, bytes.NewReader(body))
	if err != nil {
		return wopanError(http.StatusBadGateway, "upstream_unavailable")
	}
	if s.auth != "" {
		req.Header.Set("Authorization", s.auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.upstream.Do(req)
	if err != nil {
		return wopanError(http.StatusBadGateway, "upstream_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return wopanError(http.StatusBadGateway, "upstream_unavailable")
	}
	payload, err := readLimitedBody(resp, wopanUpstreamBodyLimit)
	if err != nil {
		return wopanError(http.StatusBadGateway, "upstream_invalid_response")
	}
	var envelope struct {
		Code *int            `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if !wopanUnambiguousJSON(payload) || json.Unmarshal(payload, &envelope) != nil || envelope.Code == nil || *envelope.Code != 200 || len(envelope.Data) == 0 || bytes.Equal(envelope.Data, []byte("null")) || json.Unmarshal(envelope.Data, dst) != nil {
		return wopanError(http.StatusBadGateway, "upstream_invalid_response")
	}
	return nil
}

func (h *WopanAdminHandler) storage(ctx context.Context, s wopanUpstreamSession, id int) (wopanStorage, error) {
	var value wopanStorage
	if err := h.upstreamJSON(ctx, s, http.MethodGet, "/api/admin/storage/get?id="+strconv.Itoa(id), nil, &value); err != nil {
		return value, err
	}
	if value.ID != id || value.Driver != "WoPan" {
		return value, wopanError(http.StatusConflict, "storage_not_wopan")
	}
	return value, nil
}

// Reject duplicate keys (including in raw additions) rather than letting two
// parsers choose different account, scope or authorization values. Upstream
// schema extension fields remain allowed; recursion is deliberately bounded.
func wopanUnambiguousJSON(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var visit func(int) bool
	visit = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'):
			keys := make(map[string]bool)
			for decoder.More() {
				token, err = decoder.Token()
				key, ok := token.(string)
				if err != nil || !ok || keys[key] {
					return false
				}
				keys[key] = true
				if !visit(depth + 1) {
					return false
				}
			}
			token, err = decoder.Token()
			return err == nil && token == json.Delim('}')
		case json.Delim('['):
			for decoder.More() {
				if !visit(depth + 1) {
					return false
				}
			}
			token, err = decoder.Token()
			return err == nil && token == json.Delim(']')
		case json.Delim('}'), json.Delim(']'):
			return false
		default:
			return true
		}
	}
	if !visit(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func wopanValidCredential(value string) bool {
	return len(value) >= 16 && len(value) <= 4096 && !strings.Contains(value, "*") && !strings.ContainsFunc(value, unicode.IsSpace) && !strings.ContainsFunc(value, unicode.IsControl)
}

func wopanDescribe(value wopanStorage) (wopanStorageView, wopanAddition) {
	view := wopanStorageView{StorageID: value.ID, MountPath: value.MountPath, Scope: "personal"}
	var addition wopanAddition
	if !wopanUnambiguousJSON([]byte(value.Addition)) || json.Unmarshal([]byte(value.Addition), &addition) != nil {
		view.UnsupportedReason = "storage_credentials_unavailable"
		return view, addition
	}
	if addition.FamilyID != "" {
		view.Scope = "family"
		view.UnsupportedReason = "family_not_supported"
	} else if value.Disabled || value.Status != "work" {
		view.UnsupportedReason = "storage_unavailable"
	} else if value.ID <= 0 || !strings.HasPrefix(value.MountPath, "/") || !wopanValidCredential(addition.AccessToken) || !wopanValidCredential(addition.RefreshToken) {
		view.UnsupportedReason = "storage_credentials_unavailable"
	} else {
		view.Available, view.ClearSupported = true, true
	}
	return view, addition
}

func wopanPersonal(value wopanStorage) (wopanAddition, error) {
	view, addition := wopanDescribe(value)
	if !view.Available {
		return addition, wopanError(http.StatusConflict, view.UnsupportedReason)
	}
	return addition, nil
}

func wopanStorageHash(value wopanStorage) [32]byte {
	encoded, _ := json.Marshal(value)
	return sha256.Sum256(encoded)
}

func (h *WopanAdminHandler) fail(w http.ResponseWriter, err error) {
	public := &wopanAdminError{http.StatusBadGateway, "provider_unavailable"}
	var known *wopanAdminError
	if errors.As(err, &known) {
		public = known
	}
	RespondJSON(w, public.status, APIResponse{Code: public.status, Msg: public.code})
}

func wopanPrivate(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// Storages discovers any configured WoPan mount; no mount or ID is hardcoded.
func (h *WopanAdminHandler) Storages(w http.ResponseWriter, r *http.Request) {
	wopanPrivate(w)
	local, err := h.localAdmin(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), wopanOperationTimeout)
	defer cancel()
	s, err := h.snapshot()
	if err == nil {
		err = h.upstreamAdmin(ctx, &s, local)
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	views := make([]wopanStorageView, 0)
	seen := make(map[int]bool)
	for page, count := 1, 0; ; page++ {
		var batch struct {
			Content []wopanStorage `json:"content"`
			Total   *int           `json:"total"`
		}
		if err = h.upstreamJSON(ctx, s, http.MethodGet, "/api/admin/storage/list?page="+strconv.Itoa(page)+"&per_page=100", nil, &batch); err != nil {
			h.fail(w, err)
			return
		}
		if batch.Total == nil || *batch.Total < 0 || *batch.Total > 1000 || len(batch.Content) > 100 || count+len(batch.Content) > 1000 || (len(batch.Content) == 0 && count < *batch.Total) {
			h.fail(w, wopanError(http.StatusBadGateway, "storage_list_limit"))
			return
		}
		for _, entry := range batch.Content {
			if entry.ID <= 0 || seen[entry.ID] {
				h.fail(w, wopanError(http.StatusBadGateway, "upstream_invalid_response"))
				return
			}
			seen[entry.ID] = true
			if entry.Driver != "WoPan" {
				continue
			}
			// List responses can deliberately hide additions. Fetch the raw
			// selected record instead of changing global privacy settings.
			value, getErr := h.storage(ctx, s, entry.ID)
			if getErr != nil {
				h.fail(w, getErr)
				return
			}
			view, _ := wopanDescribe(value)
			views = append(views, view)
		}
		count += len(batch.Content)
		if count >= *batch.Total {
			break
		}
		if page >= 10 {
			h.fail(w, wopanError(http.StatusBadGateway, "storage_list_limit"))
			return
		}
	}
	if !h.unchanged(s) {
		h.fail(w, wopanError(http.StatusConflict, "configuration_changed"))
		return
	}
	RespondSuccess(w, map[string]interface{}{"storages": views})
}

// Quota reports the personal account's quota, not the mount folder's size.
// No cache is used: errors can never turn into stale or fabricated zero bytes.
func (h *WopanAdminHandler) Quota(w http.ResponseWriter, r *http.Request) {
	wopanPrivate(w)
	local, err := h.localAdmin(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	values := r.URL.Query()["storage_id"]
	id := 0
	if len(values) == 1 {
		id, _ = strconv.Atoi(values[0])
	}
	if id <= 0 {
		h.fail(w, wopanError(http.StatusBadRequest, "invalid_storage_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), wopanOperationTimeout)
	defer cancel()
	s, err := h.snapshot()
	if err == nil {
		err = h.upstreamAdmin(ctx, &s, local)
	}
	var value wopanStorage
	if err == nil {
		value, err = h.storage(ctx, s, id)
	}
	var addition wopanAddition
	if err == nil {
		addition, err = wopanPersonal(value)
	}
	var account wopan.Account
	if err == nil {
		account, err = h.provider.Account(ctx, addition.AccessToken)
	}
	if err == nil && account.ID == "" {
		err = wopanError(http.StatusBadGateway, "provider_invalid_response")
	}
	var quota wopan.Quota
	if err == nil {
		quota, err = h.provider.Quota(ctx, addition.AccessToken, account.ID)
	}
	if err == nil && (quota.TotalBytes <= 0 || quota.UsedBytes < 0 || quota.UsedBytes > quota.TotalBytes || quota.AvailableBytes < 0 || quota.AvailableBytes != quota.TotalBytes-quota.UsedBytes) {
		err = wopanError(http.StatusBadGateway, "provider_invalid_response")
	}
	if err == nil && !h.unchanged(s) {
		err = wopanError(http.StatusConflict, "configuration_changed")
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	RespondSuccess(w, map[string]interface{}{
		"storage_id": id, "mount_path": value.MountPath, "scope": "personal",
		"total_bytes": strconv.FormatInt(quota.TotalBytes, 10), "used_bytes": strconv.FormatInt(quota.UsedBytes, 10), "available_bytes": strconv.FormatInt(quota.AvailableBytes, 10),
		"checked_at": h.now().UTC().Format(time.RFC3339), "recycle_bin_bytes": nil,
	})
}

type wopanPrepareRequest struct {
	StorageID int `json:"storage_id"`
}
type wopanClearRequest struct {
	StorageID          int    `json:"storage_id"`
	ConfirmationToken  string `json:"confirmation_token"`
	ConfirmationPhrase string `json:"confirmation_phrase"`
}

// wopanRequest rejects duplicates as well as unknown/case-variant fields,
// trailing JSON and ambiguous nulls. The limit is independent of Content-Length.
func wopanRequest(r *http.Request, dst interface{}, allowed ...string) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return wopanError(http.StatusUnsupportedMediaType, "json_content_type_required")
	}
	if r.Body == nil {
		return wopanError(http.StatusBadRequest, "invalid_json")
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(payload) > 4096 {
		return wopanError(http.StatusBadRequest, "invalid_json")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return wopanError(http.StatusBadRequest, "invalid_json")
	}
	fields := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		fields[key] = false
	}
	for dec.More() {
		token, err = dec.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return wopanError(http.StatusBadRequest, "invalid_json")
		}
		seen, allowed := fields[key]
		if !allowed || seen {
			return wopanError(http.StatusBadRequest, "invalid_json")
		}
		fields[key] = true
		var raw json.RawMessage
		if dec.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return wopanError(http.StatusBadRequest, "invalid_json")
		}
	}
	if _, err = dec.Token(); err != nil {
		return wopanError(http.StatusBadRequest, "invalid_json")
	}
	if _, err = dec.Token(); err != io.EOF {
		return wopanError(http.StatusBadRequest, "invalid_json")
	}
	for _, present := range fields {
		if !present {
			return wopanError(http.StatusBadRequest, "invalid_json")
		}
	}
	if json.Unmarshal(payload, dst) != nil {
		return wopanError(http.StatusBadRequest, "invalid_json")
	}
	return nil
}

func (h *WopanAdminHandler) pruneLocked() {
	now := h.now()
	for key, challenge := range h.pending {
		if !now.Before(challenge.expires) {
			delete(h.pending, key)
		}
	}
}

func (h *WopanAdminHandler) PrepareRecycle(w http.ResponseWriter, r *http.Request) {
	wopanPrivate(w)
	local, err := h.localAdmin(r)
	if err == nil {
		err = wopanCSRF(r)
	}
	var input wopanPrepareRequest
	if err == nil {
		err = wopanRequest(r, &input, "storage_id")
	}
	if err == nil && input.StorageID <= 0 {
		err = wopanError(http.StatusBadRequest, "invalid_storage_id")
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), wopanOperationTimeout)
	defer cancel()
	s, err := h.snapshot()
	if err == nil {
		err = h.upstreamAdmin(ctx, &s, local)
	}
	var value wopanStorage
	if err == nil {
		value, err = h.storage(ctx, s, input.StorageID)
	}
	var addition wopanAddition
	if err == nil {
		addition, err = wopanPersonal(value)
	}
	var account wopan.Account
	if err == nil {
		account, err = h.provider.Account(ctx, addition.AccessToken)
	}
	if err == nil && account.ID == "" {
		err = wopanError(http.StatusBadGateway, "provider_invalid_response")
	}
	if err == nil && !h.unchanged(s) {
		err = wopanError(http.StatusConflict, "configuration_changed")
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		h.fail(w, wopanError(http.StatusServiceUnavailable, "confirmation_unavailable"))
		return
	}
	token := base64.RawURLEncoding.EncodeToString(nonce[:])
	challenge := wopanChallenge{local.username, local.session, s.origin, s.revision, s.configHash, value.ID, wopanStorageHash(value), account.ID, h.now().Add(wopanChallengeTTL)}
	h.mu.Lock()
	h.pruneLocked()
	if len(h.pending) >= wopanStateLimit {
		h.mu.Unlock()
		h.fail(w, wopanError(http.StatusTooManyRequests, "confirmation_limit"))
		return
	}
	h.pending[sha256.Sum256([]byte(token))] = challenge
	h.mu.Unlock()
	RespondSuccess(w, map[string]interface{}{
		"storage_id": value.ID, "mount_path": value.MountPath, "scope": "personal_account",
		"confirmation_token": token, "confirmation_phrase": wopanConfirmationPhrase,
		"expires_at": challenge.expires.UTC().Format(time.RFC3339),
		"warning":    "不可恢复；清空整个个人账号回收站，不仅当前挂载目录",
	})
}

func (h *WopanAdminHandler) ClearRecycle(w http.ResponseWriter, r *http.Request) {
	wopanPrivate(w)
	local, err := h.localAdmin(r)
	if err == nil {
		err = wopanCSRF(r)
	}
	var input wopanClearRequest
	if err == nil {
		err = wopanRequest(r, &input, "storage_id", "confirmation_token", "confirmation_phrase")
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	outcome := "rejected"
	defer func() {
		log.Info().Str("username", local.username).Int("storage_id", input.StorageID).Str("outcome", outcome).Msg("wopan_recycle_clear")
	}()
	// Consume before any network request, including reauthentication and read
	// validation. Failure/timeout/parallel clear can never make this reusable.
	key := sha256.Sum256([]byte(input.ConfirmationToken))
	h.mu.Lock()
	h.pruneLocked()
	challenge, found := h.pending[key]
	delete(h.pending, key)
	h.mu.Unlock()
	if !found || challenge.username != local.username || challenge.session != local.session || challenge.storageID != input.StorageID {
		h.fail(w, wopanError(http.StatusConflict, "confirmation_invalid"))
		return
	}
	if input.ConfirmationPhrase != wopanConfirmationPhrase {
		h.fail(w, wopanError(http.StatusBadRequest, "confirmation_phrase_mismatch"))
		return
	}
	s, err := h.snapshot()
	if err == nil && (s.origin != challenge.origin || s.revision != challenge.revision || s.configHash != challenge.configHash) {
		err = wopanError(http.StatusConflict, "configuration_changed")
	}
	ctx, cancel := context.WithTimeout(r.Context(), wopanOperationTimeout)
	defer cancel()
	if err == nil {
		err = h.upstreamAdmin(ctx, &s, local)
	}
	var value wopanStorage
	if err == nil {
		value, err = h.storage(ctx, s, input.StorageID)
	}
	var addition wopanAddition
	if err == nil {
		addition, err = wopanPersonal(value)
	}
	if err == nil && wopanStorageHash(value) != challenge.storageHash {
		err = wopanError(http.StatusConflict, "storage_changed")
	}
	var account wopan.Account
	if err == nil {
		account, err = h.provider.Account(ctx, addition.AccessToken)
	}
	if err == nil && (account.ID == "" || account.ID != challenge.accountID) {
		err = wopanError(http.StatusConflict, "account_changed")
	}
	if err == nil && !h.unchanged(s) {
		err = wopanError(http.StatusConflict, "configuration_changed")
	}
	if err == nil {
		_, err = h.localAdmin(r)
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	// The provider origin is fixed, so serialize the actual personal account
	// even if management configuration changes its AList origin mid-flight.
	accountKey := sha256.Sum256([]byte(account.ID))
	h.mu.Lock()
	if h.inflight[accountKey] || len(h.inflight) >= wopanStateLimit {
		h.mu.Unlock()
		h.fail(w, wopanError(http.StatusConflict, "clear_in_progress"))
		return
	}
	h.inflight[accountKey] = true
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.inflight, accountKey); h.mu.Unlock() }()
	if ctx.Err() != nil || !h.unchanged(s) {
		h.fail(w, wopanError(http.StatusConflict, "configuration_changed"))
		return
	}
	// Exactly one attempt. Any provider error after submitting is deliberately
	// outcome-unknown: neither server nor browser should retry automatically.
	if err = h.provider.EmptyRecycle(ctx, addition.AccessToken); err != nil {
		outcome = "clear_outcome_unknown"
		h.fail(w, wopanError(http.StatusBadGateway, outcome))
		return
	}
	outcome = "accepted"
	RespondSuccess(w, map[string]interface{}{
		"status": "accepted", "storage_id": value.ID, "mount_path": value.MountPath,
		"message": "清空请求已成功提交；容量回收可能延迟",
	})
}
