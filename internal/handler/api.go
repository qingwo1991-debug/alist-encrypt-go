package handler

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/appservice"
	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxydict"
	"github.com/alist-encrypt-go/internal/restart"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

// APIHandler handles /enc-api/* routes
type APIHandler struct {
	cfg        *config.Config
	jwtAuth    *auth.JWTAuth
	userDAO    *dao.UserDAO
	passwdDAO  *dao.PasswdDAO
	mysqlStore *mysqlstore.Store
	dictMgr    *proxydict.Manager
	svc        *appservice.Service
}

var deprecatedRangeCompatTTLWarned uint32

// NewAPIHandler creates a new API handler
func NewAPIHandler(cfg *config.Config, userDAO *dao.UserDAO, passwdDAO *dao.PasswdDAO, mysqlStore *mysqlstore.Store) *APIHandler {
	expireHours := cfg.JWTExpire
	if expireHours <= 0 {
		expireHours = 48
	}
	dictMgr := proxydict.NewManager(filepath.Join("conf", "proxy_domain_dict.json"), filepath.Join("configs", "proxy_domain_dict.seed.json"))
	return &APIHandler{
		cfg:        cfg,
		jwtAuth:    auth.NewJWTAuth(cfg.JWTSecret, time.Duration(expireHours)*time.Hour),
		userDAO:    userDAO,
		passwdDAO:  passwdDAO,
		mysqlStore: mysqlStore,
		dictMgr:    dictMgr,
		svc: appservice.New(appservice.Deps{
			Cfg:        cfg,
			UserDAO:    userDAO,
			PasswdDAO:  passwdDAO,
			MySQLStore: mysqlStore,
			DictMgr:    dictMgr,
		}),
	}
}

// Login handles user authentication
func (h *APIHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	userInfo, token, err := h.svc.Login(req.Username, req.Password)
	if err != nil {
		// Match Node.js error message exactly: "passwword error" (note the typo in original)
		RespondAPIError(w, 500, "passwword error")
		return
	}
	RespondSuccess(w, map[string]interface{}{
		"userInfo": userInfo,
		"jwtToken": token,
	})
}

// GetUserInfo returns current user info
func (h *APIHandler) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	// Get actual username from database
	data, _ := h.svc.UserInfo()
	RespondSuccess(w, data)
}

// GetBuildInfo returns lightweight capability metadata for platform-specific clients.
func (h *APIHandler) GetBuildInfo(w http.ResponseWriter, r *http.Request) {
	RespondSuccess(w, h.svc.BuildInfo())
}

// UpdatePasswd updates user password
func (h *APIHandler) UpdatePasswd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		NewPassword string `json:"newpassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	// Check minimum password length (original uses 7, message says 8)
	if err := h.svc.UpdatePassword(req.Username, req.Password, req.NewPassword); err != nil {
		if strings.Contains(err.Error(), "too short") {
			RespondAPIError(w, 500, err.Error())
			return
		}
		RespondAPIError(w, 500, "password error")
		return
	}
	RespondSuccessMsg(w, "update success")
}

// UpdateUsername updates user username
func (h *APIHandler) UpdateUsername(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		NewUsername string `json:"newusername"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	if err := h.svc.UpdateUsername(req.Username, req.Password, req.NewUsername); err != nil {
		if strings.Contains(err.Error(), "too short") {
			RespondAPIError(w, 500, err.Error())
			return
		}
		RespondAPIError(w, 500, "password error")
		return
	}
	RespondSuccessMsg(w, "update success")
}

// GetAlistConfig returns Alist server configuration
func (h *APIHandler) GetAlistConfig(w http.ResponseWriter, r *http.Request) {
	RespondSuccess(w, h.svc.GetAlistConfig())
}

// SaveAlistConfig saves Alist server configuration
func (h *APIHandler) SaveAlistConfig(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}
	if err := h.svc.SaveAlistConfig(raw); err != nil {
		if strings.Contains(err.Error(), "deprecated") {
			RespondAPIError(w, 500, err.Error())
			return
		}
		RespondAPIError(w, 500, err.Error())
		return
	}
	RespondSuccessMsg(w, "save ok")
}

// ValidateScanConfig verifies that the configured scan credentials can access Alist WebDAV.
func (h *APIHandler) ValidateScanConfig(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}

	result, err := h.svc.ValidateScanConfig(raw, r.Context())
	if err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}
	RespondSuccess(w, result)
}

// GetWebdavConfig returns WebDAV server configurations
func (h *APIHandler) GetWebdavConfig(w http.ResponseWriter, r *http.Request) {
	RespondSuccess(w, h.svc.GetWebdavConfig())
}

// GetProxyDomainDictionary returns cached proxy provider dictionary.
func (h *APIHandler) GetProxyDomainDictionary(w http.ResponseWriter, r *http.Request) {
	dict, err := h.svc.GetProxyDomainDictionary()
	if err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}
	RespondSuccess(w, dict)
}

// RefreshProxyDomainDictionary rescans OpenList and refreshes dictionary.
func (h *APIHandler) RefreshProxyDomainDictionary(w http.ResponseWriter, r *http.Request) {
	dict, err := h.svc.RefreshProxyDomainDictionary()
	if err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}
	RespondSuccess(w, dict)
}

// SaveWebdavConfig adds a new WebDAV server configuration
func (h *APIHandler) SaveWebdavConfig(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}

	if err := h.svc.SaveWebdavConfig(raw); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	RespondSuccess(w, h.svc.GetWebdavConfig())
}

// UpdateWebdavConfig updates a WebDAV server configuration
func (h *APIHandler) UpdateWebdavConfig(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}

	if err := h.svc.UpdateWebdavConfig(raw); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	RespondSuccess(w, h.svc.GetWebdavConfig())
}

// DelWebdavConfig deletes a WebDAV server configuration
func (h *APIHandler) DelWebdavConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	if err := h.svc.DeleteWebdavConfig(req.ID); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	RespondSuccess(w, h.svc.GetWebdavConfig())
}

// EncodeFoldName encodes folder name with password
func (h *APIHandler) EncodeFoldName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password      string `json:"password"`
		EncType       string `json:"encType"`
		FolderPasswd  string `json:"folderPasswd"`
		FolderEncType string `json:"folderEncType"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	RespondSuccess(w, h.svc.EncodeFolderName(req.Password, req.EncType, req.FolderPasswd, req.FolderEncType))
}

// DecodeFoldName decodes folder name
func (h *APIHandler) DecodeFoldName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password      string `json:"password"`
		EncType       string `json:"encType"`
		FolderNameEnc string `json:"folderNameEnc"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	data, err := h.svc.DecodeFolderName(req.Password, req.EncType, req.FolderNameEnc)
	if err != nil {
		RespondAPIError(w, 500, "folderName is error")
		return
	}

	RespondSuccess(w, data)
}

// GetSchemeConfig returns server scheme configuration
func (h *APIHandler) GetSchemeConfig(w http.ResponseWriter, r *http.Request) {
	RespondSuccess(w, h.svc.GetSchemeConfig())
}

// SaveSchemeConfig saves scheme configuration
// Returns needRestart: true if server restart is required
func (h *APIHandler) SaveSchemeConfig(w http.ResponseWriter, r *http.Request) {
	var scheme config.SchemeConfig
	if err := json.NewDecoder(r.Body).Decode(&scheme); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}

	needRestart, err := h.svc.SaveSchemeConfig(scheme)
	if err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	RespondSuccess(w, map[string]interface{}{
		"message":     "save ok",
		"needRestart": needRestart,
	})

	// Trigger restart asynchronously if needed
	if needRestart {
		go func() {
			time.Sleep(100 * time.Millisecond) // Let response complete
			restart.Trigger()
		}()
	}
}

// ExportFileMeta exports file metadata from MySQL for external sync
func (h *APIHandler) ExportFileMeta(w http.ResponseWriter, r *http.Request) {
	if h.mysqlStore == nil {
		RespondAPIError(w, 500, "mysql not enabled")
		return
	}

	limit := 1000
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			if parsed > 5000 {
				parsed = 5000
			}
			limit = parsed
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	var updatedAfter time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			updatedAfter = time.Unix(parsed, 0)
		}
	}
	if updatedAfter.IsZero() {
		if v := r.URL.Query().Get("updated_after"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				updatedAfter = t
			}
		}
	}

	filter := mysqlstore.FileMetaFilter{
		ProviderHost: r.URL.Query().Get("provider"),
		OriginalPath: r.URL.Query().Get("path"),
		PathPrefix:   r.URL.Query().Get("path_prefix"),
		UpdatedAfter: updatedAfter,
		CursorKey:    r.URL.Query().Get("cursor"),
		Limit:        limit,
		Offset:       offset,
	}

	records, err := h.svc.ExportFileMeta(r.Context(), filter)
	if err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	var maxUpdated time.Time
	nextCursor := ""
	for _, record := range records {
		if record.UpdatedAt.After(maxUpdated) {
			maxUpdated = record.UpdatedAt
		}
		nextCursor = record.KeyHash
	}
	nextSince := int64(0)
	nextSinceRFC3339 := ""
	if !maxUpdated.IsZero() {
		nextSince = maxUpdated.Unix()
		nextSinceRFC3339 = maxUpdated.UTC().Format(time.RFC3339)
	}

	RespondSuccess(w, map[string]interface{}{
		"items":              records,
		"limit":              limit,
		"offset":             offset,
		"has_more":           len(records) == limit,
		"next_since":         nextSince,
		"next_since_rfc3339": nextSinceRFC3339,
		"next_cursor":        nextCursor,
	})
}

func parseExportSinceParams(r *http.Request) time.Time {
	var updatedAfter time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			updatedAfter = time.Unix(parsed, 0)
		}
	}
	if updatedAfter.IsZero() {
		if v := r.URL.Query().Get("updated_after"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				updatedAfter = t
			}
		}
	}
	return updatedAfter
}

func exportLimitAndCursor(r *http.Request) (int, string) {
	limit := 1000
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			if parsed > 5000 {
				parsed = 5000
			}
			limit = parsed
		}
	}
	return limit, r.URL.Query().Get("cursor")
}

// ExportStrategy exports strategy metadata for DB_EXPORT sync.
func (h *APIHandler) ExportStrategy(w http.ResponseWriter, r *http.Request) {
	if h.mysqlStore == nil {
		RespondAPIError(w, 500, "mysql not enabled")
		return
	}
	records, err := h.svc.ExportStrategies(r.Context())
	if err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}
	updatedAfter := parseExportSinceParams(r)
	limit, cursor := exportLimitAndCursor(r)
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].UpdatedAt.Equal(records[j].UpdatedAt) {
			return records[i].KeyHash < records[j].KeyHash
		}
		return records[i].UpdatedAt.Before(records[j].UpdatedAt)
	})
	items := make([]map[string]interface{}, 0, limit)
	nextCursor := ""
	var maxUpdated time.Time
	started := cursor == ""
	for _, record := range records {
		if !updatedAfter.IsZero() && record.UpdatedAt.Before(updatedAfter) {
			continue
		}
		if !started {
			if record.KeyHash == cursor {
				started = true
			}
			continue
		}
		if len(items) >= limit {
			break
		}
		items = append(items, map[string]interface{}{
			"KeyHash":      record.KeyHash,
			"ProviderHost": record.ProviderHost,
			"OriginalPath": record.OriginalPath,
			"NetworkType":  "any",
			"Strategy":     record.Preferred,
			"UpdatedAt":    record.UpdatedAt.UTC().Format(time.RFC3339),
			"LastAccessed": record.LastAccessed.UTC().Format(time.RFC3339),
		})
		if record.UpdatedAt.After(maxUpdated) {
			maxUpdated = record.UpdatedAt
		}
		nextCursor = record.KeyHash
	}
	nextSince := int64(0)
	if !maxUpdated.IsZero() {
		nextSince = maxUpdated.Unix()
	}
	RespondSuccess(w, map[string]interface{}{
		"items":       items,
		"has_more":    len(items) == limit,
		"next_since":  nextSince,
		"next_cursor": nextCursor,
		"limit":       limit,
	})
}

// ExportRangeCompat exports range compatibility metadata for DB_EXPORT sync.
func (h *APIHandler) ExportRangeCompat(w http.ResponseWriter, r *http.Request) {
	if h.mysqlStore == nil {
		RespondAPIError(w, 500, "mysql not enabled")
		return
	}
	records, err := h.svc.ExportRangeCompats(r.Context())
	if err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}
	updatedAfter := parseExportSinceParams(r)
	limit, cursor := exportLimitAndCursor(r)
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].UpdatedAt.Equal(records[j].UpdatedAt) {
			return records[i].KeyHash < records[j].KeyHash
		}
		return records[i].UpdatedAt.Before(records[j].UpdatedAt)
	})
	items := make([]map[string]interface{}, 0, limit)
	nextCursor := ""
	var maxUpdated time.Time
	started := cursor == ""
	for _, record := range records {
		if !updatedAfter.IsZero() && record.UpdatedAt.Before(updatedAfter) {
			continue
		}
		if !started {
			if record.KeyHash == cursor {
				started = true
			}
			continue
		}
		if len(items) >= limit {
			break
		}
		item := map[string]interface{}{
			"KeyHash":      record.KeyHash,
			"ProviderHost": record.ProviderHost,
			"OriginalPath": record.StorageKey,
			"UpdatedAt":    record.UpdatedAt.UTC().Format(time.RFC3339),
			"LastAccessed": record.LastAccessed.UTC().Format(time.RFC3339),
			"LastReason":   record.LastReason,
		}
		if !record.NextProbeAt.IsZero() {
			item["BlockedUntil"] = record.NextProbeAt.UTC().Format(time.RFC3339)
		}
		if record.ConsecutiveFailures > 0 {
			item["Failures"] = record.ConsecutiveFailures
		}
		items = append(items, item)
		if record.UpdatedAt.After(maxUpdated) {
			maxUpdated = record.UpdatedAt
		}
		nextCursor = record.KeyHash
	}
	nextSince := int64(0)
	if !maxUpdated.IsZero() {
		nextSince = maxUpdated.Unix()
	}
	RespondSuccess(w, map[string]interface{}{
		"items":       items,
		"has_more":    len(items) == limit,
		"next_since":  nextSince,
		"next_cursor": nextCursor,
		"limit":       limit,
	})
}

// CleanupLegacyBoltDB removes the legacy BoltDB file after MySQL has been configured.
func (h *APIHandler) CleanupLegacyBoltDB(w http.ResponseWriter, r *http.Request) {
	msg, err := h.svc.CleanupLegacyBoltDB()
	if err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}
	RespondSuccessMsg(w, msg)
}

// GetProxyRoutingConfig returns current proxy configuration.
func (h *APIHandler) GetProxyRoutingConfig(w http.ResponseWriter, r *http.Request) {
	RespondSuccess(w, h.svc.GetProxyRoutingConfig())
}

// SaveProxyRoutingConfig saves current proxy config.
func (h *APIHandler) SaveProxyRoutingConfig(w http.ResponseWriter, r *http.Request) {
	var proxyCfg config.ProxyConfig
	if err := json.NewDecoder(r.Body).Decode(&proxyCfg); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}
	if err := h.svc.SaveProxyRoutingConfig(proxyCfg); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}
	RespondSuccessMsg(w, "save ok")
}

// HandleCheckFilePath validates a local file path exists and counts files.
func HandleCheckFilePath(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FolderPath string `json:"folderPath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondAPIError(w, 500, "Invalid request")
		return
	}
	if req.FolderPath == "" {
		RespondAPIError(w, 500, "folderPath is required")
		return
	}
	info, err := os.Stat(req.FolderPath)
	if err != nil {
		RespondAPIError(w, 500, "Path does not exist: "+err.Error())
		return
	}
	if !info.IsDir() {
		RespondAPIError(w, 500, "Path is not a directory")
		return
	}
	var fileCount int
	var totalBytes int64
	filepath.WalkDir(req.FolderPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, e := d.Info(); e == nil {
			fileCount++
			totalBytes += info.Size()
		}
		return nil
	})
	RespondSuccess(w, map[string]interface{}{
		"fileCount":  fileCount,
		"totalBytes": totalBytes,
		"exists":     true,
	})
}
