package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
)

// generateUUID generates a UUID v4 string like Node.js crypto.randomUUID()
func generateUUID() string {
	uuid := make([]byte, 16)
	rand.Read(uuid)
	// Set version (4) and variant (RFC 4122)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// APIHandler handles /enc-api/* routes
type APIHandler struct {
	cfg       *config.Config
	jwtAuth   *auth.JWTAuth
	userDAO   *dao.UserDAO
	passwdDAO *dao.PasswdDAO
}

// NewAPIHandler creates a new API handler
func NewAPIHandler(cfg *config.Config, userDAO *dao.UserDAO, passwdDAO *dao.PasswdDAO) *APIHandler {
	expireHours := cfg.JWTExpire
	if expireHours <= 0 {
		expireHours = 48
	}
	return &APIHandler{
		cfg:       cfg,
		jwtAuth:   auth.NewJWTAuth(cfg.JWTSecret, time.Duration(expireHours)*time.Hour),
		userDAO:   userDAO,
		passwdDAO: passwdDAO,
	}
}

// Login handles user authentication
func (h *APIHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "Invalid request"})
		return
	}

	if err := h.userDAO.Validate(req.Username, req.Password); err != nil {
		// Match Node.js error message exactly: "passwword error" (note the typo in original)
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "passwword error"})
		return
	}

	// Generate UUID token like Node.js version (not JWT)
	token := generateUUID()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": 0,
		"data": map[string]interface{}{
			"userInfo": map[string]interface{}{
				"username":   req.Username,
				"headImgUrl": "/public/logo.svg",
			},
			"jwtToken": token,
		},
	})
}

// GetUserInfo returns current user info
func (h *APIHandler) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": 0,
		"data": map[string]interface{}{
			"codes": []int{16, 9, 10, 11, 12, 13, 15},
			"userInfo": map[string]interface{}{
				"username":   "admin",
				"headImgUrl": "/public/logo.svg",
			},
			"menuList": []interface{}{},
			"roles":    []string{"admin"},
			"version":  config.Version,
		},
	})
}

// UpdatePasswd updates user password
func (h *APIHandler) UpdatePasswd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		NewPassword string `json:"newpassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "Invalid request"})
		return
	}

	if len(req.NewPassword) < 8 {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "password too short, at less 8 digits"})
		return
	}

	if err := h.userDAO.Validate(req.Username, req.Password); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "password error"})
		return
	}

	if err := h.userDAO.UpdatePassword(req.Username, req.NewPassword); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"code": 0, "msg": "update success"})
}

// GetAlistConfig returns Alist server configuration
func (h *APIHandler) GetAlistConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": 0,
		"data": h.cfg.AlistServer,
	})
}

// SaveAlistConfig saves Alist server configuration
func (h *APIHandler) SaveAlistConfig(w http.ResponseWriter, r *http.Request) {
	// Use raw map to handle encPath being either string or array
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "Invalid request: " + err.Error()})
		return
	}

	// Convert back to JSON and decode to struct
	server := config.AlistServer{
		Name:       getStringField(raw, "name"),
		Path:       getStringField(raw, "path"),
		Describe:   getStringField(raw, "describe"),
		ServerHost: getStringField(raw, "serverHost"),
		ServerPort: getIntField(raw, "serverPort"),
		HTTPS:      getBoolField(raw, "https"),
	}

	// Handle passwdList
	if passwdListRaw, ok := raw["passwdList"].([]interface{}); ok {
		for _, item := range passwdListRaw {
			if passwdMap, ok := item.(map[string]interface{}); ok {
				passwd := config.PasswdInfo{
					Password:  getStringField(passwdMap, "password"),
					EncType:   getStringField(passwdMap, "encType"),
					Describe:  getStringField(passwdMap, "describe"),
					Enable:    getBoolField(passwdMap, "enable"),
					EncName:   getBoolField(passwdMap, "encName"),
					EncSuffix: getStringField(passwdMap, "encSuffix"),
				}
				// Handle encPath as string or array
				passwd.EncPath = getStringArrayField(passwdMap, "encPath")
				server.PasswdList = append(server.PasswdList, passwd)
			}
		}
	}

	if err := h.cfg.UpdateAlistServer(server); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"code": 0, "msg": "save ok"})
}

// Helper functions for parsing raw JSON
func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getIntField(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}

func getBoolField(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getStringArrayField(m map[string]interface{}, key string) []string {
	// Handle as array
	if arr, ok := m[key].([]interface{}); ok {
		var result []string
		for _, v := range arr {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	// Handle as comma-separated string
	if s, ok := m[key].(string); ok && s != "" {
		return strings.Split(s, ",")
	}
	return nil
}

// GetWebdavConfig returns WebDAV server configurations
func (h *APIHandler) GetWebdavConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": 0,
		"data": h.cfg.WebDAVServer,
	})
}

// SaveWebdavConfig adds a new WebDAV server configuration
func (h *APIHandler) SaveWebdavConfig(w http.ResponseWriter, r *http.Request) {
	var server config.WebDAVServer
	if err := json.NewDecoder(r.Body).Decode(&server); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "Invalid request"})
		return
	}

	// Generate ID
	id := make([]byte, 16)
	rand.Read(id)
	server.ID = hex.EncodeToString(id)

	if err := h.cfg.AddWebDAVServer(server); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"code": 0, "data": h.cfg.WebDAVServer})
}

// UpdateWebdavConfig updates a WebDAV server configuration
func (h *APIHandler) UpdateWebdavConfig(w http.ResponseWriter, r *http.Request) {
	var server config.WebDAVServer
	if err := json.NewDecoder(r.Body).Decode(&server); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "Invalid request"})
		return
	}

	if err := h.cfg.UpdateWebDAVServer(server); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"code": 0, "data": h.cfg.WebDAVServer})
}

// DelWebdavConfig deletes a WebDAV server configuration
func (h *APIHandler) DelWebdavConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "Invalid request"})
		return
	}

	if err := h.cfg.DeleteWebDAVServer(req.ID); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"code": 0, "data": h.cfg.WebDAVServer})
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
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "Invalid request"})
		return
	}

	folderNameEnc := encryption.EncodeFolderName(req.Password, req.EncType, req.FolderPasswd, req.FolderEncType)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": 0,
		"data": map[string]interface{}{
			"folderNameEnc": folderNameEnc,
		},
	})
}

// DecodeFoldName decodes folder name
func (h *APIHandler) DecodeFoldName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password      string `json:"password"`
		EncType       string `json:"encType"`
		FolderNameEnc string `json:"folderNameEnc"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "Invalid request"})
		return
	}

	folderEncType, folderPasswd, ok := encryption.DecodeFolderName(req.Password, req.EncType, req.FolderNameEnc)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{"code": 500, "msg": "folderName is error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code": 0,
		"data": map[string]interface{}{
			"folderEncType": folderEncType,
			"folderPasswd":  folderPasswd,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
