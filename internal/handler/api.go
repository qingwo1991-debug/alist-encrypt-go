package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/restart"
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
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	if err := h.userDAO.Validate(req.Username, req.Password); err != nil {
		// Match Node.js error message exactly: "passwword error" (note the typo in original)
		RespondAPIError(w, 500, "passwword error")
		return
	}

	// Generate UUID token like Node.js version (not JWT)
	token := generateUUID()

	RespondSuccess(w, map[string]interface{}{
		"userInfo": map[string]interface{}{
			"username":   req.Username,
			"headImgUrl": "/public/logo.svg",
		},
		"jwtToken": token,
	})
}

// GetUserInfo returns current user info
func (h *APIHandler) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	// Get actual username from database
	user, err := h.userDAO.GetFirstUser()
	username := "admin"
	if err == nil && user != nil {
		username = user.Username
	}

	RespondSuccess(w, map[string]interface{}{
		"codes": []int{16, 9, 10, 11, 12, 13, 15},
		"userInfo": map[string]interface{}{
			"username":   username,
			"headImgUrl": "/public/logo.svg",
		},
		"menuList": []interface{}{},
		"roles":    []string{"admin"},
		"version":  config.Version,
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
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	// Check minimum password length (original uses 7, message says 8)
	if len(req.NewPassword) < 7 {
		RespondAPIError(w, 500, "password too short, at less 8 digits")
		return
	}

	if err := h.userDAO.Validate(req.Username, req.Password); err != nil {
		RespondAPIError(w, 500, "password error")
		return
	}

	if err := h.userDAO.UpdatePassword(req.Username, req.NewPassword); err != nil {
		RespondAPIError(w, 500, err.Error())
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

	if len(req.NewUsername) < 3 {
		RespondAPIError(w, 500, "username too short, at least 3 characters")
		return
	}

	if err := h.userDAO.Validate(req.Username, req.Password); err != nil {
		RespondAPIError(w, 500, "password error")
		return
	}

	// Delete old user and create new one with same password
	if err := h.userDAO.Delete(req.Username); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	if err := h.userDAO.Create(req.NewUsername, req.Password); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	RespondSuccessMsg(w, "update success")
}

// GetAlistConfig returns Alist server configuration
func (h *APIHandler) GetAlistConfig(w http.ResponseWriter, r *http.Request) {
	RespondSuccess(w, h.cfg.AlistServer)
}

// SaveAlistConfig saves Alist server configuration
func (h *APIHandler) SaveAlistConfig(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}

	server := config.ParseAlistServerFromMap(raw)

	if err := h.cfg.UpdateAlistServer(server); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	RespondSuccessMsg(w, "save ok")
}

// GetWebdavConfig returns WebDAV server configurations
func (h *APIHandler) GetWebdavConfig(w http.ResponseWriter, r *http.Request) {
	RespondSuccess(w, h.cfg.WebDAVServer)
}

// SaveWebdavConfig adds a new WebDAV server configuration
func (h *APIHandler) SaveWebdavConfig(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}

	server := config.ParseWebDAVServerFromMap(raw)

	// Generate ID
	id := make([]byte, 16)
	rand.Read(id)
	server.ID = hex.EncodeToString(id)

	if err := h.cfg.AddWebDAVServer(server); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	RespondSuccess(w, h.cfg.WebDAVServer)
}

// UpdateWebdavConfig updates a WebDAV server configuration
func (h *APIHandler) UpdateWebdavConfig(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}

	server := config.ParseWebDAVServerFromMap(raw)

	if err := h.cfg.UpdateWebDAVServer(server); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	RespondSuccess(w, h.cfg.WebDAVServer)
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

	if err := h.cfg.DeleteWebDAVServer(req.ID); err != nil {
		RespondAPIError(w, 500, err.Error())
		return
	}

	RespondSuccess(w, h.cfg.WebDAVServer)
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

	folderNameEnc := encryption.EncodeFolderName(req.Password, req.EncType, req.FolderPasswd, req.FolderEncType)
	RespondSuccess(w, map[string]interface{}{
		"folderNameEnc": folderNameEnc,
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
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	folderEncType, folderPasswd, ok := encryption.DecodeFolderName(req.Password, req.EncType, req.FolderNameEnc)
	if !ok {
		RespondAPIError(w, 500, "folderName is error")
		return
	}

	RespondSuccess(w, map[string]interface{}{
		"folderEncType": folderEncType,
		"folderPasswd":  folderPasswd,
	})
}

// GetSchemeConfig returns server scheme configuration
func (h *APIHandler) GetSchemeConfig(w http.ResponseWriter, r *http.Request) {
	RespondSuccess(w, h.cfg.Scheme)
}

// SaveSchemeConfig saves scheme configuration
// Returns needRestart: true if server restart is required
func (h *APIHandler) SaveSchemeConfig(w http.ResponseWriter, r *http.Request) {
	var scheme config.SchemeConfig
	if err := json.NewDecoder(r.Body).Decode(&scheme); err != nil {
		RespondAPIError(w, 500, "Invalid request: "+err.Error())
		return
	}

	needRestart, err := h.cfg.UpdateScheme(scheme)
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
