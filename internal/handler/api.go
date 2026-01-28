package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
)

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
		expireHours = 24
	}
	return &APIHandler{
		cfg:       cfg,
		jwtAuth:   auth.NewJWTAuth(cfg.JWTSecret, time.Duration(expireHours)*time.Hour),
		userDAO:   userDAO,
		passwdDAO: passwdDAO,
	}
}

// LoginRequest represents login request body
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents login response
type LoginResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

// Login handles user authentication
func (h *APIHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, LoginResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if err := h.userDAO.Validate(req.Username, req.Password); err != nil {
		writeJSON(w, http.StatusUnauthorized, LoginResponse{Code: 401, Message: "Invalid credentials"})
		return
	}

	token, err := h.jwtAuth.GenerateToken(req.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, LoginResponse{Code: 500, Message: "Failed to generate token"})
		return
	}

	writeJSON(w, http.StatusOK, LoginResponse{Code: 200, Message: "Success", Token: token})
}

// GetConfig returns current configuration
func (h *APIHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"code":    200,
		"message": "success",
		"data": map[string]interface{}{
			"scheme": map[string]interface{}{
				"address":      h.cfg.Scheme.Address,
				"http_port":    h.cfg.Scheme.HTTPPort,
				"https_port":   h.cfg.Scheme.HTTPSPort,
				"force_https":  h.cfg.Scheme.ForceHTTPS,
				"enable_h2c":   h.cfg.Scheme.EnableH2C,
			},
			"alist": map[string]interface{}{
				"host":  h.cfg.Alist.Host,
				"port":  h.cfg.Alist.Port,
				"https": h.cfg.Alist.HTTPS,
			},
			"cache": map[string]interface{}{
				"enable":           h.cfg.Cache.Enable,
				"expiration":       h.cfg.Cache.Expiration,
				"cleanup_interval": h.cfg.Cache.CleanupInterval,
			},
			"proxy": map[string]interface{}{
				"max_idle_conns":         h.cfg.Proxy.MaxIdleConns,
				"max_idle_conns_per_host": h.cfg.Proxy.MaxIdleConnsPerHost,
				"enable_http2":           h.cfg.Proxy.EnableHTTP2,
				"insecure_skip_verify":   h.cfg.Proxy.InsecureSkipVerify,
			},
			"log": map[string]interface{}{
				"level":  h.cfg.Log.Level,
				"format": h.cfg.Log.Format,
			},
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// SetConfig updates configuration
func (h *APIHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	// Config updates would require restart, so just acknowledge
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":    200,
		"message": "Config update requires restart",
	})
}

// GetPasswdConfig returns password configurations
func (h *APIHandler) GetPasswdConfig(w http.ResponseWriter, r *http.Request) {
	configs, err := h.passwdDAO.GetAll()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"code":    500,
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":    200,
		"message": "success",
		"data":    configs,
	})
}

// SetPasswdConfigRequest represents password config update request
type SetPasswdConfigRequest struct {
	Path      string   `json:"path"`
	Password  string   `json:"password"`
	EncType   string   `json:"encType"`
	EncPath   []string `json:"encPath"`
	EncName   bool     `json:"encName"`
	EncSuffix string   `json:"encSuffix"`
	Enable    bool     `json:"enable"`
}

// SetPasswdConfig updates password configuration
func (h *APIHandler) SetPasswdConfig(w http.ResponseWriter, r *http.Request) {
	var req SetPasswdConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"code":    400,
			"message": "Invalid request",
		})
		return
	}

	info := &config.PasswdInfo{
		Path:      req.Path,
		Password:  req.Password,
		EncType:   req.EncType,
		EncPath:   req.EncPath,
		EncName:   req.EncName,
		EncSuffix: req.EncSuffix,
		Enable:    req.Enable,
	}

	if info.EncType == "" {
		info.EncType = "aesctr"
	}

	if err := h.passwdDAO.Set(info); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"code":    500,
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":    200,
		"message": "success",
	})
}

// DeletePasswdConfigRequest represents password config delete request
type DeletePasswdConfigRequest struct {
	Path string `json:"path"`
}

// DeletePasswdConfig deletes password configuration
func (h *APIHandler) DeletePasswdConfig(w http.ResponseWriter, r *http.Request) {
	var req DeletePasswdConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"code":    400,
			"message": "Invalid request",
		})
		return
	}

	if err := h.passwdDAO.Delete(req.Path); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"code":    500,
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":    200,
		"message": "success",
	})
}

// ChangePasswordRequest represents password change request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ChangePassword changes user password
func (h *APIHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"code":    400,
			"message": "Invalid request",
		})
		return
	}

	// For now, assume admin user
	if err := h.userDAO.Validate("admin", req.OldPassword); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"code":    401,
			"message": "Invalid old password",
		})
		return
	}

	if err := h.userDAO.UpdatePassword("admin", req.NewPassword); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"code":    500,
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":    200,
		"message": "success",
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
