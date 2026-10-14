package handler

import (
	"github.com/alist-encrypt-go/internal/config"
	"net/http"
)

func recoveryMutationError(cfg *config.Config, operation string) error {
	if cfg.RecoveryRequired() {
		return &protectedMutationError{http.StatusServiceUnavailable, "recovery_reconciliation_required", operation}
	}
	return nil
}
func rejectRecoveryMutation(cfg *config.Config, w http.ResponseWriter, operation string) bool {
	if err := recoveryMutationError(cfg, operation); err != nil {
		respondProtectedMutationError(w, err)
		return true
	}
	return false
}

// RecoveryProxyReadAllowed is intentionally an exact endpoint/method allowlist.
// Unknown upstream endpoints can have side effects even on GET. Do not infer
// safety from the HTTP verb or parse arbitrary streamed upload request bodies.
func RecoveryProxyReadAllowed(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	switch r.URL.Path {
	case "/api/fs/get", "/api/fs/list", "/api/fs/search", "/api/fs/dirs", "/api/fs/archive/meta", "/api/fs/archive/list":
		return r.Method == http.MethodPost || r.Method == http.MethodGet || r.Method == http.MethodHead
	case "/api/fs/link":
		return r.Method == http.MethodPost
	}
	return false
}
