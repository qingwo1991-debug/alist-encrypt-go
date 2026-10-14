package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/alist-encrypt-go/internal/config"
)

// Protected mutations remain unsupported until remote changes and complete
// original-name audit migration can be coordinated. This guard performs no I/O
// and deliberately does not depend on filename length, encryption rules, cached
// object types, or caller credentials. PUT and DELETE have separate semantics.
type protectedMutationError struct {
	status    int
	reason    string
	operation string
}

func (e *protectedMutationError) Error() string {
	return fmt.Sprintf("%s: %s", e.reason, e.operation)
}

func mutationProtectionEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, limit := range cfg.AlistServerSnapshot().FilenameWriteLimits {
		if limit > 0 {
			return true
		}
	}
	return false
}

func invalidMutation(operation string) error {
	return &protectedMutationError{http.StatusBadRequest, "invalid_mutation_path", operation}
}

// Paths are actual storage values: API JSON is literal and DAV URL.Path has
// already been decoded by net/url. Do not decode '%' again or reinterpret '+';
// that would confuse unrelated literal objects with protected objects.
func mutationPathVariants(value string) ([]string, error) {
	if !utf8.ValidString(value) || !strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.ContainsFunc(value, unicode.IsControl) {
		return nil, fmt.Errorf("invalid absolute path")
	}
	return []string{path.Clean(value)}, nil
}

func mutationNameVariants(value string) ([]string, error) {
	if !utf8.ValidString(value) || value == "" || value == "." || value == ".." || strings.ContainsAny(value, "/\\") || strings.ContainsFunc(value, unicode.IsControl) {
		return nil, fmt.Errorf("invalid basename")
	}
	return []string{value}, nil
}

func mutationSubtreesIntersect(a, b string) bool {
	return a == "/" || b == "/" || a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// guardProtectedMutation is shared by API and DAV. Each affected path may name
// a file or a directory; conservatively regard it as a subtree without probing
// upstream. Unknown paths are rejected only when protection is configured.
func guardProtectedMutation(cfg *config.Config, operation string, affectedPaths ...string) error {
	if !mutationProtectionEnabled(cfg) {
		return nil
	}
	if len(affectedPaths) == 0 {
		return invalidMutation(operation)
	}
	var candidates []string
	for _, p := range affectedPaths {
		variants, err := mutationPathVariants(p)
		if err != nil {
			return invalidMutation(operation)
		}
		candidates = append(candidates, variants...)
	}
	for prefix, limit := range cfg.AlistServerSnapshot().FilenameWriteLimits {
		if limit <= 0 {
			continue
		}
		prefixes, err := mutationPathVariants(prefix)
		if err != nil {
			return invalidMutation(operation)
		}
		for _, scope := range prefixes {
			for _, candidate := range candidates {
				if mutationSubtreesIntersect(scope, candidate) {
					return &protectedMutationError{http.StatusNotImplemented, "protected_operation_unsupported", operation}
				}
			}
		}
	}
	return nil
}

func guardProtectedRename(cfg *config.Config, source, name string) error {
	if !mutationProtectionEnabled(cfg) {
		return nil
	}
	sources, err := mutationPathVariants(source)
	if err != nil {
		return invalidMutation("rename")
	}
	names, err := mutationNameVariants(name)
	if err != nil {
		return invalidMutation("rename")
	}
	affected := append([]string(nil), sources...)
	for _, src := range sources {
		for _, n := range names {
			affected = append(affected, path.Join(path.Dir(src), n))
		}
	}
	return guardProtectedMutation(cfg, "rename", affected...)
}

func guardProtectedBatchMutation(cfg *config.Config, operation, srcDir, dstDir string, names []string) error {
	if !mutationProtectionEnabled(cfg) {
		return nil
	}
	sources, err := mutationPathVariants(srcDir)
	if err != nil {
		return invalidMutation(operation)
	}
	destinations, err := mutationPathVariants(dstDir)
	if err != nil || len(names) == 0 {
		return invalidMutation(operation)
	}
	var affected []string
	for _, name := range names {
		variants, err := mutationNameVariants(name)
		if err != nil {
			return invalidMutation(operation)
		}
		for _, dir := range append(append([]string(nil), sources...), destinations...) {
			for _, n := range variants {
				affected = append(affected, path.Join(dir, n))
			}
		}
	}
	return guardProtectedMutation(cfg, operation, affected...)
}

// guardProtectedProxyMutation closes NoRoute bypasses of the dedicated API
// handlers. Unknown schemas (including multipart uploads, driver Other actions,
// offline tasks and direct uploads) cannot establish all affected paths safely.
// While protection is configured they are refused even for unrelated mounts.
// No body is read: streamed bodies remain untouched and there is no unbounded
// parsing or guessed-path authorization. Dedicated PUT/DELETE routes are intact.
func guardProtectedProxyMutation(cfg *config.Config, r *http.Request) error {
	if !mutationProtectionEnabled(cfg) || r == nil || r.URL == nil {
		return nil
	}
	variants, err := mutationPathVariants(r.URL.Path)
	if err != nil {
		// A malformed endpoint spelling cannot establish that it is outside fs.
		return invalidMutation("proxy")
	}
	isFS := false
	for _, endpoint := range variants {
		if endpoint == "/api/fs" || strings.HasPrefix(endpoint, "/api/fs/") {
			isFS = true
		}
	}
	if !isFS {
		return nil
	}
	// Only exact endpoint spellings may use this allowlist. Otherwise alternate
	// routing/canonicalization upstream might dispatch a different operation.
	canonical := len(variants) == 1 && variants[0] == r.URL.Path
	read := false
	if canonical {
		switch r.URL.Path {
		case "/api/fs/get", "/api/fs/list", "/api/fs/search", "/api/fs/dirs", "/api/fs/archive/meta", "/api/fs/archive/list":
			read = r.Method == http.MethodPost || r.Method == http.MethodGet || r.Method == http.MethodHead
		case "/api/fs/link":
			read = r.Method == http.MethodPost
		}
	}
	if read {
		return nil
	}
	return &protectedMutationError{http.StatusNotImplemented, "protected_operation_unsupported", "proxy_fs_unclassified"}
}

// Capability refusal is not an authentication failure or upstream failure.
// Authentication remains the surrounding middleware/protocol's responsibility;
// this local guard never validates, substitutes, or forwards credentials.
func respondProtectedMutationError(w http.ResponseWriter, err error) {
	e, ok := err.(*protectedMutationError)
	if !ok {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.status)
	_ = json.NewEncoder(w).Encode(APIResponse{Code: e.status, Msg: e.Error(), Data: map[string]string{"reason": e.reason, "operation": e.operation}})
}
