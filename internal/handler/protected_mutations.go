package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// mutationPathVariants compares both literal and percent-decoded spellings.
// Repeated encodings are bounded and fail closed rather than hiding a protected
// subtree. '+' is a literal path character, not a query-string space.
func mutationPathVariants(value string) ([]string, error) {
	var variants []string
	for depth := 0; depth < 8; depth++ {
		if !utf8.ValidString(value) || !strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.ContainsFunc(value, unicode.IsControl) {
			return nil, fmt.Errorf("invalid absolute path")
		}
		variants = append(variants, path.Clean(value))
		if !strings.Contains(value, "%") {
			return variants, nil
		}
		decoded, err := url.PathUnescape(value)
		if err != nil {
			return nil, err
		}
		value = decoded
	}
	return nil, fmt.Errorf("excessively encoded path")
}

func mutationNameVariants(value string) ([]string, error) {
	paths, err := mutationPathVariants("/" + value)
	if err != nil {
		return nil, err
	}
	var names []string
	// Check the unclean spelling too: dot components must not silently disappear.
	for depth := 0; depth < 8; depth++ {
		if value == "" || value == "." || value == ".." || strings.ContainsAny(value, "/\\") {
			return nil, fmt.Errorf("invalid basename")
		}
		if !strings.Contains(value, "%") {
			break
		}
		value, err = url.PathUnescape(value)
		if err != nil {
			return nil, err
		}
	}
	for _, p := range paths {
		names = append(names, strings.TrimPrefix(p, "/"))
	}
	return names, nil
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
