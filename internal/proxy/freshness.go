package proxy

import (
	"context"
	"net/http"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/errors"
)

type strictFreshnessKey struct{}
type strictFreshnessCheck struct {
	revision uint64
	target   string
}

// WithStrictFreshnessCheck binds a successful caller-authorized metadata query
// and fresh geometry inspection to this request, target and configuration epoch.
// This is not a provider revision and must never enable cross-request reuse.
func WithStrictFreshnessCheck(ctx context.Context, revision uint64, target string) context.Context {
	return context.WithValue(ctx, strictFreshnessKey{}, strictFreshnessCheck{revision, target})
}

func strictFreshnessEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.AlistServerSnapshot().StrictFreshness
}

func (s *StreamProxy) strictFreshnessFailure(r *http.Request, target string) *StreamOutcome {
	proof, ok := r.Context().Value(strictFreshnessKey{}).(strictFreshnessCheck)
	if !strictFreshnessEnabled(s.cfg) && !ok {
		return nil
	}
	if !ok || proof.target != target || proof.revision != s.cfg.RuntimeRevision() || r.Context().Err() != nil {
		return &StreamOutcome{Err: errors.NewProxyError("strict freshness requires current authorized metadata inspection"), FailureReason: "strict_freshness_unconfirmed"}
	}
	return nil
}
