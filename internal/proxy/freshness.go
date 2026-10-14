package proxy

import (
	"context"
	"fmt"
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

// Guard the actual publication boundary, including HEAD and V3 after expensive
// KDF/sniff/record reads. Do not hold the config lock across network writes.
// This check rejects superseded writes; it is not atomic transfer revocation.
type strictFreshnessWriter struct {
	http.ResponseWriter
	proxy   *StreamProxy
	request *http.Request
	target  string
}

func (w *strictFreshnessWriter) WriteHeader(status int) {
	if w.proxy.strictFreshnessFailure(w.request, w.target) != nil {
		return
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *strictFreshnessWriter) Write(data []byte) (int, error) {
	if w.proxy.strictFreshnessFailure(w.request, w.target) != nil {
		return 0, fmt.Errorf("strict freshness superseded before response publication")
	}
	return w.ResponseWriter.Write(data)
}
func (s *StreamProxy) guardStrictFreshnessWriter(w http.ResponseWriter, r *http.Request, target string) http.ResponseWriter {
	_, checked := r.Context().Value(strictFreshnessKey{}).(strictFreshnessCheck)
	if !checked && !strictFreshnessEnabled(s.cfg) {
		return w
	}
	return &strictFreshnessWriter{ResponseWriter: w, proxy: s, request: r, target: target}
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
