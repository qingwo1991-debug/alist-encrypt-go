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
	proxy     *StreamProxy
	request   *http.Request
	target    string
	committed bool
	status    int
	failure   error
}

func (w *strictFreshnessWriter) deny() {
	w.failure = fmt.Errorf("strict freshness superseded before response publication")
	if w.committed {
		return
	} // already-started transfers cannot change status
	// A silent dropped HEAD WriteHeader becomes an implicit HTTP 200. Commit
	// an explicit empty failure instead, removing all stale geometry/evidence.
	for key := range w.Header() {
		w.Header().Del(key)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", "0")
	w.status = http.StatusServiceUnavailable
	w.committed = true
	w.ResponseWriter.WriteHeader(w.status)
}
func (w *strictFreshnessWriter) WriteHeader(status int) {
	if w.failure != nil {
		return
	}
	if w.proxy.strictFreshnessFailure(w.request, w.target) != nil {
		w.deny()
		return
	}
	if w.committed {
		return
	}
	w.committed = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *strictFreshnessWriter) Write(data []byte) (int, error) {
	if w.failure != nil {
		return 0, w.failure
	}
	if w.proxy.strictFreshnessFailure(w.request, w.target) != nil {
		w.deny()
		return 0, w.failure
	}
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}
func finishStrictFreshnessOutcome(w http.ResponseWriter, out *StreamOutcome) *StreamOutcome {
	guard, ok := w.(*strictFreshnessWriter)
	if !ok || guard.failure == nil {
		return out
	}
	if out == nil {
		out = &StreamOutcome{}
	}
	out.Err = guard.failure
	out.FailureReason = "strict_freshness_unconfirmed"
	out.Retryable = false
	out.NoLearning = true
	out.ResponseStarted = guard.committed
	out.StatusCode = guard.status
	return out
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
