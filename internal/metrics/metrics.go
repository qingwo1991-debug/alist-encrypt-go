// Package metrics is a minimal Prometheus-text exposition registry.
//
// The project intentionally avoids the prometheus/client_golang dependency
// (it cross-compiles to mobile targets); this package covers the small
// counter/gauge/histogram surface the proxy needs and renders the standard
// text format so any Prometheus-compatible scraper can consume it.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

const histogramBucketCount = 11

var histogramBuckets = [histogramBucketCount]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type seriesKey struct {
	name   string
	labels string
}

type histogram struct {
	buckets [histogramBucketCount]uint64
	count   uint64
	sum     float64
}

// Registry is a goroutine-safe collection of counters, gauges and
// histograms keyed by metric name plus a canonical label string.
type Registry struct {
	mu         sync.Mutex
	counters   map[seriesKey]float64
	gauges     map[seriesKey]float64
	histograms map[seriesKey]*histogram
}

func NewRegistry() *Registry {
	return &Registry{
		counters:   make(map[seriesKey]float64),
		gauges:     make(map[seriesKey]float64),
		histograms: make(map[seriesKey]*histogram),
	}
}

func canonicalLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", k, labels[k])
	}
	return b.String()
}

// Inc increments a counter.
func (r *Registry) Inc(name string, labels map[string]string, delta float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := seriesKey{name, canonicalLabels(labels)}
	r.counters[k] += delta
}

// SetGauge sets a gauge to an absolute value.
func (r *Registry) SetGauge(name string, labels map[string]string, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := seriesKey{name, canonicalLabels(labels)}
	r.gauges[k] = value
}

// Observe records a duration observation into a fixed-bucket histogram.
func (r *Registry) Observe(name string, labels map[string]string, seconds float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := seriesKey{name, canonicalLabels(labels)}
	h := r.histograms[k]
	if h == nil {
		h = &histogram{}
		r.histograms[k] = h
	}
	for i, bound := range histogramBuckets {
		if seconds <= bound {
			h.buckets[i]++
		}
	}
	h.count++
	h.sum += seconds
}

func labelString(labels map[string]string) string {
	canon := canonicalLabels(labels)
	if canon == "" {
		return ""
	}
	return "{" + canon + "}"
}

// WriteTo renders the registry in Prometheus text exposition format.
func (r *Registry) WriteTo(w http.ResponseWriter) {
	r.mu.Lock()
	type counterRow struct {
		key   seriesKey
		value float64
	}
	counters := make([]counterRow, 0, len(r.counters))
	for k, v := range r.counters {
		counters = append(counters, counterRow{k, v})
	}
	gauges := make([]counterRow, 0, len(r.gauges))
	for k, v := range r.gauges {
		gauges = append(gauges, counterRow{k, v})
	}
	hists := make([]struct {
		key seriesKey
		h   *histogram
	}, 0, len(r.histograms))
	for k, h := range r.histograms {
		hists = append(hists, struct {
			key seriesKey
			h   *histogram
		}{k, h})
	}
	r.mu.Unlock()

	sort.Slice(counters, func(i, j int) bool {
		return counters[i].key.name+"\x00"+counters[i].key.labels < counters[j].key.name+"\x00"+counters[j].key.labels
	})
	sort.Slice(gauges, func(i, j int) bool {
		return gauges[i].key.name+"\x00"+gauges[i].key.labels < gauges[j].key.name+"\x00"+gauges[j].key.labels
	})
	sort.Slice(hists, func(i, j int) bool {
		return hists[i].key.name+"\x00"+hists[i].key.labels < hists[j].key.name+"\x00"+hists[j].key.labels
	})

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	var b strings.Builder
	for _, row := range counters {
		fmt.Fprintf(&b, "# TYPE %s counter\n%s%s %g\n", row.key.name, row.key.name, labelSuffix(row.key.labels), row.value)
	}
	for _, row := range gauges {
		fmt.Fprintf(&b, "# TYPE %s gauge\n%s%s %g\n", row.key.name, row.key.name, labelSuffix(row.key.labels), row.value)
	}
	for _, row := range hists {
		labels := labelSuffix(row.key.labels)
		base := row.key.name
		fmt.Fprintf(&b, "# TYPE %s histogram\n", base)
		for i, bound := range histogramBuckets {
			le := fmt.Sprintf("%g", bound)
			fmt.Fprintf(&b, "%s_bucket%s %d\n", base, mergeLabels(labels, "le=\""+le+"\""), row.h.buckets[i])
		}
		fmt.Fprintf(&b, "%s_bucket%s %d\n", base, mergeLabels(labels, "le=\"+Inf\""), row.h.count)
		fmt.Fprintf(&b, "%s_sum%s %g\n%s_count%s %d\n", base, labels, row.h.sum, base, labels, row.h.count)
	}
	_, _ = w.Write([]byte(b.String()))
}

// labelSuffix turns the canonical "k=v,k2=v2" form into a {...} suffix.
func labelSuffix(canon string) string {
	if canon == "" {
		return ""
	}
	return "{" + canon + "}"
}

// mergeLabels inserts an extra label into a canonical label string for
// histogram bucket series.
func mergeLabels(canonSuffix, extra string) string {
	inner := strings.TrimSuffix(strings.TrimPrefix(canonSuffix, "{"), "}")
	if inner == "" {
		return "{" + extra + "}"
	}
	return "{" + inner + "," + extra + "}"
}

// Default is the process-wide registry used by handlers.
var Default = NewRegistry()

// Package-level helpers bound to Default for call-site brevity.

func Inc(name string, labels map[string]string, delta float64) {
	Default.Inc(name, labels, delta)
}

func SetGauge(name string, labels map[string]string, value float64) {
	Default.SetGauge(name, labels, value)
}

func Observe(name string, labels map[string]string, seconds float64) {
	Default.Observe(name, labels, seconds)
}

// Handler serves the default registry in Prometheus text format.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		Default.WriteTo(w)
	}
}
