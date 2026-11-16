package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistryExposition(t *testing.T) {
	r := NewRegistry()
	r.Inc("test_counter_total", map[string]string{"result": "ok"}, 2)
	r.SetGauge("test_gauge", nil, 42)
	r.Observe("test_latency_seconds", map[string]string{"result": "hit"}, 0.03)
	r.Observe("test_latency_seconds", map[string]string{"result": "hit"}, 0.3)

	rec := httptest.NewRecorder()
	r.WriteTo(rec)
	body := rec.Body.String()

	for _, want := range []string{
		`test_counter_total{result="ok"} 2`,
		`test_gauge 42`,
		`test_latency_seconds_bucket{result="hit",le="0.05"} 1`,
		`test_latency_seconds_bucket{result="hit",le="0.5"} 2`,
		`test_latency_seconds_bucket{result="hit",le="+Inf"} 2`,
		`test_latency_seconds_count{result="hit"} 2`,
		"# TYPE test_counter_total counter",
		"# TYPE test_latency_seconds histogram",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in output:\n%s", want, body)
		}
	}
}

func TestRegistryLabelOrdering(t *testing.T) {
	r := NewRegistry()
	r.Inc("m", map[string]string{"b": "2", "a": "1"}, 1)
	rec := httptest.NewRecorder()
	r.WriteTo(rec)
	if !strings.Contains(rec.Body.String(), `m{a="1",b="2"} 1`) {
		t.Fatalf("labels not canonicalized: %s", rec.Body.String())
	}
}
