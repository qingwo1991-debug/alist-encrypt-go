package config

import "testing"

func TestParseAlistServerFromMapRangeLearningDefaults(t *testing.T) {
	raw := map[string]interface{}{
		"name": "alist",
	}
	server := ParseAlistServerFromMap(raw)
	if server.RangeFailToDowngrade != 2 {
		t.Fatalf("expected default RangeFailToDowngrade=2, got %d", server.RangeFailToDowngrade)
	}
	if server.RangeSuccessToRecover != 3 {
		t.Fatalf("expected default RangeSuccessToRecover=3, got %d", server.RangeSuccessToRecover)
	}
	if server.RangeReprobeMinutes != 30 {
		t.Fatalf("expected default RangeReprobeMinutes=30, got %d", server.RangeReprobeMinutes)
	}
	if server.RangeProbeTimeoutSeconds != 8 {
		t.Fatalf("expected default RangeProbeTimeoutSeconds=8, got %d", server.RangeProbeTimeoutSeconds)
	}
}

func TestDefaultConfigRangeLearningValues(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AlistServer.RangeFailToDowngrade != 2 {
		t.Fatalf("range fail_to_downgrade=%d, want 2", cfg.AlistServer.RangeFailToDowngrade)
	}
	if cfg.AlistServer.RangeSuccessToRecover != 3 {
		t.Fatalf("range success_to_recover=%d, want 3", cfg.AlistServer.RangeSuccessToRecover)
	}
	if cfg.AlistServer.RangeReprobeMinutes != 30 {
		t.Fatalf("range reprobe=%d, want 30", cfg.AlistServer.RangeReprobeMinutes)
	}
	if cfg.AlistServer.RangeProbeTimeoutSeconds != 8 {
		t.Fatalf("range probe timeout=%d, want 8", cfg.AlistServer.RangeProbeTimeoutSeconds)
	}
}

func TestParseAlistServerFromMapRangeLearningExplicitValues(t *testing.T) {
	raw := map[string]interface{}{
		"name":                     "alist",
		"rangeFailToDowngrade":     float64(4),
		"rangeSuccessToRecover":    float64(6),
		"rangeReprobeMinutes":      float64(45),
		"rangeProbeTimeoutSeconds": float64(12),
	}
	server := ParseAlistServerFromMap(raw)
	if server.RangeFailToDowngrade != 4 {
		t.Fatalf("RangeFailToDowngrade=%d, want 4", server.RangeFailToDowngrade)
	}
	if server.RangeSuccessToRecover != 6 {
		t.Fatalf("RangeSuccessToRecover=%d, want 6", server.RangeSuccessToRecover)
	}
	if server.RangeReprobeMinutes != 45 {
		t.Fatalf("RangeReprobeMinutes=%d, want 45", server.RangeReprobeMinutes)
	}
	if server.RangeProbeTimeoutSeconds != 12 {
		t.Fatalf("RangeProbeTimeoutSeconds=%d, want 12", server.RangeProbeTimeoutSeconds)
	}
}

func TestParseAlistServerFromMapEnableBackgroundProbeDefaultTrue(t *testing.T) {
	raw := map[string]interface{}{
		"name": "alist",
	}
	server := ParseAlistServerFromMap(raw)
	if !server.EnableBackgroundProbe {
		t.Fatalf("EnableBackgroundProbe should default to true when missing")
	}
}

func TestParseAlistServerFromMapRangeLearningClamp(t *testing.T) {
	raw := map[string]interface{}{
		"name":                     "alist",
		"rangeFailToDowngrade":     float64(0),
		"rangeSuccessToRecover":    float64(999),
		"rangeReprobeMinutes":      float64(-1),
		"rangeProbeTimeoutSeconds": float64(999),
	}
	server := ParseAlistServerFromMap(raw)
	if server.RangeFailToDowngrade != 2 {
		t.Fatalf("RangeFailToDowngrade=%d, want 2", server.RangeFailToDowngrade)
	}
	if server.RangeSuccessToRecover != 20 {
		t.Fatalf("RangeSuccessToRecover=%d, want 20", server.RangeSuccessToRecover)
	}
	if server.RangeReprobeMinutes != 30 {
		t.Fatalf("RangeReprobeMinutes=%d, want 30", server.RangeReprobeMinutes)
	}
	if server.RangeProbeTimeoutSeconds != 60 {
		t.Fatalf("RangeProbeTimeoutSeconds=%d, want 60", server.RangeProbeTimeoutSeconds)
	}
}
