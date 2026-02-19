package config

import (
	"encoding/json"
	"testing"
)

func TestMigrateLegacyRangeCompatTTL(t *testing.T) {
	input := []byte(`{"alistServer":{"rangeCompatTtlMinutes":45,"enableRangeCompatCache":true}}`)
	changed, out := migrateLegacyRangeCompatTTL(input)
	if !changed {
		t.Fatalf("expected migration changed=true")
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("unmarshal migrated output: %v", err)
	}
	alist, ok := raw["alistServer"].(map[string]interface{})
	if !ok {
		t.Fatalf("alistServer missing")
	}
	if _, exists := alist["rangeCompatTtlMinutes"]; exists {
		t.Fatalf("legacy key should be removed")
	}
	if got := int(alist["rangeReprobeMinutes"].(float64)); got != 45 {
		t.Fatalf("rangeReprobeMinutes=%d, want 45", got)
	}
}

func TestMigrateLegacyRangeCompatTTLNoopWhenNewExists(t *testing.T) {
	input := []byte(`{"alistServer":{"rangeCompatTtlMinutes":45,"rangeReprobeMinutes":30}}`)
	changed, out := migrateLegacyRangeCompatTTL(input)
	if !changed {
		t.Fatalf("expected migration changed=true for old-key cleanup")
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("unmarshal migrated output: %v", err)
	}
	alist := raw["alistServer"].(map[string]interface{})
	if got := int(alist["rangeReprobeMinutes"].(float64)); got != 30 {
		t.Fatalf("rangeReprobeMinutes=%d, want 30", got)
	}
}
