package config

import (
	"encoding/json"
	"testing"
)

func TestFilenameWriteLimitsExplicitAndCloned(t *testing.T) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(`{"filenameWriteLimits":{"/156联通云盘/encrypt":100}}`), &raw); err != nil {
		t.Fatal(err)
	}
	parsed := ParseAlistServerFromMap(raw)
	if parsed.FilenameWriteLimits["/156联通云盘/encrypt"] != 100 {
		t.Fatalf("limits=%v", parsed.FilenameWriteLimits)
	}
	cfg := &Config{AlistServer: parsed}
	snapshot := cfg.AlistServerSnapshot()
	snapshot.FilenameWriteLimits["/156联通云盘/encrypt"] = 50
	if cfg.AlistServerSnapshot().FilenameWriteLimits["/156联通云盘/encrypt"] != 100 {
		t.Fatal("snapshot aliased mutable map")
	}
	cfg.mu.RLock()
	saved := cfg.snapshotLocked()
	cfg.mu.RUnlock()
	saved.AlistServer.FilenameWriteLimits["/156联通云盘/encrypt"] = 60
	if cfg.AlistServerSnapshot().FilenameWriteLimits["/156联通云盘/encrypt"] != 100 {
		t.Fatal("save snapshot aliased mutable map")
	}
	if ParseAlistServerFromMap(map[string]interface{}{}).FilenameWriteLimits != nil {
		t.Fatal("must remain opt-in")
	}
}

func TestFilenameWriteLimitsValidation(t *testing.T) {
	for _, prefix := range []string{"/", "relative", "/mount/", "/mount/../other", "/mount/*", "/mount?", "/mount\\other"} {
		if validateFilenameWriteLimits(map[string]int{prefix: 100}) == nil {
			t.Errorf("accepted unsafe prefix %q", prefix)
		}
	}
	for _, limit := range []int{0, 31, 256} {
		if validateFilenameWriteLimits(map[string]int{"/mount": limit}) == nil {
			t.Errorf("accepted limit %d", limit)
		}
	}
	if err := validateFilenameWriteLimits(map[string]int{"/156联通云盘/encrypt": 100}); err != nil {
		t.Fatal(err)
	}
}
