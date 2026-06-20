package config

import "testing"

func TestParseAlistServerFromMapPlayFirstFallbackDefault(t *testing.T) {
	raw := map[string]interface{}{
		"name": "alist",
	}

	server := ParseAlistServerFromMap(raw)
	if server.PlayFirstFallback {
		t.Fatalf("PlayFirstFallback should default to false when missing")
	}
}

func TestParseAlistServerFromMapPlayFirstFallbackExplicitFalse(t *testing.T) {
	raw := map[string]interface{}{
		"name":              "alist",
		"playFirstFallback": false,
	}

	server := ParseAlistServerFromMap(raw)
	if server.PlayFirstFallback {
		t.Fatalf("PlayFirstFallback should respect explicit false")
	}
}

func TestParseAlistServerFromMapStreamLimitDefaults(t *testing.T) {
	server := ParseAlistServerFromMap(map[string]interface{}{"name": "alist"})
	if server.MaxActiveStreams != 32 {
		t.Fatalf("MaxActiveStreams=%d, want 32", server.MaxActiveStreams)
	}
	if server.StreamOverloadStatus != 429 {
		t.Fatalf("StreamOverloadStatus=%d, want 429", server.StreamOverloadStatus)
	}
}

func TestParseAlistServerFromMapStreamLimitClampsInvalidStatus(t *testing.T) {
	server := ParseAlistServerFromMap(map[string]interface{}{
		"name":                 "alist",
		"maxActiveStreams":     float64(2048),
		"streamOverloadStatus": float64(500),
	})
	if server.MaxActiveStreams != 1024 {
		t.Fatalf("MaxActiveStreams=%d, want 1024", server.MaxActiveStreams)
	}
	if server.StreamOverloadStatus != 429 {
		t.Fatalf("StreamOverloadStatus=%d, want 429", server.StreamOverloadStatus)
	}
}
