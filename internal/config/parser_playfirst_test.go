package config

import "testing"

func TestParseAlistServerFromMapPlayFirstFallbackDefault(t *testing.T) {
	raw := map[string]interface{}{
		"name": "alist",
	}

	server := ParseAlistServerFromMap(raw)
	if !server.PlayFirstFallback {
		t.Fatalf("PlayFirstFallback should default to true when missing")
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
