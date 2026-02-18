package handler

import "testing"

func TestNormalizeDecryptedListItem(t *testing.T) {
	t.Run("video extension rewrites path and type", func(t *testing.T) {
		item := map[string]interface{}{
			"path": "/enc/abc123.bin",
			"type": float64(0),
		}
		normalizeDecryptedListItem(item, "ocewwe ewrw+ 测试のans.mp4")

		if got, _ := item["path"].(string); got != "/enc/ocewwe ewrw+ 测试のans.mp4" {
			t.Fatalf("path mismatch: got %q", got)
		}
		if got, _ := item["type"].(float64); got != 2 {
			t.Fatalf("type mismatch: got %v want 2", got)
		}
	})

	t.Run("unknown extension keeps original type", func(t *testing.T) {
		item := map[string]interface{}{
			"path": "/enc/abc123.bin",
			"type": float64(0),
		}
		normalizeDecryptedListItem(item, "readme.xyz")

		if got, _ := item["path"].(string); got != "/enc/readme.xyz" {
			t.Fatalf("path mismatch: got %q", got)
		}
		if got, _ := item["type"].(float64); got != 0 {
			t.Fatalf("type should stay unchanged: got %v want 0", got)
		}
	})
}

