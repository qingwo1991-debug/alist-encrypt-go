package static

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/public"
)

func TestPickEmbeddedDistFallsBackFromPlaceholderToEncryptDist(t *testing.T) {
	dist, candidate, err := pickEmbeddedDist(public.Public)
	if err != nil {
		t.Fatalf("pickEmbeddedDist() error = %v", err)
	}
	if candidate != "dist/enc" {
		t.Fatalf("candidate=%q, want %q", candidate, "dist/enc")
	}

	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	body := string(index)
	if strings.Contains(body, encryptPlaceholderMarker) {
		t.Fatalf("selected dist still contains placeholder marker")
	}
	if !strings.Contains(body, `id="app"`) {
		t.Fatalf("selected dist does not look like the SPA entry")
	}
}
