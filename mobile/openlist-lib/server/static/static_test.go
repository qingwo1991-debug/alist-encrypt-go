package static

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/OpenListTeam/OpenList/v4/public"
)

// makeDistFS builds an in-memory filesystem mirroring the public/ layout so
// pickEmbeddedDist can be exercised deterministically without depending on
// whether the real OpenList frontend has been installed locally.
func makeDistFS(distIndex string, encIndex string) fstest.MapFS {
	m := fstest.MapFS{}
	if distIndex != "" {
		m["dist/index.html"] = &fstest.MapFile{Data: []byte(distIndex)}
	}
	if encIndex != "" {
		m["dist/enc/index.html"] = &fstest.MapFile{Data: []byte(encIndex)}
	}
	return m
}

func TestPickEmbeddedDistPrefersRealFrontend(t *testing.T) {
	fsys := makeDistFS(
		`<!doctype html><html><div id="root"></div></html>`,
		`<!doctype html><div id="app"></div>`,
	)
	dist, candidate, err := pickEmbeddedDist(fsys)
	if err != nil {
		t.Fatalf("pickEmbeddedDist() error = %v", err)
	}
	if candidate != "dist" {
		t.Fatalf("candidate=%q, want %q", candidate, "dist")
	}
	if _, err := fs.ReadFile(dist, "index.html"); err != nil {
		t.Fatalf("read index.html from selected dist: %v", err)
	}
}

func TestPickEmbeddedDistSkipsPlaceholderAndFallsBackToEnc(t *testing.T) {
	fsys := makeDistFS(
		encryptPlaceholderMarker, // placeholder present in dist/index.html
		`<!doctype html><div id="app"></div>`,
	)
	dist, candidate, err := pickEmbeddedDist(fsys)
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

func TestPickEmbeddedDistFallsBackWhenDistIndexMissing(t *testing.T) {
	// No dist/index.html at all — the CI checkout state before the frontend
	// is fetched. Must fall back to dist/enc.
	fsys := makeDistFS("", `<!doctype html><div id="app"></div>`)
	_, candidate, err := pickEmbeddedDist(fsys)
	if err != nil {
		t.Fatalf("pickEmbeddedDist() error = %v", err)
	}
	if candidate != "dist/enc" {
		t.Fatalf("candidate=%q, want %q", candidate, "dist/enc")
	}
}

// TestPickEmbeddedDistWithRealEmbed sanity-checks the actual embedded
// filesystem. The result depends on whether install_openlist_web.sh has been
// run: with the real frontend it picks "dist"; without it (CI checkout) it
// falls back to "dist/enc". Either is acceptable, so the test only asserts
// that a valid dist is selected.
func TestPickEmbeddedDistWithRealEmbed(t *testing.T) {
	dist, candidate, err := pickEmbeddedDist(public.Public)
	if err != nil {
		t.Fatalf("pickEmbeddedDist(public.Public) error = %v", err)
	}
	if dist == nil {
		t.Fatal("expected non-nil dist fs")
	}
	if candidate != "dist" && candidate != "dist/enc" {
		t.Fatalf("candidate=%q, want dist or dist/enc", candidate)
	}
}
