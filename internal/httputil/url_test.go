package httputil

import (
	"net/http"
	"testing"
)

func TestBuildTargetURL(t *testing.T) {
	base := "http://alist:5244"

	t.Run("no request", func(t *testing.T) {
		u := BuildTargetURL(base, "/d/path", nil)
		if u != "http://alist:5244/d/path" {
			t.Errorf("got %q", u)
		}
	})

	t.Run("with query", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/d/path?sign=abc&type=full", nil)
		u := BuildTargetURL(base, "/d/path", r)
		if u != "http://alist:5244/d/path?sign=abc&type=full" {
			t.Errorf("got %q", u)
		}
	})
}

func TestBuildTargetURLStripped(t *testing.T) {
	base := "http://alist:5244"

	// With query params — should be stripped
	r, _ := http.NewRequest("GET", "/d/path?sign=abc&token=xyz", nil)
	u := BuildTargetURL(base, "/d/encrypted_path", r)
	if u != "http://alist:5244/d/encrypted_path?sign=abc&token=xyz" {
		t.Errorf("BuildTargetURL with r should include query, got %q", u)
	}

	// With stripped — should NOT include query
	u2 := BuildTargetURLStripped(base, "/d/encrypted_path")
	if u2 != "http://alist:5244/d/encrypted_path" {
		t.Errorf("BuildTargetURLStripped should exclude query, got %q", u2)
	}

	// Verify BuildTargetURLWithQuery
	u3 := BuildTargetURLWithQuery(base, "/d/path", "sign=new")
	if u3 != "http://alist:5244/d/path?sign=new" {
		t.Errorf("got %q", u3)
	}

	u4 := BuildTargetURLWithQuery(base, "/d/path", "")
	if u4 != "http://alist:5244/d/path" {
		t.Errorf("got %q", u4)
	}
}

func TestBuildTargetURLStrippedSignBug(t *testing.T) {
	// Simulates the bug: original path has sign, but we changed the path
	// BuildTargetURL would forward the sign, BuildTargetURLStripped drops it
	base := "http://alist:5244"

	originalPath := "/d/%E7%A7%BB%E5%8A%A8%E4%BA%91%E7%9B%98192/encrypt/oceans.mp4"
	encryptedPath := "/d/%E7%A7%BB%E5%8A%A8%E4%BA%91%E7%9B%98192/encrypt/I6O1l9Hp5V+YO0--P.bin"

	r, _ := http.NewRequest("GET", originalPath+"?sign=valid_for_original_path", nil)

	// Old behavior (bug): sign forwarded with new path
	oldURL := BuildTargetURL(base, encryptedPath, r)
	if oldURL != base+encryptedPath+"?sign=valid_for_original_path" {
		t.Errorf("old URL should include query, got %q", oldURL)
	}

	// New behavior (fixed): sign stripped
	newURL := BuildTargetURLStripped(base, encryptedPath)
	if newURL != base+encryptedPath {
		t.Errorf("new URL should NOT include query, got %q", newURL)
	}

	// Verify the old URL would be wrong (sign doesn't match new path)
	if oldURL == newURL {
		t.Error("old and new URLs should differ")
	}
}
