package encrypt

import (
	"strings"
	"testing"
)

func TestBuildRealPathCandidatesWithExternalSuffixSamples(t *testing.T) {
	ep := &EncryptPath{
		Path:      "/enc/*",
		Password:  "123456",
		EncType:   EncTypeAESCTR,
		EncName:   true,
		EncSuffix: ".mkv",
		Enable:    true,
	}
	samples := []string{
		"/enc/cGlHlVLp5VOWIUjjGMwQ5GehcmRIOMtFfhjkaCwucg0b5V+AFX--P.mkv",
		"/enc/cGlHlVLp5VOWIUjGmdw9wx3HOGiu9pw5uZHt8hl-W_20250426_070756.mkv",
		"/enc/cGlHlVLp5VOWIUjOGUt85GM+c~RIOMtF5V+AFX--5_20250427_005342.mkv",
		"/enc/cGlHlVLp5VOWIUjGmM~Zmx3ocgFu9pw5fZHt8hl-F_20250427_005434.mkv",
	}
	for _, sample := range samples {
		candidates := buildRealPathCandidates(ep, sample)
		if len(candidates) == 0 {
			t.Fatalf("expected candidates for %s", sample)
		}
		for _, candidate := range candidates {
			if !strings.HasPrefix(candidate, "/enc/") {
				t.Fatalf("expected candidate to keep parent path, got %q for %s", candidate, sample)
			}
		}
	}
}

func TestBuildRealPathCandidatesPrefersCachedRealName(t *testing.T) {
	ep := &EncryptPath{
		Path:      "/enc/*",
		Password:  "123456",
		EncType:   EncTypeAESCTR,
		EncName:   true,
		EncSuffix: ".bin",
		Enable:    true,
	}

	showPath := "/enc/MFCW-019.mp4"
	CacheNameMapping("/enc", "MFCW-019.mp4", "GUigmo3YcGdyIf03s")

	candidates := buildRealPathCandidates(ep, showPath)
	if len(candidates) < 2 {
		t.Fatalf("expected multiple candidates, got %v", candidates)
	}
	if candidates[1] != "/enc/GUigmo3YcGdyIf03s" {
		t.Fatalf("expected cached real name candidate first, got %v", candidates)
	}
}

func TestFSRemoveNotFoundParser(t *testing.T) {
	if !fsRemoveNotFound(404, []byte(`{"code":404,"message":"not found"}`)) {
		t.Fatalf("expected not found for 404")
	}
	if !fsRemoveNotFound(200, []byte(`{"code":500,"message":"Object Not Found"}`)) {
		t.Fatalf("expected not found for object-not-found message")
	}
	if fsRemoveNotFound(200, []byte(`{"code":200,"message":"ok"}`)) {
		t.Fatalf("did not expect not found for success payload")
	}
}
