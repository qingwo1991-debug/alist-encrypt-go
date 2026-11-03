package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

// Length protection must never enable filename encryption or infer a provider
// limit. In either opt-out case it must not inspect the upstream or reserve a name.
func TestFilenameLengthProtectionRespectsConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		encName bool
		limits  map[string]int
		target  string
	}{
		{"filename encryption disabled", false, map[string]int{"/limited": 100}, "/limited/file.mp4"},
		{"no configured limit", true, nil, "/limited/file.mp4"},
		{"different directory", true, map[string]int{"/limited": 100}, "/other/file.mp4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AlistServer.FilenameWriteLimits = tc.limits
			info := &config.PasswdInfo{Enable: true, EncName: tc.encName, EncType: "chacha20", Password: "synthetic", EncSuffix: ".private"}
			req := httptest.NewRequest("PUT", "/api/fs/put", nil)
			legacy := "/unchanged/legacy-name.private"
			claim, raw, err := prepareFilenameWrite(cfg, nil, req, info, tc.target, legacy, 5, false, nil)
			if err != nil || claim != nil || raw != legacy {
				t.Fatalf("configuration overridden: claim=%v raw=%q err=%v", claim, raw, err)
			}
		})
	}
}

func TestFilenameLengthLimitUsesMostSpecificConfiguredDirectory(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100, "/limited/child": 64}
	for _, tc := range []struct {
		p    string
		want int
	}{{"/limited/file", 100}, {"/limited/child/file", 64}, {"/limited-other/file", 0}, {"/other/file", 0}} {
		if got := protectedFilenameLimit(cfg, tc.p); got != tc.want {
			t.Errorf("%s limit=%d want=%d", tc.p, got, tc.want)
		}
	}
}
