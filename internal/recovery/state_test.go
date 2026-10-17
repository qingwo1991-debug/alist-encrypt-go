package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		fenced     bool
		stage      string
	}{
		{"absent", "", false, "normal"},
		{"prepared", `{"version":1,"stage":"prepared","operation_id":"op-1","generation":1,"bundle_sha256":"` + strings.Repeat("ab", 32) + `"}`, true, "prepared"},
		{"unknown", `{"version":2}`, true, "invalid"},
		{"corrupt", `{`, true, "invalid"},
		{"empty", " ", true, "invalid"},
		{"approved", `{"version":1,"stage":"reconciled"}`, true, "invalid"},
		{"oversize", strings.Repeat("x", 4097), true, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.body != "" {
				if err := os.WriteFile(filepath.Join(dir, SidecarName), []byte(tc.body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			s := Load(dir)
			if s.Required() != tc.fenced || s.Status().Stage != tc.stage {
				t.Fatalf("%+v", s.Status())
			}
		})
	}
}
func TestLoadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(dir, SidecarName)); err != nil {
		t.Skip(err)
	}
	if !Load(dir).Required() {
		t.Fatal("symlink allowed")
	}
}
