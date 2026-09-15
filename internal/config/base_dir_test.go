package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBaseDirFromExecutable(t *testing.T) {
	// No conf/config.json next to the exe → not a portable bundle.
	if got := baseDirFromExecutable(t.TempDir()); got != "" {
		t.Fatalf("baseDirFromExecutable(empty) = %q, want empty", got)
	}

	// Portable layout: exe dir contains conf/config.json → base is exe dir.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "conf"), 0755); err != nil {
		t.Fatal(err)
	}
	exePath := filepath.Join(root, "alist-encrypt-go")
	if err := os.WriteFile(filepath.Join(root, "conf", "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := baseDirFromExecutable(exePath); got != root {
		t.Fatalf("baseDirFromExecutable = %q, want %q", got, root)
	}

	// conf/config.json present but a directory, not file → not portable.
	dirRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirRoot, "conf", "config.json"), 0755); err != nil {
		t.Fatal(err)
	}
	if got := baseDirFromExecutable(filepath.Join(dirRoot, "tool")); got != "" {
		t.Fatalf("baseDirFromExecutable(config-as-dir) = %q, want empty", got)
	}
}

func TestResolveBaseDirEnvOverride(t *testing.T) {
	env := filepath.Join(t.TempDir(), "custom-root")
	t.Setenv("ALIST_ENCRYPT_BASE_DIR", env)
	if got := resolveBaseDir(); got != env {
		t.Fatalf("resolveBaseDir = %q, want env override %q", got, env)
	}
	// env takes priority over a portable layout next to the executable.
	t.Setenv("ALIST_ENCRYPT_BASE_DIR", "")
	if got := resolveBaseDir(); got == "" {
		t.Fatal("resolveBaseDir returned empty")
	}
}
