package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePasswordFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	return path
}

func TestLoadPasswordFromFileRemovesOneLF(t *testing.T) {
	f := &flags{passwordFile: writePasswordFile(t, "secret\n")}
	if err := loadPassword(f); err != nil {
		t.Fatalf("loadPassword: %v", err)
	}
	if f.password != "secret" {
		t.Fatalf("password=%q, want %q", f.password, "secret")
	}
}

func TestLoadPasswordFromFileRemovesOneCRLF(t *testing.T) {
	f := &flags{passwordFile: writePasswordFile(t, "secret\r\n")}
	if err := loadPassword(f); err != nil {
		t.Fatalf("loadPassword: %v", err)
	}
	if f.password != "secret" {
		t.Fatalf("password=%q, want %q", f.password, "secret")
	}
}

func TestLoadPasswordFromFilePreservesSpacesAndExtraNewline(t *testing.T) {
	f := &flags{passwordFile: writePasswordFile(t, "  secret  \n\n")}
	if err := loadPassword(f); err != nil {
		t.Fatalf("loadPassword: %v", err)
	}
	if f.password != "  secret  \n" {
		t.Fatalf("password=%q, want spaces and only one newline removed", f.password)
	}
}

func TestLoadPasswordRejectsConflictingSources(t *testing.T) {
	f := &flags{password: "inline", passwordFile: writePasswordFile(t, "file-secret")}
	if err := loadPassword(f); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("loadPassword error=%v, want mutually exclusive error", err)
	}
}

func TestLoadPasswordRejectsMissingSource(t *testing.T) {
	if err := loadPassword(&flags{}); err == nil {
		t.Fatal("loadPassword accepted missing password source")
	}
}

func TestLoadPasswordRejectsEmptyFile(t *testing.T) {
	f := &flags{passwordFile: writePasswordFile(t, "\n")}
	if err := loadPassword(f); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("loadPassword error=%v, want empty-file error", err)
	}
}

func TestLoadPasswordRejectsNUL(t *testing.T) {
	f := &flags{passwordFile: writePasswordFile(t, "secret\x00value")}
	if err := loadPassword(f); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("loadPassword error=%v, want NUL-byte error", err)
	}
}
