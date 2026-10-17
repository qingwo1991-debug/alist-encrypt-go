package storage

import (
	"errors"
	"github.com/alist-encrypt-go/internal/recovery"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryFencesFilenameReservation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, recovery.SidecarName), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rec := FilenameRecord{Origin: "http://example.com", EncryptedPath: "/raw/file", OriginalPath: "/plain/file", DisplayName: "file", AuthScope: strings.Repeat("a", 64), RuleFingerprint: strings.Repeat("b", 64)}
	if _, err := s.ReserveFilename(rec); !errors.Is(err, recovery.ErrRequired) {
		t.Fatalf("reservation error=%v", err)
	}
	if _, ok, err := s.GetFilenameReservation(rec.Origin, rec.EncryptedPath); err != nil || ok {
		t.Fatalf("audit mutated: %v %v", ok, err)
	}
	// Cache/admin writes are not indiscriminately blocked by the remote-write fence.
	if err := s.Set(BucketConfig, "test", []byte("ok")); err != nil {
		t.Fatal(err)
	}
}
