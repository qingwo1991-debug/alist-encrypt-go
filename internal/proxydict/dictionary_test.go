package proxydict

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanOpenListDrivers(t *testing.T) {
	tmp := t.TempDir()
	driverDir := filepath.Join(tmp, "drivers", "google_drive")
	if err := os.MkdirAll(driverDir, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	metaContent := `package google_drive
var config = struct{Name string}{Name:"GoogleDrive"}
`
	// Keep the same pattern used by real OpenList meta files.
	metaContent = "package google_drive\nvar meta = struct{ Name string }{\n\tName: \"GoogleDrive\",\n}\n"
	if err := os.WriteFile(filepath.Join(driverDir, "meta.go"), []byte(metaContent), 0644); err != nil {
		t.Fatalf("write meta failed: %v", err)
	}
	driverContent := `package google_drive
const api = "https://www.googleapis.com/drive/v3/files"
const photo = "https://photoslibrary.googleapis.com/v1/mediaItems"
`
	if err := os.WriteFile(filepath.Join(driverDir, "driver.go"), []byte(driverContent), 0644); err != nil {
		t.Fatalf("write driver failed: %v", err)
	}

	dict, err := scanOpenListDrivers(tmp)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(dict.Providers) != 1 {
		t.Fatalf("providers len=%d, want 1", len(dict.Providers))
	}
	item := dict.Providers[0]
	if item.ProviderNameZH != "谷歌云盘" {
		t.Fatalf("provider zh=%q, want 谷歌云盘", item.ProviderNameZH)
	}
	if len(item.Domains) < 2 {
		t.Fatalf("domains len=%d, want >=2", len(item.Domains))
	}
}
