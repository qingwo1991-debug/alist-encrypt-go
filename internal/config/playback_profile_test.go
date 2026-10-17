package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlaybackProfileParser(t *testing.T) {
	if got := DefaultConfig().AlistServer.PlaybackProfile; got != PlaybackProfileStandard {
		t.Fatalf("default profile = %q", got)
	}
	for _, profile := range []string{"", PlaybackProfileStandard, PlaybackProfileTrustedLocal, "unknown", "TRUSTED_LOCAL"} {
		t.Run(profile, func(t *testing.T) {
			raw := map[string]interface{}{}
			if profile != "" {
				raw["playbackProfile"] = profile
			}
			server := ParseAlistServerFromMap(raw)
			want := normalizePlaybackProfile(profile)
			if server.PlaybackProfile != want {
				t.Fatalf("parsed profile = %q, want %q", server.PlaybackProfile, want)
			}
			// Preserve unknown strings so runtime validation can reject typos.
			valid := profile == "" || profile == PlaybackProfileStandard || profile == PlaybackProfileTrustedLocal
			if err := validatePlaybackProfile(server.PlaybackProfile); (err == nil) != valid {
				t.Fatalf("validation error = %v, valid = %v", err, valid)
			}
		})
	}
}

func TestPlaybackProfileUpdateRoundTrip(t *testing.T) {
	baseDir := t.TempDir()
	cfg := LoadFromBaseDir(baseDir)
	server := cfg.AlistServerSnapshot()
	server.PlaybackProfile = PlaybackProfileTrustedLocal
	if err := cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	if got := LoadFromBaseDir(baseDir).AlistServerSnapshot().PlaybackProfile; got != PlaybackProfileTrustedLocal {
		t.Fatalf("reloaded profile = %q", got)
	}
	server.PlaybackProfile = "" // older clients do not send the new field
	if err := cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	if got := cfg.AlistServerSnapshot().PlaybackProfile; got != PlaybackProfileStandard {
		t.Fatalf("legacy update profile = %q", got)
	}
}

func TestPlaybackProfileRejectsInvalidRuntimeUpdates(t *testing.T) {
	baseDir := t.TempDir()
	cfg := LoadFromBaseDir(baseDir)
	path := filepath.Join(baseDir, "conf", "config.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"unknown", "TRUSTED_LOCAL", " trusted_local "} {
		t.Run(profile, func(t *testing.T) {
			server := cfg.AlistServerSnapshot()
			server.PlaybackProfile = profile
			if err := cfg.UpdateAlistServer(server); err == nil || !strings.Contains(err.Error(), "playbackProfile") {
				t.Fatalf("UpdateAlistServer error = %v", err)
			}
			if err := cfg.ReplaceFromJSON([]byte(`{"alistServer":{"playbackProfile":"` + profile + `"}}`)); err == nil || !strings.Contains(err.Error(), "playbackProfile") {
				t.Fatalf("ReplaceFromJSON error = %v", err)
			}
			if got := cfg.AlistServerSnapshot().PlaybackProfile; got != PlaybackProfileStandard {
				t.Fatalf("invalid update changed live profile to %q", got)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("invalid update changed persisted configuration")
			}
		})
	}
}

func TestPlaybackProfileSaveValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.configPath = filepath.Join(t.TempDir(), "config.json")
	cfg.AlistServer.PlaybackProfile = "unknown"
	if err := cfg.Save(); err == nil {
		t.Fatal("Save accepted invalid profile")
	}
	cfg.AlistServer.PlaybackProfile = ""
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"playbackProfile": "standard"`)) {
		t.Fatal("Save did not persist explicit standard default")
	}
}

func TestPlaybackProfileStartupFallsBackToStandard(t *testing.T) {
	for _, profile := range []string{"", "unknown", PlaybackProfileTrustedLocal} {
		t.Run(profile, func(t *testing.T) {
			cfg := LoadFromBaseDir(t.TempDir())
			data := []byte(`{"alistServer":{"playbackProfile":"` + profile + `"}}`)
			if err := os.WriteFile(cfg.configPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			loaded := loadConfigAt(cfg.configPath)
			want := PlaybackProfileStandard
			if profile == PlaybackProfileTrustedLocal {
				want = PlaybackProfileTrustedLocal
			}
			if got := loaded.AlistServerSnapshot().PlaybackProfile; got != want {
				t.Fatalf("startup profile = %q, want %q", got, want)
			}
		})
	}
}
