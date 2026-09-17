package encrypt

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConfigSaveFailurePreservesMemory(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*ConfigManager) error
	}{
		{"listen", func(m *ConfigManager) error { return m.SetProxyListenLocalOnly(true) }},
		{"h2c", func(m *ConfigManager) error { return m.SetEnableH2C(true) }},
		{"advanced", func(m *ConfigManager) error {
			return m.SetAdvancedConfigFromJSON(`{"proxyListenLocalOnly":true,"streamBufferKb":256}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A directory cannot be replaced by the atomic configuration file rename,
			// even when tests run as root. No permissions-dependent failure injection.
			configPath := filepath.Join(t.TempDir(), "config-directory")
			if err := os.Mkdir(configPath, 0700); err != nil {
				t.Fatal(err)
			}
			m := NewConfigManager(configPath)
			before := m.GetConfig()
			if err := tc.set(m); err == nil {
				t.Fatal("expected persistence failure")
			}
			if !reflect.DeepEqual(before, m.GetConfig()) {
				t.Fatal("failed save must preserve previous in-memory configuration")
			}
		})
	}
}
