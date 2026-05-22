package encrypt

import "testing"

func TestUpdateEncryptPath_EmptyPasswordKeepsOriginal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EncryptPaths = []*EncryptPath{
		{
			Path:      "/media/*",
			Password:  "old-pass",
			EncType:   EncTypeAESCTR,
			EncName:   true,
			EncSuffix: ".bin",
			Enable:    true,
		},
	}
	manager := &ConfigManager{
		configPath: t.TempDir() + "/encrypt.json",
		config:     cfg,
	}

	err := manager.UpdateEncryptPath(0, "/media/*", "", EncTypeAESCTR, true, ".bin", true)
	if err != nil {
		t.Fatalf("UpdateEncryptPath failed: %v", err)
	}
	got := manager.config.EncryptPaths[0].Password
	if got != "old-pass" {
		t.Fatalf("password mismatch: got=%q want=%q", got, "old-pass")
	}
}

func TestUpdateConfig_RegexMatchesSubPathLikeNewProxyServer(t *testing.T) {
	cfg := &ProxyConfig{
		AlistHost: "127.0.0.1",
		AlistPort: 5244,
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/video",
				Password: "123456",
				EncType:  EncTypeAESCTR,
				EncName:  true,
				Enable:   true,
			},
		},
	}
	p, err := NewProxyServer(cfg)
	if err != nil {
		t.Fatalf("NewProxyServer failed: %v", err)
	}
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	if ep := p.findEncryptPath("/video/movie.mp4"); ep == nil {
		t.Fatalf("expected initial config to match sub-path")
	}

	update := &ProxyConfig{
		AlistHost: "127.0.0.1",
		AlistPort: 5244,
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/video",
				Password: "123456",
				EncType:  EncTypeAESCTR,
				EncName:  true,
				Enable:   true,
			},
		},
	}
	p.UpdateConfig(update)

	if ep := p.findEncryptPath("/video/movie.mp4"); ep == nil {
		t.Fatalf("expected updated config to match sub-path")
	}
}
