package encrypt

import (
	"net"
	"testing"
)

func TestStartFailsSynchronouslyWhenPortIsInUse(t *testing.T) {
	occupied, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer occupied.Close()

	port := occupied.Addr().(*net.TCPAddr).Port
	cfg := DefaultConfig()
	cfg.ProxyPort = port
	cfg.ProviderCatalogEnabled = false
	cfg.ProviderCatalogTTLMinutes = 1
	cfg.ProviderCatalogBootstrapOnStart = false

	p, err := NewProxyServer(cfg)
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopCacheCleanup()
	defer p.stopRangeProbeLoop()
	defer p.stopDBExportSyncLoop()
	defer p.closeLocalStore()

	if err := p.Start(); err == nil {
		t.Fatal("expected Start to fail while configured port is occupied")
	}
	if p.IsRunning() {
		t.Fatal("server must not report running after listen failure")
	}
}
