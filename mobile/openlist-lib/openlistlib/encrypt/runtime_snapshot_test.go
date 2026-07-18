package encrypt

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
)

func TestShowNameCacheConcurrentAccessAndClear(t *testing.T) {
	ClearShowNameCache()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				name := fmt.Sprintf("show-%d-%d", worker, i)
				CacheNameMapping("/media", name, "encrypted-"+name)
				_, _ = GetCachedRealName("/media", name)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			ClearShowNameCache()
		}
	}()
	wg.Wait()

	CacheNameMapping("/media", "final", "encrypted-final")
	if got, ok := GetCachedRealName("/media", "final"); !ok || got != "encrypted-final" {
		t.Fatalf("cache unusable after concurrent clear: got=%q ok=%v", got, ok)
	}
}

func TestUpdateConfigConcurrentRuntimeSnapshots(t *testing.T) {
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	streamTransport := baseTransport.Clone()
	p := &ProxyServer{
		config:          DefaultConfig(),
		transport:       baseTransport,
		streamTransport: streamTransport,
		httpClient:      &http.Client{Transport: baseTransport},
		probeClient:     &http.Client{Transport: baseTransport},
		streamClient:    &http.Client{Transport: streamTransport},
	}

	const iterations = 100
	var readers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < iterations; i++ {
				runtime := p.runtimeSnapshot()
				if runtime.config == nil || runtime.httpClient == nil || runtime.probeClient == nil || runtime.streamClient == nil {
					t.Errorf("incomplete runtime snapshot: %+v", runtime)
					return
				}
				_ = runtime.config.AlistHost
				_ = runtime.httpClient.Timeout
				_ = runtime.probeClient.Timeout
			}
		}()
	}

	for i := 0; i < iterations; i++ {
		cfg := DefaultConfig()
		cfg.AlistHost = fmt.Sprintf("127.0.0.%d", i%250+1)
		cfg.UpstreamTimeoutSeconds = i%30 + 5
		cfg.ProbeTimeoutSeconds = i%10 + 1
		p.UpdateConfig(cfg)
		// The server must own a detached copy after UpdateConfig returns.
		cfg.AlistHost = "caller-mutated"
	}
	readers.Wait()
}
