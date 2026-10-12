package encrypt

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	internalnet "github.com/OpenListTeam/OpenList/v4/internal/net"
)

func TestDriverRouteTrustedIdentityOverridesPolicyHints(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted headers overrode storage identity")
		w.WriteHeader(500)
	}))
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Encrypt-Provider") != "spoof" {
			t.Error("trusted provider was injected into wire headers")
		}
		io.WriteString(w, "proxy")
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	cfg := DefaultConfig()
	cfg.EnableLocalBypass = false
	cfg.AlistHost = "control.example"
	pool := newRouteTransportPool(cfg, &http.Transport{}, &http.Transport{})
	defer pool.RetireRouteTransports()
	pool.resolver = func(r *http.Request) (*url.URL, error) {
		identity, ok := internalnet.DriverRouteIdentityFromContext(r.Context())
		if !ok || identity.Driver != "Mega" || r.Header.Get("X-Encrypt-Provider") != "mega" || r.Header.Get("X-Encrypt-Driver") != "Mega" {
			t.Errorf("policy request not trusted: %+v %v %v", identity, ok, r.Header)
		}
		return proxyURL, nil
	}
	client := http.Client{Transport: &driverRouteRoundTripper{identity: internalnet.DriverRouteIdentity{Driver: "Mega", Provider: "mega"}, pool: pool}}
	req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
	req.Header.Set("X-Encrypt-Provider", "spoof")
	req.Header.Set("X-Encrypt-Driver", "spoof")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(data) != "proxy" {
		t.Fatalf("data=%q error=%v", data, err)
	}
	if req.Header.Get("X-Encrypt-Provider") != "spoof" {
		t.Fatal("request mutated")
	}
}

func TestDriverRouteFactorySnapshotsConfigAndReleases(t *testing.T) {
	defer UninstallDriverRouteFactory()
	cfg := DefaultConfig()
	InstallDriverRouteFactory(cfg)
	client, release := internalnet.NewDriverHTTPClient(internalnet.DriverRouteIdentity{Driver: "Mega", Provider: "mega"}, 0)
	rt, ok := client.Transport.(*driverRouteRoundTripper)
	if !ok {
		t.Fatalf("transport=%T", client.Transport)
	}
	if rt.pool.limit != 32 || client.Timeout != 0 {
		t.Fatal("wrong session admission/timeout")
	}
	cfg.AlistHost = "changed.example"
	if rt.pool.config.AlistHost == cfg.AlistHost {
		t.Fatal("mutable configuration captured")
	}
	release()
	release()
	rt.pool.mu.Lock()
	closed := rt.pool.closed
	rt.pool.mu.Unlock()
	if !closed {
		t.Fatal("release didn't retire driver pool")
	}
}
