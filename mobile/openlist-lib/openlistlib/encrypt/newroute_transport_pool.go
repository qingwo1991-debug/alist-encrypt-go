package encrypt

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	opnet "github.com/OpenListTeam/OpenList/v4/internal/net"
	"golang.org/x/net/http2"
)

var ErrRoutePoolBusy = errors.New("network route transport pool busy")

type routeTransportKey struct {
	ProxyRef         [32]byte
	Token            string
	Generation       int64
	BridgeEpoch      uint64
	TLSProfile       string
	LegacyMark       uint32
	LegacyGeneration uint64
	H2C              bool
}

type providerRouteDecision struct {
	proxy    *url.URL
	token    string
	snapshot NativeRouteSnapshot
}

// EvaluateProviderPolicy resolves policy before DNS. HTTP proxy bypass and
// native physical selection are independent: dual-network is explicit opt-in.
// Neither provider nor driver is inferred from an origin hostname.
func EvaluateProviderPolicy(cfg *ProxyConfig, req *http.Request, snapshot NativeRouteSnapshot, resolver func(*http.Request) (*url.URL, error)) (providerRouteDecision, error) {
	d := providerRouteDecision{snapshot: snapshot, token: snapshot.DefaultToken}
	policyReq := req
	if req != nil {
		if identity, trusted := opnet.DriverRouteIdentityFromContext(req.Context()); trusted {
			// Only policy evaluation sees these detached headers. The actual
			// provider request retains its original headers without identity leaks.
			policyReq = req.Clone(req.Context())
			policyReq.Header.Set("X-Encrypt-Driver", identity.Driver)
			policyReq.Header.Set("X-Encrypt-Provider", identity.Provider)
		}
	}
	proxy, err := resolver(policyReq)
	if err != nil {
		return d, err
	}
	d.proxy = proxy
	if cfg == nil || req == nil || req.URL == nil {
		return d, nil
	}
	host := req.URL.Hostname()
	if isControlPlaneHost(cfg, host) || (cfg.EnableLocalBypass && isLocalOrPrivateHost(host)) {
		// Local/control calls bypass HTTP proxy, not the VPN. Native default tokens
		// preserve the captured default Network when supported.
		d.proxy = nil
		return d, nil
	}
	action := ""
	if normalizeRoutingMode(cfg.RoutingMode) != routingModeOff {
		action, _ = matchRoutingRules(cfg, policyReq.Header.Get("X-Encrypt-Provider"), policyReq.Header.Get("X-Encrypt-Driver"))
		if action == "" {
			action, _ = matchBuiltinRouting(policyReq.Header.Get("X-Encrypt-Provider"), policyReq.Header.Get("X-Encrypt-Driver"))
		}
		if action == "" {
			action = normalizeRoutingUnmatchedDefault(cfg.RoutingUnmatchedDefault)
		}
	}
	if cfg.EnableDualNetwork && action == routingActionDirect && snapshot.Bridge != nil {
		if snapshot.PhysicalToken == "" {
			return d, ErrNativeRouteUnavailable
		}
		d.token = snapshot.PhysicalToken
	}
	return d, nil
}

type routeTransportEntry struct {
	transport *http.Transport
	h2c       *http2.Transport
	active    int
	touched   uint64
	retired   bool
}

type routeTransportPool struct {
	mu              sync.Mutex
	entries         map[routeTransportKey]*routeTransportEntry
	clock           uint64
	generation      int64
	bridgeEpoch     uint64
	closed          bool
	config          *ProxyConfig
	resolver        func(*http.Request) (*url.URL, error)
	control, stream *http.Transport
	limit           int
	h2cSupported    bool
}

func newRouteTransportPool(cfg *ProxyConfig, control, stream *http.Transport, h2cSupported ...bool) *routeTransportPool {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if control == nil {
		control = http.DefaultTransport.(*http.Transport).Clone()
	}
	if stream == nil {
		stream = control.Clone()
	}
	// Disable the legacy host->mark side channel in request evaluation. Native
	// transport closures capture their complete route, including DNS and proxy.
	policy := cloneProxyConfig(cfg)
	if policy != nil {
		policy.EnableDualNetwork = false
	}
	return &routeTransportPool{entries: make(map[routeTransportKey]*routeTransportEntry), config: cloneProxyConfig(cfg), resolver: newProxyResolverWithProbe(policy, nil), control: control, stream: stream, limit: 32, h2cSupported: len(h2cSupported) > 0 && h2cSupported[0] && cfg.EnableH2C}
}

type routePoolRoundTripper struct {
	pool    *routeTransportPool
	profile string
}

func (r *routePoolRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.pool.roundTrip(req, r.profile)
}

func (p *routeTransportPool) roundTrip(req *http.Request, profile string) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	snapshot := SnapshotNativeRoutes()
	decision, err := EvaluateProviderPolicy(p.config, req, snapshot, p.resolver)
	if err != nil {
		return nil, err
	}
	key := routeTransportKey{Token: decision.token, Generation: snapshot.Generation, BridgeEpoch: snapshot.BridgeEpoch, TLSProfile: profile, H2C: p.useH2C(req, profile, decision)}
	if decision.proxy != nil {
		key.ProxyRef = sha256.Sum256([]byte(decision.proxy.String()))
	}
	if snapshot.Bridge == nil && p.config.EnableDualNetwork {
		path := globalDualNetworkLatency.chooseNetwork(providerKeyFromRequest(req), p.config.DualNetworkPreference)
		globalDualNetwork.mu.RLock()
		if globalDualNetwork.enabled {
			if !globalDualNetwork.failedMarks[path.mark] && (path.mark == globalDualNetwork.wifi || path.mark == globalDualNetwork.cell) {
				key.LegacyMark = path.mark
			}
		}
		key.LegacyGeneration = globalDualNetwork.generation
		globalDualNetwork.mu.RUnlock()
	}
	var closeIdle []*routeTransportEntry
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrRoutePoolBusy
	}
	// A request which captured an older snapshot may still start safely, but
	// must not retire newer-generation pools when it reaches this lock late.
	if snapshot.BridgeEpoch > p.bridgeEpoch {
		p.bridgeEpoch = snapshot.BridgeEpoch
		p.generation = snapshot.Generation
	} else if snapshot.BridgeEpoch == p.bridgeEpoch && snapshot.Generation > p.generation {
		p.generation = snapshot.Generation
	}
	// Old generations drain naturally; no live response is interrupted.
	for k, e := range p.entries {
		if k.BridgeEpoch < p.bridgeEpoch || k.BridgeEpoch == p.bridgeEpoch && k.Generation < p.generation {
			e.retired = true
			if e.active == 0 {
				delete(p.entries, k)
				closeIdle = append(closeIdle, e)
			}
		}
	}
	e := p.entries[key]
	if e == nil {
		if len(p.entries) >= p.limit {
			var oldestKey routeTransportKey
			var oldest *routeTransportEntry
			for k, candidate := range p.entries {
				if candidate.active == 0 && (oldest == nil || candidate.touched < oldest.touched) {
					oldestKey, oldest = k, candidate
				}
			}
			if oldest != nil {
				delete(p.entries, oldestKey)
				closeIdle = append(closeIdle, oldest)
			}
		}
		if len(p.entries) >= p.limit {
			p.mu.Unlock()
			for _, t := range closeIdle {
				t.closeIdleConnections()
			}
			return nil, ErrRoutePoolBusy
		}
		template := p.control
		if profile == "media" {
			template = p.stream
		}
		transport := template.Clone()
		// ConfigureTransport's TLSNextProto closures own an HTTP/2 connection
		// pool. Do not copy those closures across distinct native decisions.
		transport.TLSNextProto = nil
		transport.ForceAttemptHTTP2 = true
		fixedProxy := decision.proxy
		transport.Proxy = func(*http.Request) (*url.URL, error) { return fixedProxy, nil }
		dialer := net.Dialer{Timeout: time.Duration(clampSeconds(p.config.UpstreamTimeoutSeconds, 60, 5, 600)) * time.Second, KeepAlive: 60 * time.Second}
		if snapshot.Bridge != nil {
			// Do not pre-resolve using net.DefaultResolver: native Dialer performs
			// same-network DNS and preserves HTTP hostname/TLS SNI.
			transport.DialContext = snapshot.DialerPreferIPv4(dialer, decision.token, true)
		} else {
			// Legacy explicitly configured fwmarks remain a separate compatibility
			// facility, never interpreted as Android Network handles.
			legacyDial := dialer.DialContext
			if key.LegacyMark != 0 {
				legacyDial = dualNetworkDialContext(&dialer, networkPath{mark: key.LegacyMark})
			}
			transport.DialContext = preferIPv4DialContext(legacyDial)
		}
		e = &routeTransportEntry{transport: transport, retired: snapshot.BridgeEpoch < p.bridgeEpoch || snapshot.BridgeEpoch == p.bridgeEpoch && snapshot.Generation < p.generation}
		if key.H2C {
			// A fresh HTTP/2 connection pool per immutable route. Never reuse the
			// startup probe transport or ConfigureTransport closures across routes.
			routeDial := transport.DialContext
			e.h2c = &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
				return routeDial(ctx, network, address)
			}}
		}
		p.entries[key] = e
	}
	p.clock++
	e.touched = p.clock
	e.active++
	p.mu.Unlock()
	for _, t := range closeIdle {
		t.closeIdleConnections()
	}
	resp, err := e.roundTrip(req)
	if err != nil {
		p.release(key, e)
		return nil, err
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		p.release(key, e)
	} else {
		resp.Body = &routeResponseBody{ReadCloser: resp.Body, release: func() { p.release(key, e) }}
	}
	return resp, nil
}

func (p *routeTransportPool) release(key routeTransportKey, e *routeTransportEntry) {
	p.mu.Lock()
	e.active--
	closeNow := e.active == 0 && (e.retired || p.closed)
	if closeNow && p.entries[key] == e {
		delete(p.entries, key)
	}
	p.mu.Unlock()
	if closeNow {
		e.closeIdleConnections()
	}
}

// RetireRouteTransports prevents new admissions and retires idle connections;
// body leases retain active transports until EOF/Close, without killing media.
func (p *routeTransportPool) RetireRouteTransports() {
	if p == nil {
		return
	}
	var idle []*routeTransportEntry
	p.mu.Lock()
	p.closed = true
	for k, e := range p.entries {
		e.retired = true
		if e.active == 0 {
			delete(p.entries, k)
			idle = append(idle, e)
		}
	}
	p.mu.Unlock()
	for _, t := range idle {
		t.closeIdleConnections()
	}
}

// H2C is restricted to the successfully probed backend and bounded control
// requests. Media keeps its existing response-header timeout transport.
func (p *routeTransportPool) useH2C(req *http.Request, profile string, decision providerRouteDecision) bool {
	if !p.h2cSupported || decision.proxy != nil || profile == "media" || req.URL.Scheme != "http" {
		return false
	}
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	return strings.EqualFold(req.URL.Hostname(), strings.Trim(p.config.AlistHost, "[]")) && port == strconv.Itoa(p.config.AlistPort)
}

func (e *routeTransportEntry) closeIdleConnections() {
	e.transport.CloseIdleConnections()
	if e.h2c != nil {
		e.h2c.CloseIdleConnections()
	}
}

func (e *routeTransportEntry) roundTrip(req *http.Request) (*http.Response, error) {
	if e.h2c == nil {
		return e.transport.RoundTrip(req)
	}
	resp, err := e.h2c.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	// Never replay POST or a streaming body after an ambiguous HTTP/2 error.
	// Only a bodyless GET/HEAD with no received response may use HTTP/1 fallback.
	if resp != nil || req.Context().Err() != nil || (req.Method != http.MethodGet && req.Method != http.MethodHead) || (req.Body != nil && req.Body != http.NoBody) {
		return resp, err
	}
	return e.transport.RoundTrip(req)
}

type routeResponseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *routeResponseBody) Read(buf []byte) (int, error) {
	n, err := b.ReadCloser.Read(buf)
	if err == io.EOF {
		b.once.Do(b.release)
	}
	return n, err
}
func (b *routeResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

var _ http.RoundTripper = (*routePoolRoundTripper)(nil)
