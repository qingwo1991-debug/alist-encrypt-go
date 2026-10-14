package encrypt

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	internalnet "github.com/OpenListTeam/OpenList/v4/internal/net"
)

// InstallDriverRouteFactory registers policy for newly initialized storage
// sessions. Each session owns a bounded pool; reconfiguration does not mutate
// existing sessions. Native topology is still captured separately per request.
func InstallDriverRouteFactory(cfg *ProxyConfig) {
	_ = internalnet.SetDriverTransportFactory(driverRouteFactory(cfg))
}

// PublishDriverRouteFactory requires the embedded generation capability.
func PublishDriverRouteFactory(owner *internalnet.EmbeddedLease, cfg *ProxyConfig) error {
	return owner.Publish(driverRouteFactory(cfg))
}
func driverRouteFactory(cfg *ProxyConfig) func(internalnet.DriverRouteIdentity) (http.RoundTripper, func()) {
	snapshot := cloneProxyConfig(cfg)
	if snapshot == nil {
		snapshot = DefaultConfig()
	}
	// Preserve the legacy backend TLS setting, captured once with this factory
	// rather than rereading mutable configuration during individual requests.
	insecureTLS := conf.Conf != nil && conf.Conf.TlsInsecureSkipVerify
	return func(identity internalnet.DriverRouteIdentity) (http.RoundTripper, func()) {
		control := http.DefaultTransport.(*http.Transport).Clone()
		control.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureTLS}
		control.ResponseHeaderTimeout = 60 * time.Second
		pool := newRouteTransportPool(snapshot, control, control.Clone())
		return &driverRouteRoundTripper{identity: identity, pool: pool}, pool.RetireRouteTransports
	}
}

// UninstallDriverRouteFactory stops registration without retiring existing
// sessions: their owner must release them on driver Drop.
func UninstallDriverRouteFactory() { internalnet.SetDriverTransportFactory(nil) }

type driverRouteRoundTripper struct {
	identity internalnet.DriverRouteIdentity
	pool     *routeTransportPool
}

func (r *driverRouteRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	request := req.WithContext(internalnet.WithDriverRouteIdentity(req.Context(), r.identity))
	return r.pool.roundTrip(request, "driver-control")
}
