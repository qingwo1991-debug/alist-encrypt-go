package net

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// DriverRouteIdentity is trusted storage-driver metadata, not a request header.
type DriverRouteIdentity struct{ Driver, Provider string }
type driverRouteIdentityKey struct{}

func WithDriverRouteIdentity(ctx context.Context, identity DriverRouteIdentity) context.Context {
	return context.WithValue(ctx, driverRouteIdentityKey{}, identity)
}
func DriverRouteIdentityFromContext(ctx context.Context) (DriverRouteIdentity, bool) {
	identity, ok := ctx.Value(driverRouteIdentityKey{}).(DriverRouteIdentity)
	return identity, ok && identity.Driver != ""
}

var driverFactoryMu sync.RWMutex
var driverFactory func(DriverRouteIdentity) (http.RoundTripper, func())

// SetDriverTransportFactory affects new clients only. Existing storage sessions
// retain their captured configuration until Drop/reinitialization.
func SetDriverTransportFactory(factory func(DriverRouteIdentity) (http.RoundTripper, func())) {
	driverFactoryMu.Lock()
	driverFactory = factory
	driverFactoryMu.Unlock()
}

// NewDriverHTTPClient returns an independent storage-session client. Release is
// idempotent and retires idle transports, never canceling an active body.
func NewDriverHTTPClient(identity DriverRouteIdentity, timeout time.Duration) (*http.Client, func()) {
	driverFactoryMu.RLock()
	factory := driverFactory
	driverFactoryMu.RUnlock()
	if factory != nil && identity.Driver != "" {
		transport, release := factory(identity)
		if transport != nil {
			if release == nil {
				release = func() {}
			}
			var once sync.Once
			return &http.Client{Transport: transport, Timeout: timeout}, func() { once.Do(release) }
		}
	}
	client := NewHttpClient()
	client.Timeout = timeout
	var once sync.Once
	return client, func() { once.Do(client.CloseIdleConnections) }
}
