package net

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DriverRouteIdentity is trusted storage-driver metadata, not a request header.
type DriverRouteIdentity struct {
	Driver, Provider, Storage, Server string
	Epoch                             uint64
}
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
func SetDriverTransportFactory(factory func(DriverRouteIdentity) (http.RoundTripper, func())) error {
	embeddedOwner.Lock()
	defer embeddedOwner.Unlock()
	if embeddedOwner.lease != nil {
		return errors.New("embedded_instance_factory_owned")
	}
	driverFactoryMu.Lock()
	defer driverFactoryMu.Unlock()
	driverFactory = factory
	return nil
}

var ownedDriverClients int

// NewDriverHTTPClient returns an independent storage-session client. Release is
// idempotent and retires idle transports, never canceling an active body.
func NewDriverHTTPClient(identity DriverRouteIdentity, timeout time.Duration) (*http.Client, func()) {
	embeddedOwner.Lock()
	if l := embeddedOwner.lease; l != nil && (l.stopping || identity.Server != fmt.Sprintf("embedded-%d", l.generation) || identity.Storage == "") {
		embeddedOwner.Unlock()
		return &http.Client{Transport: rejectedDriverTransport{}}, func() {}
	}
	driverFactoryMu.Lock()
	factory := driverFactory
	owned := embeddedOwner.lease != nil
	if owned {
		ownedDriverClients++
	}
	driverFactoryMu.Unlock()
	embeddedOwner.Unlock()
	finish := func() {
		if owned {
			driverFactoryMu.Lock()
			ownedDriverClients--
			driverFactoryMu.Unlock()
		}
	}
	wrap := func(client *http.Client, release func()) (*http.Client, func()) {
		t := &ownedDriverTransport{base: client.Transport, release: func() { release(); finish() }}
		client.Transport = t
		return client, t.retire
	}
	if factory != nil && identity.Driver != "" {
		transport, release := factory(identity)
		if transport != nil {
			if release == nil {
				release = func() {}
			}
			return wrap(&http.Client{Transport: transport, Timeout: timeout}, release)
		}
	}
	client := NewHttpClient()
	client.Timeout = timeout
	transport := client.Transport
	return wrap(client, func() {
		if t, ok := transport.(interface{ CloseIdleConnections() }); ok {
			t.CloseIdleConnections()
		}
	})
}

type rejectedDriverTransport struct{}

func (rejectedDriverTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("embedded_instance_stopping")
}

// Retirement closes admission; live response bodies retain the pool until EOF
// or Close. It does not claim to cancel/join an uncooperative SDK.
type ownedDriverTransport struct {
	mu                sync.Mutex
	base              http.RoundTripper
	active            int
	retired, released bool
	release           func()
}

func (t *ownedDriverTransport) done() { t.mu.Lock(); defer t.mu.Unlock(); t.active--; t.finish() }
func (t *ownedDriverTransport) finish() {
	if t.retired && t.active == 0 && !t.released {
		t.released = true
		t.release()
	}
}
func (t *ownedDriverTransport) retire() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.retired = true
	t.finish()
}
func (t *ownedDriverTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if t.retired {
		t.mu.Unlock()
		return nil, errors.New("driver_session_retired")
	}
	t.active++
	t.mu.Unlock()
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(req)
	if err != nil {
		t.done()
		return response, err
	}
	if response.Body == nil {
		t.done()
	} else {
		response.Body = &ownedDriverBody{ReadCloser: response.Body, done: t.done}
	}
	return response, nil
}

type ownedDriverBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (b *ownedDriverBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.once.Do(b.done)
	}
	return n, err
}
func (b *ownedDriverBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.done); return err }
