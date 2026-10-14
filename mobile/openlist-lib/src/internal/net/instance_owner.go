package net

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// EmbeddedLease fences the fixed upstream's process-global registry. Pointer
// ownership, not a caller-supplied string, authorizes mutation and cleanup.
type EmbeddedLease struct {
	ctx        context.Context
	cancel     context.CancelFunc
	generation uint64
	epoch      uint64
	stopping   bool
}

var embeddedOwner struct {
	sync.Mutex
	lease      *EmbeddedLease
	generation uint64
}

func AcquireEmbeddedLease() (*EmbeddedLease, error) {
	embeddedOwner.Lock()
	defer embeddedOwner.Unlock()
	if embeddedOwner.lease != nil {
		return nil, errors.New("embedded_instance_overlap: previous generation still owns global state")
	}
	embeddedOwner.generation++
	ctx, cancel := context.WithCancel(context.Background())
	l := &EmbeddedLease{ctx: ctx, cancel: cancel, generation: embeddedOwner.generation}
	embeddedOwner.lease = l
	return l, nil
}
func (l *EmbeddedLease) Context() context.Context { return l.ctx }
func (l *EmbeddedLease) Publish(factory func(DriverRouteIdentity) (http.RoundTripper, func())) error {
	embeddedOwner.Lock()
	defer embeddedOwner.Unlock()
	if l == nil || embeddedOwner.lease != l || l.stopping {
		return errors.New("embedded_instance_not_owner")
	}
	driverFactoryMu.Lock()
	defer driverFactoryMu.Unlock()
	l.epoch++
	driverFactory = factory
	return nil
}

// BeginStop closes factory admission and cancels this generation. Callers must
// join their own pipelines before Release; cancellation alone is not a join.
func (l *EmbeddedLease) BeginStop() error {
	embeddedOwner.Lock()
	defer embeddedOwner.Unlock()
	if l == nil || embeddedOwner.lease != l {
		return errors.New("embedded_instance_not_owner")
	}
	l.stopping = true
	l.cancel()
	return nil
}
func (l *EmbeddedLease) Release() error {
	embeddedOwner.Lock()
	defer embeddedOwner.Unlock()
	if l == nil || embeddedOwner.lease != l {
		return errors.New("embedded_instance_not_owner")
	}
	driverFactoryMu.Lock()
	defer driverFactoryMu.Unlock()
	if ownedDriverClients != 0 {
		return fmt.Errorf("embedded_instance_pending: %d driver clients/bodies have not joined", ownedDriverClients)
	}
	l.cancel()
	driverFactory = nil
	embeddedOwner.lease = nil
	return nil
}

// StorageSessionContext is deliberately independent of the Init operation's
// deadline. Only the generation owner and driver Drop end a successful session.
func StorageSessionContext(init context.Context) context.Context {
	if ctx, ok := init.Value(storageSessionKey{}).(context.Context); ok {
		return ctx
	}
	return context.Background()
}

type storageSessionKey struct{}

func BootstrapStorageContext(init context.Context, driver, provider, storage string) context.Context {
	embeddedOwner.Lock()
	defer embeddedOwner.Unlock()
	identity := DriverRouteIdentity{Driver: driver, Provider: provider, Storage: storage}
	session := context.Background()
	if l := embeddedOwner.lease; l != nil {
		identity.Server = fmt.Sprintf("embedded-%d", l.generation)
		identity.Epoch = l.epoch
		session = l.ctx
	}
	init = context.WithValue(init, storageSessionKey{}, session)
	return WithDriverRouteIdentity(init, identity)
}

func (l *EmbeddedLease) PendingEpoch() uint64 {
	embeddedOwner.Lock()
	defer embeddedOwner.Unlock()
	if embeddedOwner.lease != l {
		return 0
	}
	return l.epoch
}
