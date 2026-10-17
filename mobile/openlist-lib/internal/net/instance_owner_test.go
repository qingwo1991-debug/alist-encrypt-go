package net

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmbeddedLeaseOverlapOwnerAndLiveBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("owned")) }))
	defer upstream.Close()
	lease, err := AcquireEmbeddedLease()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.BeginStop(); _ = lease.Release() }()
	if _, err := AcquireEmbeddedLease(); err == nil {
		t.Fatal("overlap accepted")
	}
	if err := (&EmbeddedLease{}).Release(); err == nil {
		t.Fatal("non-owner cleanup accepted")
	}
	if err := SetDriverTransportFactory(nil); err == nil {
		t.Fatal("unowned overwrite accepted")
	}
	if err := lease.Publish(func(DriverRouteIdentity) (http.RoundTripper, func()) {
		return http.DefaultTransport.(*http.Transport).Clone(), func() {}
	}); err != nil {
		t.Fatal(err)
	}
	init, cancel := context.WithCancel(context.Background())
	init = BootstrapStorageContext(init, "Mega", "mega", "41")
	identity, _ := DriverRouteIdentityFromContext(init)
	session := StorageSessionContext(init)
	cancel()
	if session.Err() != nil {
		t.Fatal("Init cancellation killed session")
	}
	if identity.Storage != "41" || identity.Server == "" || identity.Epoch != 1 {
		t.Fatalf("identity=%+v", identity)
	}
	client, release := NewDriverHTTPClient(identity, 0)
	response, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	release()
	_ = lease.BeginStop()
	if err := lease.Release(); err == nil {
		t.Fatal("live body released owner")
	}
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "owned" {
		t.Fatalf("body=%q err=%v", data, err)
	}
	response.Body.Close()
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	next, err := AcquireEmbeddedLease()
	if err != nil {
		t.Fatal(err)
	}
	if next.generation == lease.generation {
		t.Fatal("generation reused")
	}
	_ = next.BeginStop()
	if err := next.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedLeaseFailedInitAndSnapshots(t *testing.T) {
	lease, err := AcquireEmbeddedLease()
	if err != nil {
		t.Fatal(err)
	}
	calls := []DriverRouteIdentity{}
	factory := func(identity DriverRouteIdentity) (http.RoundTripper, func()) {
		calls = append(calls, identity)
		return http.DefaultTransport.(*http.Transport).Clone(), func() {}
	}
	if err := lease.Publish(factory); err != nil {
		t.Fatal(err)
	}
	oldCtx := BootstrapStorageContext(context.Background(), "Mega", "mega", "1")
	old, _ := DriverRouteIdentityFromContext(oldCtx)
	client, release := NewDriverHTTPClient(old, 0)
	_ = client
	// Failure cleanup owns only this client; another owner cannot clear factory.
	release()
	if err := lease.Publish(factory); err != nil {
		t.Fatal(err)
	}
	nextCtx := BootstrapStorageContext(context.Background(), "Mega", "mega", "2")
	next, _ := DriverRouteIdentityFromContext(nextCtx)
	_, releaseNext := NewDriverHTTPClient(next, 0)
	releaseNext()
	if old.Epoch != 1 || next.Epoch != 2 || lease.PendingEpoch() != 2 || len(calls) != 2 {
		t.Fatalf("old=%+v next=%+v calls=%d", old, next, len(calls))
	}
	_ = lease.BeginStop()
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
}
