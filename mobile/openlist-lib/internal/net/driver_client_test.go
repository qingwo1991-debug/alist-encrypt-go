package net

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type driverTestTransport func(*http.Request) (*http.Response, error)

func (f driverTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDriverRouteClientFactorySnapshotAndRelease(t *testing.T) {
	defer SetDriverTransportFactory(nil)
	oldCalls, newCalls, releases := 0, 0, 0
	identity := DriverRouteIdentity{Driver: "Mega", Provider: "mega"}
	SetDriverTransportFactory(func(got DriverRouteIdentity) (http.RoundTripper, func()) {
		if got != identity {
			t.Fatalf("identity=%+v", got)
		}
		return driverTestTransport(func(r *http.Request) (*http.Response, error) {
			oldCalls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("old")), Header: make(http.Header)}, nil
		}), func() { releases++ }
	})
	old, release := NewDriverHTTPClient(identity, 0)
	SetDriverTransportFactory(func(DriverRouteIdentity) (http.RoundTripper, func()) {
		return driverTestTransport(func(r *http.Request) (*http.Response, error) {
			newCalls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("new")), Header: make(http.Header)}, nil
		}), nil
	})
	next, nextRelease := NewDriverHTTPClient(identity, 0)
	defer nextRelease()
	for _, client := range []*http.Client{old, next, old} {
		response, err := client.Get("http://example.invalid")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	release()
	release()
	if oldCalls != 2 || newCalls != 1 || releases != 1 {
		t.Fatalf("old=%d new=%d releases=%d", oldCalls, newCalls, releases)
	}
}

func TestDriverRouteIdentityIsTyped(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
	request.Header.Set("X-Encrypt-Driver", "spoof")
	if _, ok := DriverRouteIdentityFromContext(request.Context()); ok {
		t.Fatal("header became trusted identity")
	}
	identity := DriverRouteIdentity{Driver: "Mega", Provider: "mega"}
	ctx := WithDriverRouteIdentity(request.Context(), identity)
	got, ok := DriverRouteIdentityFromContext(ctx)
	if !ok || got != identity {
		t.Fatalf("identity=%+v ok=%v", got, ok)
	}
}
