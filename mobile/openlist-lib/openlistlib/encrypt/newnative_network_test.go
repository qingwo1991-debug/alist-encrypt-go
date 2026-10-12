package encrypt

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestNativeAddressBudgetAllowsFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	calls := 0
	conn, err := dialNativeAddresses(ctx, "tcp", []string{"2001:db8::1", "192.0.2.1"}, "443", func(attempt context.Context, _, address string) (net.Conn, error) {
		calls++
		if calls == 1 {
			deadline, ok := attempt.Deadline()
			parentDeadline, _ := ctx.Deadline()
			if !ok || !deadline.Before(parentDeadline) {
				t.Fatal("first address was granted the complete dial budget")
			}
			<-attempt.Done()
			return nil, attempt.Err()
		}
		if address != "192.0.2.1:443" || attempt.Err() != nil {
			t.Fatalf("fallback did not retain budget: %s %v", address, attempt.Err())
		}
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}, false)
	if err != nil || calls != 2 || conn == nil {
		t.Fatalf("fallback: calls=%d conn=%v err=%v", calls, conn, err)
	}
	_ = conn.Close()
}

func TestNativeAddressCancellationStopsFurtherAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, err := dialNativeAddresses(ctx, "tcp", []string{"2001:db8::1", "192.0.2.1"}, "443", func(context.Context, string, string) (net.Conn, error) {
		calls++
		cancel()
		return nil, context.Canceled
	}, false)
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled attempts=%d err=%v", calls, err)
	}
}

func TestNativeAddressPreferenceAndFamilyFiltering(t *testing.T) {
	for _, tc := range []struct {
		network string
		prefer  bool
		want    []string
	}{
		{"tcp", true, []string{"192.0.2.1:443", "192.0.2.2:443", "[2001:db8::1]:443", "[2001:db8::2]:443"}},
		{"tcp4", false, []string{"192.0.2.1:443", "192.0.2.2:443"}},
		{"tcp6", true, []string{"[2001:db8::1]:443", "[2001:db8::2]:443"}},
	} {
		t.Run(tc.network, func(t *testing.T) {
			calls := 0
			_, err := dialNativeAddresses(context.Background(), tc.network, []string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"}, "443", func(_ context.Context, _ string, address string) (net.Conn, error) {
				if calls >= len(tc.want) || address != tc.want[calls] {
					t.Fatalf("address[%d]=%s want %v", calls, address, tc.want)
				}
				calls++
				return nil, syscall.ECONNREFUSED
			}, tc.prefer)
			if calls != len(tc.want) || !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("attempts=%d err=%v", calls, err)
			}
		})
	}
}

type fakeNativeBridge struct {
	mu        sync.Mutex
	events    []string
	payload   string
	startCode int64
	cancel    context.CancelFunc
	canceled  int
	tokens    []string
}

func (b *fakeNativeBridge) BindSocket(fd int64, token string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, "bind")
	b.tokens = append(b.tokens, token)
	if fd < 0 {
		return 9
	}
	return 0
}
func (b *fakeNativeBridge) StartDNS(id, token, host string, timeout int64) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, "dns")
	b.tokens = append(b.tokens, token)
	if timeout < 1 || timeout > 15000 {
		return 22
	}
	return b.startCode
}
func (b *fakeNativeBridge) PollDNS(id string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		b.cancel()
	}
	return b.payload
}
func (b *fakeNativeBridge) CancelDNS(id string) { b.mu.Lock(); defer b.mu.Unlock(); b.canceled++ }

func TestNativeDialerPreservesControlAndBindsBeforeConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	bridge := &fakeNativeBridge{payload: `{"status":"ok","addresses":["127.0.0.1"]}`}
	dialer := net.Dialer{Control: func(network, address string, raw syscall.RawConn) error {
		bridge.mu.Lock()
		defer bridge.mu.Unlock()
		bridge.events = append(bridge.events, "original")
		return nil
	}}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	snapshot := NativeRouteSnapshot{Bridge: bridge, Generation: 17}
	conn, err := snapshot.Dialer(dialer, "physical-17")(context.Background(), "tcp", net.JoinHostPort("example.invalid", port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := bridge.events; len(got) != 3 || got[0] != "dns" || got[1] != "original" || got[2] != "bind" {
		t.Fatalf("events %v", got)
	}
	if bridge.canceled != 1 {
		t.Fatalf("cancel count %d", bridge.canceled)
	}
	for _, token := range bridge.tokens {
		if token != "physical-17" {
			t.Fatal(token)
		}
	}
}
func TestNativeDialerControlContextPrecedence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	bridge := &fakeNativeBridge{}
	dialer := net.Dialer{Control: func(string, string, syscall.RawConn) error { t.Fatal("obsolete Control called"); return nil }, ControlContext: func(context.Context, string, string, syscall.RawConn) error {
		bridge.events = append(bridge.events, "context")
		return nil
	}}
	conn, err := (NativeRouteSnapshot{Bridge: bridge}).Dialer(dialer, "default-token")(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if len(bridge.events) != 2 || bridge.events[0] != "context" || bridge.events[1] != "bind" {
		t.Fatal(bridge.events)
	}
}
func TestNativeDNSCancellationRetiresOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge := &fakeNativeBridge{payload: `{"status":"pending"}`, cancel: cancel}
	_, err := resolveNativeName(ctx, bridge, "physical", "example.invalid", 1)
	if !errors.Is(err, context.Canceled) || bridge.canceled != 1 {
		t.Fatalf("err %v cancel %d", err, bridge.canceled)
	}
	if len(bridge.events) != 1 {
		t.Fatal(bridge.events)
	}
}
func TestNativeDNSRejectsInvalidAndUnsupported(t *testing.T) {
	for _, payload := range []string{`{"status":"ok","addresses":["not-ip"]}`, `{"status":"ok","addresses":[]}`, `{"status":"unknown"}`, `invalid`} {
		bridge := &fakeNativeBridge{payload: payload}
		if _, err := resolveNativeName(context.Background(), bridge, "physical", "example.invalid", 1); !errors.Is(err, ErrNativeRouteUnavailable) {
			t.Fatal(err)
		}
		if bridge.canceled != 1 {
			t.Fatal(bridge.canceled)
		}
	}
	bridge := &fakeNativeBridge{startCode: 95}
	_, err := resolveNativeName(context.Background(), bridge, "physical", "example.invalid", 1)
	if !errors.Is(err, ErrNativeRouteUnavailable) || !errors.Is(err, syscall.ENOTSUP) || bridge.canceled != 1 {
		t.Fatal(err)
	}
}
func TestNativeExplicitRouteNeverFallsBackWithoutBridge(t *testing.T) {
	dial := (NativeRouteSnapshot{}).Dialer(net.Dialer{}, "physical")
	if _, err := dial(context.Background(), "tcp", "127.0.0.1:1"); !errors.Is(err, ErrNativeRouteUnavailable) {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := (NativeRouteSnapshot{}).Dialer(net.Dialer{}, "")(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
func TestNativeBridgeReplacementRetiresIdentityWithoutAdvancingGeneration(t *testing.T) {
	before := SnapshotNativeRoutes()
	t.Cleanup(func() {
		nativeRoutes.Lock()
		nativeRoutes.snapshot = before
		nativeRoutes.Unlock()
	})
	SetNativeNetworkRoutes("old-default", "old-physical", before.Generation+1)
	old := SnapshotNativeRoutes()
	bridge := &fakeNativeBridge{}
	SetNativeNetworkBridge(bridge)
	current := SnapshotNativeRoutes()
	if current.Generation != old.Generation || current.BridgeEpoch <= old.BridgeEpoch {
		t.Fatalf("bridge replacement changed native generation or retained identity: old=%+v current=%+v", old, current)
	}
	if current.DefaultToken != "" || current.PhysicalToken != "" || current.Bridge != bridge {
		t.Fatal("replacement retained stale routes")
	}
	SetNativeNetworkRoutes("new-default", "new-physical", old.Generation+1)
	if SnapshotNativeRoutes().DefaultToken != "new-default" {
		t.Fatal("next native-owned generation publication was rejected")
	}
}

func TestNativeDNSCanceledResultCannotRevive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge := &fakeNativeBridge{payload: `{"status":"ok","addresses":["127.0.0.1"]}`, cancel: cancel}
	if _, err := resolveNativeName(ctx, bridge, "physical", "example.invalid", 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if bridge.canceled != 1 {
		t.Fatal(bridge.canceled)
	}
}
