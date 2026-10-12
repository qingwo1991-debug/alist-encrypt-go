package encrypt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// NativeNetworkBridge has the primitive-only mobile facade contract.
type NativeNetworkBridge interface {
	BindSocket(fd int64, token string) int64
	StartDNS(id string, token string, host string, timeoutMillis int64) int64
	PollDNS(id string) string
	CancelDNS(id string)
}

var ErrNativeRouteUnavailable = errors.New("native network route unavailable")

type NativeRouteSnapshot struct {
	DefaultToken  string
	PhysicalToken string
	Generation    int64
	BridgeEpoch   uint64
	Bridge        NativeNetworkBridge
}

var nativeRoutes struct {
	sync.RWMutex
	snapshot NativeRouteSnapshot
}
var nativeDNSSequence atomic.Uint64

func SetNativeNetworkBridge(bridge NativeNetworkBridge) {
	nativeRoutes.Lock()
	defer nativeRoutes.Unlock()
	// Bridge replacement has its own identity; do not advance the native-owned
	// generation counter and accidentally reject the next Kotlin publication.
	nativeRoutes.snapshot.BridgeEpoch++
	nativeRoutes.snapshot.DefaultToken = ""
	nativeRoutes.snapshot.PhysicalToken = ""
	nativeRoutes.snapshot.Bridge = bridge
}
func SetNativeNetworkRoutes(defaultToken, physicalToken string, generation int64) {
	nativeRoutes.Lock()
	defer nativeRoutes.Unlock()
	if generation <= nativeRoutes.snapshot.Generation {
		return
	}
	nativeRoutes.snapshot.DefaultToken = defaultToken
	nativeRoutes.snapshot.PhysicalToken = physicalToken
	nativeRoutes.snapshot.Generation = generation
}
func SnapshotNativeRoutes() NativeRouteSnapshot {
	nativeRoutes.RLock()
	defer nativeRoutes.RUnlock()
	return nativeRoutes.snapshot
}

// BuildNativeDialer captures the bridge now. Pools should prefer snapshot.Dialer
// to capture tokens, generation and bridge atomically in one snapshot.
func BuildNativeDialer(dialer net.Dialer, token string, generation int64) func(context.Context, string, string) (net.Conn, error) {
	snapshot := SnapshotNativeRoutes()
	snapshot.Generation = generation
	return snapshot.Dialer(dialer, token)
}

func nativeRouteError(code int64) error {
	if code <= 0 || code > 4095 {
		return ErrNativeRouteUnavailable
	}
	return fmt.Errorf("%w: %w", ErrNativeRouteUnavailable, syscall.Errno(code))
}

// Dialer binds synchronously inside RawConn.Control before connect. TLS retains
// the original HTTP host: only the TCP endpoint address is rewritten after DNS.
func (snapshot NativeRouteSnapshot) Dialer(dialer net.Dialer, token string) func(context.Context, string, string) (net.Conn, error) {
	return snapshot.DialerPreferIPv4(dialer, token, false)
}

// DialerPreferIPv4 keeps selected-network DNS inside this immutable route. The
// preference only orders validated answers; it never resolves on a default network.
func (snapshot NativeRouteSnapshot) DialerPreferIPv4(dialer net.Dialer, token string, preferIPv4 bool) func(context.Context, string, string) (net.Conn, error) {
	if token == "" {
		if preferIPv4 {
			return preferIPv4DialContext(dialer.DialContext)
		}
		return dialer.DialContext
	}
	bridge := snapshot.Bridge
	originalControl, originalContext := dialer.Control, dialer.ControlContext
	dialer.Control = nil
	dialer.ControlContext = func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if bridge == nil {
			return ErrNativeRouteUnavailable
		}
		if originalContext != nil {
			if err := originalContext(ctx, network, address, raw); err != nil {
				return err
			}
		} else if originalControl != nil {
			if err := originalControl(network, address, raw); err != nil {
				return err
			}
		}
		var bindError error
		if err := raw.Control(func(fd uintptr) {
			if uint64(fd) > ^uint64(0)>>1 {
				bindError = ErrNativeRouteUnavailable
				return
			}
			if code := bridge.BindSocket(int64(fd), token); code != 0 {
				bindError = nativeRouteError(code)
			}
		}); err != nil {
			return err
		}
		if bindError != nil {
			return bindError
		}
		return ctx.Err()
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// Preserve net.Dialer's whole-operation deadline across native DNS and
		// serial address attempts, rather than granting each address a new timeout.
		deadline := dialer.Deadline
		if dialer.Timeout > 0 {
			relative := time.Now().Add(dialer.Timeout)
			if deadline.IsZero() || relative.Before(deadline) {
				deadline = relative
			}
		}
		if !deadline.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if bridge == nil {
			return nil, ErrNativeRouteUnavailable
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		hosts := []string{host}
		if net.ParseIP(host) == nil {
			hosts, err = resolveNativeName(ctx, bridge, token, host, snapshot.Generation)
			if err != nil {
				return nil, err
			}
		}
		return dialNativeAddresses(ctx, network, hosts, port, dialer.DialContext, preferIPv4)
	}
}

// nativeAddressDeadline reserves time for later addresses, including under short
// caller deadlines. Unlike Happy Eyeballs this is sequential, but one blackholed
// IPv6 answer cannot consume the complete logical dial budget before IPv4 runs.
func nativeAddressDeadline(ctx context.Context, remainingAddresses int) (time.Time, bool) {
	if remainingAddresses < 1 {
		remainingAddresses = 1
	}
	if deadline, ok := ctx.Deadline(); ok {
		budget := time.Until(deadline) / time.Duration(remainingAddresses)
		if remainingAddresses > 1 && budget > time.Second {
			budget = time.Second
		}
		return time.Now().Add(budget), true
	}
	if remainingAddresses > 1 {
		return time.Now().Add(3 * time.Second), true
	}
	return time.Time{}, false
}

func dialNativeAddresses(ctx context.Context, network string, hosts []string, port string, dial func(context.Context, string, string) (net.Conn, error), preferIPv4 bool) (net.Conn, error) {
	addresses := make([]string, 0, len(hosts))
	for _, host := range hosts {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, ErrNativeRouteUnavailable
		}
		if (network == "tcp4" || network == "udp4") && ip.To4() == nil {
			continue
		}
		if (network == "tcp6" || network == "udp6") && ip.To4() != nil {
			continue
		}
		addresses = append(addresses, host)
	}
	if preferIPv4 {
		ordered := make([]string, 0, len(addresses))
		for _, host := range addresses {
			if net.ParseIP(host).To4() != nil {
				ordered = append(ordered, host)
			}
		}
		for _, host := range addresses {
			if net.ParseIP(host).To4() == nil {
				ordered = append(ordered, host)
			}
		}
		addresses = ordered
	}
	var last error
	for i, ip := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attemptCtx := ctx
		cancel := func() {}
		if deadline, limited := nativeAddressDeadline(ctx, len(addresses)-i); limited {
			attemptCtx, cancel = context.WithDeadline(ctx, deadline)
		}
		conn, err := dial(attemptCtx, network, net.JoinHostPort(ip, port))
		cancel()
		if err == nil {
			if canceled := ctx.Err(); canceled != nil {
				if conn != nil {
					_ = conn.Close()
				}
				return nil, canceled
			}
			return conn, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		last = err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if last == nil {
		last = ErrNativeRouteUnavailable
	}
	return nil, last
}

type nativeDNSResult struct {
	Status    string   `json:"status"`
	Addresses []string `json:"addresses"`
	Code      int64    `json:"code"`
}

func resolveNativeName(ctx context.Context, bridge NativeNetworkBridge, token, host string, generation int64) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if bridge == nil || token == "" || strings.TrimSpace(host) == "" {
		return nil, ErrNativeRouteUnavailable
	}
	timeout := 15 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	millis := timeout.Milliseconds()
	if millis < 1 {
		millis = 1
	}
	id := strconv.FormatInt(generation, 10) + ":" + strconv.FormatUint(nativeDNSSequence.Add(1), 10)
	// Always retire native state, including ambiguous Start failures. Cancellation
	// must be idempotent in native code and never resurrect a terminal query.
	defer bridge.CancelDNS(id)
	if code := bridge.StartDNS(id, token, host, millis); code != 0 {
		return nil, nativeRouteError(code)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		payload := bridge.PollDNS(id)
		if len(payload) > 16384 {
			return nil, ErrNativeRouteUnavailable
		}
		var result nativeDNSResult
		if err := json.Unmarshal([]byte(payload), &result); err != nil {
			return nil, ErrNativeRouteUnavailable
		}
		switch result.Status {
		case "ok":
			if len(result.Addresses) == 0 || len(result.Addresses) > 64 {
				return nil, ErrNativeRouteUnavailable
			}
			addresses := make([]string, 0, len(result.Addresses))
			seen := make(map[string]bool, len(result.Addresses))
			for _, address := range result.Addresses {
				ip := net.ParseIP(address)
				if ip == nil {
					return nil, ErrNativeRouteUnavailable
				}
				canonical := ip.String()
				if !seen[canonical] {
					seen[canonical] = true
					addresses = append(addresses, canonical)
				}
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return addresses, nil
		case "error":
			return nil, nativeRouteError(result.Code)
		case "pending":
		default:
			return nil, ErrNativeRouteUnavailable
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, context.DeadlineExceeded
		case <-ticker.C:
		}
	}
}
