package bootstrap

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func testDrain(t *testing.T, g *endpointGeneration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return g.drain(ctx)
}

func TestEndpointSealRejectsLatePreparation(t *testing.T) {
	g := &endpointGeneration{}
	if err := testDrain(t, g); err != nil {
		t.Fatal(err)
	}
	var prepared atomic.Bool
	if g.start("late", func() error { prepared.Store(true); return nil }, func() error { t.Error("late Serve"); return nil }, func(context.Context) error { return nil }, nil, nil) {
		t.Fatal("sealed generation admitted endpoint")
	}
	if prepared.Load() {
		t.Fatal("socket preparation ran after seal")
	}
}

func TestEndpointJoinIsDeadlineAwareAndRetryable(t *testing.T) {
	g := &endpointGeneration{}
	gate := make(chan struct{})
	entered := make(chan struct{})
	var stops atomic.Int32
	g.start("gated", nil, func() error { close(entered); <-gate; return nil }, func(context.Context) error { stops.Add(1); return nil }, nil, nil)
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain = %v; Serve still owned", err)
	}
	if stops.Load() != 1 {
		t.Fatal("stop not called")
	}
	close(gate)
	if err := testDrain(t, g); err != nil {
		t.Fatal(err)
	}
	if stops.Load() != 1 {
		t.Fatal("successful stop repeated during join retry")
	}
}

func TestEndpointFailedStopRetainsRetry(t *testing.T) {
	g := &endpointGeneration{}
	done := make(chan struct{})
	var stops atomic.Int32
	sentinel := errors.New("actual stop failure")
	g.start("fake", nil, func() error { <-done; return nil }, func(context.Context) error {
		if stops.Add(1) == 1 {
			close(done)
			return sentinel
		}
		return nil
	}, nil, nil)
	if err := testDrain(t, g); !errors.Is(err, sentinel) {
		t.Fatalf("lost stop error: %v", err)
	}
	if err := testDrain(t, g); err != nil {
		t.Fatal(err)
	}
	if stops.Load() != 2 {
		t.Fatalf("stop calls = %d", stops.Load())
	}
}

func TestEndpointInFlightStopNotRepeated(t *testing.T) {
	g := &endpointGeneration{}
	gate := make(chan struct{})
	var stops atomic.Int32
	g.start("fake", nil, func() error { <-gate; return nil }, func(context.Context) error { stops.Add(1); <-gate; return nil }, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(gate)
	if err := testDrain(t, g); err != nil {
		t.Fatal(err)
	}
	if stops.Load() != 1 {
		t.Fatalf("concurrent stop calls: %d", stops.Load())
	}
}

func TestEndpointShutdownBeforeHTTPServe(t *testing.T) {
	g := &endpointGeneration{}
	srv := &http.Server{Addr: "127.0.0.1:0"}
	gate := make(chan struct{})
	enteredStop := make(chan struct{})
	g.start("http", nil, func() error { <-gate; return srv.ListenAndServe() }, func(ctx context.Context) error { err := srv.Shutdown(ctx); close(enteredStop); return err }, nil, nil)
	result := make(chan error, 1)
	go func() { result <- testDrain(t, g) }()
	<-enteredStop
	close(gate)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !srvIsClosed(srv) {
		t.Fatal("server admitted a new listener after shutdown")
	}
}

func srvIsClosed(srv *http.Server) bool { return errors.Is(srv.ListenAndServe(), http.ErrServerClosed) }

func TestEndpointHTTPRealHandlerDrain(t *testing.T) {
	g := &endpointGeneration{}
	entered, finish := make(chan struct{}), make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-finish; _, _ = io.WriteString(w, "ok") })}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	g.start("http", nil, func() error { return srv.Serve(listener) }, srv.Shutdown, nil, nil)
	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: time.Second}
		response, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("active handler not retained: %v", err)
	}
	close(finish)
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	if err := testDrain(t, g); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointReadyPreventsShutdownBeforeBind(t *testing.T) {
	g := &endpointGeneration{}
	ready := make(chan struct{})
	finish := make(chan struct{})
	admitted := make(chan struct{})
	var bound atomic.Bool
	go func() {
		g.start("non-http", nil, func() error {
			bound.Store(true)
			close(ready)
			<-finish
			return nil
		}, func(context.Context) error {
			if !bound.Load() {
				t.Error("stop preceded socket readiness")
			}
			close(finish)
			return nil
		}, func() error { <-ready; return nil }, nil)
		close(admitted)
	}()
	<-ready
	if err := testDrain(t, g); err != nil {
		t.Fatal(err)
	}
	<-admitted
}

func TestEndpointFailedReadinessDoesNotStopUnboundServer(t *testing.T) {
	g := &endpointGeneration{}
	bindErr := errors.New("bind failed")
	g.start("sftp-like", nil, func() error { return bindErr }, func(context.Context) error { t.Error("stop called on unbound server"); return nil }, func() error { return bindErr }, nil)
	if err := testDrain(t, g); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointHookCanReenterDrain(t *testing.T) {
	g := &endpointGeneration{}
	result := make(chan error, 1)
	finish := make(chan struct{})
	g.start("fake", nil, func() error { <-finish; return nil }, func(context.Context) error { return nil }, nil, func(error) { result <- testDrain(t, g) })
	close(finish)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hook self-joined counted ownership")
	}
}
