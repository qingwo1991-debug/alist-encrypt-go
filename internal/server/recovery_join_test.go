//go:build unix

package server

import (
	"context"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/recovery"
	"github.com/gin-gonic/gin"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRecoveryOwnershipHeldUntilActualHandlerReturn(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.DataDir = dir
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.engine.GET("/ownership-gate", func(c *gin.Context) {
		close(entered)
		<-c.Request.Context().Done()
		close(canceled)
		<-release
		c.Status(204)
	})
	listening := make(chan net.Listener, 1)
	s.listenFactory = func(string, string) (net.Listener, error) {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e == nil {
			listening <- l
		}
		return l, e
	}
	started := make(chan error, 1)
	go func() { started <- s.Start() }()
	listener := <-listening
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		response, e := http.Get("http://" + listener.Addr().String() + "/ownership-gate")
		if e == nil {
			response.Body.Close()
		}
	}()
	<-entered
	stopCtx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- s.Shutdown(stopCtx) }()
	<-canceled
	acquireCtx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if l, e := recovery.Acquire(acquireCtx, dir); e == nil {
		l.Close()
		t.Error("expired Shutdown released ownership before actual handler return")
	}
	stop()
	select {
	case <-stopped:
		t.Fatal("Shutdown abandoned actual handler")
	default:
	}
	close(release)
	<-stopped
	<-started
	<-clientDone
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	l, err := recovery.Acquire(ctx, dir)
	if err != nil {
		t.Fatal("ownership not released after real join", err)
	}
	l.Close()
}
