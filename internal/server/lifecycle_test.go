package server

import (
	"context"
	"crypto/tls"

	"encoding/json"
	"errors"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/dao"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/gin-gonic/gin"
)

func TestLifecycleLateConnectionStatesNeverResurrect(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		t.Run(map[bool]string{false: "closed-before-delayed-state", true: "sealed-before-delayed-state"}[sealed], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			socket, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{}
			conn := &ownedConnection{Conn: socket, owner: s}
			s.ownedConnState(conn, http.StateNew)
			gated, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				close(gated)
				<-release
				s.ownedConnState(conn, http.StateHijacked)
				s.ownedConnState(conn, http.StateActive)
				s.ownedConnState(conn, http.StateIdle)
				close(done)
			}()
			<-gated
			if sealed {
				s.lifecycleMu.Lock()
				s.stopping = true
				s.lifecycleMu.Unlock()
				s.closeOwnedConnections()
			} else {
				_ = conn.Close()
			}
			close(release)
			<-done
			s.lifecycleMu.Lock()
			remaining := len(s.connections)
			closed := conn.closed
			s.lifecycleMu.Unlock()
			if remaining != 0 || !closed {
				t.Fatal("late callback resurrected socket", remaining, closed)
			}
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if _, err = client.Read(one[:]); err != io.EOF {
				t.Fatal("owned real socket not closed", err)
			}
		})
	}
}

func TestLifecycleActualH2CRequestOwnedAndSessionClosed(t *testing.T) {
	store, owner := backupFixture(t)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	engine := gin.New()
	engine.GET("/h2gate", func(c *gin.Context) {
		if c.Request.ProtoMajor != 2 {
			t.Error("not an actual HTTP/2 request")
		}
		close(entered)
		<-c.Request.Context().Done()
		close(canceled)
		<-release
		if err := store.SetJSON(storage.BucketConfig, "h2-handler-real-return", true); err != nil {
			t.Error(err)
		}
		c.Status(200)
	})
	cfg := &config.Config{Scheme: &config.SchemeConfig{EnableH2C: true}}
	s := &Server{cfg: cfg, engine: engine, store: store, backups: owner}
	listening := make(chan net.Listener, 1)
	s.listenFactory = func(string, string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			listening <- listener
		}
		return listener, err
	}
	started := make(chan error, 1)
	go func() { started <- s.Start() }()
	listener := <-listening
	transport := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		response, err := client.Get("http://" + listener.Addr().String() + "/h2gate")
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	<-entered
	s.lifecycleMu.Lock()
	hijacked := 0
	for _, state := range s.connections {
		if state == http.StateHijacked {
			hijacked++
		}
	}
	s.lifecycleMu.Unlock()
	if hijacked == 0 {
		t.Error("h2c connection not tracked as hijacked")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- s.Shutdown(context.Background()) }()
	<-canceled
	select {
	case <-stopped:
		t.Fatal("h2c active handler abandoned")
	default:
	}
	if err := store.SetJSON(storage.BucketConfig, "h2-store-not-yet-closed", true); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	<-started
	<-clientDone
	s.lifecycleMu.Lock()
	remaining := len(s.connections)
	s.lifecycleMu.Unlock()
	if remaining != 0 {
		t.Fatal("owned h2c session leaked", remaining)
	}
}

func TestBackupActualServerRoutesAndDisk(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SetJSON(storage.BucketUsers, "operator", dao.User{Username: "operator", PasswordHash: "unused"}); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	cfg := config.DefaultConfig()
	cfg.DataDir = dir
	cfg.JWTSecret = "actual-server-secret"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	listening := make(chan net.Listener, 1)
	s.listenFactory = func(string, string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			listening <- listener
		}
		return listener, err
	}
	started := make(chan error, 1)
	go func() { started <- s.Start() }()
	listener := <-listening
	token, err := auth.NewJWTAuth(cfg.JWTSecret, time.Hour).GenerateToken("operator")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest("POST", "http://"+listener.Addr().String()+"/enc-api/admin/backups", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 202 {
		t.Fatal(response.StatusCode)
	}
	var job backupStatus
	if err = json.NewDecoder(response.Body).Decode(&job); err != nil {
		t.Fatal(err)
	}
	s.backups.wait()
	status, _ := s.backups.status(job.ID, false)
	if status.State != "succeeded" {
		t.Fatal(status)
	}
	if err = storage.ValidateSnapshotBundle(context.Background(), filepath.Join(dir, "backups", job.ID+".tar"), backupMaxBytes); err != nil {
		t.Fatal(err)
	}
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = <-started; err != nil {
		t.Fatal(err)
	}
}

func TestLifecyclePreparationFailureClosesSibling(t *testing.T) {
	store, owner := backupFixture(t)
	cfg := &config.Config{Scheme: &config.SchemeConfig{HTTPSPort: 443, CertFile: "unused", KeyFile: "unused"}}
	s := &Server{cfg: cfg, engine: gin.New(), store: store, backups: owner}
	var first net.Listener
	s.listenFactory = func(string, string) (net.Listener, error) {
		if first != nil {
			return nil, errors.New("second listener failed")
		}
		var err error
		first, err = net.Listen("tcp", "127.0.0.1:0")
		return first, err
	}
	if err := s.Start(); err == nil {
		t.Fatal("startup failure swallowed")
	}
	connection, err := net.DialTimeout("tcp", first.Addr().String(), time.Second)
	if err == nil {
		_ = connection.Close()
		t.Fatal("sibling listener survived failure")
	}
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Both preparation boundaries use actual sockets, not a fake HTTP Server.
func TestLifecycleStopDuringListenerPreparation(t *testing.T) {
	for _, afterListen := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-listen", true: "before-publication"}[afterListen], func(t *testing.T) {
			store, owner := backupFixture(t)
			s := &Server{cfg: &config.Config{}, engine: gin.New(), store: store, backups: owner}
			entered, release := make(chan struct{}), make(chan struct{})
			// Callback is reached only after the lifecycle seal and preparation join.
			var listener net.Listener
			s.listenFactory = func(string, string) (net.Listener, error) {
				var err error
				if afterListen {
					listener, err = net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						return nil, err
					}
				}
				close(entered)
				<-release
				if !afterListen {
					listener, err = net.Listen("tcp", "127.0.0.1:0")
				}
				return listener, err
			}
			started := make(chan error, 1)
			go func() { started <- s.Start() }()
			<-entered
			// Observe the exact seal without timing sleeps, then release the OS factory.
			stop := make(chan error, 1)
			go func() { stop <- s.Shutdown(context.Background()) }()
			<-s.lifecycleSealSignal()
			if err := store.SetJSON(storage.BucketConfig, "preparation-still-owned", true); err != nil {
				t.Fatal(err)
			}
			close(release)
			if err := <-started; err == nil {
				t.Fatal("late preparation admitted")
			}
			if err := <-stop; err != nil {
				t.Fatal(err)
			}
			connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err == nil {
				_ = connection.Close()
				t.Fatal("late listener survived stop")
			}
			if err = s.Start(); err == nil {
				t.Fatal("restart admitted")
			}
			if err = s.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestLifecycleShutdownTimeoutJoinsRealHandler(t *testing.T) {
	store, owner := backupFixture(t)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	engine := gin.New()
	engine.GET("/gate", func(c *gin.Context) {
		close(entered)
		<-c.Request.Context().Done()
		close(canceled)
		<-release
		if err := store.SetJSON(storage.BucketConfig, "actual-handler-return", true); err != nil {
			t.Error(err)
		}
		c.Status(200)
	})
	s := &Server{cfg: &config.Config{}, engine: engine, store: store, backups: owner}
	listening := make(chan net.Listener, 1)
	s.listenFactory = func(string, string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			listening <- listener
		}
		return listener, err
	}
	started := make(chan error, 1)
	go func() { started <- s.Start() }()
	listener := <-listening
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		response, err := http.Get("http://" + listener.Addr().String() + "/gate")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
	}()
	<-entered
	if err := s.Start(); err == nil {
		t.Fatal("duplicate Start admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- s.Shutdown(ctx) }()
	<-canceled
	select {
	case <-stopped:
		t.Fatal("shutdown abandoned active handler")
	default:
	}
	if err := store.SetJSON(storage.BucketConfig, "still-open-after-timeout", true); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-stopped; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	<-clientDone
	<-started
	if err := s.Shutdown(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestLifecycleNeverStartedSealed(t *testing.T) {
	store, owner := backupFixture(t)
	s := &Server{cfg: &config.Config{}, store: store, backups: owner}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil {
		t.Fatal("never-started stopped instance restarted")
	}
}
