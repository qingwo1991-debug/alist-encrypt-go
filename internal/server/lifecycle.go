package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
)

type ownedListener struct {
	net.Listener
	owner *Server
}

func (l *ownedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &ownedConnection{Conn: conn, owner: l.owner}, nil
}

type ownedConnection struct {
	net.Conn
	owner  *Server
	closed bool // guarded by owner's lifecycleMu, including state publication
}

func (c *ownedConnection) Close() error {
	// Mark closed before the OS call: a delayed ConnState callback cannot
	// re-register this socket while Close blocks or after Close already returned.
	c.owner.lifecycleMu.Lock()
	c.closed = true
	delete(c.owner.connections, c)
	c.owner.lifecycleMu.Unlock()
	return c.Conn.Close()
}

type serverEndpoint struct {
	server   *http.Server
	listener net.Listener
	tls      bool
}

func (s *Server) lifecycleSealSignal() <-chan struct{} {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.sealedSignal == nil {
		s.sealedSignal = make(chan struct{})
	}
	return s.sealedSignal
}
func (s *Server) listen(network, address string) (net.Listener, error) {
	if s.listenFactory != nil {
		return s.listenFactory(network, address)
	}
	return net.Listen(network, address)
}

// Preparation runs outside lifecycleMu: an OS listen or test factory can block.
// Shutdown seals first and joins prepareWG before accessing published listeners.
func (s *Server) prepareListeners() (endpoints []serverEndpoint, err error) {
	defer func() {
		if err != nil {
			for _, endpoint := range endpoints {
				_ = endpoint.listener.Close()
			}
		}
	}()
	httpServer := s.prepareHTTP()
	listener, err := s.listen("tcp", httpServer.Addr)
	if err != nil {
		return nil, err
	}
	endpoints = append(endpoints, serverEndpoint{server: httpServer, listener: listener})
	if s.cfg.IsHTTPSEnabled() {
		httpsServer := s.prepareHTTPS()
		listener, err = s.listen("tcp", httpsServer.Addr)
		if err != nil {
			return endpoints, err
		}
		endpoints = append(endpoints, serverEndpoint{server: httpsServer, listener: listener, tls: true})
	}
	if s.cfg.IsUnixSocketEnabled() {
		unixServer, unixListener, unixErr := s.prepareUnix()
		if unixErr != nil {
			return endpoints, unixErr
		}
		endpoints = append(endpoints, serverEndpoint{server: unixServer, listener: unixListener})
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.stopping {
		return endpoints, fmt.Errorf("server stopped during listener preparation")
	}
	s.httpServer = httpServer
	for i := range endpoints {
		endpoints[i].listener = &ownedListener{Listener: endpoints[i].listener, owner: s}
	}
	for _, endpoint := range endpoints {
		if endpoint.tls {
			s.httpsServer = endpoint.server
		} else if endpoint.server != httpServer {
			s.unixServer = endpoint.server
		}
		s.listeners = append(s.listeners, endpoint.listener)
	}
	// Registered before Stop can Wait, even before Serve goroutines are launched.
	s.serveWG.Add(len(endpoints))
	return endpoints, nil
}

// net/http drops hijacked sessions from Shutdown's ownership. Retain those
// sockets (including h2c) until instance Stop closes them; closed callbacks remove
// ordinary connections. No lifecycle mutex is held across connection.Close.
func (s *Server) ownedConnState(conn net.Conn, state http.ConnState) {
	s.lifecycleMu.Lock()
	if state == http.StateClosed {
		delete(s.connections, conn)
		s.lifecycleMu.Unlock()
		return
	}
	owned, isOwned := conn.(*ownedConnection)
	if s.stopping || (isOwned && owned.closed) {
		// No state (including Active/Idle) can repopulate the registry after
		// sealing, and no late Hijacked callback can resurrect a closed socket.
		delete(s.connections, conn)
		s.lifecycleMu.Unlock()
		_ = conn.Close()
		return
	}
	if s.connections == nil {
		s.connections = make(map[net.Conn]http.ConnState)
	}
	s.connections[conn] = state
	s.lifecycleMu.Unlock()
}
func (s *Server) closeOwnedConnections() {
	s.lifecycleMu.Lock()
	connections := make([]net.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.connections = make(map[net.Conn]http.ConnState)
	s.lifecycleMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}
func (s *Server) ownedHTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.lifecycleMu.Lock()
		if s.stopping {
			s.lifecycleMu.Unlock()
			http.Error(w, "server stopping", http.StatusServiceUnavailable)
			return
		}
		if s.requestContext == nil {
			s.requestContext, s.requestCancel = context.WithCancel(context.Background())
		}
		ownerContext := s.requestContext
		s.requestWG.Add(1)
		s.lifecycleMu.Unlock()
		defer s.requestWG.Done()
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(ownerContext, cancel)
		defer stop()
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
