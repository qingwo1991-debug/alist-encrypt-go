package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
)

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
