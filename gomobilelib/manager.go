package gomobilelib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/buildinfo"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/server"
)

type Manager struct {
	mu        sync.Mutex
	baseDir   string
	cfg       *config.Config
	srv       *server.Server
	running   bool
	startedAt time.Time
	lastErr   string
}

func NewManager(baseDir string) *Manager {
	return &Manager{baseDir: strings.TrimSpace(baseDir)}
}

func (m *Manager) ensureConfigLocked() *config.Config {
	if m.cfg == nil {
		if m.baseDir == "" {
			m.cfg = config.Load()
		} else {
			m.cfg = config.LoadFromBaseDir(m.baseDir)
		}
	}
	return m.cfg
}

func (m *Manager) LoadConfigJSON() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.ensureConfigLocked()
	data, err := json.Marshal(cfg)
	if err != nil {
		return `{"error":"failed to marshal config"}`
	}
	return string(data)
}

func (m *Manager) SaveConfigJSON(configJSON string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.ensureConfigLocked()
	if err := json.Unmarshal([]byte(configJSON), cfg); err != nil {
		return err
	}
	return cfg.Save()
}

func (m *Manager) GetBuildInfoJSON() string {
	payload := map[string]interface{}{
		"version":         config.Version,
		"embedded_web_ui": buildinfo.EmbeddedWebUI(),
		"management_mode": buildinfo.ManagementMode(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return `{"error":"failed to marshal build info"}`
	}
	return string(data)
}

func (m *Manager) GetStatusJSON() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.ensureConfigLocked()
	status := map[string]interface{}{
		"running":         m.running,
		"started_at":      m.startedAt.Format(time.RFC3339),
		"last_error":      m.lastErr,
		"version":         config.Version,
		"management_mode": buildinfo.ManagementMode(),
		"embedded_web_ui": buildinfo.EmbeddedWebUI(),
		"base_dir":        m.baseDir,
		"http_port":       m.getHTTPPortLocked(cfg),
		"alist_url":       cfg.GetAlistURL(),
	}
	data, err := json.Marshal(status)
	if err != nil {
		return `{"error":"failed to marshal status"}`
	}
	return string(data)
}

func (m *Manager) GetVersion() string {
	return config.Version
}

func (m *Manager) GetHTTPPort() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getHTTPPortLocked(m.ensureConfigLocked())
}

func (m *Manager) getHTTPPortLocked(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	if cfg.Scheme != nil && cfg.Scheme.HTTPPort > 0 {
		return cfg.Scheme.HTTPPort
	}
	if cfg.Port > 0 {
		return cfg.Port
	}
	host, port, err := net.SplitHostPort(cfg.GetHTTPAddr())
	if err == nil && host != "" {
		if p, err := parseInt(port); err == nil {
			return p
		}
	}
	return 0
}

func (m *Manager) StartService() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	cfg := m.ensureConfigLocked()
	srv, err := server.New(cfg)
	if err != nil {
		m.lastErr = err.Error()
		m.mu.Unlock()
		return err
	}
	m.srv = srv
	m.running = true
	m.startedAt = time.Now()
	m.lastErr = ""
	m.mu.Unlock()

	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.mu.Lock()
			m.lastErr = err.Error()
			m.running = false
			m.mu.Unlock()
		}
	}()

	return nil
}

func (m *Manager) StopService(timeoutMs int64) error {
	m.mu.Lock()
	srv := m.srv
	m.mu.Unlock()
	if srv == nil {
		return nil
	}

	timeout := 5 * time.Second
	if timeoutMs > 0 {
		timeout = time.Duration(timeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := srv.Shutdown(ctx)

	m.mu.Lock()
	m.running = false
	if err != nil {
		m.lastErr = err.Error()
	}
	m.mu.Unlock()
	return err
}

func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *Manager) SetBaseDir(baseDir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.baseDir = strings.TrimSpace(baseDir)
	m.cfg = nil
}

func parseInt(v string) (int, error) {
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	return n, err
}
