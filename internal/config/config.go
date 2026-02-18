package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

const Version = "1.0.0"

// PasswdInfo represents encryption configuration for a path
type PasswdInfo struct {
	Password  string   `json:"password"`
	EncType   string   `json:"encType"`   // "aesctr" or "rc4md5"
	Describe  string   `json:"describe"`  // Description
	Enable    bool     `json:"enable"`    // Enable encryption
	EncName   bool     `json:"encName"`   // Enable filename encryption
	EncSuffix string   `json:"encSuffix"` // Custom file extension
	EncPath   []string `json:"encPath"`   // Regex patterns for path matching
}

// StreamStrategyOverride forces stream strategy for matching paths.
type StreamStrategyOverride struct {
	PathPrefix string `json:"pathPrefix"`
	Strategy   string `json:"strategy"` // range, chunked, full
}

// AlistServer represents the main Alist server configuration
type AlistServer struct {
	Name                        string                   `json:"name"`
	Path                        string                   `json:"path"`
	Describe                    string                   `json:"describe"`
	ServerHost                  string                   `json:"serverHost"`
	ServerPort                  int                      `json:"serverPort"`
	HTTPS                       bool                     `json:"https"`
	EnableH2C                   bool                     `json:"enableH2c"` // Enable HTTP/2 cleartext to backend
	PasswdList                  []PasswdInfo             `json:"passwdList"`
	StreamStrategyOverrides     []StreamStrategyOverride `json:"streamStrategyOverrides"`
	EnableSizeMap               bool                     `json:"enableSizeMap"`
	SizeMapTtlMinutes           int                      `json:"sizeMapTtlMinutes"`
	EnableRangeCompatCache      bool                     `json:"enableRangeCompatCache"`
	RangeCompatTtlMinutes       int                      `json:"rangeCompatTtlMinutes"`
	EnableParallelDecrypt       bool                     `json:"enableParallelDecrypt"`
	ParallelDecryptConcurrency  int                      `json:"parallelDecryptConcurrency"`
	StreamBufferKb              int                      `json:"streamBufferKb"`
	FollowRedirectForDecrypt    bool                     `json:"followRedirectForDecrypt"`
	RedirectMaxHops             int                      `json:"redirectMaxHops"`
	AllowLooseDecode            bool                     `json:"allowLooseDecode"`
	RequestTimeoutSeconds       int                      `json:"requestTimeoutSeconds"`
	EnableStartupProbe          bool                     `json:"enableStartupProbe"`
	StartupProbeDelaySeconds    int                      `json:"startupProbeDelaySeconds"`
	StartupProbeIntervalMinutes int                      `json:"startupProbeIntervalMinutes"`
	NegativeCacheMinutes        int                      `json:"negativeCacheMinutes"`
	StartupProbeDeepScan        bool                     `json:"startupProbeDeepScan"`
	ScanUsername                string                   `json:"scanUsername"`
	ScanPassword                string                   `json:"scanPassword"`
	ScanAuthHeader              string                   `json:"scanAuthHeader"`
	ScanVideoOnly               bool                     `json:"scanVideoOnly"`
	ScanMaxDepth                int                      `json:"scanMaxDepth"`
	ScanConcurrency             int                      `json:"scanConcurrency"`
	EnableStrategyStore         bool                     `json:"enableStrategyStore"`
	StrategyStoreFile           string                   `json:"strategyStoreFile"`
	StrategyFailToDowngrade     int                      `json:"strategyFailToDowngrade"`
	StrategySuccessToRecover    int                      `json:"strategySuccessToRecover"`
	StrategyCooldownMinutes     int                      `json:"strategyCooldownMinutes"`
	EnableBackgroundProbe       bool                     `json:"enableBackgroundProbe"`
	ProbeConcurrency            int                      `json:"probeConcurrency"`
	ProbeProviderConcurrency    int                      `json:"probeProviderConcurrency"`
	ProbeMinDelayMs             int                      `json:"probeMinDelayMs"`
	ProbeMaxDelayMs             int                      `json:"probeMaxDelayMs"`
	ProbeCooldownMinutes        int                      `json:"probeCooldownMinutes"`
	ProbeQueueSize              int                      `json:"probeQueueSize"`
	ProbeMinSizeBytes           int64                    `json:"probeMinSizeBytes"`
	PlayFirstFallback           bool                     `json:"playFirstFallback"`
}

// WebDAVServer represents a WebDAV server configuration
type WebDAVServer struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Describe   string       `json:"describe"`
	Path       string       `json:"path"`   // Regex path pattern
	Enable     bool         `json:"enable"` // Enable this WebDAV proxy
	ServerHost string       `json:"serverHost"`
	ServerPort int          `json:"serverPort"`
	HTTPS      bool         `json:"https"`
	PasswdList []PasswdInfo `json:"passwdList"`
}

// SchemeConfig represents server scheme configuration (extended)
type SchemeConfig struct {
	Address      string `json:"address"`
	HTTPPort     int    `json:"http_port"`
	HTTPSPort    int    `json:"https_port"`
	ForceHTTPS   bool   `json:"force_https"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	UnixFile     string `json:"unix_file"`
	UnixFilePerm string `json:"unix_file_perm"`
	EnableH2C    bool   `json:"enable_h2c"`
}

// ProxyConfig represents HTTP proxy client configuration
type ProxyConfig struct {
	MaxIdleConns        int  `json:"max_idle_conns"`
	MaxIdleConnsPerHost int  `json:"max_idle_conns_per_host"`
	MaxConnsPerHost     int  `json:"max_conns_per_host"`
	IdleConnTimeout     int  `json:"idle_conn_timeout"` // seconds
	EnableHTTP2         bool `json:"enable_http2"`
	InsecureSkipVerify  bool `json:"insecure_skip_verify"`
}

// LogConfig represents logging configuration
type LogConfig struct {
	Enable bool   `json:"enable"`
	Level  string `json:"level"`  // debug, info, warn, error
	Format string `json:"format"` // console, json
	Name   string `json:"name"`   // log file path
}

// DBConfig represents database configuration
type DBConfig struct {
	Type                   string `json:"type"` // mysql
	DSN                    string `json:"dsn"`
	MaxOpenConns           int    `json:"max_open_conns"`
	MaxIdleConns           int    `json:"max_idle_conns"`
	ConnMaxLifetimeSeconds int    `json:"conn_max_lifetime_seconds"`
	ConnMaxIdleSeconds     int    `json:"conn_max_idle_seconds"`
	FlushIntervalSeconds   int    `json:"flush_interval_seconds"`
	CleanupDays            int    `json:"cleanup_days"`
	CleanupIntervalHours   int    `json:"cleanup_interval_hours"`
	DisableCleanup         bool   `json:"disable_cleanup"`
}

// Config represents the main configuration (compatible with Node.js version)
type Config struct {
	// Core settings (compatible with original)
	AlistServer  AlistServer    `json:"alistServer"`
	WebDAVServer []WebDAVServer `json:"webdavServer"`
	Port         int            `json:"port"`

	// Extended settings
	Scheme    *SchemeConfig `json:"scheme,omitempty"`
	Proxy     *ProxyConfig  `json:"proxy,omitempty"`
	Log       *LogConfig    `json:"log,omitempty"`
	Database  *DBConfig     `json:"database,omitempty"`
	DataDir   string        `json:"data_dir,omitempty"`
	JWTSecret string        `json:"jwt_secret,omitempty"`
	JWTExpire int           `json:"jwt_expire,omitempty"`

	// Internal
	configPath string
	mu         sync.RWMutex
}

var (
	cfg     *Config
	cfgOnce sync.Once
)

// getDefaultAlistHost returns the default Alist host based on environment
func getDefaultAlistHost() string {
	// Check environment variable first (for Docker deployment)
	if host := os.Getenv("ALIST_HOST"); host != "" {
		return host
	}
	// Check if running in Docker (common indicators)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "alist" // Default Docker service name
	}
	return "localhost"
}

// getDefaultAlistPort returns the default Alist port from environment or default
func getDefaultAlistPort() int {
	if port := os.Getenv("ALIST_PORT"); port != "" {
		if p, err := fmt.Sscanf(port, "%d", new(int)); err == nil && p > 0 {
			var portNum int
			fmt.Sscanf(port, "%d", &portNum)
			return portNum
		}
	}
	return 5244
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		AlistServer: AlistServer{
			Name:                        "alist",
			Path:                        "/*",
			Describe:                    "alist config",
			ServerHost:                  getDefaultAlistHost(),
			ServerPort:                  getDefaultAlistPort(),
			HTTPS:                       false,
			EnableSizeMap:               true,
			SizeMapTtlMinutes:           1440,
			EnableRangeCompatCache:      true,
			RangeCompatTtlMinutes:       60,
			EnableParallelDecrypt:       false,
			ParallelDecryptConcurrency:  4,
			StreamBufferKb:              512,
			FollowRedirectForDecrypt:    true,
			RedirectMaxHops:             2,
			AllowLooseDecode:            false,
			RequestTimeoutSeconds:       20,
			EnableStartupProbe:          false,
			StartupProbeDelaySeconds:    5,
			StartupProbeIntervalMinutes: 0,
			NegativeCacheMinutes:        120,
			StartupProbeDeepScan:        false,
			ScanUsername:                "",
			ScanPassword:                "",
			ScanAuthHeader:              "",
			ScanVideoOnly:               true,
			ScanMaxDepth:                0,
			ScanConcurrency:             2,
			EnableStrategyStore:         true,
			StrategyStoreFile:           "",
			StrategyFailToDowngrade:     2,
			StrategySuccessToRecover:    5,
			StrategyCooldownMinutes:     30,
			EnableBackgroundProbe:       false,
			ProbeConcurrency:            4,
			ProbeProviderConcurrency:    1,
			ProbeMinDelayMs:             3000,
			ProbeMaxDelayMs:             15000,
			ProbeCooldownMinutes:        1440,
			ProbeQueueSize:              1000,
			ProbeMinSizeBytes:           100 * 1024 * 1024,
			PlayFirstFallback:           true,
			PasswdList: []PasswdInfo{
				{
					Password: "123456",
					Describe: "my video",
					EncType:  "aesctr",
					Enable:   true,
					EncName:  false,
					EncPath:  []string{"/encrypt/*"},
				},
			},
		},
		WebDAVServer: []WebDAVServer{},
		Port:         5344,
		Scheme: &SchemeConfig{
			Address:   "0.0.0.0",
			HTTPPort:  5344,
			HTTPSPort: -1,
			EnableH2C: false,
		},
		Proxy: &ProxyConfig{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     100,
			IdleConnTimeout:     90,
			EnableHTTP2:         true,
			InsecureSkipVerify:  false,
		},
		Log: &LogConfig{
			Enable: true,
			Level:  "info",
			Format: "console",
		},
		Database: &DBConfig{
			Type:                   "",
			DSN:                    "",
			MaxOpenConns:           10,
			MaxIdleConns:           5,
			ConnMaxLifetimeSeconds: 300,
			ConnMaxIdleSeconds:     60,
			FlushIntervalSeconds:   5,
			CleanupDays:            30,
			CleanupIntervalHours:   24,
			DisableCleanup:         false,
		},
		DataDir:   "./data",
		JWTSecret: "alist-encrypt-secret",
		JWTExpire: 48,
	}
}

// Load loads configuration from file
func Load() *Config {
	cfgOnce.Do(func() {
		cfg = DefaultConfig()

		// Find config file
		confDir := filepath.Join(getWorkDir(), "conf")
		configPath := filepath.Join(confDir, "config.json")

		// Ensure conf directory exists
		if err := os.MkdirAll(confDir, 0755); err != nil {
			log.Warn().Err(err).Msg("Failed to create conf directory")
		}

		// Try to load config file
		if data, err := os.ReadFile(configPath); err == nil {
			if err := json.Unmarshal(data, cfg); err != nil {
				log.Error().Err(err).Msg("Failed to parse config file")
			} else {
				log.Info().Str("path", configPath).Msg("Config loaded")
			}
		} else {
			// Create default config file
			log.Info().Msg("Config file not found, creating default")
			cfg.Save()
		}

		cfg.applyEnvOverrides()

		cfg.configPath = configPath

		// Apply port to scheme if not set
		if cfg.Scheme == nil {
			cfg.Scheme = &SchemeConfig{
				Address:   "0.0.0.0",
				HTTPPort:  cfg.Port,
				HTTPSPort: -1,
			}
		} else if cfg.Scheme.HTTPPort == 0 {
			cfg.Scheme.HTTPPort = cfg.Port
		}

		// Normalize/migrate historical encPath expansion pollution and persist once.
		if cfg.normalizeEncPaths() {
			if err := cfg.Save(); err != nil {
				log.Warn().Err(err).Msg("Failed to persist normalized encPath rules")
			}
		}
	})
	return cfg
}

func (c *Config) normalizeEncPaths() bool {
	changed := false
	if normalizePasswdListEncPaths(c.AlistServer.PasswdList) {
		changed = true
	}
	for i := range c.WebDAVServer {
		if normalizePasswdListEncPaths(c.WebDAVServer[i].PasswdList) {
			changed = true
		}
	}
	return changed
}

// Save saves configuration to file
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	configPath := c.configPath
	if configPath == "" {
		configPath = filepath.Join(getWorkDir(), "conf", "config.json")
	}

	// Create a snapshot for saving (without expanded paths)
	snapshot := &Config{
		AlistServer:  c.AlistServer,
		WebDAVServer: c.WebDAVServer,
		Port:         c.Port,
		Scheme:       c.Scheme,
		Proxy:        c.Proxy,
		Log:          c.Log,
		DataDir:      c.DataDir,
		JWTSecret:    c.JWTSecret,
		JWTExpire:    c.JWTExpire,
	}
	snapshot.normalizeEncPaths()

	data, err := json.MarshalIndent(snapshot, "", "\t")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

func (c *Config) applyEnvOverrides() {
	if c.Database == nil {
		c.Database = &DBConfig{}
	}

	if dbType := os.Getenv("DB_TYPE"); dbType != "" {
		c.Database.Type = dbType
	}
	if dsn := os.Getenv("DB_DSN"); dsn != "" {
		c.Database.DSN = dsn
	}
	if v, ok := getEnvBool("DB_DISABLE_CLEANUP"); ok {
		c.Database.DisableCleanup = v
	}

	if v, ok := getEnvBool("PROBE_ENABLE"); ok {
		c.AlistServer.EnableBackgroundProbe = v
	}
	if v, ok := getEnvInt("PROBE_CONCURRENCY"); ok {
		c.AlistServer.ProbeConcurrency = v
	}
	if v, ok := getEnvInt("PROBE_PROVIDER_CONCURRENCY"); ok {
		c.AlistServer.ProbeProviderConcurrency = v
	}
	if v, ok := getEnvInt("PROBE_MIN_DELAY_MS"); ok {
		c.AlistServer.ProbeMinDelayMs = v
	}
	if v, ok := getEnvInt("PROBE_MAX_DELAY_MS"); ok {
		c.AlistServer.ProbeMaxDelayMs = v
	}
	if v, ok := getEnvInt("PROBE_COOLDOWN_MINUTES"); ok {
		c.AlistServer.ProbeCooldownMinutes = v
	}
	if v, ok := getEnvInt("PROBE_QUEUE_SIZE"); ok {
		c.AlistServer.ProbeQueueSize = v
	}
	if v, ok := getEnvInt("PROBE_MIN_SIZE_BYTES"); ok {
		if v > 0 {
			c.AlistServer.ProbeMinSizeBytes = int64(v)
		}
	}
	if v, ok := getEnvBool("PLAY_FIRST_FALLBACK"); ok {
		c.AlistServer.PlayFirstFallback = v
	}
}

func getEnvBool(key string) (bool, bool) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return false, false
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

func getEnvInt(key string) (int, bool) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// Get returns the global config instance
func Get() *Config {
	if cfg == nil {
		return Load()
	}
	return cfg
}

// GetAlistURL returns the Alist base URL
func (c *Config) GetAlistURL() string {
	scheme := "http"
	if c.AlistServer.HTTPS {
		scheme = "https"
	}
	if c.AlistServer.ServerPort == 80 || c.AlistServer.ServerPort == 443 {
		return fmt.Sprintf("%s://%s", scheme, c.AlistServer.ServerHost)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, c.AlistServer.ServerHost, c.AlistServer.ServerPort)
}

// GetHTTPAddr returns the HTTP listen address
func (c *Config) GetHTTPAddr() string {
	if c.Scheme != nil {
		return fmt.Sprintf("%s:%d", c.Scheme.Address, c.Scheme.HTTPPort)
	}
	return fmt.Sprintf("0.0.0.0:%d", c.Port)
}

// GetHTTPSAddr returns the HTTPS listen address
func (c *Config) GetHTTPSAddr() string {
	if c.Scheme == nil || c.Scheme.HTTPSPort <= 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", c.Scheme.Address, c.Scheme.HTTPSPort)
}

// IsHTTPSEnabled returns whether HTTPS is enabled
func (c *Config) IsHTTPSEnabled() bool {
	return c.Scheme != nil && c.Scheme.HTTPSPort > 0 && c.Scheme.CertFile != "" && c.Scheme.KeyFile != ""
}

// IsH2CEnabled returns whether h2c is enabled
func (c *Config) IsH2CEnabled() bool {
	return c.Scheme != nil && c.Scheme.EnableH2C
}

// IsUnixSocketEnabled returns whether Unix socket is enabled
func (c *Config) IsUnixSocketEnabled() bool {
	return c.Scheme != nil && c.Scheme.UnixFile != ""
}

// UpdateAlistServer updates Alist server config and saves
func (c *Config) UpdateAlistServer(server AlistServer) error {
	normalizePasswdListEncPaths(server.PasswdList)
	c.mu.Lock()
	c.AlistServer = server
	c.mu.Unlock()

	return c.Save()
}

// AddWebDAVServer adds a new WebDAV server config
func (c *Config) AddWebDAVServer(server WebDAVServer) error {
	normalizePasswdListEncPaths(server.PasswdList)
	c.mu.Lock()
	c.WebDAVServer = append(c.WebDAVServer, server)
	c.mu.Unlock()
	return c.Save()
}

// UpdateWebDAVServer updates a WebDAV server config
func (c *Config) UpdateWebDAVServer(server WebDAVServer) error {
	normalizePasswdListEncPaths(server.PasswdList)
	c.mu.Lock()
	for i, s := range c.WebDAVServer {
		if s.ID == server.ID {
			c.WebDAVServer[i] = server
			break
		}
	}
	c.mu.Unlock()
	return c.Save()
}

// DeleteWebDAVServer deletes a WebDAV server config
func (c *Config) DeleteWebDAVServer(id string) error {
	c.mu.Lock()
	for i, s := range c.WebDAVServer {
		if s.ID == id {
			c.WebDAVServer = append(c.WebDAVServer[:i], c.WebDAVServer[i+1:]...)
			break
		}
	}
	c.mu.Unlock()
	return c.Save()
}

// UpdateScheme updates scheme configuration and saves
// Returns true if server restart is required (H2C changed)
func (c *Config) UpdateScheme(scheme SchemeConfig) (bool, error) {
	c.mu.Lock()
	oldH2C := c.Scheme != nil && c.Scheme.EnableH2C
	newH2C := scheme.EnableH2C
	needRestart := oldH2C != newH2C

	if c.Scheme == nil {
		c.Scheme = &SchemeConfig{}
	}
	*c.Scheme = scheme
	c.mu.Unlock()

	return needRestart, c.Save()
}

func getWorkDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}
