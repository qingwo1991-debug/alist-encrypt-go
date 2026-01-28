package config

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// SchemeConfig represents server scheme configuration
type SchemeConfig struct {
	Address      string `json:"address" mapstructure:"address"`
	HTTPPort     int    `json:"http_port" mapstructure:"http_port"`
	HTTPSPort    int    `json:"https_port" mapstructure:"https_port"`
	ForceHTTPS   bool   `json:"force_https" mapstructure:"force_https"`
	CertFile     string `json:"cert_file" mapstructure:"cert_file"`
	KeyFile      string `json:"key_file" mapstructure:"key_file"`
	UnixFile     string `json:"unix_file" mapstructure:"unix_file"`
	UnixFilePerm string `json:"unix_file_perm" mapstructure:"unix_file_perm"`
	EnableH2C    bool   `json:"enable_h2c" mapstructure:"enable_h2c"`
}

// AlistConfig represents Alist server configuration
type AlistConfig struct {
	Host  string `json:"host" mapstructure:"host"`
	Port  int    `json:"port" mapstructure:"port"`
	HTTPS bool   `json:"https" mapstructure:"https"`
}

// CacheConfig represents cache configuration
type CacheConfig struct {
	Enable     bool `json:"enable" mapstructure:"enable"`
	Expiration int  `json:"expiration" mapstructure:"expiration"` // minutes
	CleanupInterval int `json:"cleanup_interval" mapstructure:"cleanup_interval"` // minutes
}

// ProxyConfig represents HTTP proxy client configuration
type ProxyConfig struct {
	MaxIdleConns        int  `json:"max_idle_conns" mapstructure:"max_idle_conns"`
	MaxIdleConnsPerHost int  `json:"max_idle_conns_per_host" mapstructure:"max_idle_conns_per_host"`
	MaxConnsPerHost     int  `json:"max_conns_per_host" mapstructure:"max_conns_per_host"`
	IdleConnTimeout     int  `json:"idle_conn_timeout" mapstructure:"idle_conn_timeout"` // seconds
	EnableHTTP2         bool `json:"enable_http2" mapstructure:"enable_http2"`
	InsecureSkipVerify  bool `json:"insecure_skip_verify" mapstructure:"insecure_skip_verify"`
}

// LogConfig represents logging configuration
type LogConfig struct {
	Level      string `json:"level" mapstructure:"level"`           // debug, info, warn, error
	Format     string `json:"format" mapstructure:"format"`         // console, json
	Output     string `json:"output" mapstructure:"output"`         // stdout, file path
	MaxSize    int    `json:"max_size" mapstructure:"max_size"`     // MB
	MaxBackups int    `json:"max_backups" mapstructure:"max_backups"`
	MaxAge     int    `json:"max_age" mapstructure:"max_age"`       // days
}

// Config represents the main configuration
type Config struct {
	Scheme    SchemeConfig `json:"scheme" mapstructure:"scheme"`
	Alist     AlistConfig  `json:"alist" mapstructure:"alist"`
	Cache     CacheConfig  `json:"cache" mapstructure:"cache"`
	Proxy     ProxyConfig  `json:"proxy" mapstructure:"proxy"`
	Log       LogConfig    `json:"log" mapstructure:"log"`
	DataDir   string       `json:"data_dir" mapstructure:"data_dir"`
	JWTSecret string       `json:"jwt_secret" mapstructure:"jwt_secret"`
	JWTExpire int          `json:"jwt_expire" mapstructure:"jwt_expire"` // hours

	// Deprecated: for backward compatibility
	Port       int    `json:"port,omitempty" mapstructure:"port"`
	AlistHost  string `json:"alist_host,omitempty" mapstructure:"alist_host"`
	AlistPort  int    `json:"alist_port,omitempty" mapstructure:"alist_port"`
	AlistHTTPS bool   `json:"alist_https,omitempty" mapstructure:"alist_https"`
	LogLevel   string `json:"log_level,omitempty" mapstructure:"log_level"`
}

// PasswdInfo represents encryption configuration for a path
type PasswdInfo struct {
	Password  string   `json:"password"`
	EncType   string   `json:"encType"`   // "aesctr" or "rc4md5"
	Path      string   `json:"path"`      // Base path (deprecated, use encPath)
	EncPath   []string `json:"encPath"`   // Regex patterns for path matching
	EncName   bool     `json:"encName"`   // Enable filename encryption
	EncSuffix string   `json:"encSuffix"` // Custom file extension
	Enable    bool     `json:"enable"`    // Enable this config
}

var (
	cfg  *Config
	once sync.Once
)

func Load() *Config {
	once.Do(func() {
		viper.SetConfigName("config")
		viper.SetConfigType("json")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./configs")
		viper.AddConfigPath("$HOME/.alist-encrypt")

		// Scheme defaults
		viper.SetDefault("scheme.address", "0.0.0.0")
		viper.SetDefault("scheme.http_port", 5344)
		viper.SetDefault("scheme.https_port", -1)
		viper.SetDefault("scheme.force_https", false)
		viper.SetDefault("scheme.enable_h2c", false)

		// Alist defaults
		viper.SetDefault("alist.host", "localhost")
		viper.SetDefault("alist.port", 5244)
		viper.SetDefault("alist.https", false)

		// Cache defaults
		viper.SetDefault("cache.enable", true)
		viper.SetDefault("cache.expiration", 10)
		viper.SetDefault("cache.cleanup_interval", 5)

		// Proxy defaults
		viper.SetDefault("proxy.max_idle_conns", 100)
		viper.SetDefault("proxy.max_idle_conns_per_host", 100)
		viper.SetDefault("proxy.max_conns_per_host", 100)
		viper.SetDefault("proxy.idle_conn_timeout", 90)
		viper.SetDefault("proxy.enable_http2", true)
		viper.SetDefault("proxy.insecure_skip_verify", false)

		// Log defaults
		viper.SetDefault("log.level", "info")
		viper.SetDefault("log.format", "console")
		viper.SetDefault("log.output", "stdout")

		// Other defaults
		viper.SetDefault("data_dir", "./data")
		viper.SetDefault("jwt_secret", "alist-encrypt-secret-change-me")
		viper.SetDefault("jwt_expire", 24)

		// Legacy defaults (for backward compatibility)
		viper.SetDefault("port", 5344)
		viper.SetDefault("alist_host", "localhost")
		viper.SetDefault("alist_port", 5244)
		viper.SetDefault("alist_https", false)
		viper.SetDefault("log_level", "info")

		// Environment variables
		viper.SetEnvPrefix("ALIST_ENCRYPT")
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		viper.AutomaticEnv()

		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				log.Warn().Msg("Config file not found, using defaults")
			} else {
				log.Error().Err(err).Msg("Error reading config file")
			}
		}

		cfg = &Config{}
		if err := viper.Unmarshal(cfg); err != nil {
			log.Fatal().Err(err).Msg("Failed to unmarshal config")
		}

		// Handle legacy config migration
		cfg.migrateFromLegacy()
	})
	return cfg
}

// migrateFromLegacy handles backward compatibility with old config format
func (c *Config) migrateFromLegacy() {
	// If new config is empty but legacy exists, migrate
	if c.Scheme.HTTPPort == 0 && c.Port > 0 {
		c.Scheme.HTTPPort = c.Port
	}
	if c.Alist.Host == "" && c.AlistHost != "" {
		c.Alist.Host = c.AlistHost
	}
	if c.Alist.Port == 0 && c.AlistPort > 0 {
		c.Alist.Port = c.AlistPort
	}
	if !c.Alist.HTTPS && c.AlistHTTPS {
		c.Alist.HTTPS = c.AlistHTTPS
	}
	if c.Log.Level == "" && c.LogLevel != "" {
		c.Log.Level = c.LogLevel
	}
}

func Get() *Config {
	if cfg == nil {
		return Load()
	}
	return cfg
}

// GetAlistURL returns the Alist base URL
func (c *Config) GetAlistURL() string {
	scheme := "http"
	if c.Alist.HTTPS {
		scheme = "https"
	}
	if c.Alist.Port == 80 || c.Alist.Port == 443 {
		return fmt.Sprintf("%s://%s", scheme, c.Alist.Host)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, c.Alist.Host, c.Alist.Port)
}

// GetHTTPAddr returns the HTTP listen address
func (c *Config) GetHTTPAddr() string {
	return fmt.Sprintf("%s:%d", c.Scheme.Address, c.Scheme.HTTPPort)
}

// GetHTTPSAddr returns the HTTPS listen address
func (c *Config) GetHTTPSAddr() string {
	if c.Scheme.HTTPSPort <= 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", c.Scheme.Address, c.Scheme.HTTPSPort)
}

// IsHTTPSEnabled returns whether HTTPS is enabled
func (c *Config) IsHTTPSEnabled() bool {
	return c.Scheme.HTTPSPort > 0 && c.Scheme.CertFile != "" && c.Scheme.KeyFile != ""
}

// IsUnixSocketEnabled returns whether Unix socket is enabled
func (c *Config) IsUnixSocketEnabled() bool {
	return c.Scheme.UnixFile != ""
}
