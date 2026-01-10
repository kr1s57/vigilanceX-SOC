package config

import (
	"log/slog"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	App         AppConfig
	ClickHouse  ClickHouseConfig
	Redis       RedisConfig
	Sophos      SophosConfig
	SophosSSH   SophosSSHConfig
	ThreatIntel ThreatIntelConfig
	JWT         JWTConfig
	Admin       AdminConfig
	License     LicenseConfig
	OSINTProxy  OSINTProxyConfig
	SMTP        SMTPConfig
}

// SMTPConfig holds SMTP email configuration
type SMTPConfig struct {
	Host       string
	Port       int
	Security   string // tls, ssl, none
	FromEmail  string
	Username   string
	Password   string
	Recipients []string
	Timeout    time.Duration
}

// LicenseConfig holds license server configuration
type LicenseConfig struct {
	ServerURL    string
	LicenseKey   string
	HeartbeatInt time.Duration
	GracePeriod  time.Duration
	Enabled      bool
	StorePath    string
}

// OSINTProxyConfig holds OSINT proxy configuration
type OSINTProxyConfig struct {
	Enabled   bool
	ServerURL string
	Timeout   time.Duration
	RateLimit int // requests per minute
}

type SophosSSHConfig struct {
	Host         string
	Port         int
	User         string
	KeyPath      string
	LogPath      string
	SyncInterval time.Duration
}

type AppConfig struct {
	Env  string
	Port int
	Host string
}

type ClickHouseConfig struct {
	Host     string
	Port     int
	HTTPPort int
	User     string
	Password string
	Database string
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

type SophosConfig struct {
	Host           string
	Port           int
	User           string
	Password       string
	BanGroup       string
	PermanentGroup string
	Timeout        time.Duration
}

type ThreatIntelConfig struct {
	// Tier 2 providers (moderate limits)
	AbuseIPDBKey string
	GreyNoiseKey string
	CrowdSecKey  string // v2.9.6: CrowdSec CTI API (50/day)
	// Tier 3 providers (limited)
	VirusTotalKey string
	CriminalIPKey string
	PulsediveKey  string
	// Tier 1: OTX needs key, others (IPSum, ThreatFox, URLhaus, ShodanIDB) don't
	AlienVaultKey string

	// Cache settings
	CacheTTL       time.Duration
	RateLimitDelay time.Duration

	// v2.9.5: Cascade configuration
	CascadeEnabled bool // Enable tiered cascade (saves API quota)
	Tier2Threshold int  // Score threshold to query Tier 2 (default: 30)
	Tier3Threshold int  // Score threshold to query Tier 3 (default: 60)
}

type JWTConfig struct {
	Secret string
	Expiry time.Duration
}

type AdminConfig struct {
	Username string
	Password string
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/app")
	viper.AddConfigPath("/etc/vigilancex")

	// Environment variables
	viper.AutomaticEnv()

	// Bind environment variables
	bindEnvVars()

	// Set defaults
	setDefaults()

	// Try to read config file (optional)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			slog.Warn("Error reading config file", "error", err)
		}
	}

	config := &Config{
		App: AppConfig{
			Env:  viper.GetString("APP_ENV"),
			Port: viper.GetInt("APP_PORT"),
			Host: viper.GetString("APP_HOST"),
		},
		ClickHouse: ClickHouseConfig{
			Host:     viper.GetString("CLICKHOUSE_HOST"),
			Port:     viper.GetInt("CLICKHOUSE_PORT"),
			HTTPPort: viper.GetInt("CLICKHOUSE_HTTP_PORT"),
			User:     viper.GetString("CLICKHOUSE_USER"),
			Password: viper.GetString("CLICKHOUSE_PASSWORD"),
			Database: viper.GetString("CLICKHOUSE_DATABASE"),
		},
		Redis: RedisConfig{
			Host:     viper.GetString("REDIS_HOST"),
			Port:     viper.GetInt("REDIS_PORT"),
			Password: viper.GetString("REDIS_PASSWORD"),
			DB:       viper.GetInt("REDIS_DB"),
		},
		Sophos: SophosConfig{
			Host:           viper.GetString("SOPHOS_HOST"),
			Port:           viper.GetInt("SOPHOS_PORT"),
			User:           viper.GetString("SOPHOS_USER"),
			Password:       viper.GetString("SOPHOS_PASSWORD"),
			BanGroup:       viper.GetString("SOPHOS_BAN_GROUP"),
			PermanentGroup: viper.GetString("SOPHOS_PERMANENT_GROUP"),
			Timeout:        viper.GetDuration("SOPHOS_TIMEOUT"),
		},
		ThreatIntel: ThreatIntelConfig{
			// Tier 2 providers (moderate limits)
			AbuseIPDBKey: viper.GetString("ABUSEIPDB_API_KEY"),
			GreyNoiseKey: viper.GetString("GREYNOISE_API_KEY"),
			CrowdSecKey:  viper.GetString("CROWDSEC_API_KEY"), // v2.9.6
			// Tier 3 providers (limited)
			VirusTotalKey: viper.GetString("VIRUSTOTAL_API_KEY"),
			CriminalIPKey: viper.GetString("CRIMINALIP_API_KEY"),
			PulsediveKey:  viper.GetString("PULSEDIVE_API_KEY"),
			// Tier 1: only OTX needs key
			AlienVaultKey: viper.GetString("ALIENVAULT_API_KEY"),
			// Cache settings
			CacheTTL:       viper.GetDuration("THREAT_INTEL_CACHE_TTL"),
			RateLimitDelay: viper.GetDuration("THREAT_INTEL_RATE_LIMIT"),
			// v2.9.5: Cascade configuration
			CascadeEnabled: viper.GetBool("CASCADE_ENABLED"),
			Tier2Threshold: viper.GetInt("CASCADE_TIER2_THRESHOLD"),
			Tier3Threshold: viper.GetInt("CASCADE_TIER3_THRESHOLD"),
		},
		JWT: JWTConfig{
			Secret: viper.GetString("JWT_SECRET"),
			Expiry: viper.GetDuration("JWT_EXPIRY"),
		},
		Admin: AdminConfig{
			Username: viper.GetString("ADMIN_USERNAME"),
			Password: viper.GetString("ADMIN_PASSWORD"),
		},
		SophosSSH: SophosSSHConfig{
			Host:         viper.GetString("SOPHOS_SSH_HOST"),
			Port:         viper.GetInt("SOPHOS_SSH_PORT"),
			User:         viper.GetString("SOPHOS_SSH_USER"),
			KeyPath:      viper.GetString("SOPHOS_SSH_KEY_PATH"),
			LogPath:      viper.GetString("SOPHOS_SSH_LOG_PATH"),
			SyncInterval: viper.GetDuration("SOPHOS_SSH_SYNC_INTERVAL"),
		},
		License: LicenseConfig{
			ServerURL:    viper.GetString("LICENSE_SERVER_URL"),
			LicenseKey:   viper.GetString("LICENSE_KEY"),
			HeartbeatInt: viper.GetDuration("LICENSE_HEARTBEAT_INTERVAL"),
			GracePeriod:  viper.GetDuration("LICENSE_GRACE_PERIOD"),
			Enabled:      viper.GetBool("LICENSE_ENABLED"),
			StorePath:    viper.GetString("LICENSE_STORE_PATH"),
		},
		OSINTProxy: OSINTProxyConfig{
			Enabled:   viper.GetBool("OSINT_PROXY_ENABLED"),
			ServerURL: viper.GetString("OSINT_PROXY_URL"),
			Timeout:   viper.GetDuration("OSINT_PROXY_TIMEOUT"),
			RateLimit: viper.GetInt("OSINT_PROXY_RATE_LIMIT"),
		},
		SMTP: SMTPConfig{
			Host:       viper.GetString("SMTP_HOST"),
			Port:       viper.GetInt("SMTP_PORT"),
			Security:   viper.GetString("SMTP_SECURITY"),
			FromEmail:  viper.GetString("SMTP_FROM_EMAIL"),
			Username:   viper.GetString("SMTP_USERNAME"),
			Password:   viper.GetString("SMTP_PASSWORD"),
			Recipients: viper.GetStringSlice("SMTP_RECIPIENTS"),
			Timeout:    viper.GetDuration("SMTP_TIMEOUT"),
		},
	}

	return config, nil
}

func bindEnvVars() {
	// App
	viper.BindEnv("APP_ENV")
	viper.BindEnv("APP_PORT")
	viper.BindEnv("APP_HOST")

	// ClickHouse
	viper.BindEnv("CLICKHOUSE_HOST")
	viper.BindEnv("CLICKHOUSE_PORT")
	viper.BindEnv("CLICKHOUSE_HTTP_PORT")
	viper.BindEnv("CLICKHOUSE_USER")
	viper.BindEnv("CLICKHOUSE_PASSWORD")
	viper.BindEnv("CLICKHOUSE_DATABASE")

	// Redis
	viper.BindEnv("REDIS_HOST")
	viper.BindEnv("REDIS_PORT")
	viper.BindEnv("REDIS_PASSWORD")
	viper.BindEnv("REDIS_DB")

	// Sophos
	viper.BindEnv("SOPHOS_HOST")
	viper.BindEnv("SOPHOS_PORT")
	viper.BindEnv("SOPHOS_USER")
	viper.BindEnv("SOPHOS_PASSWORD")
	viper.BindEnv("SOPHOS_BAN_GROUP")
	viper.BindEnv("SOPHOS_PERMANENT_GROUP")
	viper.BindEnv("SOPHOS_TIMEOUT")

	// Threat Intel - Tier 2 providers (moderate limits)
	viper.BindEnv("ABUSEIPDB_API_KEY")
	viper.BindEnv("GREYNOISE_API_KEY")
	viper.BindEnv("CROWDSEC_API_KEY") // v2.9.6
	// Threat Intel - Tier 3 providers (limited)
	viper.BindEnv("VIRUSTOTAL_API_KEY")
	viper.BindEnv("CRIMINALIP_API_KEY")
	viper.BindEnv("PULSEDIVE_API_KEY")
	// Threat Intel - Tier 1 (only OTX needs key)
	viper.BindEnv("ALIENVAULT_API_KEY")
	// Threat Intel - Cache settings
	viper.BindEnv("THREAT_INTEL_CACHE_TTL")
	viper.BindEnv("THREAT_INTEL_RATE_LIMIT")
	// Threat Intel - v2.9.5 Cascade configuration
	viper.BindEnv("CASCADE_ENABLED")
	viper.BindEnv("CASCADE_TIER2_THRESHOLD")
	viper.BindEnv("CASCADE_TIER3_THRESHOLD")

	// JWT
	viper.BindEnv("JWT_SECRET")
	viper.BindEnv("JWT_EXPIRY")

	// Admin
	viper.BindEnv("ADMIN_USERNAME")
	viper.BindEnv("ADMIN_PASSWORD")

	// Sophos SSH
	viper.BindEnv("SOPHOS_SSH_HOST")
	viper.BindEnv("SOPHOS_SSH_PORT")
	viper.BindEnv("SOPHOS_SSH_USER")
	viper.BindEnv("SOPHOS_SSH_KEY_PATH")
	viper.BindEnv("SOPHOS_SSH_LOG_PATH")
	viper.BindEnv("SOPHOS_SSH_SYNC_INTERVAL")

	// License
	viper.BindEnv("LICENSE_SERVER_URL")
	viper.BindEnv("LICENSE_KEY")
	viper.BindEnv("LICENSE_HEARTBEAT_INTERVAL")
	viper.BindEnv("LICENSE_GRACE_PERIOD")
	viper.BindEnv("LICENSE_ENABLED")
	viper.BindEnv("LICENSE_STORE_PATH")

	// OSINT Proxy
	viper.BindEnv("OSINT_PROXY_ENABLED")
	viper.BindEnv("OSINT_PROXY_URL")
	viper.BindEnv("OSINT_PROXY_TIMEOUT")
	viper.BindEnv("OSINT_PROXY_RATE_LIMIT")

	// SMTP
	viper.BindEnv("SMTP_HOST")
	viper.BindEnv("SMTP_PORT")
	viper.BindEnv("SMTP_SECURITY")
	viper.BindEnv("SMTP_FROM_EMAIL")
	viper.BindEnv("SMTP_USERNAME")
	viper.BindEnv("SMTP_PASSWORD")
	viper.BindEnv("SMTP_RECIPIENTS")
	viper.BindEnv("SMTP_TIMEOUT")
}

func setDefaults() {
	// App defaults
	viper.SetDefault("APP_ENV", "development")
	viper.SetDefault("APP_PORT", 8080)
	viper.SetDefault("APP_HOST", "0.0.0.0")

	// ClickHouse defaults
	viper.SetDefault("CLICKHOUSE_HOST", "localhost")
	viper.SetDefault("CLICKHOUSE_PORT", 9000)
	viper.SetDefault("CLICKHOUSE_HTTP_PORT", 8123)
	viper.SetDefault("CLICKHOUSE_USER", "vigilance")
	viper.SetDefault("CLICKHOUSE_DATABASE", "vigilance_x")

	// Redis defaults
	viper.SetDefault("REDIS_HOST", "localhost")
	viper.SetDefault("REDIS_PORT", 6379)
	viper.SetDefault("REDIS_DB", 0)

	// Sophos defaults
	viper.SetDefault("SOPHOS_PORT", 4444)
	viper.SetDefault("SOPHOS_BAN_GROUP", "VIGILANCE_X_BLOCKLIST")
	viper.SetDefault("SOPHOS_PERMANENT_GROUP", "VIGILANCE_X_PERMANENT")
	viper.SetDefault("SOPHOS_TIMEOUT", 30*time.Second)

	// Threat Intel defaults
	viper.SetDefault("THREAT_INTEL_CACHE_TTL", 24*time.Hour)
	viper.SetDefault("THREAT_INTEL_RATE_LIMIT", 200*time.Millisecond)
	// v2.9.5: Cascade defaults (enabled by default to save API quota)
	viper.SetDefault("CASCADE_ENABLED", true)
	viper.SetDefault("CASCADE_TIER2_THRESHOLD", 30) // Query Tier 2 if score >= 30
	viper.SetDefault("CASCADE_TIER3_THRESHOLD", 60) // Query Tier 3 if score >= 60

	// JWT defaults
	viper.SetDefault("JWT_EXPIRY", 24*time.Hour)
	viper.SetDefault("JWT_SECRET", "vigilancex-default-jwt-secret-change-me")

	// Admin defaults
	viper.SetDefault("ADMIN_USERNAME", "admin")
	viper.SetDefault("ADMIN_PASSWORD", "VigilanceX2024!")

	// Sophos SSH defaults
	viper.SetDefault("SOPHOS_SSH_PORT", 22)
	viper.SetDefault("SOPHOS_SSH_USER", "admin")
	viper.SetDefault("SOPHOS_SSH_KEY_PATH", "/root/.ssh/id_rsa_xgs")
	viper.SetDefault("SOPHOS_SSH_LOG_PATH", "/log/reverseproxy.log")
	viper.SetDefault("SOPHOS_SSH_SYNC_INTERVAL", 5*time.Minute)

	// License defaults
	viper.SetDefault("LICENSE_SERVER_URL", "http://10.56.126.126")
	viper.SetDefault("LICENSE_HEARTBEAT_INTERVAL", 12*time.Hour)
	viper.SetDefault("LICENSE_GRACE_PERIOD", 72*time.Hour) // v3.0: 3 days grace period (commercial distribution)
	viper.SetDefault("LICENSE_ENABLED", true)
	viper.SetDefault("LICENSE_STORE_PATH", "/app/data/license.json")

	// OSINT Proxy defaults
	viper.SetDefault("OSINT_PROXY_ENABLED", false)
	viper.SetDefault("OSINT_PROXY_TIMEOUT", 30*time.Second)
	viper.SetDefault("OSINT_PROXY_RATE_LIMIT", 60)

	// SMTP defaults
	viper.SetDefault("SMTP_HOST", "")
	viper.SetDefault("SMTP_PORT", 587)
	viper.SetDefault("SMTP_SECURITY", "tls")
	viper.SetDefault("SMTP_TIMEOUT", 30*time.Second)
}

func (c *Config) IsDevelopment() bool {
	return c.App.Env == "development"
}

func (c *Config) IsProduction() bool {
	return c.App.Env == "production"
}

func SetupLogger(cfg *Config) *slog.Logger {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if cfg.IsDevelopment() {
		opts.Level = slog.LevelDebug
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger
}
