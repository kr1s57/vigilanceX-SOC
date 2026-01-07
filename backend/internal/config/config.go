package config

import (
	"log/slog"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	App        AppConfig
	ClickHouse ClickHouseConfig
	Redis      RedisConfig
	Sophos     SophosConfig
	SophosSSH  SophosSSHConfig
	ThreatIntel ThreatIntelConfig
	JWT        JWTConfig
}

type SophosSSHConfig struct {
	Host       string
	Port       int
	User       string
	KeyPath    string
	LogPath    string
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
	// Core providers
	AbuseIPDBKey   string
	VirusTotalKey  string
	AlienVaultKey  string
	// v1.6 providers
	GreyNoiseKey   string
	CriminalIPKey  string
	PulsediveKey   string
	// IPSum doesn't need API key (public GitHub data)
	CacheTTL       time.Duration
	RateLimitDelay time.Duration
}

type JWTConfig struct {
	Secret string
	Expiry time.Duration
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
			// Core providers
			AbuseIPDBKey:   viper.GetString("ABUSEIPDB_API_KEY"),
			VirusTotalKey:  viper.GetString("VIRUSTOTAL_API_KEY"),
			AlienVaultKey:  viper.GetString("ALIENVAULT_API_KEY"),
			// v1.6 providers
			GreyNoiseKey:   viper.GetString("GREYNOISE_API_KEY"),
			CriminalIPKey:  viper.GetString("CRIMINALIP_API_KEY"),
			PulsediveKey:   viper.GetString("PULSEDIVE_API_KEY"),
			CacheTTL:       viper.GetDuration("THREAT_INTEL_CACHE_TTL"),
			RateLimitDelay: viper.GetDuration("THREAT_INTEL_RATE_LIMIT"),
		},
		JWT: JWTConfig{
			Secret: viper.GetString("JWT_SECRET"),
			Expiry: viper.GetDuration("JWT_EXPIRY"),
		},
		SophosSSH: SophosSSHConfig{
			Host:         viper.GetString("SOPHOS_SSH_HOST"),
			Port:         viper.GetInt("SOPHOS_SSH_PORT"),
			User:         viper.GetString("SOPHOS_SSH_USER"),
			KeyPath:      viper.GetString("SOPHOS_SSH_KEY_PATH"),
			LogPath:      viper.GetString("SOPHOS_SSH_LOG_PATH"),
			SyncInterval: viper.GetDuration("SOPHOS_SSH_SYNC_INTERVAL"),
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

	// Threat Intel - Core providers
	viper.BindEnv("ABUSEIPDB_API_KEY")
	viper.BindEnv("VIRUSTOTAL_API_KEY")
	viper.BindEnv("ALIENVAULT_API_KEY")
	// Threat Intel - v1.6 providers
	viper.BindEnv("GREYNOISE_API_KEY")
	viper.BindEnv("CRIMINALIP_API_KEY")
	viper.BindEnv("PULSEDIVE_API_KEY")
	viper.BindEnv("THREAT_INTEL_CACHE_TTL")
	viper.BindEnv("THREAT_INTEL_RATE_LIMIT")

	// JWT
	viper.BindEnv("JWT_SECRET")
	viper.BindEnv("JWT_EXPIRY")

	// Sophos SSH
	viper.BindEnv("SOPHOS_SSH_HOST")
	viper.BindEnv("SOPHOS_SSH_PORT")
	viper.BindEnv("SOPHOS_SSH_USER")
	viper.BindEnv("SOPHOS_SSH_KEY_PATH")
	viper.BindEnv("SOPHOS_SSH_LOG_PATH")
	viper.BindEnv("SOPHOS_SSH_SYNC_INTERVAL")
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

	// JWT defaults
	viper.SetDefault("JWT_EXPIRY", 24*time.Hour)

	// Sophos SSH defaults
	viper.SetDefault("SOPHOS_SSH_PORT", 22)
	viper.SetDefault("SOPHOS_SSH_USER", "admin")
	viper.SetDefault("SOPHOS_SSH_KEY_PATH", "/root/.ssh/id_rsa_xgs")
	viper.SetDefault("SOPHOS_SSH_LOG_PATH", "/log/reverseproxy.log")
	viper.SetDefault("SOPHOS_SSH_SYNC_INTERVAL", 5*time.Minute)
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
