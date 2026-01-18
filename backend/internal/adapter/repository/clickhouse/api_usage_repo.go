package clickhouse

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// APIProviderConfig represents configuration for an API provider
type APIProviderConfig struct {
	ProviderID       string    `json:"provider_id"`
	APIKey           string    `json:"api_key"`
	DailyQuota       int       `json:"daily_quota"` // -1 = unlimited
	Enabled          bool      `json:"enabled"`
	LastSuccess      time.Time `json:"last_success"`
	LastError        time.Time `json:"last_error"`
	LastErrorMessage string    `json:"last_error_message"`
	DisplayName      string    `json:"display_name"`
	Description      string    `json:"description"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// APIUsageDaily represents daily usage statistics
type APIUsageDaily struct {
	ProviderID   string    `json:"provider_id"`
	Date         time.Time `json:"date"`
	SuccessCount int       `json:"success_count"`
	ErrorCount   int       `json:"error_count"`
}

// APIProviderStatus combines config with current usage
type APIProviderStatus struct {
	Config       APIProviderConfig `json:"config"`
	TodaySuccess int               `json:"today_success"`
	TodayErrors  int               `json:"today_errors"`
	QuotaUsed    int               `json:"quota_used"`
	QuotaMax     int               `json:"quota_max"` // -1 = unlimited
	HasError     bool              `json:"has_error"`
}

// APIUsageRepository handles API usage tracking in ClickHouse
type APIUsageRepository struct {
	conn *Connection
}

// NewAPIUsageRepository creates a new API usage repository
func NewAPIUsageRepository(conn *Connection) *APIUsageRepository {
	return &APIUsageRepository{conn: conn}
}

// GetProviderConfig retrieves configuration for a specific provider
func (r *APIUsageRepository) GetProviderConfig(ctx context.Context, providerID string) (*APIProviderConfig, error) {
	query := `
		SELECT
			provider_id,
			api_key,
			daily_quota,
			enabled,
			last_success,
			last_error,
			last_error_message,
			display_name,
			description,
			updated_at
		FROM vigilance_x.api_provider_config
		FINAL
		WHERE provider_id = ?
		LIMIT 1
	`

	var config APIProviderConfig
	var enabled uint8
	var dailyQuota int32

	row := r.conn.QueryRow(ctx, query, providerID)
	err := row.Scan(
		&config.ProviderID,
		&config.APIKey,
		&dailyQuota,
		&enabled,
		&config.LastSuccess,
		&config.LastError,
		&config.LastErrorMessage,
		&config.DisplayName,
		&config.Description,
		&config.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("get provider config: %w", err)
	}

	config.DailyQuota = int(dailyQuota)
	config.Enabled = enabled == 1

	return &config, nil
}

// GetAllProviderConfigs retrieves all provider configurations
func (r *APIUsageRepository) GetAllProviderConfigs(ctx context.Context) ([]APIProviderConfig, error) {
	query := `
		SELECT
			provider_id,
			api_key,
			daily_quota,
			enabled,
			last_success,
			last_error,
			last_error_message,
			display_name,
			description,
			updated_at
		FROM vigilance_x.api_provider_config
		FINAL
		ORDER BY display_name
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query provider configs: %w", err)
	}
	defer rows.Close()

	var configs []APIProviderConfig
	for rows.Next() {
		var config APIProviderConfig
		var enabled uint8
		var dailyQuota int32

		err := rows.Scan(
			&config.ProviderID,
			&config.APIKey,
			&dailyQuota,
			&enabled,
			&config.LastSuccess,
			&config.LastError,
			&config.LastErrorMessage,
			&config.DisplayName,
			&config.Description,
			&config.UpdatedAt,
		)
		if err != nil {
			continue
		}

		config.DailyQuota = int(dailyQuota)
		config.Enabled = enabled == 1
		configs = append(configs, config)
	}

	return configs, nil
}

// UpdateProviderConfig updates a provider's configuration
func (r *APIUsageRepository) UpdateProviderConfig(ctx context.Context, config *APIProviderConfig) error {
	// Get current version
	var currentVersion uint64
	row := r.conn.QueryRow(ctx,
		"SELECT max(version) FROM vigilance_x.api_provider_config WHERE provider_id = ?",
		config.ProviderID)
	if err := row.Scan(&currentVersion); err != nil {
		currentVersion = 0
	}

	enabled := uint8(0)
	if config.Enabled {
		enabled = 1
	}

	query := `
		INSERT INTO vigilance_x.api_provider_config (
			provider_id, api_key, daily_quota, enabled,
			last_success, last_error, last_error_message,
			display_name, description, updated_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, now(), ?)
	`

	err := r.conn.Exec(ctx, query,
		config.ProviderID,
		config.APIKey,
		config.DailyQuota,
		enabled,
		config.LastSuccess,
		config.LastError,
		config.LastErrorMessage,
		config.DisplayName,
		config.Description,
		currentVersion+1,
	)

	if err != nil {
		return fmt.Errorf("update provider config: %w", err)
	}

	slog.Info("[API_USAGE] Provider config updated",
		"provider", config.ProviderID,
		"enabled", config.Enabled,
		"quota", config.DailyQuota)

	return nil
}

// UpdateProviderAPIKey updates only the API key for a provider
func (r *APIUsageRepository) UpdateProviderAPIKey(ctx context.Context, providerID, apiKey string) error {
	config, err := r.GetProviderConfig(ctx, providerID)
	if err != nil {
		// Create new config if not exists
		config = &APIProviderConfig{
			ProviderID: providerID,
			DailyQuota: -1,
			Enabled:    true,
		}
	}

	config.APIKey = apiKey
	config.UpdatedAt = time.Now()

	return r.UpdateProviderConfig(ctx, config)
}

// UpdateProviderQuota updates the daily quota for a provider
func (r *APIUsageRepository) UpdateProviderQuota(ctx context.Context, providerID string, quota int) error {
	config, err := r.GetProviderConfig(ctx, providerID)
	if err != nil {
		return err
	}

	config.DailyQuota = quota
	config.UpdatedAt = time.Now()

	return r.UpdateProviderConfig(ctx, config)
}

// RecordSuccess records a successful API request
func (r *APIUsageRepository) RecordSuccess(ctx context.Context, providerID string) error {
	// Update daily counter
	err := r.conn.Exec(ctx, `
		INSERT INTO vigilance_x.api_usage_daily (provider_id, date, success_count, error_count, updated_at)
		VALUES (?, today(), 1, 0, now())
	`, providerID)
	if err != nil {
		slog.Warn("[API_USAGE] Failed to record success counter", "provider", providerID, "error", err)
	}

	// Update last success timestamp
	config, err := r.GetProviderConfig(ctx, providerID)
	if err == nil {
		config.LastSuccess = time.Now()
		config.LastErrorMessage = "" // Clear last error on success
		r.UpdateProviderConfig(ctx, config)
	}

	return nil
}

// RecordError records a failed API request
func (r *APIUsageRepository) RecordError(ctx context.Context, providerID, errorMessage string) error {
	// Update daily counter
	err := r.conn.Exec(ctx, `
		INSERT INTO vigilance_x.api_usage_daily (provider_id, date, success_count, error_count, updated_at)
		VALUES (?, today(), 0, 1, now())
	`, providerID)
	if err != nil {
		slog.Warn("[API_USAGE] Failed to record error counter", "provider", providerID, "error", err)
	}

	// Update last error timestamp and message
	config, err := r.GetProviderConfig(ctx, providerID)
	if err == nil {
		config.LastError = time.Now()
		config.LastErrorMessage = errorMessage
		r.UpdateProviderConfig(ctx, config)
	}

	return nil
}

// GetTodayUsage returns today's usage for a provider
func (r *APIUsageRepository) GetTodayUsage(ctx context.Context, providerID string) (successCount, errorCount int, err error) {
	query := `
		SELECT
			sum(success_count) as success,
			sum(error_count) as errors
		FROM vigilance_x.api_usage_daily
		WHERE provider_id = ? AND date = today()
	`

	var success, errors uint64
	row := r.conn.QueryRow(ctx, query, providerID)
	if err := row.Scan(&success, &errors); err != nil {
		return 0, 0, nil // No data for today
	}

	return int(success), int(errors), nil
}

// GetAllProvidersStatus returns status for all providers with today's usage
func (r *APIUsageRepository) GetAllProvidersStatus(ctx context.Context) ([]APIProviderStatus, error) {
	configs, err := r.GetAllProviderConfigs(ctx)
	if err != nil {
		return nil, err
	}

	var statuses []APIProviderStatus
	for _, config := range configs {
		success, errors, _ := r.GetTodayUsage(ctx, config.ProviderID)

		status := APIProviderStatus{
			Config:       config,
			TodaySuccess: success,
			TodayErrors:  errors,
			QuotaUsed:    success,
			QuotaMax:     config.DailyQuota,
			HasError:     config.LastErrorMessage != "" && config.LastError.After(config.LastSuccess),
		}

		// Mask API key for security
		if len(status.Config.APIKey) > 8 {
			status.Config.APIKey = status.Config.APIKey[:4] + "****" + status.Config.APIKey[len(status.Config.APIKey)-4:]
		} else if len(status.Config.APIKey) > 0 {
			status.Config.APIKey = "****"
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// CheckQuota checks if a provider has remaining quota
func (r *APIUsageRepository) CheckQuota(ctx context.Context, providerID string) (bool, int, error) {
	config, err := r.GetProviderConfig(ctx, providerID)
	if err != nil {
		return false, 0, err
	}

	// Unlimited quota
	if config.DailyQuota == -1 {
		return true, -1, nil
	}

	success, _, err := r.GetTodayUsage(ctx, providerID)
	if err != nil {
		return true, config.DailyQuota, nil
	}

	remaining := config.DailyQuota - success
	return remaining > 0, remaining, nil
}

// LogRequest logs a detailed API request (for debugging)
func (r *APIUsageRepository) LogRequest(ctx context.Context, providerID, endpoint string, success bool, responseTimeMs int, errorMessage, ipQueried, triggeredBy string) error {
	successInt := uint8(0)
	if success {
		successInt = 1
	}

	return r.conn.Exec(ctx, `
		INSERT INTO vigilance_x.api_request_log (
			provider_id, endpoint, success, response_time_ms,
			error_message, ip_queried, triggered_by
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, providerID, endpoint, successInt, responseTimeMs, errorMessage, ipQueried, triggeredBy)
}

// GetProviderAPIKey returns the API key for a provider (unmasked, for internal use)
func (r *APIUsageRepository) GetProviderAPIKey(ctx context.Context, providerID string) (string, error) {
	var apiKey string
	row := r.conn.QueryRow(ctx, `
		SELECT api_key FROM vigilance_x.api_provider_config FINAL WHERE provider_id = ?
	`, providerID)

	if err := row.Scan(&apiKey); err != nil {
		return "", err
	}

	return apiKey, nil
}

// IsProviderConfigured checks if a provider has an API key configured
func (r *APIUsageRepository) IsProviderConfigured(ctx context.Context, providerID string) bool {
	apiKey, err := r.GetProviderAPIKey(ctx, providerID)
	return err == nil && apiKey != ""
}

// DefaultProviderQuotas contains the default daily quotas for each TI provider
// v3.57.111: Initialize providers with correct quotas
var DefaultProviderQuotas = map[string]struct {
	DisplayName string
	DailyQuota  int // -1 = unlimited
}{
	"crowdsec_cti": {"CrowdSec CTI", 50},      // Free tier: 50/day
	"abuseipdb":    {"AbuseIPDB", 1000},       // Free tier: 1000/day
	"greynoise":    {"GreyNoise", 50},         // Community: 50/day
	"virustotal":   {"VirusTotal", 500},       // Public API: 500/day
	"criminalip":   {"Criminal IP", 500},      // Free tier: 500/day
	"pulsedive":    {"Pulsedive", 30},         // Free tier: 30/day
	"alienvault":   {"AlienVault OTX", -1},    // Unlimited (OTX)
	"ipsum":        {"IPsum", -1},             // Free list
	"threatfox":    {"ThreatFox", -1},         // Free API
	"urlhaus":      {"URLhaus", -1},           // Free API
	"shodan":       {"Shodan InternetDB", -1}, // Free InternetDB
}

// EnsureDefaultProviders creates provider configs with default quotas if they don't exist
// Also fixes existing providers that have incorrect quotas (e.g., -1 instead of 50)
// v3.57.111: Called at startup to ensure all providers have correct quota settings
func (r *APIUsageRepository) EnsureDefaultProviders(ctx context.Context) error {
	for providerID, info := range DefaultProviderQuotas {
		// Check if provider already exists
		existing, err := r.GetProviderConfig(ctx, providerID)
		if err == nil {
			// Provider exists - check if quota needs fixing
			// Only update if current quota is -1 (unlimited) but should have a limit
			if existing.DailyQuota == -1 && info.DailyQuota > 0 {
				existing.DailyQuota = info.DailyQuota
				existing.DisplayName = info.DisplayName
				existing.UpdatedAt = time.Now()
				if err := r.UpdateProviderConfig(ctx, existing); err != nil {
					slog.Warn("[API_USAGE] Failed to fix provider quota",
						"provider", providerID,
						"error", err)
				} else {
					slog.Info("[API_USAGE] Fixed provider quota",
						"provider", providerID,
						"quota", info.DailyQuota)
				}
			}
			continue
		}

		// Create provider with default quota
		config := &APIProviderConfig{
			ProviderID:  providerID,
			DisplayName: info.DisplayName,
			DailyQuota:  info.DailyQuota,
			Enabled:     true,
			UpdatedAt:   time.Now(),
		}

		if err := r.UpdateProviderConfig(ctx, config); err != nil {
			slog.Warn("[API_USAGE] Failed to create default provider config",
				"provider", providerID,
				"error", err)
		} else {
			slog.Info("[API_USAGE] Created default provider config",
				"provider", providerID,
				"quota", info.DailyQuota)
		}
	}

	return nil
}
