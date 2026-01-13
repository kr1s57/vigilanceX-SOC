package apiusage

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
)

// Service manages API usage tracking across all providers
type Service struct {
	repo *clickhouse.APIUsageRepository
	mu   sync.RWMutex

	// Cache for API keys to avoid DB lookups on every request
	keyCache     map[string]string
	keyCacheTTL  time.Duration
	keyCacheTime map[string]time.Time
}

// NewService creates a new API usage service
func NewService(repo *clickhouse.APIUsageRepository) *Service {
	return &Service{
		repo:         repo,
		keyCache:     make(map[string]string),
		keyCacheTTL:  5 * time.Minute,
		keyCacheTime: make(map[string]time.Time),
	}
}

// GetAPIKey returns the API key for a provider (with caching)
func (s *Service) GetAPIKey(ctx context.Context, providerID string) (string, error) {
	s.mu.RLock()
	if key, ok := s.keyCache[providerID]; ok {
		if time.Since(s.keyCacheTime[providerID]) < s.keyCacheTTL {
			s.mu.RUnlock()
			return key, nil
		}
	}
	s.mu.RUnlock()

	// Fetch from DB
	key, err := s.repo.GetProviderAPIKey(ctx, providerID)
	if err != nil {
		return "", err
	}

	// Update cache
	s.mu.Lock()
	s.keyCache[providerID] = key
	s.keyCacheTime[providerID] = time.Now()
	s.mu.Unlock()

	return key, nil
}

// IsConfigured checks if a provider has an API key configured
func (s *Service) IsConfigured(ctx context.Context, providerID string) bool {
	key, err := s.GetAPIKey(ctx, providerID)
	return err == nil && key != ""
}

// CheckQuota checks if a provider has remaining quota
// Returns: (hasQuota, remainingQuota, error)
func (s *Service) CheckQuota(ctx context.Context, providerID string) (bool, int, error) {
	return s.repo.CheckQuota(ctx, providerID)
}

// RecordSuccess records a successful API request
func (s *Service) RecordSuccess(ctx context.Context, providerID string) {
	if err := s.repo.RecordSuccess(ctx, providerID); err != nil {
		slog.Warn("[API_USAGE] Failed to record success", "provider", providerID, "error", err)
	}
}

// RecordError records a failed API request
func (s *Service) RecordError(ctx context.Context, providerID, errorMessage string) {
	if err := s.repo.RecordError(ctx, providerID, errorMessage); err != nil {
		slog.Warn("[API_USAGE] Failed to record error", "provider", providerID, "error", err)
	}
}

// GetAllProvidersStatus returns status for all providers
func (s *Service) GetAllProvidersStatus(ctx context.Context) ([]clickhouse.APIProviderStatus, error) {
	return s.repo.GetAllProvidersStatus(ctx)
}

// GetProviderStatus returns status for a specific provider
func (s *Service) GetProviderStatus(ctx context.Context, providerID string) (*clickhouse.APIProviderStatus, error) {
	config, err := s.repo.GetProviderConfig(ctx, providerID)
	if err != nil {
		return nil, err
	}

	success, errors, _ := s.repo.GetTodayUsage(ctx, providerID)

	status := &clickhouse.APIProviderStatus{
		Config:       *config,
		TodaySuccess: success,
		TodayErrors:  errors,
		QuotaUsed:    success,
		QuotaMax:     config.DailyQuota,
		HasError:     config.LastErrorMessage != "" && config.LastError.After(config.LastSuccess),
	}

	// Mask API key
	if len(status.Config.APIKey) > 8 {
		status.Config.APIKey = status.Config.APIKey[:4] + "****" + status.Config.APIKey[len(status.Config.APIKey)-4:]
	} else if len(status.Config.APIKey) > 0 {
		status.Config.APIKey = "****"
	}

	return status, nil
}

// UpdateProviderAPIKey updates the API key for a provider
func (s *Service) UpdateProviderAPIKey(ctx context.Context, providerID, apiKey string) error {
	err := s.repo.UpdateProviderAPIKey(ctx, providerID, apiKey)
	if err != nil {
		return err
	}

	// Invalidate cache
	s.mu.Lock()
	delete(s.keyCache, providerID)
	delete(s.keyCacheTime, providerID)
	s.mu.Unlock()

	slog.Info("[API_USAGE] API key updated", "provider", providerID)
	return nil
}

// UpdateProviderQuota updates the daily quota for a provider
func (s *Service) UpdateProviderQuota(ctx context.Context, providerID string, quota int) error {
	return s.repo.UpdateProviderQuota(ctx, providerID, quota)
}

// UpdateProviderConfig updates full configuration for a provider
func (s *Service) UpdateProviderConfig(ctx context.Context, providerID string, apiKey string, quota int, enabled bool) error {
	config, err := s.repo.GetProviderConfig(ctx, providerID)
	if err != nil {
		// Create new config
		config = &clickhouse.APIProviderConfig{
			ProviderID:  providerID,
			DisplayName: providerID,
			Enabled:     true,
		}
	}

	// Only update API key if provided and not masked
	if apiKey != "" && !containsMask(apiKey) {
		config.APIKey = apiKey
		// Invalidate cache
		s.mu.Lock()
		delete(s.keyCache, providerID)
		delete(s.keyCacheTime, providerID)
		s.mu.Unlock()
	}

	config.DailyQuota = quota
	config.Enabled = enabled
	config.UpdatedAt = time.Now()

	return s.repo.UpdateProviderConfig(ctx, config)
}

// ExecuteWithTracking wraps an API call with quota checking and tracking
func (s *Service) ExecuteWithTracking(ctx context.Context, providerID string, fn func() error) error {
	// Check quota first
	hasQuota, remaining, err := s.CheckQuota(ctx, providerID)
	if err != nil {
		slog.Warn("[API_USAGE] Failed to check quota", "provider", providerID, "error", err)
		// Continue anyway - don't block on tracking errors
	} else if !hasQuota {
		errMsg := fmt.Sprintf("daily quota exceeded for %s (limit: %d)", providerID, remaining)
		s.RecordError(ctx, providerID, errMsg)
		return fmt.Errorf(errMsg)
	}

	// Execute the function
	startTime := time.Now()
	err = fn()
	duration := time.Since(startTime)

	if err != nil {
		s.RecordError(ctx, providerID, err.Error())
		slog.Debug("[API_USAGE] Request failed",
			"provider", providerID,
			"duration_ms", duration.Milliseconds(),
			"error", err)
		return err
	}

	s.RecordSuccess(ctx, providerID)
	slog.Debug("[API_USAGE] Request succeeded",
		"provider", providerID,
		"duration_ms", duration.Milliseconds())

	return nil
}

// containsMask checks if a string contains masking characters
func containsMask(s string) bool {
	for _, c := range s {
		if c == '*' {
			return true
		}
	}
	return false
}
