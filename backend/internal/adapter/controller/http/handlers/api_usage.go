package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
)

// APIUsageService interface for the API usage service
type APIUsageService interface {
	GetAllProvidersStatus(ctx context.Context) ([]clickhouse.APIProviderStatus, error)
	GetProviderStatus(ctx context.Context, providerID string) (*clickhouse.APIProviderStatus, error)
	UpdateProviderAPIKey(ctx context.Context, providerID, apiKey string) error
	UpdateProviderQuota(ctx context.Context, providerID string, quota int) error
	UpdateProviderConfig(ctx context.Context, providerID string, apiKey string, quota int, enabled bool) error
}

// APIUsageHandler handles API usage HTTP requests
type APIUsageHandler struct {
	service APIUsageService
}

// NewAPIUsageHandler creates a new handler
func NewAPIUsageHandler(service APIUsageService) *APIUsageHandler {
	return &APIUsageHandler{service: service}
}

// GetAllProviders returns status for all API providers
// GET /api/v1/integrations/providers
func (h *APIUsageHandler) GetAllProviders(w http.ResponseWriter, r *http.Request) {
	statuses, err := h.service.GetAllProvidersStatus(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get providers", err)
		return
	}

	if statuses == nil {
		statuses = []clickhouse.APIProviderStatus{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"providers": statuses,
	})
}

// GetProvider returns status for a specific provider
// GET /api/v1/integrations/providers/{id}
func (h *APIUsageHandler) GetProvider(w http.ResponseWriter, r *http.Request) {
	// Extract provider ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		ErrorResponse(w, http.StatusBadRequest, "Provider ID required", nil)
		return
	}
	providerID := parts[len(parts)-1]

	status, err := h.service.GetProviderStatus(r.Context(), providerID)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "Provider not found", err)
		return
	}

	JSONResponse(w, http.StatusOK, status)
}

// UpdateProviderRequest represents the request body for updating a provider
type UpdateProviderRequest struct {
	APIKey     string `json:"api_key"`
	DailyQuota int    `json:"daily_quota"` // -1 = unlimited
	Enabled    *bool  `json:"enabled"`
}

// UpdateProvider updates a provider's configuration
// PUT /api/v1/integrations/providers/{id}
func (h *APIUsageHandler) UpdateProvider(w http.ResponseWriter, r *http.Request) {
	// Extract provider ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		ErrorResponse(w, http.StatusBadRequest, "Provider ID required", nil)
		return
	}
	providerID := parts[len(parts)-1]

	var req UpdateProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Get current status to preserve values not being updated
	current, err := h.service.GetProviderStatus(r.Context(), providerID)
	if err != nil {
		// Provider doesn't exist - create with defaults
		current = &clickhouse.APIProviderStatus{
			Config: clickhouse.APIProviderConfig{
				ProviderID: providerID,
				DailyQuota: -1,
				Enabled:    true,
			},
		}
	}

	// Apply updates
	enabled := current.Config.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	quota := current.Config.DailyQuota
	if req.DailyQuota != 0 {
		quota = req.DailyQuota
	}

	err = h.service.UpdateProviderConfig(r.Context(), providerID, req.APIKey, quota, enabled)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to update provider", err)
		return
	}

	slog.Info("[API_USAGE] Provider updated via API",
		"provider", providerID,
		"enabled", enabled,
		"quota", quota)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Provider configuration updated",
	})
}

// UpdateAPIKey updates only the API key for a provider
// PUT /api/v1/integrations/providers/{id}/key
func (h *APIUsageHandler) UpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	// Extract provider ID from URL
	pathParts := strings.Split(r.URL.Path, "/")
	// Path is /api/v1/integrations/providers/{id}/key
	if len(pathParts) < 6 {
		ErrorResponse(w, http.StatusBadRequest, "Provider ID required", nil)
		return
	}
	providerID := pathParts[len(pathParts)-2] // Get ID before /key

	var req struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.APIKey == "" {
		ErrorResponse(w, http.StatusBadRequest, "API key required", nil)
		return
	}

	// Don't update if masked
	if strings.Contains(req.APIKey, "*") {
		ErrorResponse(w, http.StatusBadRequest, "Cannot update with masked key", nil)
		return
	}

	err := h.service.UpdateProviderAPIKey(r.Context(), providerID, req.APIKey)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to update API key", err)
		return
	}

	slog.Info("[API_USAGE] API key updated via API", "provider", providerID)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "API key updated",
	})
}

// UpdateQuota updates the daily quota for a provider
// PUT /api/v1/integrations/providers/{id}/quota
func (h *APIUsageHandler) UpdateQuota(w http.ResponseWriter, r *http.Request) {
	// Extract provider ID from URL
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 6 {
		ErrorResponse(w, http.StatusBadRequest, "Provider ID required", nil)
		return
	}
	providerID := pathParts[len(pathParts)-2]

	var req struct {
		DailyQuota int `json:"daily_quota"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	err := h.service.UpdateProviderQuota(r.Context(), providerID, req.DailyQuota)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to update quota", err)
		return
	}

	slog.Info("[API_USAGE] Quota updated via API",
		"provider", providerID,
		"quota", req.DailyQuota)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Daily quota updated",
	})
}
