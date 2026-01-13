package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/kr1s57/vigilancex/internal/adapter/external/crowdsec"
	cs "github.com/kr1s57/vigilancex/internal/usecase/crowdsec"
)

// CrowdSecBlocklistService interface for the blocklist service
type CrowdSecBlocklistService interface {
	GetConfig(ctx context.Context) (*cs.BlocklistConfig, error)
	UpdateConfig(ctx context.Context, config *cs.BlocklistConfig) error
	TestConnection(ctx context.Context) error
	ListAvailableBlocklists(ctx context.Context) ([]crowdsec.BlocklistInfo, error)
	ListSubscribedBlocklists(ctx context.Context) ([]crowdsec.BlocklistInfo, error)
	SyncBlocklist(ctx context.Context, blocklistID, blocklistName string) (*crowdsec.BlocklistSyncResult, error)
	SyncAllEnabled(ctx context.Context) ([]*crowdsec.BlocklistSyncResult, error)
	GetStatus(ctx context.Context) map[string]interface{}
	GetSyncHistory(ctx context.Context, limit int) ([]cs.SyncHistoryEntry, error)
	IsRunning() bool
}

// CrowdSecBlocklistHandler handles CrowdSec blocklist HTTP requests
type CrowdSecBlocklistHandler struct {
	service CrowdSecBlocklistService
}

// NewCrowdSecBlocklistHandler creates a new handler
func NewCrowdSecBlocklistHandler(service CrowdSecBlocklistService) *CrowdSecBlocklistHandler {
	return &CrowdSecBlocklistHandler{service: service}
}

// GetConfig returns the current CrowdSec blocklist configuration
// GET /api/v1/crowdsec/blocklist/config
func (h *CrowdSecBlocklistHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.service.GetConfig(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get config", err)
		return
	}

	// Mask API key for security
	maskedConfig := *config
	if len(maskedConfig.APIKey) > 8 {
		maskedConfig.APIKey = maskedConfig.APIKey[:4] + "****" + maskedConfig.APIKey[len(maskedConfig.APIKey)-4:]
	} else if len(maskedConfig.APIKey) > 0 {
		maskedConfig.APIKey = "****"
	}

	JSONResponse(w, http.StatusOK, maskedConfig)
}

// UpdateConfig updates the CrowdSec blocklist configuration
// PUT /api/v1/crowdsec/blocklist/config
func (h *CrowdSecBlocklistHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Get existing config
	config, err := h.service.GetConfig(r.Context())
	if err != nil {
		config = &cs.BlocklistConfig{
			SyncIntervalHours: 6,
			XGSGroupName:      "grp_VGX-CrowdSec",
		}
	}

	// Apply updates
	if v, ok := updates["enabled"]; ok {
		config.Enabled = v.(bool)
	}
	if v, ok := updates["api_key"]; ok {
		apiKey := v.(string)
		// Only update if not masked
		if apiKey != "" && apiKey != "****" && !containsMask(apiKey) {
			config.APIKey = apiKey
		}
	}
	if v, ok := updates["sync_interval_hours"]; ok {
		config.SyncIntervalHours = int(v.(float64))
	}
	if v, ok := updates["xgs_group_name"]; ok {
		config.XGSGroupName = v.(string)
	}
	if v, ok := updates["enabled_lists"]; ok {
		lists := v.([]interface{})
		config.EnabledLists = make([]string, len(lists))
		for i, l := range lists {
			config.EnabledLists[i] = l.(string)
		}
	}

	if err := h.service.UpdateConfig(r.Context(), config); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to save config", err)
		return
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Config updated",
		"enabled", config.Enabled,
		"enabled_lists", len(config.EnabledLists))

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "CrowdSec blocklist configuration updated",
	})
}

// TestConnection tests the CrowdSec API connection
// POST /api/v1/crowdsec/blocklist/test
func (h *CrowdSecBlocklistHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	err := h.service.TestConnection(r.Context())
	if err != nil {
		slog.Error("[CROWDSEC_BLOCKLIST] Connection test failed", "error", err)
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Connection test successful")
	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "CrowdSec API connection successful",
	})
}

// ListBlocklists returns available and subscribed blocklists
// GET /api/v1/crowdsec/blocklist/lists
func (h *CrowdSecBlocklistHandler) ListBlocklists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get subscribed blocklists
	subscribed, err := h.service.ListSubscribedBlocklists(ctx)
	if err != nil {
		slog.Warn("[CROWDSEC_BLOCKLIST] Failed to list subscribed blocklists", "error", err)
		subscribed = []crowdsec.BlocklistInfo{}
	}

	// Also try to get all available (might fail if no permission)
	available, err := h.service.ListAvailableBlocklists(ctx)
	if err != nil {
		slog.Warn("[CROWDSEC_BLOCKLIST] Failed to list available blocklists", "error", err)
		available = []crowdsec.BlocklistInfo{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"subscribed": subscribed,
		"available":  available,
	})
}

// SyncBlocklist triggers a sync for a specific blocklist
// POST /api/v1/crowdsec/blocklist/sync/{id}
func (h *CrowdSecBlocklistHandler) SyncBlocklist(w http.ResponseWriter, r *http.Request) {
	// Extract blocklist ID from URL
	blocklistID := r.URL.Path[len("/api/v1/crowdsec/blocklist/sync/"):]
	if blocklistID == "" {
		ErrorResponse(w, http.StatusBadRequest, "Blocklist ID required", nil)
		return
	}

	// Get blocklist name from query param or body
	blocklistName := r.URL.Query().Get("name")
	if blocklistName == "" {
		blocklistName = blocklistID
	}

	if h.service.IsRunning() {
		ErrorResponse(w, http.StatusConflict, "Sync already in progress", nil)
		return
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Manual sync triggered", "blocklist_id", blocklistID)

	result, err := h.service.SyncBlocklist(r.Context(), blocklistID, blocklistName)
	if err != nil {
		slog.Error("[CROWDSEC_BLOCKLIST] Sync failed", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Sync failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  result,
	})
}

// SyncAll triggers a sync for all enabled blocklists
// POST /api/v1/crowdsec/blocklist/sync
func (h *CrowdSecBlocklistHandler) SyncAll(w http.ResponseWriter, r *http.Request) {
	if h.service.IsRunning() {
		ErrorResponse(w, http.StatusConflict, "Sync already in progress", nil)
		return
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Sync all triggered")

	results, err := h.service.SyncAllEnabled(r.Context())
	if err != nil {
		slog.Error("[CROWDSEC_BLOCKLIST] Sync all failed", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Sync failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"results": results,
	})
}

// GetStatus returns the current service status
// GET /api/v1/crowdsec/blocklist/status
func (h *CrowdSecBlocklistHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := h.service.GetStatus(r.Context())
	JSONResponse(w, http.StatusOK, status)
}

// GetHistory returns sync history
// GET /api/v1/crowdsec/blocklist/history
func (h *CrowdSecBlocklistHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	history, err := h.service.GetSyncHistory(r.Context(), 50)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get history", err)
		return
	}

	if history == nil {
		history = []cs.SyncHistoryEntry{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"history": history,
	})
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
