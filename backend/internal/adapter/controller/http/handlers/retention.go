package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// RetentionService interface for retention operations
type RetentionService interface {
	GetSettings(ctx context.Context) (*entity.RetentionSettings, error)
	UpdateSettings(ctx context.Context, settings *entity.RetentionSettings, updatedBy string) error
	RunCleanup(ctx context.Context, settings *entity.RetentionSettings) *entity.CleanupResult
	GetStorageStats(ctx context.Context) (*entity.StorageStats, error)
	IsRunning() bool
}

// RetentionHandler handles retention HTTP requests
type RetentionHandler struct {
	service RetentionService
}

// NewRetentionHandler creates a new retention handler
func NewRetentionHandler(service RetentionService) *RetentionHandler {
	return &RetentionHandler{service: service}
}

// GetSettings returns the current retention settings
// GET /api/v1/retention/settings
func (h *RetentionHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.service.GetSettings(r.Context())
	if err != nil {
		settings = entity.DefaultRetentionSettings()
	}

	JSONResponse(w, http.StatusOK, settings)
}

// UpdateSettings updates the retention settings
// PUT /api/v1/retention/settings
func (h *RetentionHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	// First get existing settings to merge with
	existingSettings, err := h.service.GetSettings(r.Context())
	if err != nil {
		existingSettings = entity.DefaultRetentionSettings()
	}

	// Decode partial update into a map to know which fields were sent
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Apply updates to existing settings
	if v, ok := updates["retention_enabled"]; ok {
		existingSettings.RetentionEnabled = v.(bool)
	}
	if v, ok := updates["events_retention_days"]; ok {
		existingSettings.EventsRetentionDays = int(v.(float64))
	}
	if v, ok := updates["modsec_logs_retention_days"]; ok {
		existingSettings.ModsecLogsRetentionDays = int(v.(float64))
	}
	if v, ok := updates["firewall_events_retention_days"]; ok {
		existingSettings.FirewallEventsRetentionDays = int(v.(float64))
	}
	if v, ok := updates["vpn_events_retention_days"]; ok {
		existingSettings.VpnEventsRetentionDays = int(v.(float64))
	}
	if v, ok := updates["heartbeat_events_retention_days"]; ok {
		existingSettings.HeartbeatEventsRetentionDays = int(v.(float64))
	}
	if v, ok := updates["atp_events_retention_days"]; ok {
		existingSettings.AtpEventsRetentionDays = int(v.(float64))
	}
	if v, ok := updates["antivirus_events_retention_days"]; ok {
		existingSettings.AntivirusEventsRetentionDays = int(v.(float64))
	}
	if v, ok := updates["ban_history_retention_days"]; ok {
		existingSettings.BanHistoryRetentionDays = int(v.(float64))
	}
	if v, ok := updates["audit_log_retention_days"]; ok {
		existingSettings.AuditLogRetentionDays = int(v.(float64))
	}
	if v, ok := updates["cleanup_interval_hours"]; ok {
		existingSettings.CleanupIntervalHours = int(v.(float64))
	}

	// Get username from context (set by auth middleware)
	username := "admin"
	if u, ok := r.Context().Value("username").(string); ok {
		username = u
	}

	slog.Info("[RETENTION] Updating settings",
		"events_days", existingSettings.EventsRetentionDays,
		"enabled", existingSettings.RetentionEnabled,
		"updated_by", username)

	if err := h.service.UpdateSettings(r.Context(), existingSettings, username); err != nil {
		slog.Error("[RETENTION] Failed to save settings", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	slog.Info("[RETENTION] Settings saved successfully")

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"message":  "Retention settings updated",
		"settings": existingSettings,
	})
}

// RunCleanup triggers a manual cleanup
// POST /api/v1/retention/cleanup
func (h *RetentionHandler) RunCleanup(w http.ResponseWriter, r *http.Request) {
	slog.Info("[RETENTION] Manual cleanup requested")

	result := h.service.RunCleanup(r.Context(), nil)

	if !result.Success {
		slog.Error("[RETENTION] Manual cleanup failed", "error", result.Error)
		ErrorResponse(w, http.StatusInternalServerError, "Cleanup failed", nil)
		return
	}

	slog.Info("[RETENTION] Manual cleanup completed",
		"total_deleted", result.TotalDeleted,
		"duration_ms", result.EndTime.Sub(result.StartTime).Milliseconds())

	JSONResponse(w, http.StatusOK, result)
}

// GetStorageStats returns storage usage statistics
// GET /api/v1/retention/storage
func (h *RetentionHandler) GetStorageStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.service.GetStorageStats(r.Context())
	if err != nil {
		slog.Error("[RETENTION] Failed to get storage stats", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get storage stats", err)
		return
	}

	JSONResponse(w, http.StatusOK, stats)
}

// GetStatus returns the retention service status
// GET /api/v1/retention/status
func (h *RetentionHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	settings, err := h.service.GetSettings(r.Context())
	if err != nil {
		settings = entity.DefaultRetentionSettings()
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"worker_running": h.service.IsRunning(),
		"enabled":        settings.RetentionEnabled,
		"last_cleanup":   settings.LastCleanup,
		"next_cleanup":   settings.LastCleanup.Add(time.Duration(settings.CleanupIntervalHours) * time.Hour),
		"interval_hours": settings.CleanupIntervalHours,
	})
}
