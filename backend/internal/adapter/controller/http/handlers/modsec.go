package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kr1s57/vigilancex/internal/usecase/modsec"
)

// ModSecHandler handles ModSec-related requests
type ModSecHandler struct {
	service *modsec.Service
}

// NewModSecHandler creates a new ModSec handler
func NewModSecHandler(service *modsec.Service) *ModSecHandler {
	return &ModSecHandler{service: service}
}

// GetStats returns ModSec sync statistics
func (h *ModSecHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "ModSec sync service not configured", nil)
		return
	}

	stats := h.service.GetStats()
	response := map[string]interface{}{
		"last_sync":       stats.LastSync,
		"entries_fetched": stats.EntriesFetched,
		"events_updated":  stats.EventsUpdated,
		"last_error":      stats.LastError,
		"is_running":      stats.IsRunning,
		"is_configured":   h.service.IsConfigured(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// SyncNow triggers an immediate synchronization
func (h *ModSecHandler) SyncNow(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "ModSec sync service not configured", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	err := h.service.SyncNow(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Sync failed", err)
		return
	}

	stats := h.service.GetStats()
	response := map[string]interface{}{
		"message":         "Sync completed",
		"entries_fetched": stats.EntriesFetched,
		"events_updated":  stats.EventsUpdated,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// TestConnection tests the SSH connection to XGS
func (h *ModSecHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "ModSec sync service not configured", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	err := h.service.TestConnection(ctx)
	if err != nil {
		response := map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := map[string]interface{}{
		"status":  "ok",
		"message": "SSH connection successful",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
