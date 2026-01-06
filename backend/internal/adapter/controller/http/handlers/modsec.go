package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/kr1s57/vigilancex/internal/usecase/modsec"
)


// ModSecHandler handles ModSec-related requests
type ModSecHandler struct {
	service *modsec.Service
	repo    *clickhouse.ModSecRepository
}

// NewModSecHandler creates a new ModSec handler
func NewModSecHandler(service *modsec.Service, repo *clickhouse.ModSecRepository) *ModSecHandler {
	return &ModSecHandler{service: service, repo: repo}
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

// GetLogs returns ModSec logs with filters
func (h *ModSecHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	if h.repo == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "ModSec repository not configured", nil)
		return
	}

	// Parse query parameters
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))

	filters := entity.ModSecLogFilters{
		SrcIP:      q.Get("src_ip"),
		Hostname:   q.Get("hostname"),
		RuleID:     q.Get("rule_id"),
		AttackType: q.Get("attack_type"),
		UniqueID:   q.Get("unique_id"),
		SearchTerm: q.Get("search"),
	}

	// Parse time filters
	if startStr := q.Get("start_time"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			filters.StartTime = t
		}
	}
	if endStr := q.Get("end_time"); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			filters.EndTime = t
		}
	}

	logs, total, err := h.repo.GetLogs(r.Context(), filters, limit, offset)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch ModSec logs", err)
		return
	}

	response := map[string]interface{}{
		"data": logs,
		"pagination": map[string]interface{}{
			"total":    total,
			"limit":    limit,
			"offset":   offset,
			"has_more": uint64(offset+len(logs)) < total,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetGroupedLogs returns ModSec logs grouped by request (unique_id)
func (h *ModSecHandler) GetGroupedLogs(w http.ResponseWriter, r *http.Request) {
	if h.repo == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "ModSec repository not configured", nil)
		return
	}

	// Parse query parameters
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	offset, _ := strconv.Atoi(q.Get("offset"))

	filters := entity.ModSecLogFilters{
		SrcIP:      q.Get("src_ip"),
		Hostname:   q.Get("hostname"),
		RuleID:     q.Get("rule_id"),
		AttackType: q.Get("attack_type"),
		Country:    q.Get("country"),
		SearchTerm: q.Get("search"),
	}

	// Parse time filters
	if startStr := q.Get("start_time"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			filters.StartTime = t
		}
	}
	if endStr := q.Get("end_time"); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			filters.EndTime = t
		}
	}

	groups, total, err := h.repo.GetGroupedByRequest(r.Context(), filters, limit, offset)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch grouped ModSec logs", err)
		return
	}

	// Geolocation is now included in the query results directly
	response := map[string]interface{}{
		"data": groups,
		"pagination": map[string]interface{}{
			"total":    total,
			"limit":    limit,
			"offset":   offset,
			"has_more": uint64(offset+len(groups)) < total,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetHostnames returns unique hostnames from ModSec logs
func (h *ModSecHandler) GetHostnames(w http.ResponseWriter, r *http.Request) {
	if h.repo == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "ModSec repository not configured", nil)
		return
	}

	hostnames, err := h.repo.GetUniqueHostnames(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch hostnames", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hostnames)
}

// GetRuleStats returns statistics about ModSec rules
func (h *ModSecHandler) GetRuleStats(w http.ResponseWriter, r *http.Request) {
	if h.repo == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "ModSec repository not configured", nil)
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}

	stats, err := h.repo.GetRuleStats(r.Context(), period)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch rule stats", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GetAttackTypeStats returns statistics by attack type
func (h *ModSecHandler) GetAttackTypeStats(w http.ResponseWriter, r *http.Request) {
	if h.repo == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "ModSec repository not configured", nil)
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}

	stats, err := h.repo.GetAttackTypeStats(r.Context(), period)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch attack type stats", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
