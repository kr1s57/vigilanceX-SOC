package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/usecase/blocklists"
)

// BlocklistsHandler handles blocklist-related HTTP requests
type BlocklistsHandler struct {
	service *blocklists.Service
}

// NewBlocklistsHandler creates a new blocklists handler
func NewBlocklistsHandler(service *blocklists.Service) *BlocklistsHandler {
	return &BlocklistsHandler{service: service}
}

// GetStats returns overall blocklist statistics
// GET /api/v1/blocklists/stats
func (h *BlocklistsHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.service.GetStats(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get blocklist stats", err)
		return
	}

	JSONResponse(w, http.StatusOK, stats)
}

// GetFeeds returns status of all configured feeds
// GET /api/v1/blocklists/feeds
func (h *BlocklistsHandler) GetFeeds(w http.ResponseWriter, r *http.Request) {
	statuses, err := h.service.GetFeedStatuses(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get feed statuses", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"feeds": statuses,
		"count": len(statuses),
	})
}

// SyncAll triggers a manual sync of all feeds
// POST /api/v1/blocklists/sync
func (h *BlocklistsHandler) SyncAll(w http.ResponseWriter, r *http.Request) {
	results, err := h.service.SyncAllFeeds(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to sync feeds", err)
		return
	}

	// Count successes
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"message":       "Sync completed",
		"total_feeds":   len(results),
		"success_count": successCount,
		"results":       results,
	})
}

// SyncFeed triggers a manual sync of a specific feed
// POST /api/v1/blocklists/feeds/{name}/sync
func (h *BlocklistsHandler) SyncFeed(w http.ResponseWriter, r *http.Request) {
	feedName := chi.URLParam(r, "name")
	if feedName == "" {
		ErrorResponse(w, http.StatusBadRequest, "Feed name required", nil)
		return
	}

	result, err := h.service.SyncFeed(r.Context(), feedName)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "Feed not found or sync failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, result)
}

// CheckIP checks if an IP is in any blocklist
// GET /api/v1/blocklists/check/{ip}
func (h *BlocklistsHandler) CheckIP(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		ErrorResponse(w, http.StatusBadRequest, "IP address required", nil)
		return
	}

	info, err := h.service.CheckIP(r.Context(), ip)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to check IP", err)
		return
	}

	JSONResponse(w, http.StatusOK, info)
}

// GetHighRiskIPs returns IPs that appear in multiple blocklists
// GET /api/v1/blocklists/high-risk?min_lists=2
func (h *BlocklistsHandler) GetHighRiskIPs(w http.ResponseWriter, r *http.Request) {
	minLists := 2
	if val := r.URL.Query().Get("min_lists"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed >= 2 {
			minLists = parsed
		}
	}

	ips, err := h.service.GetHighRiskIPs(r.Context(), minLists)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get high risk IPs", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"min_lists": minLists,
		"count":     len(ips),
		"ips":       ips,
	})
}

// GetConfiguredFeeds returns list of configured feeds
// GET /api/v1/blocklists/feeds/configured
func (h *BlocklistsHandler) GetConfiguredFeeds(w http.ResponseWriter, r *http.Request) {
	feeds := h.service.GetConfiguredFeeds()

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"feeds": feeds,
		"count": len(feeds),
	})
}
