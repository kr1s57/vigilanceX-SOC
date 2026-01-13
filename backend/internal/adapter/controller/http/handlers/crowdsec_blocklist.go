package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/kr1s57/vigilancex/internal/adapter/external/crowdsec"
	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/entity"
	cs "github.com/kr1s57/vigilancex/internal/usecase/crowdsec"
)

// CrowdSecBlocklistService interface for the blocklist service (Phase 1)
type CrowdSecBlocklistService interface {
	GetConfig(ctx context.Context) (*cs.BlocklistConfig, error)
	UpdateConfig(ctx context.Context, config *cs.BlocklistConfig) error
	TestConnection(ctx context.Context) error
	ListBlocklists(ctx context.Context) (available []crowdsec.BlocklistInfo, subscribed []crowdsec.BlocklistInfo, err error)
	SyncBlocklist(ctx context.Context, blocklistID, blocklistLabel string) (*cs.SyncResult, error)
	SyncAll(ctx context.Context) ([]*cs.SyncResult, error)
	GetStatus(ctx context.Context) map[string]interface{}
	GetSyncHistory(ctx context.Context, limit int) ([]cs.SyncHistoryEntry, error)
	GetAllIPs(ctx context.Context) ([]cs.BlocklistIP, error)
	IsRunning() bool
}

// CrowdSecBlocklistRepository interface for direct DB access
type CrowdSecBlocklistRepository interface {
	GetIPsPaginated(ctx context.Context, query clickhouse.IPListQuery) (*clickhouse.IPListResult, error)
	GetBlocklistSummary(ctx context.Context) ([]map[string]interface{}, error)
	GetUniqueCountries(ctx context.Context) ([]string, error)
	GetIPsWithoutCountry(ctx context.Context, limit int) ([]string, error)
	UpdateIPCountry(ctx context.Context, ip, countryCode string) error
}

// CrowdSecGeoIPClient interface for geolocation lookups
type CrowdSecGeoIPClient interface {
	Lookup(ctx context.Context, ip string) (*entity.GeoLocation, error)
}

// CrowdSecBlocklistHandler handles CrowdSec blocklist HTTP requests
type CrowdSecBlocklistHandler struct {
	service   CrowdSecBlocklistService
	repo      CrowdSecBlocklistRepository
	geoClient CrowdSecGeoIPClient
}

// NewCrowdSecBlocklistHandler creates a new handler
func NewCrowdSecBlocklistHandler(service CrowdSecBlocklistService, repo CrowdSecBlocklistRepository) *CrowdSecBlocklistHandler {
	return &CrowdSecBlocklistHandler{service: service, repo: repo}
}

// SetGeoIPClient sets the GeoIP client for country enrichment
func (h *CrowdSecBlocklistHandler) SetGeoIPClient(client CrowdSecGeoIPClient) {
	h.geoClient = client
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
	response := map[string]interface{}{
		"enabled":               config.Enabled,
		"sync_interval_minutes": config.SyncIntervalMinutes,
		"last_sync":             config.LastSync,
		"total_ips":             config.TotalIPs,
		"total_blocklists":      config.TotalBlocklists,
	}

	// Mask API key
	if len(config.APIKey) > 8 {
		response["api_key"] = config.APIKey[:4] + "****" + config.APIKey[len(config.APIKey)-4:]
	} else if len(config.APIKey) > 0 {
		response["api_key"] = "****"
	} else {
		response["api_key"] = ""
	}

	JSONResponse(w, http.StatusOK, response)
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
			SyncIntervalMinutes: 120,
		}
	}

	// Apply updates
	if v, ok := updates["enabled"]; ok {
		config.Enabled = v.(bool)
	}
	if v, ok := updates["api_key"]; ok {
		apiKey := v.(string)
		// Only update if not masked
		if apiKey != "" && !containsMask(apiKey) {
			config.APIKey = apiKey
		}
	}
	if v, ok := updates["sync_interval_minutes"]; ok {
		config.SyncIntervalMinutes = int(v.(float64))
	}

	if err := h.service.UpdateConfig(r.Context(), config); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to save config", err)
		return
	}

	slog.Info("[CROWDSEC_BL_API] Config updated", "enabled", config.Enabled)

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
		slog.Error("[CROWDSEC_BL_API] Connection test failed", "error", err)
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	slog.Info("[CROWDSEC_BL_API] Connection test successful")
	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "CrowdSec API connection successful",
	})
}

// ListBlocklists returns available and subscribed blocklists
// GET /api/v1/crowdsec/blocklist/lists
func (h *CrowdSecBlocklistHandler) ListBlocklists(w http.ResponseWriter, r *http.Request) {
	available, subscribed, err := h.service.ListBlocklists(r.Context())
	if err != nil {
		slog.Warn("[CROWDSEC_BL_API] Failed to list blocklists", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to list blocklists", err)
		return
	}

	if available == nil {
		available = []crowdsec.BlocklistInfo{}
	}
	if subscribed == nil {
		subscribed = []crowdsec.BlocklistInfo{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"available":  available,
		"subscribed": subscribed,
	})
}

// SyncAll triggers a sync for all subscribed blocklists
// POST /api/v1/crowdsec/blocklist/sync
func (h *CrowdSecBlocklistHandler) SyncAll(w http.ResponseWriter, r *http.Request) {
	if h.service.IsRunning() {
		ErrorResponse(w, http.StatusConflict, "Sync already in progress", nil)
		return
	}

	slog.Info("[CROWDSEC_BL_API] Sync all triggered")

	results, err := h.service.SyncAll(r.Context())
	if err != nil {
		slog.Error("[CROWDSEC_BL_API] Sync all failed", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Sync failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"results": results,
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

	// Get blocklist name from query param
	blocklistLabel := r.URL.Query().Get("label")
	if blocklistLabel == "" {
		blocklistLabel = blocklistID
	}

	if h.service.IsRunning() {
		ErrorResponse(w, http.StatusConflict, "Sync already in progress", nil)
		return
	}

	slog.Info("[CROWDSEC_BL_API] Manual sync triggered", "blocklist_id", blocklistID)

	result, err := h.service.SyncBlocklist(r.Context(), blocklistID, blocklistLabel)
	if err != nil {
		slog.Error("[CROWDSEC_BL_API] Sync failed", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Sync failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  result,
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

// GetIPs returns all IPs from the blocklist database
// GET /api/v1/crowdsec/blocklist/ips
func (h *CrowdSecBlocklistHandler) GetIPs(w http.ResponseWriter, r *http.Request) {
	ips, err := h.service.GetAllIPs(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get IPs", err)
		return
	}

	if ips == nil {
		ips = []cs.BlocklistIP{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"ips":   ips,
		"count": len(ips),
	})
}

// EnrichedBlocklistIP represents a blocklist IP with country info
type EnrichedBlocklistIP struct {
	IP             string `json:"ip"`
	BlocklistID    string `json:"blocklist_id"`
	BlocklistLabel string `json:"blocklist_label"`
	FirstSeen      string `json:"first_seen"`
	LastSeen       string `json:"last_seen"`
	CountryCode    string `json:"country_code"`
	CountryName    string `json:"country_name"`
}

// GetIPsPaginated returns IPs with pagination, search and filters
// GET /api/v1/crowdsec/blocklist/ips/list
func (h *CrowdSecBlocklistHandler) GetIPsPaginated(w http.ResponseWriter, r *http.Request) {
	if h.repo == nil {
		ErrorResponse(w, http.StatusInternalServerError, "Repository not configured", nil)
		return
	}

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	search := r.URL.Query().Get("search")
	blocklistID := r.URL.Query().Get("blocklist_id")
	countryFilter := r.URL.Query().Get("country")

	// Default values
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	// Query with country filter (now stored in DB)
	query := clickhouse.IPListQuery{
		Page:        page,
		PageSize:    pageSize,
		Search:      search,
		BlocklistID: blocklistID,
		Country:     countryFilter,
	}

	result, err := h.repo.GetIPsPaginated(r.Context(), query)
	if err != nil {
		slog.Error("[CROWDSEC_BL_API] Failed to get paginated IPs", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get IPs", err)
		return
	}

	// Format IPs for response (country already in DB)
	var enrichedIPs []EnrichedBlocklistIP
	for _, ip := range result.IPs {
		enriched := EnrichedBlocklistIP{
			IP:             ip.IP,
			BlocklistID:    ip.BlocklistID,
			BlocklistLabel: ip.BlocklistLabel,
			FirstSeen:      ip.FirstSeen.Format("2006-01-02T15:04:05Z"),
			LastSeen:       ip.LastSeen.Format("2006-01-02T15:04:05Z"),
			CountryCode:    ip.CountryCode,
		}
		enrichedIPs = append(enrichedIPs, enriched)
	}

	if enrichedIPs == nil {
		enrichedIPs = []EnrichedBlocklistIP{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"IPs":        enrichedIPs,
		"Total":      result.Total,
		"Page":       result.Page,
		"PageSize":   result.PageSize,
		"TotalPages": result.TotalPages,
	})
}

// GetBlocklistsSummary returns summary of all blocklists
// GET /api/v1/crowdsec/blocklist/summary
func (h *CrowdSecBlocklistHandler) GetBlocklistsSummary(w http.ResponseWriter, r *http.Request) {
	if h.repo == nil {
		ErrorResponse(w, http.StatusInternalServerError, "Repository not configured", nil)
		return
	}

	summary, err := h.repo.GetBlocklistSummary(r.Context())
	if err != nil {
		slog.Error("[CROWDSEC_BL_API] Failed to get blocklist summary", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get summary", err)
		return
	}

	if summary == nil {
		summary = []map[string]interface{}{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"blocklists": summary,
	})
}

// GetUniqueCountries returns unique countries from the blocklist IPs (from DB)
// Falls back to GeoIP sampling if DB has no countries enriched yet
// GET /api/v1/crowdsec/blocklist/countries
func (h *CrowdSecBlocklistHandler) GetUniqueCountries(w http.ResponseWriter, r *http.Request) {
	if h.repo == nil {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"countries":             []map[string]string{},
			"needs_enrichment":      false,
			"total_without_country": 0,
		})
		return
	}

	// Get unique countries directly from DB
	countries, err := h.repo.GetUniqueCountries(r.Context())
	if err != nil {
		slog.Error("[CROWDSEC_BL_API] Failed to get unique countries", "error", err)
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"countries":             []map[string]string{},
			"needs_enrichment":      true,
			"total_without_country": 0,
		})
		return
	}

	// Check how many IPs need enrichment
	ipsWithoutCountry, _ := h.repo.GetIPsWithoutCountry(r.Context(), 1)
	needsEnrichment := len(ipsWithoutCountry) > 0

	// Convert to list format with code only (country_name not stored)
	var countryList []map[string]string
	for _, code := range countries {
		if code != "" {
			countryList = append(countryList, map[string]string{
				"code": code,
			})
		}
	}

	// If DB has no countries, fall back to GeoIP sampling for immediate feedback
	if len(countryList) == 0 && h.geoClient != nil && needsEnrichment {
		slog.Info("[CROWDSEC_BL_API] No countries in DB, falling back to GeoIP sampling")

		// Sample up to 40 IPs (rate limit safe)
		query := clickhouse.IPListQuery{
			Page:     1,
			PageSize: 40,
		}

		result, queryErr := h.repo.GetIPsPaginated(r.Context(), query)
		if queryErr == nil && result != nil {
			sampledCountries := make(map[string]bool)
			for _, ip := range result.IPs {
				geo, geoErr := h.geoClient.Lookup(r.Context(), ip.IP)
				if geoErr == nil && geo != nil && geo.CountryCode != "" {
					sampledCountries[geo.CountryCode] = true
				}
			}

			for code := range sampledCountries {
				countryList = append(countryList, map[string]string{
					"code": code,
				})
			}
		}
	}

	if countryList == nil {
		countryList = []map[string]string{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"countries":        countryList,
		"needs_enrichment": needsEnrichment,
	})
}

// EnrichCountries enriches IPs with country codes in batches
// POST /api/v1/crowdsec/blocklist/enrich
func (h *CrowdSecBlocklistHandler) EnrichCountries(w http.ResponseWriter, r *http.Request) {
	if h.repo == nil || h.geoClient == nil {
		ErrorResponse(w, http.StatusInternalServerError, "Repository or GeoIP client not configured", nil)
		return
	}

	// Enrich 40 IPs per call to stay under rate limit (45/min)
	batchSize := 40

	ips, err := h.repo.GetIPsWithoutCountry(r.Context(), batchSize)
	if err != nil {
		slog.Error("[CROWDSEC_BL_API] Failed to get IPs without country", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get IPs", err)
		return
	}

	if len(ips) == 0 {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"success":  true,
			"enriched": 0,
			"message":  "All IPs already have country codes",
		})
		return
	}

	enriched := 0
	for _, ip := range ips {
		geo, geoErr := h.geoClient.Lookup(r.Context(), ip)
		if geoErr != nil {
			slog.Warn("[CROWDSEC_BL_API] GeoIP lookup failed", "ip", ip, "error", geoErr)
			continue
		}
		if geo != nil && geo.CountryCode != "" {
			if err := h.repo.UpdateIPCountry(r.Context(), ip, geo.CountryCode); err != nil {
				slog.Warn("[CROWDSEC_BL_API] Failed to update IP country", "ip", ip, "error", err)
				continue
			}
			enriched++
		}
	}

	slog.Info("[CROWDSEC_BL_API] Country enrichment completed", "enriched", enriched, "batch_size", batchSize)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"enriched":  enriched,
		"remaining": len(ips) - enriched,
		"message":   "Enrichment batch completed",
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
