package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/kr1s57/vigilancex/internal/usecase/bans"
)

// GeoIPClient interface for geolocation lookups
type GeoIPClient interface {
	Lookup(ctx context.Context, ip string) (*entity.GeoLocation, error)
}

// BansHandler handles ban-related HTTP requests
type BansHandler struct {
	service     *bans.Service
	geoIPClient GeoIPClient
}

// NewBansHandler creates a new bans handler
func NewBansHandler(service *bans.Service) *BansHandler {
	return &BansHandler{service: service}
}

// SetGeoIPClient sets the GeoIP client for country enrichment
func (h *BansHandler) SetGeoIPClient(client GeoIPClient) {
	h.geoIPClient = client
}

// List returns all active bans
// GET /api/v1/bans
// v3.57.101: Country codes now come from DB JOIN (ip_geolocation), no more runtime lookups
func (h *BansHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	activeBans, err := h.service.ListActiveBans(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch bans", err)
		return
	}

	// Country codes are now included via JOIN with ip_geolocation table
	// No runtime GeoIP lookups needed - much faster!

	// Wrap in data object for frontend compatibility
	JSONResponse(w, http.StatusOK, map[string]interface{}{"data": activeBans})
}

// Get returns a specific ban by IP
// GET /api/v1/bans/{ip}
func (h *BansHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	ban, err := h.service.GetBan(ctx, ip)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "Ban not found", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{"data": ban})
}

// Stats returns ban statistics
// GET /api/v1/bans/stats
func (h *BansHandler) Stats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetStats(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch stats", err)
		return
	}

	JSONResponse(w, http.StatusOK, stats)
}

// History returns ban history for an IP
// GET /api/v1/bans/{ip}/history
func (h *BansHandler) History(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	history, err := h.service.GetHistory(ctx, ip, 50)
	if err != nil {
		// Log the actual error for debugging
		log.Printf("[ERROR] Failed to fetch ban history for %s: %v", ip, err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch history", err)
		return
	}

	log.Printf("[DEBUG] Ban history for %s: %d entries", ip, len(history))
	JSONResponse(w, http.StatusOK, map[string]interface{}{"data": history})
}

// Create bans an IP address
// POST /api/v1/bans
func (h *BansHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req entity.BanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.IP == "" {
		ErrorResponse(w, http.StatusBadRequest, "IP address is required", nil)
		return
	}
	if req.Reason == "" {
		ErrorResponse(w, http.StatusBadRequest, "Reason is required", nil)
		return
	}

	ban, err := h.service.BanIP(ctx, &req)
	if err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Failed to ban IP", err)
		return
	}

	JSONResponse(w, http.StatusCreated, map[string]interface{}{"data": ban})
}

// Delete unbans an IP address
// DELETE /api/v1/bans/{ip}?immunity_hours=24
// Query params:
//   - reason: optional unban reason
//   - immunity_hours: optional hours of immunity from auto-ban (default: 0)
func (h *BansHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	// Parse immunity_hours (default 0 = no immunity)
	immunityHours := 0
	if ih := r.URL.Query().Get("immunity_hours"); ih != "" {
		if parsed, err := strconv.Atoi(ih); err == nil && parsed > 0 {
			immunityHours = parsed
		}
	}

	req := &entity.UnbanRequest{
		IP:            ip,
		Reason:        r.URL.Query().Get("reason"),
		ImmunityHours: immunityHours,
	}

	if err := h.service.UnbanIP(ctx, req); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to unban IP", err)
		return
	}

	response := map[string]interface{}{
		"message": "IP unbanned successfully",
		"ip":      ip,
	}
	if immunityHours > 0 {
		response["immunity_hours"] = immunityHours
		response["message"] = "IP unbanned with " + strconv.Itoa(immunityHours) + "h immunity"
	}

	JSONResponse(w, http.StatusOK, response)
}

// Extend extends a ban duration
// POST /api/v1/bans/{ip}/extend
func (h *BansHandler) Extend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	var req entity.ExtendBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	req.IP = ip

	if req.DurationDays <= 0 {
		ErrorResponse(w, http.StatusBadRequest, "Duration must be positive", nil)
		return
	}

	ban, err := h.service.ExtendBan(ctx, &req)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to extend ban", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{"data": ban})
}

// MakePermanent makes a ban permanent
// POST /api/v1/bans/{ip}/permanent
func (h *BansHandler) MakePermanent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	performedBy := r.URL.Query().Get("performed_by")

	ban, err := h.service.MakePermanent(ctx, ip, performedBy)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to make permanent", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{"data": ban})
}

// Sync syncs all pending bans to Sophos XGS
// POST /api/v1/bans/sync
func (h *BansHandler) Sync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	result, err := h.service.SyncToXGS(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Sync failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, result)
}

// XGSStatus returns Sophos XGS sync status
// GET /api/v1/bans/xgs-status
func (h *BansHandler) XGSStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status, err := h.service.GetXGSStatus(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get XGS status", err)
		return
	}

	JSONResponse(w, http.StatusOK, status)
}

// Whitelist Handlers (v2.0 with soft whitelist support)

// ListWhitelist returns all whitelisted IPs
// GET /api/v1/whitelist
// Query params: ?type=hard|soft|monitor (optional filter)
func (h *BansHandler) ListWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	whitelistType := r.URL.Query().Get("type")

	var whitelist []entity.WhitelistEntry
	var err error

	if whitelistType != "" {
		whitelist, err = h.service.GetWhitelistByType(ctx, whitelistType)
	} else {
		whitelist, err = h.service.GetWhitelist(ctx)
	}

	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch whitelist", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{"data": whitelist})
}

// WhitelistStats returns whitelist statistics by type (v2.0)
// GET /api/v1/whitelist/stats
func (h *BansHandler) WhitelistStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetWhitelistStats(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch whitelist stats", err)
		return
	}

	total := 0
	for _, count := range stats {
		total += count
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"total":   total,
		"by_type": stats,
	})
}

// CheckWhitelist checks if an IP is whitelisted and returns detailed info (v2.0)
// GET /api/v1/whitelist/check/{ip}
func (h *BansHandler) CheckWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	if ip == "" {
		ErrorResponse(w, http.StatusBadRequest, "IP address required", nil)
		return
	}

	result, err := h.service.CheckWhitelist(ctx, ip)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to check whitelist", err)
		return
	}

	JSONResponse(w, http.StatusOK, result)
}

// AddWhitelist adds an IP to the whitelist (v2.0 with soft whitelist support)
// POST /api/v1/whitelist
func (h *BansHandler) AddWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req entity.WhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.IP == "" {
		ErrorResponse(w, http.StatusBadRequest, "IP address is required", nil)
		return
	}

	// Default to hard whitelist if type not specified (backward compatibility)
	if req.Type == "" {
		req.Type = entity.WhitelistTypeHard
	}

	// Validate type
	validTypes := map[string]bool{
		entity.WhitelistTypeHard:    true,
		entity.WhitelistTypeSoft:    true,
		entity.WhitelistTypeMonitor: true,
	}
	if !validTypes[req.Type] {
		ErrorResponse(w, http.StatusBadRequest, "Invalid whitelist type (must be hard, soft, or monitor)", nil)
		return
	}

	if err := h.service.AddToWhitelistV2(ctx, &req); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to add to whitelist", err)
		return
	}

	JSONResponse(w, http.StatusCreated, map[string]interface{}{
		"message": "IP added to whitelist",
		"ip":      req.IP,
		"type":    req.Type,
	})
}

// UpdateWhitelist updates an existing whitelist entry (v2.0)
// PUT /api/v1/whitelist/{ip}
func (h *BansHandler) UpdateWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	var req entity.WhitelistEntry
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	req.IP = ip

	if err := h.service.UpdateWhitelistEntry(ctx, &req); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to update whitelist entry", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Whitelist entry updated",
		"ip":      ip,
	})
}

// RemoveWhitelist removes an IP from the whitelist
// DELETE /api/v1/whitelist/{ip}
func (h *BansHandler) RemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	if err := h.service.RemoveFromWhitelist(ctx, ip); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to remove from whitelist", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{
		"message": "IP removed from whitelist",
		"ip":      ip,
	})
}
