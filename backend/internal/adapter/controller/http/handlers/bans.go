package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/kr1s57/vigilancex/internal/usecase/bans"
)

// BansHandler handles ban-related HTTP requests
type BansHandler struct {
	service *bans.Service
}

// NewBansHandler creates a new bans handler
func NewBansHandler(service *bans.Service) *BansHandler {
	return &BansHandler{service: service}
}

// List returns all active bans
// GET /api/v1/bans
func (h *BansHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	activeBans, err := h.service.ListActiveBans(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch bans", err)
		return
	}

	JSONResponse(w, http.StatusOK, activeBans)
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

	JSONResponse(w, http.StatusOK, ban)
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
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch history", err)
		return
	}

	JSONResponse(w, http.StatusOK, history)
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

	JSONResponse(w, http.StatusCreated, ban)
}

// Delete unbans an IP address
// DELETE /api/v1/bans/{ip}
func (h *BansHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	req := &entity.UnbanRequest{
		IP:     ip,
		Reason: r.URL.Query().Get("reason"),
	}

	if err := h.service.UnbanIP(ctx, req); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to unban IP", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{
		"message": "IP unbanned successfully",
		"ip":      ip,
	})
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

	JSONResponse(w, http.StatusOK, ban)
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

	JSONResponse(w, http.StatusOK, ban)
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

// Whitelist Handlers

// ListWhitelist returns all whitelisted IPs
// GET /api/v1/whitelist
func (h *BansHandler) ListWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	whitelist, err := h.service.GetWhitelist(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch whitelist", err)
		return
	}

	JSONResponse(w, http.StatusOK, whitelist)
}

// AddWhitelist adds an IP to the whitelist
// POST /api/v1/whitelist
func (h *BansHandler) AddWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		IP      string `json:"ip"`
		Reason  string `json:"reason"`
		AddedBy string `json:"added_by"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.IP == "" {
		ErrorResponse(w, http.StatusBadRequest, "IP address is required", nil)
		return
	}

	if err := h.service.AddToWhitelist(ctx, req.IP, req.Reason, req.AddedBy); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to add to whitelist", err)
		return
	}

	JSONResponse(w, http.StatusCreated, map[string]string{
		"message": "IP added to whitelist",
		"ip":      req.IP,
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
