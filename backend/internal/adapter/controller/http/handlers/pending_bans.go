package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// PendingBansStore interface for pending bans persistence
type PendingBansStore interface {
	GetPendingBans(ctx context.Context) ([]entity.PendingBan, error)
	GetPendingBanByIP(ctx context.Context, ip string) (*entity.PendingBan, error)
	GetPendingBanByID(ctx context.Context, id string) (*entity.PendingBan, error) // v3.57.118
	ApprovePendingBan(ctx context.Context, id string, reviewedBy string, note string) error
	RejectPendingBan(ctx context.Context, id string, reviewedBy string, note string) error
	GetPendingBanStats(ctx context.Context) (*entity.PendingBanStats, error)
}

// BansServiceV2 interface for D2B v2 ban operations
type BansServiceV2 interface {
	BanIP(ctx context.Context, req *entity.BanRequest) (*entity.BanStatus, error)
}

// PendingBansHandler handles pending bans HTTP requests (D2B v2)
type PendingBansHandler struct {
	store       PendingBansStore
	bansService BansServiceV2
}

// NewPendingBansHandler creates a new pending bans handler
func NewPendingBansHandler(store PendingBansStore, bansService BansServiceV2) *PendingBansHandler {
	return &PendingBansHandler{
		store:       store,
		bansService: bansService,
	}
}

// List returns all pending bans awaiting approval
// GET /api/v1/pending-bans
func (h *PendingBansHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	bans, err := h.store.GetPendingBans(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get pending bans", err)
		return
	}

	if bans == nil {
		bans = []entity.PendingBan{}
	}

	JSONResponse(w, http.StatusOK, bans)
}

// GetStats returns pending ban statistics
// GET /api/v1/pending-bans/stats
func (h *PendingBansHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.store.GetPendingBanStats(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get pending ban stats", err)
		return
	}

	if stats == nil {
		stats = &entity.PendingBanStats{}
	}

	JSONResponse(w, http.StatusOK, stats)
}

// Approve approves a pending ban and creates the actual ban
// POST /api/v1/pending-bans/{id}/approve
// v3.57.118: Fixed to use GetPendingBanByID instead of GetPendingBanByIP
func (h *PendingBansHandler) Approve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Note is optional
		req.Note = ""
	}

	// Get username from context (set by auth middleware)
	username := "admin"
	if user := r.Context().Value("username"); user != nil {
		username = user.(string)
	}

	// Get the pending ban details first (using ID, not IP)
	pending, err := h.store.GetPendingBanByID(ctx, id)
	if err != nil || pending == nil {
		log.Printf("[PENDING_BANS] Pending ban not found for ID: %s", id)
		ErrorResponse(w, http.StatusNotFound, "Pending ban not found", err)
		return
	}

	// Approve in database
	if err := h.store.ApprovePendingBan(ctx, id, username, req.Note); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to approve pending ban", err)
		return
	}

	// Create the actual ban
	banReq := &entity.BanRequest{
		IP:          pending.IP,
		Reason:      "[Approved] " + pending.Reason,
		TriggerRule: pending.TriggerRule,
		PerformedBy: username,
	}

	ban, err := h.bansService.BanIP(ctx, banReq)
	if err != nil {
		log.Printf("[PENDING_BANS] Warning: Approved but failed to create ban for %s: %v", pending.IP, err)
		// Still return success since approval was recorded
	}

	log.Printf("[PENDING_BANS] Pending ban %s approved by %s (IP: %s)", id, username, pending.IP)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Pending ban approved",
		"id":      id,
		"ip":      pending.IP,
		"ban":     ban,
	})
}

// Reject rejects a pending ban
// POST /api/v1/pending-bans/{id}/reject
func (h *PendingBansHandler) Reject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Note = ""
	}

	// Get username from context
	username := "admin"
	if user := r.Context().Value("username"); user != nil {
		username = user.(string)
	}

	// Reject in database
	if err := h.store.RejectPendingBan(ctx, id, username, req.Note); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to reject pending ban", err)
		return
	}

	log.Printf("[PENDING_BANS] Pending ban %s rejected by %s", id, username)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Pending ban rejected",
		"id":      id,
	})
}

// GetByIP returns a pending ban by IP
// GET /api/v1/pending-bans/ip/{ip}
func (h *PendingBansHandler) GetByIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	pending, err := h.store.GetPendingBanByIP(ctx, ip)
	if err != nil || pending == nil {
		ErrorResponse(w, http.StatusNotFound, "No pending ban for this IP", err)
		return
	}

	JSONResponse(w, http.StatusOK, pending)
}
