package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/usecase/blocklists"
	"github.com/kr1s57/vigilancex/internal/usecase/threats"
)

// ThreatsHandler handles threat intelligence HTTP requests
type ThreatsHandler struct {
	service           *threats.Service
	blocklistsService *blocklists.Service
}

// NewThreatsHandler creates a new threats handler
func NewThreatsHandler(service *threats.Service) *ThreatsHandler {
	return &ThreatsHandler{service: service}
}

// SetBlocklistsService sets the blocklists service for combined risk assessment
func (h *ThreatsHandler) SetBlocklistsService(svc *blocklists.Service) {
	h.blocklistsService = svc
}

// CheckIP queries threat intel for a specific IP
// GET /api/v1/threats/{ip}
func (h *ThreatsHandler) CheckIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	if ip == "" {
		ErrorResponse(w, http.StatusBadRequest, "IP address required", nil)
		return
	}

	result, err := h.service.CheckIP(ctx, ip)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to check IP", err)
		return
	}

	JSONResponse(w, http.StatusOK, result)
}

// GetStoredScore retrieves stored threat score for an IP
// GET /api/v1/threats/{ip}/stored
func (h *ThreatsHandler) GetStoredScore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	score, err := h.service.GetThreatScore(ctx, ip)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "Threat score not found", err)
		return
	}

	JSONResponse(w, http.StatusOK, score)
}

// GetTopThreats returns IPs with highest threat scores
// GET /api/v1/threats/top
func (h *ThreatsHandler) GetTopThreats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	threats, err := h.service.GetTopThreats(ctx, limit)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch top threats", err)
		return
	}

	JSONResponse(w, http.StatusOK, threats)
}

// GetThreatsByLevel returns threats filtered by level
// GET /api/v1/threats/level/{level}
func (h *ThreatsHandler) GetThreatsByLevel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	level := chi.URLParam(r, "level")

	validLevels := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
		"none":     true,
	}

	if !validLevels[level] {
		ErrorResponse(w, http.StatusBadRequest, "Invalid threat level", nil)
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	threats, err := h.service.GetThreatsByLevel(ctx, level, limit)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch threats", err)
		return
	}

	JSONResponse(w, http.StatusOK, threats)
}

// GetStats returns threat intelligence statistics
// GET /api/v1/threats/stats
func (h *ThreatsHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetThreatStats(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch stats", err)
		return
	}

	JSONResponse(w, http.StatusOK, stats)
}

// GetProviders returns configured threat intel providers
// GET /api/v1/threats/providers
func (h *ThreatsHandler) GetProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.service.GetProviderStatus()
	JSONResponse(w, http.StatusOK, providers)
}

// BatchCheck queries threat intel for multiple IPs
// POST /api/v1/threats/batch
func (h *ThreatsHandler) BatchCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		IPs []string `json:"ips"`
	}

	if err := DecodeJSON(r, &req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if len(req.IPs) == 0 {
		ErrorResponse(w, http.StatusBadRequest, "No IPs provided", nil)
		return
	}

	if len(req.IPs) > 50 {
		ErrorResponse(w, http.StatusBadRequest, "Maximum 50 IPs per batch", nil)
		return
	}

	results, err := h.service.BatchEnrichIPs(ctx, req.IPs)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Batch check failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, results)
}

// ClearCache clears the threat intel cache
// POST /api/v1/threats/cache/clear
func (h *ThreatsHandler) ClearCache(w http.ResponseWriter, r *http.Request) {
	h.service.ClearCache()

	JSONResponse(w, http.StatusOK, map[string]string{
		"message": "Cache cleared successfully",
	})
}

// ShouldBan checks if an IP should be auto-banned based on threat score
// GET /api/v1/threats/{ip}/should-ban
func (h *ThreatsHandler) ShouldBan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	threshold := 80
	if t := r.URL.Query().Get("threshold"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil && parsed > 0 {
			threshold = parsed
		}
	}

	shouldBan, reason, err := h.service.ShouldAutoBan(ctx, ip, threshold)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Check failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"ip":         ip,
		"should_ban": shouldBan,
		"reason":     reason,
		"threshold":  threshold,
	})
}

// RiskAssessment provides combined risk assessment from threat intel + blocklists
// GET /api/v1/threats/risk/{ip}
func (h *ThreatsHandler) RiskAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	if ip == "" {
		ErrorResponse(w, http.StatusBadRequest, "IP address required", nil)
		return
	}

	// Get threat intel score
	threatResult, err := h.service.CheckIP(ctx, ip)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Threat intel check failed", err)
		return
	}

	// Build response
	response := map[string]interface{}{
		"ip":               ip,
		"threat_score":     threatResult.AggregatedScore,
		"threat_level":     threatResult.ThreatLevel,
		"threat_sources":   len(threatResult.Sources),
		"is_tor":           threatResult.IsTor,
		"is_vpn":           threatResult.IsVPN,
		"is_proxy":         threatResult.IsProxy,
		"is_benign":        threatResult.IsBenign,
		"in_ipsum_lists":   threatResult.InBlocklists,
		"tags":             threatResult.Tags,
	}

	// Add blocklist check if service is available
	if h.blocklistsService != nil {
		blocklistInfo, err := h.blocklistsService.CheckIP(ctx, ip)
		if err == nil && blocklistInfo != nil {
			response["in_blocklists"] = blocklistInfo.IsBlocked
			response["blocklist_count"] = blocklistInfo.SourceCount
			response["blocklist_sources"] = blocklistInfo.Sources
			response["blocklist_categories"] = blocklistInfo.Categories
			response["blocklist_max_confidence"] = blocklistInfo.MaxConfidence
		}
	}

	// Calculate combined risk
	combinedRisk := "low"
	riskScore := threatResult.AggregatedScore

	// Boost risk if in multiple blocklists
	if blocklist, ok := response["blocklist_count"].(int); ok && blocklist > 0 {
		// Each blocklist source adds 10 points (capped at 50)
		boost := blocklist * 10
		if boost > 50 {
			boost = 50
		}
		riskScore += boost
		if riskScore > 100 {
			riskScore = 100
		}
	}

	// Determine final risk level
	switch {
	case riskScore >= 80:
		combinedRisk = "critical"
	case riskScore >= 60:
		combinedRisk = "high"
	case riskScore >= 40:
		combinedRisk = "medium"
	case riskScore >= 20:
		combinedRisk = "low"
	default:
		combinedRisk = "none"
	}

	response["combined_score"] = riskScore
	response["combined_risk"] = combinedRisk
	response["recommend_ban"] = riskScore >= 70

	JSONResponse(w, http.StatusOK, response)
}
