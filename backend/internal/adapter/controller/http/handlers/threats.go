package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/domain/scoring"
	"github.com/kr1s57/vigilancex/internal/usecase/bans"
	"github.com/kr1s57/vigilancex/internal/usecase/blocklists"
	"github.com/kr1s57/vigilancex/internal/usecase/threats"
)

// ThreatsHandler handles threat intelligence HTTP requests
type ThreatsHandler struct {
	service           *threats.Service
	blocklistsService *blocklists.Service
	bansService       *bans.Service
	combinedScorer    *scoring.CombinedScorer
}

// NewThreatsHandler creates a new threats handler
func NewThreatsHandler(service *threats.Service) *ThreatsHandler {
	return &ThreatsHandler{
		service:        service,
		combinedScorer: scoring.NewDefaultCombinedScorer(),
	}
}

// SetBlocklistsService sets the blocklists service for combined risk assessment
func (h *ThreatsHandler) SetBlocklistsService(svc *blocklists.Service) {
	h.blocklistsService = svc
}

// SetBansService sets the bans service for whitelist checking (v2.0)
func (h *ThreatsHandler) SetBansService(svc *bans.Service) {
	h.bansService = svc
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

// RiskAssessment provides combined risk assessment from threat intel + blocklists + freshness (v2.0)
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

	// Build response with threat intel data
	response := map[string]interface{}{
		"ip":             ip,
		"threat_score":   threatResult.AggregatedScore,
		"threat_level":   threatResult.ThreatLevel,
		"threat_sources": len(threatResult.Sources),
		"is_tor":         threatResult.IsTor,
		"is_vpn":         threatResult.IsVPN,
		"is_proxy":       threatResult.IsProxy,
		"is_benign":      threatResult.IsBenign,
		"in_ipsum_lists": threatResult.InBlocklists,
		"tags":           threatResult.Tags,
		"country":        threatResult.Country,
	}

	// Initialize scoring input for combined assessment
	scoreInput := scoring.CombinedScoreInput{
		ThreatIntelScore: threatResult.AggregatedScore,
		LastSeen:         threatResult.LastChecked,
	}

	// Add blocklist check if service is available
	var lastSeenTime time.Time
	if h.blocklistsService != nil {
		blocklistInfo, err := h.blocklistsService.CheckIP(ctx, ip)
		if err == nil && blocklistInfo != nil {
			response["in_blocklists"] = blocklistInfo.IsBlocked
			response["blocklist_count"] = blocklistInfo.SourceCount
			response["blocklist_sources"] = blocklistInfo.Sources
			response["blocklist_categories"] = blocklistInfo.Categories
			response["blocklist_max_confidence"] = blocklistInfo.MaxConfidence

			scoreInput.BlocklistCount = blocklistInfo.SourceCount

			// Use blocklist last_seen for freshness if available
			if blocklistInfo.LastSeen != nil && !blocklistInfo.LastSeen.IsZero() {
				lastSeenTime = *blocklistInfo.LastSeen
				scoreInput.LastSeen = lastSeenTime
				response["blocklist_last_seen"] = lastSeenTime
			}
		}
	}

	// Check whitelist status (v2.0 soft whitelist support)
	if h.bansService != nil {
		whitelistResult, err := h.bansService.CheckWhitelist(ctx, ip)
		if err == nil && whitelistResult != nil {
			response["whitelist_status"] = map[string]interface{}{
				"is_whitelisted": whitelistResult.IsWhitelisted,
				"type":           whitelistResult.EffectiveType,
				"score_modifier": whitelistResult.ScoreModifier,
				"allow_auto_ban": whitelistResult.AllowAutoBan,
			}

			if whitelistResult.IsWhitelisted {
				scoreInput.IsWhitelisted = true
				scoreInput.WhitelistModifier = whitelistResult.ScoreModifier
			}
		}
	}

	// Calculate combined score using the v2.0 combined scorer with freshness
	combinedResult := h.combinedScorer.CalculateCombinedScore(scoreInput)

	// Add combined scoring details to response
	response["combined_score"] = combinedResult.FinalScore
	response["combined_risk"] = combinedResult.RiskLevel
	response["recommend_ban"] = combinedResult.RecommendBan
	response["scoring_confidence"] = combinedResult.Confidence
	response["score_components"] = combinedResult.Components

	// Add freshness info if we have last_seen data
	if !lastSeenTime.IsZero() {
		freshnessScorer := scoring.NewDefaultFreshnessScorer()
		freshnessResult := freshnessScorer.CalculateFreshness(threatResult.AggregatedScore, lastSeenTime)
		response["freshness"] = map[string]interface{}{
			"days_since_last_seen": freshnessResult.DaysSinceLastSeen,
			"is_recent":            freshnessResult.IsRecent,
			"is_stale":             freshnessResult.IsStale,
			"multiplier":           freshnessResult.Multiplier,
			"reason":               freshnessResult.Reason,
		}
	}

	JSONResponse(w, http.StatusOK, response)
}
