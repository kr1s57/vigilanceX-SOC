package handlers

import (
	"net/http"
	"strconv"

	"github.com/kr1s57/vigilancex/internal/usecase/anomalies"
	"github.com/kr1s57/vigilancex/internal/usecase/detect2ban"
)

// AnomaliesHandler handles anomaly detection HTTP requests
type AnomaliesHandler struct {
	service *anomalies.Service
	engine  *detect2ban.Engine
}

// NewAnomaliesHandler creates a new anomalies handler
func NewAnomaliesHandler(service *anomalies.Service, engine *detect2ban.Engine) *AnomaliesHandler {
	return &AnomaliesHandler{
		service: service,
		engine:  engine,
	}
}

// GetNewIPs returns newly detected IPs
// GET /api/v1/anomalies/new-ips
func (h *AnomaliesHandler) GetNewIPs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	newIPs, err := h.service.DetectNewIPs(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to detect new IPs", err)
		return
	}

	JSONResponse(w, http.StatusOK, newIPs)
}

// GetSpikes returns detected statistical spikes
// GET /api/v1/anomalies/spikes
func (h *AnomaliesHandler) GetSpikes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	config := anomalies.DefaultSpikeConfig()

	// Parse optional parameters
	if sigma := r.URL.Query().Get("sigma"); sigma != "" {
		if parsed, err := strconv.ParseFloat(sigma, 64); err == nil && parsed > 0 {
			config.SigmaThreshold = parsed
		}
	}

	spikes, err := h.service.DetectSpikes(ctx, config)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to detect spikes", err)
		return
	}

	JSONResponse(w, http.StatusOK, spikes)
}

// GetMultiVector returns multi-vector attack detections
// GET /api/v1/anomalies/multi-vector
func (h *AnomaliesHandler) GetMultiVector(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	threshold := 2
	if t := r.URL.Query().Get("threshold"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil && parsed > 0 {
			threshold = parsed
		}
	}

	attacks, err := h.service.DetectMultiVectorAttack(ctx, threshold)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to detect multi-vector attacks", err)
		return
	}

	JSONResponse(w, http.StatusOK, attacks)
}

// GetCampaigns returns targeted campaign detections
// GET /api/v1/anomalies/campaigns
func (h *AnomaliesHandler) GetCampaigns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	threshold := 3
	if t := r.URL.Query().Get("threshold"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil && parsed > 0 {
			threshold = parsed
		}
	}

	campaigns, err := h.service.DetectTargetedCampaign(ctx, threshold)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to detect campaigns", err)
		return
	}

	JSONResponse(w, http.StatusOK, campaigns)
}

// GetBruteForce returns brute force pattern detections
// GET /api/v1/anomalies/brute-force
func (h *AnomaliesHandler) GetBruteForce(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	config := anomalies.DefaultBruteForceConfig()

	if t := r.URL.Query().Get("threshold"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil && parsed > 0 {
			config.Threshold = parsed
		}
	}

	patterns, err := h.service.DetectBruteForce(ctx, config)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to detect brute force", err)
		return
	}

	JSONResponse(w, http.StatusOK, patterns)
}

// GetRecent returns recently detected anomalies
// GET /api/v1/anomalies/recent
func (h *AnomaliesHandler) GetRecent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	anomalies, err := h.service.GetRecentAnomalies(ctx, limit)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch anomalies", err)
		return
	}

	JSONResponse(w, http.StatusOK, anomalies)
}

// GetStats returns anomaly detection statistics
// GET /api/v1/anomalies/stats
func (h *AnomaliesHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetAnomalyStats(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch stats", err)
		return
	}

	JSONResponse(w, http.StatusOK, stats)
}

// RunDetection runs a detection cycle on demand
// POST /api/v1/anomalies/detect
func (h *AnomaliesHandler) RunDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	result, err := h.service.RunDetectionCycle(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Detection cycle failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, result)
}

// Detect2Ban handlers

// GetScenarios returns loaded Detect2Ban scenarios
// GET /api/v1/detect2ban/scenarios
func (h *AnomaliesHandler) GetScenarios(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "Detect2Ban engine not available", nil)
		return
	}

	scenarios := h.engine.GetScenarios()
	JSONResponse(w, http.StatusOK, scenarios)
}

// GetEngineStatus returns Detect2Ban engine status
// GET /api/v1/detect2ban/status
func (h *AnomaliesHandler) GetEngineStatus(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"running":         false,
			"scenario_count":  0,
			"message":         "Engine not initialized",
		})
		return
	}

	status := h.engine.GetStatus()
	JSONResponse(w, http.StatusOK, status)
}

// ReloadScenarios reloads Detect2Ban scenarios
// POST /api/v1/detect2ban/reload
func (h *AnomaliesHandler) ReloadScenarios(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "Detect2Ban engine not available", nil)
		return
	}

	var req struct {
		Directory string `json:"directory"`
	}

	if err := DecodeJSON(r, &req); err != nil {
		req.Directory = "/app/scenarios" // Default
	}

	if err := h.engine.LoadScenarios(req.Directory); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to reload scenarios", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{
		"message": "Scenarios reloaded successfully",
	})
}
