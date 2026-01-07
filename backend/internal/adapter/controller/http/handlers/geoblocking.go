package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/kr1s57/vigilancex/internal/usecase/geoblocking"
)

// GeoblockingHandler handles geoblocking HTTP requests (v2.0)
type GeoblockingHandler struct {
	service *geoblocking.Service
}

// NewGeoblockingHandler creates a new geoblocking handler
func NewGeoblockingHandler(service *geoblocking.Service) *GeoblockingHandler {
	return &GeoblockingHandler{service: service}
}

// ListRules returns all geoblocking rules
// GET /api/v1/geoblocking/rules
func (h *GeoblockingHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ruleType := r.URL.Query().Get("type")

	var rules []entity.GeoBlockRule
	var err error

	if ruleType != "" {
		rules, err = h.service.GetRulesByType(ctx, ruleType)
	} else {
		rules, err = h.service.GetRules(ctx)
	}

	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch rules", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"data":  rules,
		"count": len(rules),
	})
}

// GetStats returns geoblocking statistics
// GET /api/v1/geoblocking/stats
func (h *GeoblockingHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetStats(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch stats", err)
		return
	}

	JSONResponse(w, http.StatusOK, stats)
}

// CreateRule creates a new geoblocking rule
// POST /api/v1/geoblocking/rules
func (h *GeoblockingHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req entity.GeoBlockRequest
	if err := DecodeJSON(r, &req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.RuleType == "" {
		ErrorResponse(w, http.StatusBadRequest, "rule_type is required", nil)
		return
	}
	if req.Target == "" {
		ErrorResponse(w, http.StatusBadRequest, "target is required", nil)
		return
	}
	if req.Action == "" {
		req.Action = entity.GeoActionWatch // Default to watch
	}

	rule, err := h.service.CreateRule(ctx, &req)
	if err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Failed to create rule", err)
		return
	}

	JSONResponse(w, http.StatusCreated, map[string]interface{}{
		"message": "Rule created successfully",
		"data":    rule,
	})
}

// UpdateRule updates an existing geoblocking rule
// PUT /api/v1/geoblocking/rules/{id}
func (h *GeoblockingHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	var rule entity.GeoBlockRule
	if err := DecodeJSON(r, &rule); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	rule.ID = id

	if err := h.service.UpdateRule(ctx, &rule); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to update rule", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Rule updated successfully",
		"data":    rule,
	})
}

// DeleteRule deletes a geoblocking rule
// DELETE /api/v1/geoblocking/rules/{id}
func (h *GeoblockingHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if err := h.service.DeleteRule(ctx, id); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to delete rule", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{
		"message": "Rule deleted successfully",
		"id":      id,
	})
}

// CheckIP checks an IP against geoblocking rules
// GET /api/v1/geoblocking/check/{ip}
func (h *GeoblockingHandler) CheckIP(w http.ResponseWriter, r *http.Request) {
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

// LookupGeo performs a geolocation lookup for an IP
// GET /api/v1/geoblocking/lookup/{ip}
func (h *GeoblockingHandler) LookupGeo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := chi.URLParam(r, "ip")

	if ip == "" {
		ErrorResponse(w, http.StatusBadRequest, "IP address required", nil)
		return
	}

	geo, err := h.service.LookupGeo(ctx, ip)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Geolocation lookup failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, geo)
}

// GetBlockedCountries returns list of blocked countries
// GET /api/v1/geoblocking/countries/blocked
func (h *GeoblockingHandler) GetBlockedCountries(w http.ResponseWriter, r *http.Request) {
	countries := h.service.GetBlockedCountries()

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"blocked_countries": countries,
		"count":             len(countries),
	})
}

// GetWatchedCountries returns list of watched countries
// GET /api/v1/geoblocking/countries/watched
func (h *GeoblockingHandler) GetWatchedCountries(w http.ResponseWriter, r *http.Request) {
	countries := h.service.GetWatchedCountries()

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"watched_countries": countries,
		"count":             len(countries),
	})
}

// GetHighRiskCountries returns default high-risk countries
// GET /api/v1/geoblocking/countries/high-risk
func (h *GeoblockingHandler) GetHighRiskCountries(w http.ResponseWriter, r *http.Request) {
	countries := entity.DefaultHighRiskCountries()

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"high_risk_countries": countries,
		"count":               len(countries),
	})
}

// RefreshRulesCache refreshes the geoblocking rules cache
// POST /api/v1/geoblocking/cache/refresh
func (h *GeoblockingHandler) RefreshRulesCache(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.service.RefreshRulesCache(ctx); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to refresh cache", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{
		"message": "Rules cache refreshed successfully",
	})
}
