package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// GeoZoneConfigStore interface for GeoZone config persistence
type GeoZoneConfigStore interface {
	GetGeoZoneConfig() (*entity.GeoZoneConfig, error)
	SaveGeoZoneConfig(config *entity.GeoZoneConfig) error
}

// GeoZoneHandler handles GeoZone configuration HTTP requests
type GeoZoneHandler struct {
	store GeoZoneConfigStore
}

// NewGeoZoneHandler creates a new GeoZone handler
func NewGeoZoneHandler(store GeoZoneConfigStore) *GeoZoneHandler {
	return &GeoZoneHandler{store: store}
}

// GetConfig returns the current GeoZone configuration
// GET /api/v1/geozone/config
func (h *GeoZoneHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.store.GetGeoZoneConfig()
	if err != nil {
		// Return default config if not found
		config = entity.DefaultGeoZoneConfig()
	}

	JSONResponse(w, http.StatusOK, config)
}

// UpdateConfig updates the GeoZone configuration
// PUT /api/v1/geozone/config
func (h *GeoZoneHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	// First get existing config to merge with
	existingConfig, err := h.store.GetGeoZoneConfig()
	if err != nil {
		existingConfig = entity.DefaultGeoZoneConfig()
	}

	// Decode partial update into a map to know which fields were sent
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Apply updates to existing config
	if v, ok := updates["enabled"]; ok {
		existingConfig.Enabled = v.(bool)
	}
	if v, ok := updates["authorized_countries"]; ok {
		countries := make([]string, 0)
		for _, c := range v.([]interface{}) {
			countries = append(countries, c.(string))
		}
		existingConfig.AuthorizedCountries = countries
	}
	if v, ok := updates["hostile_countries"]; ok {
		countries := make([]string, 0)
		for _, c := range v.([]interface{}) {
			countries = append(countries, c.(string))
		}
		existingConfig.HostileCountries = countries
	}
	if v, ok := updates["default_policy"]; ok {
		policy := v.(string)
		if policy != entity.GeoZoneHostile &&
			policy != entity.GeoZoneNeutral &&
			policy != entity.GeoZoneAuthorized {
			ErrorResponse(w, http.StatusBadRequest, "Invalid default_policy (must be 'hostile', 'neutral', or 'authorized')", nil)
			return
		}
		existingConfig.DefaultPolicy = policy
	}
	if v, ok := updates["waf_threshold_hzone"]; ok {
		existingConfig.WAFThresholdHzone = int(v.(float64))
	}
	if v, ok := updates["waf_threshold_zone"]; ok {
		existingConfig.WAFThresholdZone = int(v.(float64))
	}
	if v, ok := updates["threat_score_threshold"]; ok {
		existingConfig.ThreatScoreThreshold = int(v.(float64))
	}

	slog.Info("[GEOZONE] Saving config",
		"enabled", existingConfig.Enabled,
		"authorized_countries", len(existingConfig.AuthorizedCountries),
		"hostile_countries", len(existingConfig.HostileCountries),
		"default_policy", existingConfig.DefaultPolicy)

	if err := h.store.SaveGeoZoneConfig(existingConfig); err != nil {
		slog.Error("[GEOZONE] Failed to save config", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to save config", err)
		return
	}

	slog.Info("[GEOZONE] Config saved successfully")

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "GeoZone configuration updated",
		"config":  existingConfig,
	})
}

// ClassifyIP classifies an IP's country into a zone
// GET /api/v1/geozone/classify/{country}
func (h *GeoZoneHandler) ClassifyCountry(w http.ResponseWriter, r *http.Request) {
	countryCode := r.URL.Query().Get("country")
	if countryCode == "" {
		ErrorResponse(w, http.StatusBadRequest, "Country code required", nil)
		return
	}

	config, err := h.store.GetGeoZoneConfig()
	if err != nil {
		config = entity.DefaultGeoZoneConfig()
	}

	zone := config.ClassifyCountry(countryCode)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"country": countryCode,
		"zone":    zone,
		"enabled": config.Enabled,
	})
}

// GetCountryList returns the list of authorized and hostile countries
// GET /api/v1/geozone/countries
func (h *GeoZoneHandler) GetCountryList(w http.ResponseWriter, r *http.Request) {
	config, err := h.store.GetGeoZoneConfig()
	if err != nil {
		config = entity.DefaultGeoZoneConfig()
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"enabled":              config.Enabled,
		"authorized_countries": config.AuthorizedCountries,
		"hostile_countries":    config.HostileCountries,
		"default_policy":       config.DefaultPolicy,
	})
}

// AddAuthorizedCountry adds a country to the authorized list
// POST /api/v1/geozone/countries/authorized
func (h *GeoZoneHandler) AddAuthorizedCountry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Country string `json:"country"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Country == "" || len(req.Country) != 2 {
		ErrorResponse(w, http.StatusBadRequest, "Invalid country code (must be 2 letters)", nil)
		return
	}

	config, err := h.store.GetGeoZoneConfig()
	if err != nil {
		config = entity.DefaultGeoZoneConfig()
	}

	// Check if already exists
	for _, cc := range config.AuthorizedCountries {
		if cc == req.Country {
			JSONResponse(w, http.StatusOK, map[string]interface{}{
				"success": true,
				"message": "Country already authorized",
			})
			return
		}
	}

	// Add country
	config.AuthorizedCountries = append(config.AuthorizedCountries, req.Country)

	// Remove from hostile if present
	newHostile := make([]string, 0)
	for _, cc := range config.HostileCountries {
		if cc != req.Country {
			newHostile = append(newHostile, cc)
		}
	}
	config.HostileCountries = newHostile

	slog.Info("[GEOZONE] Adding authorized country",
		"country", req.Country,
		"total_authorized", len(config.AuthorizedCountries))

	if err := h.store.SaveGeoZoneConfig(config); err != nil {
		slog.Error("[GEOZONE] Failed to save config after adding country", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to save config", err)
		return
	}
	slog.Info("[GEOZONE] Country added successfully")

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Country added to authorized list",
		"country": req.Country,
	})
}

// RemoveAuthorizedCountry removes a country from the authorized list
// DELETE /api/v1/geozone/countries/authorized/{country}
func (h *GeoZoneHandler) RemoveAuthorizedCountry(w http.ResponseWriter, r *http.Request) {
	countryCode := r.URL.Query().Get("country")
	if countryCode == "" {
		ErrorResponse(w, http.StatusBadRequest, "Country code required", nil)
		return
	}

	config, err := h.store.GetGeoZoneConfig()
	if err != nil {
		config = entity.DefaultGeoZoneConfig()
	}

	// Remove country
	newAuth := make([]string, 0)
	found := false
	for _, cc := range config.AuthorizedCountries {
		if cc != countryCode {
			newAuth = append(newAuth, cc)
		} else {
			found = true
		}
	}

	if !found {
		ErrorResponse(w, http.StatusNotFound, "Country not in authorized list", nil)
		return
	}

	config.AuthorizedCountries = newAuth

	if err := h.store.SaveGeoZoneConfig(config); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to save config", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Country removed from authorized list",
		"country": countryCode,
	})
}

// AddHostileCountry adds a country to the hostile list
// POST /api/v1/geozone/countries/hostile
func (h *GeoZoneHandler) AddHostileCountry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Country string `json:"country"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Country == "" || len(req.Country) != 2 {
		ErrorResponse(w, http.StatusBadRequest, "Invalid country code (must be 2 letters)", nil)
		return
	}

	config, err := h.store.GetGeoZoneConfig()
	if err != nil {
		config = entity.DefaultGeoZoneConfig()
	}

	// Check if already exists
	for _, cc := range config.HostileCountries {
		if cc == req.Country {
			JSONResponse(w, http.StatusOK, map[string]interface{}{
				"success": true,
				"message": "Country already in hostile list",
			})
			return
		}
	}

	// Add country
	config.HostileCountries = append(config.HostileCountries, req.Country)

	// Remove from authorized if present
	newAuth := make([]string, 0)
	for _, cc := range config.AuthorizedCountries {
		if cc != req.Country {
			newAuth = append(newAuth, cc)
		}
	}
	config.AuthorizedCountries = newAuth

	slog.Info("[GEOZONE] Adding hostile country",
		"country", req.Country,
		"total_hostile", len(config.HostileCountries))

	if err := h.store.SaveGeoZoneConfig(config); err != nil {
		slog.Error("[GEOZONE] Failed to save config after adding hostile country", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to save config", err)
		return
	}
	slog.Info("[GEOZONE] Hostile country added successfully")

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Country added to hostile list",
		"country": req.Country,
	})
}
