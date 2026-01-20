package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// VigimailService interface for business logic
type VigimailService interface {
	Initialize(ctx context.Context) error
	GetConfig(ctx context.Context) (*entity.VigimailConfig, error)
	UpdateConfig(ctx context.Context, config *entity.VigimailConfig) error
	GetStatus(ctx context.Context) *entity.VigimailStatus
	GetStats(ctx context.Context) (*entity.VigimailStats, error)

	ListDomains(ctx context.Context) ([]entity.VigimailDomain, error)
	AddDomain(ctx context.Context, domain string) (*entity.VigimailDomain, error)
	DeleteDomain(ctx context.Context, domain string) error
	CheckDomain(ctx context.Context, domain string) (*entity.DomainDNSCheck, error)
	GetDomainDNS(ctx context.Context, domain string) (*entity.DomainDNSCheck, error)

	ListEmails(ctx context.Context, domain string) ([]entity.VigimailEmail, error)
	AddEmail(ctx context.Context, email string) (*entity.VigimailEmail, error)
	DeleteEmail(ctx context.Context, email string) error
	CheckEmail(ctx context.Context, email string) ([]entity.VigimailLeak, error)
	GetEmailLeaks(ctx context.Context, email string) ([]entity.VigimailLeak, error)

	CheckAll(ctx context.Context) (*entity.VigimailCheckHistory, error)

	// v3.57.119: API key testing
	TestHIBPKey(ctx context.Context, apiKey string) error
}

// VigimailHandler handles HTTP requests for Vigimail
type VigimailHandler struct {
	service VigimailService
}

// NewVigimailHandler creates a new handler
func NewVigimailHandler(service VigimailService) *VigimailHandler {
	return &VigimailHandler{service: service}
}

// ============================================
// Configuration
// ============================================

// GetConfig handles GET /api/v1/vigimail/config
func (h *VigimailHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.service.GetConfig(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get config", err)
		return
	}

	// Mask API keys
	response := map[string]interface{}{
		"enabled":              config.Enabled,
		"check_interval_hours": config.CheckIntervalHours,
		"last_check":           config.LastCheck,
	}

	if config.HIBPAPIKey != "" {
		if len(config.HIBPAPIKey) > 8 {
			response["hibp_api_key"] = config.HIBPAPIKey[:4] + "****" + config.HIBPAPIKey[len(config.HIBPAPIKey)-4:]
		} else {
			response["hibp_api_key"] = "****"
		}
	} else {
		response["hibp_api_key"] = ""
	}

	if config.LeakCheckAPIKey != "" {
		if len(config.LeakCheckAPIKey) > 8 {
			response["leakcheck_api_key"] = config.LeakCheckAPIKey[:4] + "****" + config.LeakCheckAPIKey[len(config.LeakCheckAPIKey)-4:]
		} else {
			response["leakcheck_api_key"] = "****"
		}
	} else {
		response["leakcheck_api_key"] = ""
	}

	JSONResponse(w, http.StatusOK, response)
}

// UpdateConfig handles PUT /api/v1/vigimail/config
func (h *VigimailHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	config, err := h.service.GetConfig(r.Context())
	if err != nil {
		config = entity.DefaultVigimailConfig()
	}

	// Apply updates
	if v, ok := updates["enabled"]; ok {
		config.Enabled = v.(bool)
	}
	if v, ok := updates["check_interval_hours"]; ok {
		config.CheckIntervalHours = int(v.(float64))
	}
	if v, ok := updates["hibp_api_key"]; ok {
		apiKey := v.(string)
		if apiKey != "" && !containsMask(apiKey) {
			config.HIBPAPIKey = apiKey
		}
	}
	if v, ok := updates["leakcheck_api_key"]; ok {
		apiKey := v.(string)
		if apiKey != "" && !containsMask(apiKey) {
			config.LeakCheckAPIKey = apiKey
		}
	}

	if err := h.service.UpdateConfig(r.Context(), config); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to save config", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Configuration updated",
	})
}

// GetStatus handles GET /api/v1/vigimail/status
func (h *VigimailHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := h.service.GetStatus(r.Context())
	JSONResponse(w, http.StatusOK, status)
}

// GetStats handles GET /api/v1/vigimail/stats
func (h *VigimailHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.service.GetStats(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get stats", err)
		return
	}
	JSONResponse(w, http.StatusOK, stats)
}

// ============================================
// Domains
// ============================================

// ListDomains handles GET /api/v1/vigimail/domains
func (h *VigimailHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := h.service.ListDomains(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to list domains", err)
		return
	}

	if domains == nil {
		domains = []entity.VigimailDomain{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"domains": domains,
		"count":   len(domains),
	})
}

// AddDomain handles POST /api/v1/vigimail/domains
func (h *VigimailHandler) AddDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Domain == "" {
		ErrorResponse(w, http.StatusBadRequest, "Domain is required", nil)
		return
	}

	domain, err := h.service.AddDomain(r.Context(), req.Domain)
	if err != nil {
		slog.Error("[VIGIMAIL_API] Failed to add domain", "domain", req.Domain, "error", err)
		ErrorResponse(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	JSONResponse(w, http.StatusCreated, domain)
}

// DeleteDomain handles DELETE /api/v1/vigimail/domains/{domain}
func (h *VigimailHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		ErrorResponse(w, http.StatusBadRequest, "Domain is required", nil)
		return
	}

	if err := h.service.DeleteDomain(r.Context(), domain); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to delete domain", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Domain deleted",
	})
}

// GetDomainDNS handles GET /api/v1/vigimail/domains/{domain}/dns
func (h *VigimailHandler) GetDomainDNS(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		ErrorResponse(w, http.StatusBadRequest, "Domain is required", nil)
		return
	}

	check, err := h.service.GetDomainDNS(r.Context(), domain)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "No DNS check found", err)
		return
	}

	JSONResponse(w, http.StatusOK, check)
}

// CheckDomain handles POST /api/v1/vigimail/domains/{domain}/check
func (h *VigimailHandler) CheckDomain(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		ErrorResponse(w, http.StatusBadRequest, "Domain is required", nil)
		return
	}

	check, err := h.service.CheckDomain(r.Context(), domain)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "DNS check failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, check)
}

// ============================================
// Emails
// ============================================

// ListEmails handles GET /api/v1/vigimail/emails
func (h *VigimailHandler) ListEmails(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")

	emails, err := h.service.ListEmails(r.Context(), domain)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to list emails", err)
		return
	}

	if emails == nil {
		emails = []entity.VigimailEmail{}
	}

	// Group by domain if no specific domain requested
	if domain == "" {
		grouped := make(map[string][]entity.VigimailEmail)
		for _, e := range emails {
			grouped[e.Domain] = append(grouped[e.Domain], e)
		}
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"emails_by_domain": grouped,
			"total_count":      len(emails),
		})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"emails": emails,
		"count":  len(emails),
	})
}

// AddEmail handles POST /api/v1/vigimail/emails
func (h *VigimailHandler) AddEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Email == "" {
		ErrorResponse(w, http.StatusBadRequest, "Email is required", nil)
		return
	}

	email, err := h.service.AddEmail(r.Context(), req.Email)
	if err != nil {
		slog.Error("[VIGIMAIL_API] Failed to add email", "email", req.Email, "error", err)
		ErrorResponse(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	JSONResponse(w, http.StatusCreated, email)
}

// DeleteEmail handles DELETE /api/v1/vigimail/emails/{email}
func (h *VigimailHandler) DeleteEmail(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	if email == "" {
		ErrorResponse(w, http.StatusBadRequest, "Email is required", nil)
		return
	}

	// URL decode the email (@ might be encoded)
	email = strings.ReplaceAll(email, "%40", "@")

	if err := h.service.DeleteEmail(r.Context(), email); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to delete email", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Email deleted",
	})
}

// GetEmailLeaks handles GET /api/v1/vigimail/emails/{email}/leaks
func (h *VigimailHandler) GetEmailLeaks(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	if email == "" {
		ErrorResponse(w, http.StatusBadRequest, "Email is required", nil)
		return
	}

	email = strings.ReplaceAll(email, "%40", "@")

	leaks, err := h.service.GetEmailLeaks(r.Context(), email)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get leaks", err)
		return
	}

	if leaks == nil {
		leaks = []entity.VigimailLeak{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"email": email,
		"leaks": leaks,
		"count": len(leaks),
	})
}

// CheckEmail handles POST /api/v1/vigimail/emails/{email}/check
func (h *VigimailHandler) CheckEmail(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	if email == "" {
		ErrorResponse(w, http.StatusBadRequest, "Email is required", nil)
		return
	}

	email = strings.ReplaceAll(email, "%40", "@")

	leaks, err := h.service.CheckEmail(r.Context(), email)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Leak check failed", err)
		return
	}

	if leaks == nil {
		leaks = []entity.VigimailLeak{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"email": email,
		"leaks": leaks,
		"count": len(leaks),
		"status": func() string {
			if len(leaks) > 0 {
				return "leaked"
			}
			return "clean"
		}(),
	})
}

// ============================================
// Bulk Operations
// ============================================

// CheckAll handles POST /api/v1/vigimail/check-all
func (h *VigimailHandler) CheckAll(w http.ResponseWriter, r *http.Request) {
	history, err := h.service.CheckAll(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Check failed", err)
		return
	}

	JSONResponse(w, http.StatusOK, history)
}

// ============================================
// API Key Testing (v3.57.119)
// ============================================

// TestHIBPKey handles POST /api/v1/vigimail/test-hibp
// Tests an HIBP API key before saving
func (h *VigimailHandler) TestHIBPKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.APIKey == "" {
		ErrorResponse(w, http.StatusBadRequest, "API key is required", nil)
		return
	}

	// Skip test if the key contains mask characters (not changed)
	if containsMask(req.APIKey) {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "API key unchanged, skipping test",
		})
		return
	}

	slog.Info("[VIGIMAIL_API] Testing HIBP API key")

	if err := h.service.TestHIBPKey(r.Context(), req.APIKey); err != nil {
		slog.Warn("[VIGIMAIL_API] HIBP API key test failed", "error", err)
		ErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("API key test failed: %v", err), err)
		return
	}

	slog.Info("[VIGIMAIL_API] HIBP API key test successful")
	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "API key is valid",
	})
}
