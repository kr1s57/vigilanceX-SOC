package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kr1s57/vigilancex/internal/license"
)

// LicenseHandler handles license-related API endpoints
type LicenseHandler struct {
	client *license.Client
}

// NewLicenseHandler creates a new license handler
func NewLicenseHandler(client *license.Client) *LicenseHandler {
	return &LicenseHandler{
		client: client,
	}
}

// ActivateRequest represents a license activation request
type ActivateRequest struct {
	LicenseKey string `json:"license_key"`
}

// LicenseStatusResponse represents the license status response
type LicenseStatusResponse struct {
	Licensed      bool       `json:"licensed"`
	Status        string     `json:"status"`
	CustomerName  string     `json:"customer_name,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	DaysRemaining int        `json:"days_remaining,omitempty"`
	GraceMode     bool       `json:"grace_mode"`
	Features      []string   `json:"features"`
	HardwareID    string     `json:"hardware_id,omitempty"`
	// v3.0: Firewall binding info
	BindingVersion string `json:"binding_version,omitempty"`
	FirewallSerial string `json:"firewall_serial,omitempty"`
	FirewallModel  string `json:"firewall_model,omitempty"`
	FirewallName   string `json:"firewall_name,omitempty"`
	SecureBinding  bool   `json:"secure_binding"`
}

// LicenseInfoResponse represents detailed license info (admin only)
type LicenseInfoResponse struct {
	LicenseStatusResponse
	LicenseKey   string `json:"license_key,omitempty"`
	MaxFirewalls int    `json:"max_firewalls,omitempty"`
}

// GetStatus returns the current license status
// GET /api/v1/license/status
func (h *LicenseHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	if h.client == nil {
		// License system not enabled
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(LicenseStatusResponse{
			Licensed: true,
			Status:   "disabled",
			Features: []string{"all"},
		})
		return
	}

	status := h.client.GetStatus()

	response := LicenseStatusResponse{
		Licensed:       status.Licensed,
		Status:         status.Status,
		CustomerName:   status.CustomerName,
		ExpiresAt:      status.ExpiresAt,
		DaysRemaining:  status.DaysRemaining,
		GraceMode:      status.GraceMode,
		Features:       status.Features,
		HardwareID:     status.HardwareID,
		// v3.0: Firewall binding info
		BindingVersion: status.BindingVersion,
		FirewallSerial: status.FirewallSerial,
		FirewallModel:  status.FirewallModel,
		FirewallName:   status.FirewallName,
		SecureBinding:  status.SecureBinding,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Activate activates a license key
// POST /api/v1/license/activate
func (h *LicenseHandler) Activate(w http.ResponseWriter, r *http.Request) {
	if h.client == nil {
		http.Error(w, `{"error":"License system not enabled"}`, http.StatusServiceUnavailable)
		return
	}

	var req ActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.LicenseKey == "" {
		http.Error(w, `{"error":"License key is required"}`, http.StatusBadRequest)
		return
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := h.client.Activate(ctx, req.LicenseKey); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "activation_failed",
			"message": err.Error(),
		})
		return
	}

	// Return updated status
	status := h.client.GetStatus()
	response := map[string]interface{}{
		"success": true,
		"message": "License activated successfully",
		"license": LicenseStatusResponse{
			Licensed:      status.Licensed,
			Status:        status.Status,
			CustomerName:  status.CustomerName,
			ExpiresAt:     status.ExpiresAt,
			DaysRemaining: status.DaysRemaining,
			GraceMode:     status.GraceMode,
			Features:      status.Features,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetInfo returns detailed license info (admin only)
// GET /api/v1/license/info
func (h *LicenseHandler) GetInfo(w http.ResponseWriter, r *http.Request) {
	if h.client == nil {
		http.Error(w, `{"error":"License system not enabled"}`, http.StatusServiceUnavailable)
		return
	}

	status := h.client.GetStatus()

	// Mask license key for display (show only last 4 chars)
	licenseKey := h.client.GetLicenseKey()
	if len(licenseKey) > 4 {
		licenseKey = "****-****-****-" + licenseKey[len(licenseKey)-4:]
	}

	response := LicenseInfoResponse{
		LicenseStatusResponse: LicenseStatusResponse{
			Licensed:      status.Licensed,
			Status:        status.Status,
			CustomerName:  status.CustomerName,
			ExpiresAt:     status.ExpiresAt,
			DaysRemaining: status.DaysRemaining,
			GraceMode:     status.GraceMode,
			Features:      status.Features,
			HardwareID:    status.HardwareID,
		},
		LicenseKey: licenseKey,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ForceValidate triggers an immediate license validation (admin only)
// POST /api/v1/license/validate
func (h *LicenseHandler) ForceValidate(w http.ResponseWriter, r *http.Request) {
	if h.client == nil {
		http.Error(w, `{"error":"License system not enabled"}`, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	status, err := h.client.Validate(ctx)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "validation_failed",
			"message": err.Error(),
		})
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "License validated successfully",
		"license": LicenseStatusResponse{
			Licensed:      status.Licensed,
			Status:        status.Status,
			CustomerName:  status.CustomerName,
			ExpiresAt:     status.ExpiresAt,
			DaysRemaining: status.DaysRemaining,
			GraceMode:     status.GraceMode,
			Features:      status.Features,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
