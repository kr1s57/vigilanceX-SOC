package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/crowdsec"
)

// NeuralSyncHandler handles Neural-Sync (VigilanceKey proxy) endpoints
type NeuralSyncHandler struct {
	vkClient *crowdsec.VigilanceKeyClient
}

// NewNeuralSyncHandler creates a new Neural-Sync handler
func NewNeuralSyncHandler() *NeuralSyncHandler {
	return &NeuralSyncHandler{}
}

// SetVigilanceKeyClient sets the VigilanceKey client
func (h *NeuralSyncHandler) SetVigilanceKeyClient(client *crowdsec.VigilanceKeyClient) {
	h.vkClient = client
}

// NeuralSyncConfig represents the Neural-Sync configuration
type NeuralSyncConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerURL  string `json:"server_url"`
	LicenseKey string `json:"license_key"`
	HardwareID string `json:"hardware_id"`
	Configured bool   `json:"configured"`
}

// NeuralSyncStatus represents the status of Neural-Sync connection
type NeuralSyncStatus struct {
	Enabled         bool      `json:"enabled"`
	Configured      bool      `json:"configured"`
	Connected       bool      `json:"connected"`
	ServerURL       string    `json:"server_url"`
	TotalBlocklists int       `json:"total_blocklists"`
	TotalIPs        int64     `json:"total_ips"`
	LastSync        time.Time `json:"last_sync,omitempty"`
	Error           string    `json:"error,omitempty"`
}

// NeuralSyncIP represents an IP from VigilanceKey blocklist
type NeuralSyncIP struct {
	IP             string `json:"ip"`
	BlocklistID    string `json:"blocklist_id"`
	BlocklistLabel string `json:"blocklist_label"`
	CountryCode    string `json:"country_code"`
}

// GetConfig returns the Neural-Sync configuration
// GET /api/v1/neural-sync/config
func (h *NeuralSyncHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	if h.vkClient == nil {
		JSONResponse(w, http.StatusOK, NeuralSyncConfig{
			Enabled:    false,
			Configured: false,
		})
		return
	}

	JSONResponse(w, http.StatusOK, NeuralSyncConfig{
		Enabled:    true,
		ServerURL:  h.vkClient.GetServerURL(),
		Configured: h.vkClient.IsConfigured(),
	})
}

// UpdateConfig updates the Neural-Sync configuration
// PUT /api/v1/neural-sync/config
func (h *NeuralSyncHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerURL  string `json:"server_url"`
		LicenseKey string `json:"license_key"`
		HardwareID string `json:"hardware_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if h.vkClient == nil {
		h.vkClient = crowdsec.NewVigilanceKeyClient(crowdsec.VigilanceKeyConfig{
			ServerURL:  req.ServerURL,
			LicenseKey: req.LicenseKey,
			HardwareID: req.HardwareID,
		})
	} else {
		h.vkClient.SetServerURL(req.ServerURL)
		h.vkClient.SetCredentials(req.LicenseKey, req.HardwareID)
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Neural-Sync configuration updated",
	})
}

// GetStatus returns the Neural-Sync status
// GET /api/v1/neural-sync/status
func (h *NeuralSyncHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := NeuralSyncStatus{
		Enabled:    h.vkClient != nil,
		Configured: h.vkClient != nil && h.vkClient.IsConfigured(),
	}

	if h.vkClient != nil && h.vkClient.IsConfigured() {
		status.ServerURL = h.vkClient.GetServerURL()

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		if err := h.vkClient.TestConnection(ctx); err != nil {
			status.Connected = false
			status.Error = err.Error()
		} else {
			status.Connected = true

			// Get blocklist info
			blocklists, err := h.vkClient.ListBlocklists(ctx)
			if err == nil {
				status.TotalBlocklists = len(blocklists)
				for _, bl := range blocklists {
					status.TotalIPs += bl.IPCount
				}
			}
		}
	}

	JSONResponse(w, http.StatusOK, status)
}

// TestConnection tests the Neural-Sync connection
// POST /api/v1/neural-sync/test
func (h *NeuralSyncHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	if h.vkClient == nil || !h.vkClient.IsConfigured() {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"message": "Neural-Sync not configured",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.vkClient.TestConnection(ctx); err != nil {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Connection failed: %v", err),
		})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Connection successful",
	})
}

// ListBlocklists returns available blocklists from VigilanceKey
// GET /api/v1/neural-sync/blocklists
func (h *NeuralSyncHandler) ListBlocklists(w http.ResponseWriter, r *http.Request) {
	if h.vkClient == nil || !h.vkClient.IsConfigured() {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"blocklists": []interface{}{},
			"total":      0,
			"error":      "Neural-Sync not configured",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	blocklists, err := h.vkClient.ListBlocklists(ctx)
	if err != nil {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"blocklists": []interface{}{},
			"total":      0,
			"error":      err.Error(),
		})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"blocklists": blocklists,
		"total":      len(blocklists),
	})
}

// ListIPs returns IPs from VigilanceKey blocklists
// GET /api/v1/neural-sync/ips
func (h *NeuralSyncHandler) ListIPs(w http.ResponseWriter, r *http.Request) {
	if h.vkClient == nil || !h.vkClient.IsConfigured() {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"ips":   []interface{}{},
			"total": 0,
			"page":  1,
			"error": "Neural-Sync not configured",
		})
		return
	}

	// Parse query params
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	blocklistID := r.URL.Query().Get("blocklist_id")
	countryCode := r.URL.Query().Get("country")
	search := r.URL.Query().Get("search")

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// Download IPs from all blocklists
	blocklists, err := h.vkClient.ListBlocklists(ctx)
	if err != nil {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"ips":   []interface{}{},
			"total": 0,
			"page":  page,
			"error": err.Error(),
		})
		return
	}

	var allIPs []NeuralSyncIP
	for _, bl := range blocklists {
		// Filter by blocklist if specified
		if blocklistID != "" && bl.ID != blocklistID {
			continue
		}

		ips, err := h.vkClient.DownloadBlocklist(ctx, bl.ID)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			nsIP := NeuralSyncIP{
				IP:             ip,
				BlocklistID:    bl.ID,
				BlocklistLabel: bl.Label,
			}

			// Apply filters
			if search != "" && !containsIP(ip, search) {
				continue
			}
			if countryCode != "" && nsIP.CountryCode != countryCode {
				continue
			}

			allIPs = append(allIPs, nsIP)
		}
	}

	// Pagination
	total := len(allIPs)
	totalPages := (total + pageSize - 1) / pageSize
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"ips":         allIPs[start:end],
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

func containsIP(ip, search string) bool {
	return len(search) == 0 || (len(ip) >= len(search) && ip[:len(search)] == search) ||
		(len(ip) > 0 && ip == search)
}
