package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// WAFServersRepository interface for WAF servers persistence
type WAFServersRepository interface {
	GetAll(ctx context.Context) ([]entity.WAFMonitoredServer, error)
	GetByHostname(ctx context.Context, hostname string) (*entity.WAFMonitoredServer, error)
	Create(ctx context.Context, server *entity.WAFMonitoredServer) error
	Update(ctx context.Context, server *entity.WAFMonitoredServer) error
	Delete(ctx context.Context, hostname string) error
	Exists(ctx context.Context, hostname string) (bool, error)
	GetAllHostnames(ctx context.Context) ([]string, error)
}

// ModSecLogsDeleter interface for deleting ModSec logs by hostname
type ModSecLogsDeleter interface {
	DeleteLogsByHostname(ctx context.Context, hostname string) error
}

// WAFServersHandler handles WAF servers HTTP requests
type WAFServersHandler struct {
	repo     WAFServersRepository
	logsRepo ModSecLogsDeleter
}

// NewWAFServersHandler creates a new WAF servers handler
func NewWAFServersHandler(repo WAFServersRepository, logsRepo ModSecLogsDeleter) *WAFServersHandler {
	return &WAFServersHandler{repo: repo, logsRepo: logsRepo}
}

// List returns all configured WAF servers
// GET /api/v1/waf-servers
func (h *WAFServersHandler) List(w http.ResponseWriter, r *http.Request) {
	servers, err := h.repo.GetAll(r.Context())
	if err != nil {
		slog.Error("[WAF-SERVERS] Failed to list servers", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to list servers", err)
		return
	}

	if servers == nil {
		servers = []entity.WAFMonitoredServer{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"data":  servers,
		"total": len(servers),
	})
}

// Get returns a specific WAF server by hostname
// GET /api/v1/waf-servers/{hostname}
func (h *WAFServersHandler) Get(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		ErrorResponse(w, http.StatusBadRequest, "Hostname required", nil)
		return
	}

	server, err := h.repo.GetByHostname(r.Context(), hostname)
	if err != nil {
		slog.Warn("[WAF-SERVERS] Server not found", "hostname", hostname, "error", err)
		ErrorResponse(w, http.StatusNotFound, "Server not found", nil)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"data": server,
	})
}

// Create creates a new WAF server
// POST /api/v1/waf-servers
func (h *WAFServersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req entity.WAFServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if err := req.IsValid(); err != nil {
		ErrorResponse(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Check if hostname already exists
	exists, err := h.repo.Exists(r.Context(), req.Hostname)
	if err != nil {
		slog.Error("[WAF-SERVERS] Failed to check existence", "hostname", req.Hostname, "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to check server existence", err)
		return
	}
	if exists {
		ErrorResponse(w, http.StatusConflict, "Server with this hostname already exists", nil)
		return
	}

	// Get username from context (set by JWT middleware)
	username := "system"
	if user, ok := r.Context().Value("user").(map[string]interface{}); ok {
		if u, ok := user["username"].(string); ok {
			username = u
		}
	}

	// Create entity
	server := req.ToEntity(username)

	// Save to database
	if err := h.repo.Create(r.Context(), server); err != nil {
		slog.Error("[WAF-SERVERS] Failed to create server", "hostname", req.Hostname, "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to create server", err)
		return
	}

	slog.Info("[WAF-SERVERS] Server created",
		"hostname", server.Hostname,
		"policy_enabled", server.PolicyEnabled,
		"policy_mode", server.PolicyMode,
		"created_by", username)

	JSONResponse(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Server created successfully",
		"data":    server,
	})
}

// Update updates an existing WAF server
// PUT /api/v1/waf-servers/{hostname}
func (h *WAFServersHandler) Update(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		ErrorResponse(w, http.StatusBadRequest, "Hostname required", nil)
		return
	}

	// Get existing server
	server, err := h.repo.GetByHostname(r.Context(), hostname)
	if err != nil {
		slog.Warn("[WAF-SERVERS] Server not found for update", "hostname", hostname, "error", err)
		ErrorResponse(w, http.StatusNotFound, "Server not found", nil)
		return
	}

	// Decode request
	var req entity.WAFServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request (allow partial updates by setting hostname)
	if req.Hostname == "" {
		req.Hostname = hostname
	}
	if err := req.IsValid(); err != nil {
		ErrorResponse(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Apply updates
	server.ApplyUpdate(&req)

	// Save to database
	if err := h.repo.Update(r.Context(), server); err != nil {
		slog.Error("[WAF-SERVERS] Failed to update server", "hostname", hostname, "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to update server", err)
		return
	}

	slog.Info("[WAF-SERVERS] Server updated",
		"hostname", server.Hostname,
		"policy_enabled", server.PolicyEnabled,
		"policy_mode", server.PolicyMode)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Server updated successfully",
		"data":    server,
	})
}

// Delete deletes a WAF server configuration and/or its logs
// DELETE /api/v1/waf-servers/{hostname}?delete_logs=true|false
// If the server exists in config: deletes config (and optionally logs)
// If the server doesn't exist but delete_logs=true: deletes only logs (for auto-discovered servers)
func (h *WAFServersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		ErrorResponse(w, http.StatusBadRequest, "Hostname required", nil)
		return
	}

	// Parse delete_logs parameter (default: false = keep logs for 30 days)
	deleteLogs := r.URL.Query().Get("delete_logs") == "true"

	// Check if server exists in configuration
	exists, err := h.repo.Exists(r.Context(), hostname)
	if err != nil {
		slog.Error("[WAF-SERVERS] Failed to check existence", "hostname", hostname, "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to check server existence", err)
		return
	}

	configDeleted := false
	logsDeleted := false

	// If server exists in config, delete it
	if exists {
		if err := h.repo.Delete(r.Context(), hostname); err != nil {
			slog.Error("[WAF-SERVERS] Failed to delete server", "hostname", hostname, "error", err)
			ErrorResponse(w, http.StatusInternalServerError, "Failed to delete server", err)
			return
		}
		configDeleted = true
	}

	// Delete logs if requested (works even for auto-discovered servers not in config)
	if deleteLogs && h.logsRepo != nil {
		if err := h.logsRepo.DeleteLogsByHostname(r.Context(), hostname); err != nil {
			slog.Error("[WAF-SERVERS] Failed to delete logs for server", "hostname", hostname, "error", err)
			// Don't fail the request, just log the error
		} else {
			logsDeleted = true
			slog.Info("[WAF-SERVERS] Logs deleted for server", "hostname", hostname)
		}
	}

	// If neither config nor logs were affected, return not found
	if !configDeleted && !logsDeleted && !deleteLogs {
		ErrorResponse(w, http.StatusNotFound, "Server not found in configuration", nil)
		return
	}

	// Build response message
	var message string
	if configDeleted && logsDeleted {
		message = "Server configuration and all logs deleted successfully"
	} else if configDeleted && deleteLogs && !logsDeleted {
		message = "Server configuration deleted (logs deletion may have failed)"
	} else if configDeleted {
		message = "Server configuration deleted (logs retained for 30 days)"
	} else if logsDeleted {
		message = "Logs deleted successfully (server was not in configuration)"
	} else if deleteLogs {
		message = "Log deletion initiated (server was not in configuration)"
	}

	slog.Info("[WAF-SERVERS] Server/logs deleted",
		"hostname", hostname,
		"config_deleted", configDeleted,
		"logs_deleted", logsDeleted,
		"delete_logs_requested", deleteLogs)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"message":        message,
		"config_deleted": configDeleted,
		"logs_deleted":   logsDeleted,
	})
}

// GetHostnames returns just the hostnames of configured servers
// GET /api/v1/waf-servers/hostnames
func (h *WAFServersHandler) GetHostnames(w http.ResponseWriter, r *http.Request) {
	hostnames, err := h.repo.GetAllHostnames(r.Context())
	if err != nil {
		slog.Error("[WAF-SERVERS] Failed to get hostnames", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get hostnames", err)
		return
	}

	if hostnames == nil {
		hostnames = []string{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"data":  hostnames,
		"total": len(hostnames),
	})
}

// CheckPolicy checks if a country would be banned for a specific hostname
// GET /api/v1/waf-servers/{hostname}/check-policy?country=XX
func (h *WAFServersHandler) CheckPolicy(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		ErrorResponse(w, http.StatusBadRequest, "Hostname required", nil)
		return
	}

	countryCode := r.URL.Query().Get("country")
	if countryCode == "" || len(countryCode) != 2 {
		ErrorResponse(w, http.StatusBadRequest, "Valid 2-letter country code required", nil)
		return
	}

	server, err := h.repo.GetByHostname(r.Context(), hostname)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "Server not found", nil)
		return
	}

	result := server.CheckCountryPolicy(countryCode)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"hostname":       hostname,
		"country":        countryCode,
		"policy_enabled": server.PolicyEnabled,
		"policy_mode":    server.PolicyMode,
		"result":         result,
	})
}
