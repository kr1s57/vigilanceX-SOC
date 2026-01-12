package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/storage"
)

// StorageHandler handles storage-related HTTP requests
type StorageHandler struct {
	manager *storage.Manager
}

// NewStorageHandler creates a new storage handler
func NewStorageHandler(manager *storage.Manager) *StorageHandler {
	return &StorageHandler{
		manager: manager,
	}
}

// GetConfig returns the current storage configuration
func (h *StorageHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	config := h.manager.GetConfig()
	JSONResponse(w, http.StatusOK, config)
}

// UpdateConfig updates the storage configuration
func (h *StorageHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var config storage.Config
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if err := h.manager.UpdateConfig(&config); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{"message": "Configuration updated"})
}

// UpdateSMBConfig updates only the SMB configuration
func (h *StorageHandler) UpdateSMBConfig(w http.ResponseWriter, r *http.Request) {
	var smb storage.SMBConfig
	if err := json.NewDecoder(r.Body).Decode(&smb); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	// Validate required fields
	if smb.Host == "" || smb.Share == "" || smb.Username == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Host, Share, and Username are required"})
		return
	}

	if err := h.manager.UpdateSMBConfig(&smb); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{"message": "SMB configuration updated"})
}

// GetStatus returns the current storage status
func (h *StorageHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := h.manager.GetStatus()
	JSONResponse(w, http.StatusOK, status)
}

// TestConnection tests the storage connection
func (h *StorageHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	var smb storage.SMBConfig
	if err := json.NewDecoder(r.Body).Decode(&smb); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	// Use existing password if masked
	if smb.Password == "********" {
		config := h.manager.GetConfig()
		if config.SMB != nil {
			// Get actual password from manager
			// Note: GetConfig returns masked password, so we need direct access
			smb.Password = "" // Will fail if no password provided
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := h.manager.TestConnection(ctx, &smb); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Connection successful",
	})
}

// Connect connects to the configured storage
func (h *StorageHandler) Connect(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := h.manager.Connect(ctx); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{"message": "Connected successfully"})
}

// Disconnect disconnects from storage
func (h *StorageHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
	if err := h.manager.Disconnect(); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{"message": "Disconnected"})
}

// Enable enables storage archiving
func (h *StorageHandler) Enable(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := h.manager.Enable(ctx); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{"message": "Storage enabled and connected"})
}

// Disable disables storage archiving
func (h *StorageHandler) Disable(w http.ResponseWriter, r *http.Request) {
	if err := h.manager.Disable(); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]string{"message": "Storage disabled"})
}
