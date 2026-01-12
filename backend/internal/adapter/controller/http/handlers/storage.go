package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/kr1s57/vigilancex/internal/adapter/external/storage"
	"github.com/kr1s57/vigilancex/internal/usecase/archiver"
)

// LocalStorageStats represents local ClickHouse storage statistics
type LocalStorageStats struct {
	DatabaseSize   string            `json:"database_size"`
	TotalEvents    uint64            `json:"total_events"`
	EventsByType   map[string]uint64 `json:"events_by_type"`
	DateRangeStart time.Time         `json:"date_range_start"`
	DateRangeEnd   time.Time         `json:"date_range_end"`
	StoragePath    string            `json:"storage_path"`
}

// StorageHandler handles storage-related HTTP requests
type StorageHandler struct {
	manager  *storage.Manager
	archiver *archiver.Service
	dbConn   driver.Conn
}

// NewStorageHandler creates a new storage handler
func NewStorageHandler(manager *storage.Manager) *StorageHandler {
	return &StorageHandler{
		manager: manager,
	}
}

// SetDBConnection sets the ClickHouse connection for local stats
func (h *StorageHandler) SetDBConnection(conn driver.Conn) {
	h.dbConn = conn
}

// SetArchiver sets the archiver service (called after initialization)
func (h *StorageHandler) SetArchiver(a *archiver.Service) {
	h.archiver = a
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

// GetArchiverStatus returns the archiver service status
func (h *StorageHandler) GetArchiverStatus(w http.ResponseWriter, r *http.Request) {
	if h.archiver == nil {
		JSONResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "Archiver not configured"})
		return
	}

	status := h.archiver.GetStatus()
	JSONResponse(w, http.StatusOK, status)
}

// RunArchiver triggers an immediate archive run
func (h *StorageHandler) RunArchiver(w http.ResponseWriter, r *http.Request) {
	if h.archiver == nil {
		JSONResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "Archiver not configured"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	count, err := h.archiver.ArchiveNow(ctx)
	if err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]interface{}{
			"success":  false,
			"error":    err.Error(),
			"archived": count,
		})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"message":  fmt.Sprintf("Archived %d events", count),
		"archived": count,
	})
}

// WriteTestFile writes a test file to storage for verification
func (h *StorageHandler) WriteTestFile(w http.ResponseWriter, r *http.Request) {
	if h.archiver == nil {
		JSONResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "Archiver not configured"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := h.archiver.WriteTestFile(ctx); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Test file written successfully - check test/ folder on storage",
	})
}

// GetLocalStorageStats returns local ClickHouse storage statistics
func (h *StorageHandler) GetLocalStorageStats(w http.ResponseWriter, r *http.Request) {
	if h.dbConn == nil {
		JSONResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "Database not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	stats := &LocalStorageStats{
		EventsByType: make(map[string]uint64),
		StoragePath:  "/var/lib/clickhouse (Docker: clickhouse_data)",
	}

	// Get database size
	sizeQuery := `
		SELECT formatReadableSize(sum(bytes_on_disk)) as size
		FROM system.parts
		WHERE database = 'vigilance_x' AND active = 1
	`
	row := h.dbConn.QueryRow(ctx, sizeQuery)
	if err := row.Scan(&stats.DatabaseSize); err != nil {
		slog.Warn("[STORAGE] Failed to get database size", "error", err)
		stats.DatabaseSize = "N/A"
	}

	// Get total events count
	totalQuery := `SELECT count() FROM events`
	row = h.dbConn.QueryRow(ctx, totalQuery)
	if err := row.Scan(&stats.TotalEvents); err != nil {
		slog.Warn("[STORAGE] Failed to get total events", "error", err)
	}

	// Get events by log type
	byTypeQuery := `
		SELECT log_type, count() as cnt
		FROM events
		GROUP BY log_type
		ORDER BY cnt DESC
	`
	rows, err := h.dbConn.Query(ctx, byTypeQuery)
	if err != nil {
		slog.Warn("[STORAGE] Failed to get events by type", "error", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var logType string
			var count uint64
			if err := rows.Scan(&logType, &count); err == nil {
				stats.EventsByType[logType] = count
			}
		}
	}

	// Get date range
	dateRangeQuery := `
		SELECT
			min(timestamp) as first_event,
			max(timestamp) as last_event
		FROM events
	`
	row = h.dbConn.QueryRow(ctx, dateRangeQuery)
	if err := row.Scan(&stats.DateRangeStart, &stats.DateRangeEnd); err != nil {
		slog.Warn("[STORAGE] Failed to get date range", "error", err)
	}

	JSONResponse(w, http.StatusOK, stats)
}
