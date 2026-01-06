package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/kr1s57/vigilancex/internal/usecase/reports"
)

// ReportsHandler handles report-related HTTP requests
type ReportsHandler struct {
	service *reports.Service
}

// NewReportsHandler creates a new reports handler
func NewReportsHandler(service *reports.Service) *ReportsHandler {
	return &ReportsHandler{service: service}
}

// GetDBStats returns current database statistics
func (h *ReportsHandler) GetDBStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetDBStats(ctx)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get database stats", err)
		return
	}

	JSONResponse(w, http.StatusOK, stats)
}

// GenerateReportRequest represents the request body for generating a report
type GenerateReportRequest struct {
	Type      string   `json:"type"`       // daily, weekly, monthly, custom
	Format    string   `json:"format"`     // pdf, xml
	StartDate string   `json:"start_date"` // For custom reports
	EndDate   string   `json:"end_date"`   // For custom reports
	Modules   []string `json:"modules"`    // waf, vpn, threats, bans
}

// GenerateReport generates and returns a report
func (h *ReportsHandler) GenerateReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters or request body
	var config reports.ReportConfig

	// Check if it's a GET request with query params
	if r.Method == http.MethodGet {
		config.Type = r.URL.Query().Get("type")
		if config.Type == "" {
			config.Type = "daily"
		}

		config.Format = r.URL.Query().Get("format")
		if config.Format == "" {
			config.Format = "pdf"
		}

		// Parse modules
		modules := r.URL.Query()["modules"]
		if len(modules) > 0 {
			config.Modules = modules
		}

		// Parse dates for custom reports
		if config.Type == "custom" {
			startStr := r.URL.Query().Get("start_date")
			endStr := r.URL.Query().Get("end_date")

			if startStr != "" {
				start, err := time.Parse("2006-01-02", startStr)
				if err != nil {
					ErrorResponse(w, http.StatusBadRequest, "Invalid start_date format (use YYYY-MM-DD)", err)
					return
				}
				config.StartDate = start
			}

			if endStr != "" {
				end, err := time.Parse("2006-01-02", endStr)
				if err != nil {
					ErrorResponse(w, http.StatusBadRequest, "Invalid end_date format (use YYYY-MM-DD)", err)
					return
				}
				// Set to end of day
				config.EndDate = time.Date(end.Year(), end.Month(), end.Day(), 23, 59, 59, 0, time.UTC)
			}
		}
	} else {
		// POST request with JSON body
		var req GenerateReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
			return
		}

		config.Type = req.Type
		config.Format = req.Format
		config.Modules = req.Modules

		if req.StartDate != "" {
			start, err := time.Parse("2006-01-02", req.StartDate)
			if err != nil {
				ErrorResponse(w, http.StatusBadRequest, "Invalid start_date format", err)
				return
			}
			config.StartDate = start
		}

		if req.EndDate != "" {
			end, err := time.Parse("2006-01-02", req.EndDate)
			if err != nil {
				ErrorResponse(w, http.StatusBadRequest, "Invalid end_date format", err)
				return
			}
			config.EndDate = time.Date(end.Year(), end.Month(), end.Day(), 23, 59, 59, 0, time.UTC)
		}
	}

	// Validate format
	if config.Format != "pdf" && config.Format != "xml" {
		ErrorResponse(w, http.StatusBadRequest, "Invalid format. Use 'pdf' or 'xml'", nil)
		return
	}

	// Validate type
	validTypes := map[string]bool{"daily": true, "weekly": true, "monthly": true, "custom": true}
	if !validTypes[config.Type] {
		ErrorResponse(w, http.StatusBadRequest, "Invalid type. Use 'daily', 'weekly', 'monthly', or 'custom'", nil)
		return
	}

	// Generate report
	data, filename, err := h.service.GenerateReport(ctx, config)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to generate report", err)
		return
	}

	// Set response headers for file download
	contentType := "application/pdf"
	if config.Format == "xml" {
		contentType = "application/xml"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// PreviewReport returns report data without generating the final file
func (h *ReportsHandler) PreviewReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	config := reports.ReportConfig{
		Type:   r.URL.Query().Get("type"),
		Format: "json", // Preview always returns JSON
	}

	if config.Type == "" {
		config.Type = "daily"
	}

	// Parse modules
	modules := r.URL.Query()["modules"]
	if len(modules) > 0 {
		config.Modules = modules
	}

	// Parse dates for custom reports
	if config.Type == "custom" {
		startStr := r.URL.Query().Get("start_date")
		endStr := r.URL.Query().Get("end_date")

		if startStr != "" {
			start, err := time.Parse("2006-01-02", startStr)
			if err != nil {
				ErrorResponse(w, http.StatusBadRequest, "Invalid start_date format", err)
				return
			}
			config.StartDate = start
		}

		if endStr != "" {
			end, err := time.Parse("2006-01-02", endStr)
			if err != nil {
				ErrorResponse(w, http.StatusBadRequest, "Invalid end_date format", err)
				return
			}
			config.EndDate = time.Date(end.Year(), end.Month(), end.Day(), 23, 59, 59, 0, time.UTC)
		}
	}

	data, err := h.service.GetPreviewData(ctx, config)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to get preview data", err)
		return
	}

	JSONResponse(w, http.StatusOK, data)
}
