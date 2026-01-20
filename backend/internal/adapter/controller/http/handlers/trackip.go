package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/kr1s57/vigilancex/internal/usecase/trackip"
)

// TrackIPHandler handles HTTP requests for IP/hostname tracking
type TrackIPHandler struct {
	service *trackip.Service
}

// NewTrackIPHandler creates a new TrackIPHandler
func NewTrackIPHandler(service *trackip.Service) *TrackIPHandler {
	return &TrackIPHandler{service: service}
}

// Search handles GET /api/v1/track-ip
// Query parameters:
//   - query: IP address or hostname (required)
//   - start_time: ISO8601 timestamp for start of range
//   - end_time: ISO8601 timestamp for end of range
//   - period: Alternative to start/end: "1h", "24h", "7d", "30d"
//   - limit: Max results per category (default: 100, max: 500)
func (h *TrackIPHandler) Search(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	if query == "" {
		respondError(w, http.StatusBadRequest, "query parameter is required", errors.New("missing query parameter"))
		return
	}

	// Build query parameters
	trackQuery := &entity.TrackIPQuery{
		Query: query,
		Limit: 100, // Default
	}

	// Parse limit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 500 {
			trackQuery.Limit = limit
		}
	}

	// Parse offset for pagination
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			trackQuery.Offset = offset
		}
	}

	// Parse category filter (for loading more in specific category)
	trackQuery.Category = r.URL.Query().Get("category")

	// Parse time range - either period or start_time/end_time
	if period := r.URL.Query().Get("period"); period != "" {
		startTime := getStartTimeFromPeriodTrackIP(period)
		trackQuery.StartTime = &startTime
		now := time.Now()
		trackQuery.EndTime = &now
	} else {
		// Parse explicit time range
		if startStr := r.URL.Query().Get("start_time"); startStr != "" {
			if startTime, err := time.Parse(time.RFC3339, startStr); err == nil {
				trackQuery.StartTime = &startTime
			}
		}
		if endStr := r.URL.Query().Get("end_time"); endStr != "" {
			if endTime, err := time.Parse(time.RFC3339, endStr); err == nil {
				trackQuery.EndTime = &endTime
			}
		}
	}

	// Execute search
	result, err := h.service.Search(r.Context(), trackQuery)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "search failed", err)
		return
	}

	respondJSON(w, http.StatusOK, result)
}

// getStartTimeFromPeriodTrackIP converts a period string to a start time
func getStartTimeFromPeriodTrackIP(period string) time.Time {
	now := time.Now()
	switch period {
	case "1h":
		return now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		return now.Add(-8 * time.Hour)
	case "24h":
		return now.Add(-24 * time.Hour)
	case "7d":
		return now.AddDate(0, 0, -7)
	case "30d":
		return now.AddDate(0, 0, -30)
	default:
		return now.AddDate(0, 0, -7) // Default 7 days
	}
}
