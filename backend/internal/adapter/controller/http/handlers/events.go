package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kr1s57/vigilancex/internal/usecase/events"
)

// EventsHandler handles HTTP requests for events
type EventsHandler struct {
	service *events.Service
}

// NewEventsHandler creates a new events handler
func NewEventsHandler(service *events.Service) *EventsHandler {
	return &EventsHandler{
		service: service,
	}
}

// ListEvents handles GET /api/v1/events
func (h *EventsHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	req := events.ListEventsRequest{
		LogType:    r.URL.Query().Get("log_type"),
		Category:   r.URL.Query().Get("category"),
		Severity:   r.URL.Query().Get("severity"),
		SrcIP:      r.URL.Query().Get("src_ip"),
		DstIP:      r.URL.Query().Get("dst_ip"),
		Hostname:   r.URL.Query().Get("hostname"),
		RuleID:     r.URL.Query().Get("rule_id"),
		Action:     r.URL.Query().Get("action"),
		SearchTerm: r.URL.Query().Get("search"),
	}

	// Parse limit and offset
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil {
			req.Limit = l
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil {
			req.Offset = o
		}
	}

	// Parse time range
	if startTime := r.URL.Query().Get("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			req.StartTime = t
		}
	}
	if endTime := r.URL.Query().Get("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			req.EndTime = t
		}
	}

	// Get events
	response, err := h.service.ListEvents(ctx, req)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve events", err)
		return
	}

	respondJSON(w, http.StatusOK, response)
}

// GetEvent handles GET /api/v1/events/{id}
func (h *EventsHandler) GetEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse event ID
	idStr := chi.URLParam(r, "id")
	eventID, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid event ID", err)
		return
	}

	// Get event
	event, err := h.service.GetEvent(ctx, eventID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Event not found", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": event,
	})
}

// GetTimeline handles GET /api/v1/events/timeline
func (h *EventsHandler) GetTimeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := events.TimelineRequest{
		Period:   r.URL.Query().Get("period"),
		Interval: r.URL.Query().Get("interval"),
	}

	timeline, err := h.service.GetTimeline(ctx, req)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve timeline", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": timeline,
	})
}

// GetOverview handles GET /api/v1/stats/overview
func (h *EventsHandler) GetOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	period := r.URL.Query().Get("period")

	overview, err := h.service.GetOverview(ctx, period)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve overview", err)
		return
	}

	respondJSON(w, http.StatusOK, overview)
}

// GetTopAttackers handles GET /api/v1/stats/top-attackers
func (h *EventsHandler) GetTopAttackers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	period := r.URL.Query().Get("period")
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	attackers, err := h.service.GetTopAttackers(ctx, period, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve top attackers", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": attackers,
	})
}

// GetTopTargets handles GET /api/v1/stats/top-targets
func (h *EventsHandler) GetTopTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	period := r.URL.Query().Get("period")
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	targets, err := h.service.GetTopTargets(ctx, period, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve top targets", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": targets,
	})
}

// GetGeoHeatmap handles GET /api/v1/geo/heatmap
func (h *EventsHandler) GetGeoHeatmap(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	period := r.URL.Query().Get("period")

	heatmap, err := h.service.GetGeoHeatmap(ctx, period)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve geo heatmap", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": heatmap,
	})
}

// GetHostnames handles GET /api/v1/events/hostnames
func (h *EventsHandler) GetHostnames(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	logType := r.URL.Query().Get("log_type")
	if logType == "" {
		logType = "WAF"
	}

	hostnames, err := h.service.GetUniqueHostnames(ctx, logType)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve hostnames", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": hostnames,
	})
}

// GetSyslogStatus handles GET /api/v1/status/syslog
func (h *EventsHandler) GetSyslogStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status, err := h.service.GetSyslogStatus(ctx)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get syslog status", err)
		return
	}

	respondJSON(w, http.StatusOK, status)
}

// GetCriticalAlerts handles GET /api/v1/alerts/critical
func (h *EventsHandler) GetCriticalAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	alerts, err := h.service.GetCriticalAlerts(ctx, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get critical alerts", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data":  alerts,
		"count": len(alerts),
	})
}

// Helper functions

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := map[string]interface{}{
		"error":   message,
		"status":  status,
	}

	if err != nil {
		response["details"] = err.Error()
	}

	json.NewEncoder(w).Encode(response)
}
