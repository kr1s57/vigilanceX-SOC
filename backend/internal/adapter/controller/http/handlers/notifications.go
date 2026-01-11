package handlers

import (
	"net/http"
	"strings"

	"github.com/kr1s57/vigilancex/internal/usecase/notifications"
)

// NotificationHandler handles notification-related HTTP requests
type NotificationHandler struct {
	service *notifications.Service
}

// NewNotificationHandler creates a new notification handler
func NewNotificationHandler(service *notifications.Service) *NotificationHandler {
	return &NotificationHandler{
		service: service,
	}
}

// GetSettings returns notification settings
// GET /api/v1/notifications/settings
func (h *NotificationHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings := h.service.GetSettings()
	JSONResponse(w, http.StatusOK, settings)
}

// UpdateSettings updates notification settings
// PUT /api/v1/notifications/settings
func (h *NotificationHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	// Decode as map to support partial updates
	var updates map[string]interface{}
	if err := DecodeJSON(r, &updates); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Use atomic merge to avoid race conditions with concurrent requests
	if err := h.service.MergeAndUpdateSettings(updates); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to update settings", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"message":  "Notification settings updated",
		"settings": h.service.GetSettings(),
	})
}

// SendTestEmailRequest represents a test email request
type SendTestEmailRequest struct {
	Recipients []string `json:"recipients"`
}

// SendTestEmail sends a test email
// POST /api/v1/notifications/test-email
func (h *NotificationHandler) SendTestEmail(w http.ResponseWriter, r *http.Request) {
	var req SendTestEmailRequest
	if err := DecodeJSON(r, &req); err != nil {
		// If no body provided, use default recipients
		req.Recipients = nil
	}

	// Parse recipients from comma-separated string if needed
	if len(req.Recipients) == 1 && strings.Contains(req.Recipients[0], ",") {
		parts := strings.Split(req.Recipients[0], ",")
		req.Recipients = make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				req.Recipients = append(req.Recipients, trimmed)
			}
		}
	}

	if err := h.service.SendTestEmail(r.Context(), req.Recipients); err != nil {
		// Return detailed error for debugging SMTP issues
		JSONResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to send test email",
			"details": err.Error(),
		})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Test email sent successfully",
	})
}

// GetStatus returns SMTP configuration status
// GET /api/v1/notifications/status
func (h *NotificationHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	configured := h.service.IsSMTPConfigured()
	host := h.service.GetSMTPHost()

	status := "not_configured"
	if configured {
		status = "configured"
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"configured": configured,
		"status":     status,
		"host":       host,
	})
}
