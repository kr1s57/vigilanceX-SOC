package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/kr1s57/vigilancex/internal/adapter/controller/http/middleware"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/kr1s57/vigilancex/internal/usecase/auth"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	service *auth.Service
	logger  *slog.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(service *auth.Service, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		service: service,
		logger:  logger,
	}
}

// Login handles POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req entity.LoginRequest
	if err := DecodeJSON(r, &req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.Username == "" || req.Password == "" {
		ErrorResponse(w, http.StatusBadRequest, "Username and password are required", nil)
		return
	}

	// Attempt login
	response, err := h.service.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			ErrorResponse(w, http.StatusUnauthorized, "Invalid username or password", nil)
			return
		}
		if errors.Is(err, auth.ErrUserInactive) {
			ErrorResponse(w, http.StatusForbidden, "Account is inactive", nil)
			return
		}
		h.logger.Error("Login error", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Login failed", nil)
		return
	}

	JSONResponse(w, http.StatusOK, response)
}

// Logout handles POST /api/v1/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// JWT tokens are stateless, so logout is handled client-side
	// This endpoint is just for logging purposes
	username := middleware.GetUsername(r.Context())
	h.logger.Info("User logged out", "username", username)

	SuccessResponse(w, "Logged out successfully", nil)
}

// Me handles GET /api/v1/auth/me
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		ErrorResponse(w, http.StatusUnauthorized, "Not authenticated", nil)
		return
	}

	user, err := h.service.GetUserByID(r.Context(), userID)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "User not found", nil)
		return
	}

	// Return safe user info (without password hash)
	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"user": user.ToUserInfo(),
	})
}

// ChangePassword handles POST /api/v1/auth/change-password
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		ErrorResponse(w, http.StatusUnauthorized, "Not authenticated", nil)
		return
	}

	var req entity.ChangePasswordRequest
	if err := DecodeJSON(r, &req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.OldPassword == "" || req.NewPassword == "" {
		ErrorResponse(w, http.StatusBadRequest, "Old and new password are required", nil)
		return
	}

	// Validate password strength (basic check)
	if len(req.NewPassword) < 8 {
		ErrorResponse(w, http.StatusBadRequest, "New password must be at least 8 characters", nil)
		return
	}

	// Change password
	if err := h.service.ChangePassword(r.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		if errors.Is(err, auth.ErrPasswordMismatch) {
			ErrorResponse(w, http.StatusBadRequest, "Old password is incorrect", nil)
			return
		}
		h.logger.Error("Change password error", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to change password", nil)
		return
	}

	SuccessResponse(w, "Password changed successfully", nil)
}
