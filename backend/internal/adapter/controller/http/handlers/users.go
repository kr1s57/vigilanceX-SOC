package handlers

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/kr1s57/vigilancex/internal/usecase/auth"
)

// UsersHandler handles user management endpoints (admin only)
type UsersHandler struct {
	service *auth.Service
	logger  *slog.Logger
}

// NewUsersHandler creates a new users handler
func NewUsersHandler(service *auth.Service, logger *slog.Logger) *UsersHandler {
	return &UsersHandler{
		service: service,
		logger:  logger,
	}
}

// List handles GET /api/v1/users
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	users, err := h.service.ListUsers(r.Context())
	if err != nil {
		h.logger.Error("Failed to list users", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to list users", nil)
		return
	}

	// Clear password hashes for security
	for i := range users {
		users[i].PasswordHash = ""
	}

	JSONResponse(w, http.StatusOK, entity.UserListResponse{
		Users: users,
		Count: len(users),
	})
}

// Get handles GET /api/v1/users/{id}
func (h *UsersHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		ErrorResponse(w, http.StatusBadRequest, "User ID is required", nil)
		return
	}

	user, err := h.service.GetUserByID(r.Context(), id)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "User not found", nil)
		return
	}

	// Clear password hash for security
	user.PasswordHash = ""

	JSONResponse(w, http.StatusOK, user)
}

// Create handles POST /api/v1/users
func (h *UsersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req entity.CreateUserRequest
	if err := DecodeJSON(r, &req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.Username == "" {
		ErrorResponse(w, http.StatusBadRequest, "Username is required", nil)
		return
	}
	if req.Password == "" {
		ErrorResponse(w, http.StatusBadRequest, "Password is required", nil)
		return
	}
	if req.Role == "" {
		ErrorResponse(w, http.StatusBadRequest, "Role is required", nil)
		return
	}

	// Validate password strength
	if len(req.Password) < 8 {
		ErrorResponse(w, http.StatusBadRequest, "Password must be at least 8 characters", nil)
		return
	}

	// Create user
	user, err := h.service.CreateUser(r.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to create user", "error", err)
		ErrorResponse(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Clear password hash for security
	user.PasswordHash = ""

	JSONResponse(w, http.StatusCreated, user)
}

// Update handles PUT /api/v1/users/{id}
func (h *UsersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		ErrorResponse(w, http.StatusBadRequest, "User ID is required", nil)
		return
	}

	var req entity.UpdateUserRequest
	if err := DecodeJSON(r, &req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Update user
	user, err := h.service.UpdateUser(r.Context(), id, &req)
	if err != nil {
		h.logger.Error("Failed to update user", "error", err)
		ErrorResponse(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Clear password hash for security
	user.PasswordHash = ""

	JSONResponse(w, http.StatusOK, user)
}

// Delete handles DELETE /api/v1/users/{id}
func (h *UsersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		ErrorResponse(w, http.StatusBadRequest, "User ID is required", nil)
		return
	}

	if err := h.service.DeleteUser(r.Context(), id); err != nil {
		h.logger.Error("Failed to delete user", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to delete user", nil)
		return
	}

	SuccessResponse(w, "User deleted successfully", nil)
}

// ResetPassword handles POST /api/v1/users/{id}/reset-password
func (h *UsersHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		ErrorResponse(w, http.StatusBadRequest, "User ID is required", nil)
		return
	}

	var req entity.ResetPasswordRequest
	if err := DecodeJSON(r, &req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate password
	if req.NewPassword == "" {
		ErrorResponse(w, http.StatusBadRequest, "New password is required", nil)
		return
	}
	if len(req.NewPassword) < 8 {
		ErrorResponse(w, http.StatusBadRequest, "Password must be at least 8 characters", nil)
		return
	}

	if err := h.service.ResetPassword(r.Context(), id, req.NewPassword); err != nil {
		h.logger.Error("Failed to reset password", "error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to reset password", nil)
		return
	}

	SuccessResponse(w, "Password reset successfully", nil)
}
