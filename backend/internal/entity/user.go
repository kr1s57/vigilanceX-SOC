package entity

import (
	"time"
)

// User represents a system user
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email,omitempty"`
	PasswordHash string     `json:"-"` // Never expose in JSON
	Role         string     `json:"role"`
	IsActive     bool       `json:"is_active"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// UserRole constants
const (
	RoleAdmin = "admin"
	RoleAudit = "audit"
)

// ValidRoles returns all valid role values
func ValidRoles() []string {
	return []string{RoleAdmin, RoleAudit}
}

// IsValidRole checks if a role is valid
func IsValidRole(role string) bool {
	for _, r := range ValidRoles() {
		if r == role {
			return true
		}
	}
	return false
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	Token     string   `json:"token"`
	ExpiresAt int64    `json:"expires_at"`
	User      UserInfo `json:"user"`
}

// UserInfo represents public user information
type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// ToUserInfo converts User to UserInfo (safe public representation)
func (u *User) ToUserInfo() UserInfo {
	return UserInfo{
		ID:       u.ID,
		Username: u.Username,
		Role:     u.Role,
	}
}

// CreateUserRequest represents the request to create a user
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role"`
}

// UpdateUserRequest represents the request to update a user
type UpdateUserRequest struct {
	Email    *string `json:"email,omitempty"`
	Role     *string `json:"role,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
}

// ChangePasswordRequest represents the request to change password
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ResetPasswordRequest represents the request to reset a user's password
type ResetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// UserListResponse represents the response for listing users
type UserListResponse struct {
	Users []User `json:"users"`
	Count int    `json:"count"`
}
