package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/kr1s57/vigilancex/internal/usecase/auth"
)

// Context keys for user information
type contextKey string

const (
	UserIDKey   contextKey = "user_id"
	UsernameKey contextKey = "username"
	RoleKey     contextKey = "role"
)

// JWTAuth middleware validates JWT tokens and adds user info to context
func JWTAuth(authService *auth.Service) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string

			// First try Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				// Check Bearer prefix
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
					tokenString = parts[1]
				}
			}

			// If no token in header, try query parameter (for WebSocket connections)
			if tokenString == "" {
				tokenString = r.URL.Query().Get("token")
			}

			// No token found
			if tokenString == "" {
				http.Error(w, `{"error":"Authorization header required"}`, http.StatusUnauthorized)
				return
			}

			// Validate token
			claims, err := authService.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, `{"error":"Invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// Add user info to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, UsernameKey, claims.Username)
			ctx = context.WithValue(ctx, RoleKey, claims.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole middleware checks if the user has one of the required roles
func RequireRole(roles ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := GetRole(r.Context())
			if role == "" {
				http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Check if user's role is in allowed roles
			allowed := false
			for _, allowedRole := range roles {
				if role == allowedRole {
					allowed = true
					break
				}
			}

			if !allowed {
				http.Error(w, `{"error":"Forbidden - insufficient permissions"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin is a convenience middleware that requires admin role
func RequireAdmin() func(next http.Handler) http.Handler {
	return RequireRole("admin")
}

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) string {
	if id, ok := ctx.Value(UserIDKey).(string); ok {
		return id
	}
	return ""
}

// GetUsername extracts username from context
func GetUsername(ctx context.Context) string {
	if username, ok := ctx.Value(UsernameKey).(string); ok {
		return username
	}
	return ""
}

// GetRole extracts role from context
func GetRole(ctx context.Context) string {
	if role, ok := ctx.Value(RoleKey).(string); ok {
		return role
	}
	return ""
}

// IsAdmin checks if the current user is an admin
func IsAdmin(ctx context.Context) bool {
	return GetRole(ctx) == "admin"
}
