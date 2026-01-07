package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/kr1s57/vigilancex/internal/config"
	"github.com/kr1s57/vigilancex/internal/entity"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrPasswordMismatch   = errors.New("old password is incorrect")
)

// UsersRepository interface for user data access
type UsersRepository interface {
	GetByUsername(ctx context.Context, username string) (*entity.User, error)
	GetByID(ctx context.Context, id string) (*entity.User, error)
	Create(ctx context.Context, user *entity.User) error
	Update(ctx context.Context, user *entity.User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]entity.User, error)
	UpdateLastLogin(ctx context.Context, id string) error
	UpdatePassword(ctx context.Context, id string, passwordHash string) error
	Count(ctx context.Context) (int, error)
	ExistsByUsername(ctx context.Context, username string) (bool, error)
}

// Claims represents JWT claims
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Service provides authentication functionality
type Service struct {
	repo   UsersRepository
	cfg    *config.Config
	logger *slog.Logger
}

// NewService creates a new auth service
func NewService(repo UsersRepository, cfg *config.Config, logger *slog.Logger) *Service {
	return &Service{
		repo:   repo,
		cfg:    cfg,
		logger: logger,
	}
}

// Login authenticates a user and returns a JWT token
func (s *Service) Login(ctx context.Context, username, password string) (*entity.LoginResponse, error) {
	// Find user by username
	user, err := s.repo.GetByUsername(ctx, username)
	if err != nil {
		s.logger.Warn("Login failed - user not found", "username", username)
		return nil, ErrInvalidCredentials
	}

	// Check if user is active
	if !user.IsActive {
		s.logger.Warn("Login failed - user inactive", "username", username)
		return nil, ErrUserInactive
	}

	// Verify password
	if !s.CheckPassword(user.PasswordHash, password) {
		s.logger.Warn("Login failed - invalid password", "username", username)
		return nil, ErrInvalidCredentials
	}

	// Generate JWT token
	token, expiresAt, err := s.generateToken(user)
	if err != nil {
		s.logger.Error("Failed to generate token", "error", err)
		return nil, fmt.Errorf("generate token: %w", err)
	}

	// Update last login
	if err := s.repo.UpdateLastLogin(ctx, user.ID); err != nil {
		s.logger.Warn("Failed to update last login", "error", err)
		// Don't fail login for this
	}

	s.logger.Info("User logged in", "username", username, "role", user.Role)

	return &entity.LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Unix(),
		User:      user.ToUserInfo(),
	}, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.JWT.Secret), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// HashPassword hashes a password using bcrypt
func (s *Service) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(bytes), nil
}

// CheckPassword compares a password with a hash
func (s *Service) CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ChangePassword changes a user's password
func (s *Service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Verify old password
	if !s.CheckPassword(user.PasswordHash, oldPassword) {
		return ErrPasswordMismatch
	}

	// Hash new password
	newHash, err := s.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// Update password
	if err := s.repo.UpdatePassword(ctx, userID, newHash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	s.logger.Info("Password changed", "user_id", userID)
	return nil
}

// GetUserByID retrieves a user by ID
func (s *Service) GetUserByID(ctx context.Context, id string) (*entity.User, error) {
	return s.repo.GetByID(ctx, id)
}

// ListUsers retrieves all users
func (s *Service) ListUsers(ctx context.Context) ([]entity.User, error) {
	return s.repo.List(ctx)
}

// CreateUser creates a new user
func (s *Service) CreateUser(ctx context.Context, req *entity.CreateUserRequest) (*entity.User, error) {
	// Validate role
	if !entity.IsValidRole(req.Role) {
		return nil, fmt.Errorf("invalid role: %s", req.Role)
	}

	// Check if username exists
	exists, err := s.repo.ExistsByUsername(ctx, req.Username)
	if err != nil {
		return nil, fmt.Errorf("check username: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("username already exists: %s", req.Username)
	}

	// Hash password
	hash, err := s.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &entity.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		Role:         req.Role,
		IsActive:     true,
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	s.logger.Info("User created", "username", user.Username, "role", user.Role)
	return user, nil
}

// UpdateUser updates an existing user
func (s *Service) UpdateUser(ctx context.Context, id string, req *entity.UpdateUserRequest) (*entity.User, error) {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if req.Email != nil {
		user.Email = *req.Email
	}

	if req.Role != nil {
		if !entity.IsValidRole(*req.Role) {
			return nil, fmt.Errorf("invalid role: %s", *req.Role)
		}
		user.Role = *req.Role
	}

	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	s.logger.Info("User updated", "user_id", id)
	return user, nil
}

// DeleteUser deletes a user
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	s.logger.Info("User deleted", "user_id", id)
	return nil
}

// ResetPassword resets a user's password (admin action)
func (s *Service) ResetPassword(ctx context.Context, userID, newPassword string) error {
	// Hash new password
	newHash, err := s.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// Update password
	if err := s.repo.UpdatePassword(ctx, userID, newHash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	s.logger.Info("Password reset by admin", "user_id", userID)
	return nil
}

// EnsureDefaultAdmin creates the default admin user if no users exist
func (s *Service) EnsureDefaultAdmin(ctx context.Context) error {
	count, err := s.repo.Count(ctx)
	if err != nil {
		return fmt.Errorf("count users: %w", err)
	}

	if count > 0 {
		s.logger.Debug("Users already exist, skipping default admin creation")
		return nil
	}

	// Create default admin
	hash, err := s.HashPassword(s.cfg.Admin.Password)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	admin := &entity.User{
		Username:     s.cfg.Admin.Username,
		PasswordHash: hash,
		Role:         entity.RoleAdmin,
		IsActive:     true,
	}

	if err := s.repo.Create(ctx, admin); err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}

	s.logger.Info("Default admin user created",
		"username", s.cfg.Admin.Username,
		"note", "Please change the default password!")

	// Warn if using default password
	if s.cfg.Admin.Password == "VigilanceX2024!" {
		s.logger.Warn("Using default admin password! Change it immediately via ADMIN_PASSWORD env var or the UI")
	}

	return nil
}

// generateToken creates a new JWT token for a user
func (s *Service) generateToken(user *entity.User) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.cfg.JWT.Expiry)

	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "vigilancex",
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.cfg.JWT.Secret))
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}
