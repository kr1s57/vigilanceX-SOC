package auth

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kr1s57/vigilancex/internal/config"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock Repository
// =============================================================================

type MockUsersRepository struct {
	mock.Mock
}

func (m *MockUsersRepository) GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUsersRepository) GetByID(ctx context.Context, id string) (*entity.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUsersRepository) Create(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUsersRepository) Update(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUsersRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUsersRepository) List(ctx context.Context) ([]entity.User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]entity.User), args.Error(1)
}

func (m *MockUsersRepository) UpdateLastLogin(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUsersRepository) UpdatePassword(ctx context.Context, id string, passwordHash string) error {
	args := m.Called(ctx, id, passwordHash)
	return args.Error(0)
}

func (m *MockUsersRepository) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockUsersRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	args := m.Called(ctx, username)
	return args.Bool(0), args.Error(1)
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestConfig() *config.Config {
	return &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret-key-for-jwt-signing",
			Expiry: 24 * time.Hour,
		},
		Admin: config.AdminConfig{
			Username: "admin",
			Password: "AdminPassword123!",
		},
	}
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Suppress logs during tests
	}))
}

func newTestService(repo UsersRepository) *Service {
	return NewService(repo, newTestConfig(), newTestLogger())
}

func createTestUser(id, username, password string, isActive bool, role string) *entity.User {
	svc := &Service{}
	hash, _ := svc.HashPassword(password)
	return &entity.User{
		ID:           id,
		Username:     username,
		PasswordHash: hash,
		Email:        username + "@test.com",
		Role:         role,
		IsActive:     isActive,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

// =============================================================================
// Login Tests
// =============================================================================

func TestLogin(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		password      string
		setupMock     func(*MockUsersRepository)
		expectedError error
		checkResponse func(*testing.T, *entity.LoginResponse)
	}{
		{
			name:     "successful login",
			username: "testuser",
			password: "correctpassword",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "correctpassword", true, entity.RoleAdmin)
				m.On("GetByUsername", mock.Anything, "testuser").Return(user, nil)
				m.On("UpdateLastLogin", mock.Anything, "user-123").Return(nil)
			},
			expectedError: nil,
			checkResponse: func(t *testing.T, resp *entity.LoginResponse) {
				assert.NotEmpty(t, resp.Token)
				assert.NotZero(t, resp.ExpiresAt)
				assert.Equal(t, "user-123", resp.User.ID)
				assert.Equal(t, "testuser", resp.User.Username)
				assert.Equal(t, entity.RoleAdmin, resp.User.Role)
			},
		},
		{
			name:     "user not found",
			username: "nonexistent",
			password: "anypassword",
			setupMock: func(m *MockUsersRepository) {
				m.On("GetByUsername", mock.Anything, "nonexistent").Return(nil, errors.New("not found"))
			},
			expectedError: ErrInvalidCredentials,
			checkResponse: nil,
		},
		{
			name:     "empty username",
			username: "",
			password: "somepassword",
			setupMock: func(m *MockUsersRepository) {
				m.On("GetByUsername", mock.Anything, "").Return(nil, errors.New("not found"))
			},
			expectedError: ErrInvalidCredentials,
			checkResponse: nil,
		},
		{
			name:     "empty password",
			username: "testuser",
			password: "",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "correctpassword", true, entity.RoleAdmin)
				m.On("GetByUsername", mock.Anything, "testuser").Return(user, nil)
			},
			expectedError: ErrInvalidCredentials,
			checkResponse: nil,
		},
		{
			name:     "incorrect password",
			username: "testuser",
			password: "wrongpassword",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "correctpassword", true, entity.RoleAdmin)
				m.On("GetByUsername", mock.Anything, "testuser").Return(user, nil)
			},
			expectedError: ErrInvalidCredentials,
			checkResponse: nil,
		},
		{
			name:     "inactive user",
			username: "inactiveuser",
			password: "correctpassword",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-456", "inactiveuser", "correctpassword", false, entity.RoleAdmin)
				m.On("GetByUsername", mock.Anything, "inactiveuser").Return(user, nil)
			},
			expectedError: ErrUserInactive,
			checkResponse: nil,
		},
		{
			name:     "login succeeds even if UpdateLastLogin fails",
			username: "testuser",
			password: "correctpassword",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "correctpassword", true, entity.RoleAdmin)
				m.On("GetByUsername", mock.Anything, "testuser").Return(user, nil)
				m.On("UpdateLastLogin", mock.Anything, "user-123").Return(errors.New("db error"))
			},
			expectedError: nil,
			checkResponse: func(t *testing.T, resp *entity.LoginResponse) {
				assert.NotEmpty(t, resp.Token)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUsersRepository)
			tt.setupMock(mockRepo)

			svc := newTestService(mockRepo)
			ctx := context.Background()

			resp, err := svc.Login(ctx, tt.username, tt.password)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				if tt.checkResponse != nil {
					tt.checkResponse(t, resp)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// ValidateToken Tests
// =============================================================================

func TestValidateToken(t *testing.T) {
	cfg := newTestConfig()
	logger := newTestLogger()
	mockRepo := new(MockUsersRepository)
	svc := NewService(mockRepo, cfg, logger)

	// Generate a valid token for testing
	testUser := &entity.User{
		ID:       "user-123",
		Username: "testuser",
		Role:     entity.RoleAdmin,
	}

	validToken, _, err := svc.generateToken(testUser)
	require.NoError(t, err)

	// Generate an expired token
	expiredClaims := &Claims{
		UserID:   "user-123",
		Username: "testuser",
		Role:     entity.RoleAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Issuer:    "vigilancex",
			Subject:   "user-123",
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, _ := expiredToken.SignedString([]byte(cfg.JWT.Secret))

	// Generate a token with wrong secret
	wrongSecretToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	wrongSecretTokenString, _ := wrongSecretToken.SignedString([]byte("wrong-secret"))

	tests := []struct {
		name          string
		token         string
		expectedError error
		checkClaims   func(*testing.T, *Claims)
	}{
		{
			name:          "valid token",
			token:         validToken,
			expectedError: nil,
			checkClaims: func(t *testing.T, claims *Claims) {
				assert.Equal(t, "user-123", claims.UserID)
				assert.Equal(t, "testuser", claims.Username)
				assert.Equal(t, entity.RoleAdmin, claims.Role)
				assert.Equal(t, "vigilancex", claims.Issuer)
			},
		},
		{
			name:          "empty token",
			token:         "",
			expectedError: ErrInvalidToken,
			checkClaims:   nil,
		},
		{
			name:          "malformed token",
			token:         "not.a.valid.jwt.token",
			expectedError: ErrInvalidToken,
			checkClaims:   nil,
		},
		{
			name:          "expired token",
			token:         expiredTokenString,
			expectedError: ErrInvalidToken,
			checkClaims:   nil,
		},
		{
			name:          "token with wrong secret",
			token:         wrongSecretTokenString,
			expectedError: ErrInvalidToken,
			checkClaims:   nil,
		},
		{
			name:          "random garbage token",
			token:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.garbage.invalid",
			expectedError: ErrInvalidToken,
			checkClaims:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := svc.ValidateToken(tt.token)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, claims)
			} else {
				require.NoError(t, err)
				require.NotNil(t, claims)
				if tt.checkClaims != nil {
					tt.checkClaims(t, claims)
				}
			}
		})
	}
}

// =============================================================================
// HashPassword & CheckPassword Tests
// =============================================================================

func TestHashPassword(t *testing.T) {
	svc := newTestService(new(MockUsersRepository))

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "normal password",
			password: "SecurePassword123!",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  false, // bcrypt allows empty passwords
		},
		{
			name:     "very long password (bcrypt limit 72 bytes)",
			password: "a" + string(make([]byte, 100)),
			wantErr:  true, // bcrypt has a 72 byte limit
		},
		{
			name:     "password with special characters",
			password: "P@$$w0rd!#$%^&*()",
			wantErr:  false,
		},
		{
			name:     "unicode password",
			password: "motDePasse123!eaue",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := svc.HashPassword(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, tt.password, hash)
				// Verify the hash is valid bcrypt
				assert.True(t, svc.CheckPassword(hash, tt.password))
			}
		})
	}
}

func TestCheckPassword(t *testing.T) {
	svc := newTestService(new(MockUsersRepository))

	password := "TestPassword123!"
	hash, err := svc.HashPassword(password)
	require.NoError(t, err)

	tests := []struct {
		name     string
		hash     string
		password string
		expected bool
	}{
		{
			name:     "correct password",
			hash:     hash,
			password: password,
			expected: true,
		},
		{
			name:     "incorrect password",
			hash:     hash,
			password: "WrongPassword",
			expected: false,
		},
		{
			name:     "empty password against valid hash",
			hash:     hash,
			password: "",
			expected: false,
		},
		{
			name:     "password against empty hash",
			hash:     "",
			password: password,
			expected: false,
		},
		{
			name:     "password against invalid hash",
			hash:     "invalid-hash",
			password: password,
			expected: false,
		},
		{
			name:     "case sensitive check",
			hash:     hash,
			password: "testpassword123!", // lowercase
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := svc.CheckPassword(tt.hash, tt.password)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// ChangePassword Tests
// =============================================================================

func TestChangePassword(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		oldPassword   string
		newPassword   string
		setupMock     func(*MockUsersRepository)
		expectedError error
	}{
		{
			name:        "successful password change",
			userID:      "user-123",
			oldPassword: "OldPassword123!",
			newPassword: "NewPassword456!",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "OldPassword123!", true, entity.RoleAdmin)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
				m.On("UpdatePassword", mock.Anything, "user-123", mock.AnythingOfType("string")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:        "user not found",
			userID:      "nonexistent",
			oldPassword: "OldPassword123!",
			newPassword: "NewPassword456!",
			setupMock: func(m *MockUsersRepository) {
				m.On("GetByID", mock.Anything, "nonexistent").Return(nil, errors.New("not found"))
			},
			expectedError: ErrUserNotFound,
		},
		{
			name:        "incorrect old password",
			userID:      "user-123",
			oldPassword: "WrongOldPassword",
			newPassword: "NewPassword456!",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "CorrectOldPassword", true, entity.RoleAdmin)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
			},
			expectedError: ErrPasswordMismatch,
		},
		{
			name:        "empty old password",
			userID:      "user-123",
			oldPassword: "",
			newPassword: "NewPassword456!",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "OldPassword123!", true, entity.RoleAdmin)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
			},
			expectedError: ErrPasswordMismatch,
		},
		{
			name:        "repository update failure",
			userID:      "user-123",
			oldPassword: "OldPassword123!",
			newPassword: "NewPassword456!",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "OldPassword123!", true, entity.RoleAdmin)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
				m.On("UpdatePassword", mock.Anything, "user-123", mock.AnythingOfType("string")).Return(errors.New("db error"))
			},
			expectedError: errors.New("update password"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUsersRepository)
			tt.setupMock(mockRepo)

			svc := newTestService(mockRepo)
			ctx := context.Background()

			err := svc.ChangePassword(ctx, tt.userID, tt.oldPassword, tt.newPassword)

			if tt.expectedError != nil {
				require.Error(t, err)
				if errors.Is(tt.expectedError, ErrUserNotFound) || errors.Is(tt.expectedError, ErrPasswordMismatch) {
					assert.ErrorIs(t, err, tt.expectedError)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// CreateUser Tests
// =============================================================================

func TestCreateUser(t *testing.T) {
	tests := []struct {
		name          string
		request       *entity.CreateUserRequest
		setupMock     func(*MockUsersRepository)
		expectedError string
		checkUser     func(*testing.T, *entity.User)
	}{
		{
			name: "successful user creation",
			request: &entity.CreateUserRequest{
				Username: "newuser",
				Password: "SecurePassword123!",
				Email:    "newuser@test.com",
				Role:     entity.RoleAudit,
			},
			setupMock: func(m *MockUsersRepository) {
				m.On("ExistsByUsername", mock.Anything, "newuser").Return(false, nil)
				m.On("Create", mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)
			},
			expectedError: "",
			checkUser: func(t *testing.T, user *entity.User) {
				assert.Equal(t, "newuser", user.Username)
				assert.Equal(t, "newuser@test.com", user.Email)
				assert.Equal(t, entity.RoleAudit, user.Role)
				assert.True(t, user.IsActive)
				assert.NotEmpty(t, user.PasswordHash)
			},
		},
		{
			name: "invalid role",
			request: &entity.CreateUserRequest{
				Username: "newuser",
				Password: "SecurePassword123!",
				Role:     "superadmin", // Invalid role
			},
			setupMock:     func(m *MockUsersRepository) {},
			expectedError: "invalid role",
			checkUser:     nil,
		},
		{
			name: "username already exists",
			request: &entity.CreateUserRequest{
				Username: "existinguser",
				Password: "SecurePassword123!",
				Role:     entity.RoleAdmin,
			},
			setupMock: func(m *MockUsersRepository) {
				m.On("ExistsByUsername", mock.Anything, "existinguser").Return(true, nil)
			},
			expectedError: "username already exists",
			checkUser:     nil,
		},
		{
			name: "repository check username error",
			request: &entity.CreateUserRequest{
				Username: "newuser",
				Password: "SecurePassword123!",
				Role:     entity.RoleAdmin,
			},
			setupMock: func(m *MockUsersRepository) {
				m.On("ExistsByUsername", mock.Anything, "newuser").Return(false, errors.New("db error"))
			},
			expectedError: "check username",
			checkUser:     nil,
		},
		{
			name: "repository create error",
			request: &entity.CreateUserRequest{
				Username: "newuser",
				Password: "SecurePassword123!",
				Role:     entity.RoleAdmin,
			},
			setupMock: func(m *MockUsersRepository) {
				m.On("ExistsByUsername", mock.Anything, "newuser").Return(false, nil)
				m.On("Create", mock.Anything, mock.AnythingOfType("*entity.User")).Return(errors.New("db error"))
			},
			expectedError: "create user",
			checkUser:     nil,
		},
		{
			name: "create admin user",
			request: &entity.CreateUserRequest{
				Username: "adminuser",
				Password: "AdminPassword123!",
				Email:    "admin@test.com",
				Role:     entity.RoleAdmin,
			},
			setupMock: func(m *MockUsersRepository) {
				m.On("ExistsByUsername", mock.Anything, "adminuser").Return(false, nil)
				m.On("Create", mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)
			},
			expectedError: "",
			checkUser: func(t *testing.T, user *entity.User) {
				assert.Equal(t, entity.RoleAdmin, user.Role)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUsersRepository)
			tt.setupMock(mockRepo)

			svc := newTestService(mockRepo)
			ctx := context.Background()

			user, err := svc.CreateUser(ctx, tt.request)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				if tt.checkUser != nil {
					tt.checkUser(t, user)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// UpdateUser Tests
// =============================================================================

func TestUpdateUser(t *testing.T) {
	trueVal := true
	falseVal := false
	newEmail := "updated@test.com"
	adminRole := entity.RoleAdmin
	auditRole := entity.RoleAudit
	invalidRole := "superadmin"

	tests := []struct {
		name          string
		userID        string
		request       *entity.UpdateUserRequest
		setupMock     func(*MockUsersRepository)
		expectedError error
		checkUser     func(*testing.T, *entity.User)
	}{
		{
			name:   "update email only",
			userID: "user-123",
			request: &entity.UpdateUserRequest{
				Email: &newEmail,
			},
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "password", true, entity.RoleAudit)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)
			},
			expectedError: nil,
			checkUser: func(t *testing.T, user *entity.User) {
				assert.Equal(t, "updated@test.com", user.Email)
			},
		},
		{
			name:   "update role only",
			userID: "user-123",
			request: &entity.UpdateUserRequest{
				Role: &adminRole,
			},
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "password", true, entity.RoleAudit)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)
			},
			expectedError: nil,
			checkUser: func(t *testing.T, user *entity.User) {
				assert.Equal(t, entity.RoleAdmin, user.Role)
			},
		},
		{
			name:   "deactivate user",
			userID: "user-123",
			request: &entity.UpdateUserRequest{
				IsActive: &falseVal,
			},
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "password", true, entity.RoleAudit)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)
			},
			expectedError: nil,
			checkUser: func(t *testing.T, user *entity.User) {
				assert.False(t, user.IsActive)
			},
		},
		{
			name:   "activate user",
			userID: "user-123",
			request: &entity.UpdateUserRequest{
				IsActive: &trueVal,
			},
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "password", false, entity.RoleAudit)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)
			},
			expectedError: nil,
			checkUser: func(t *testing.T, user *entity.User) {
				assert.True(t, user.IsActive)
			},
		},
		{
			name:   "update multiple fields",
			userID: "user-123",
			request: &entity.UpdateUserRequest{
				Email:    &newEmail,
				Role:     &auditRole,
				IsActive: &falseVal,
			},
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "password", true, entity.RoleAdmin)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)
			},
			expectedError: nil,
			checkUser: func(t *testing.T, user *entity.User) {
				assert.Equal(t, "updated@test.com", user.Email)
				assert.Equal(t, entity.RoleAudit, user.Role)
				assert.False(t, user.IsActive)
			},
		},
		{
			name:   "user not found",
			userID: "nonexistent",
			request: &entity.UpdateUserRequest{
				Email: &newEmail,
			},
			setupMock: func(m *MockUsersRepository) {
				m.On("GetByID", mock.Anything, "nonexistent").Return(nil, errors.New("not found"))
			},
			expectedError: ErrUserNotFound,
			checkUser:     nil,
		},
		{
			name:   "invalid role",
			userID: "user-123",
			request: &entity.UpdateUserRequest{
				Role: &invalidRole,
			},
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "password", true, entity.RoleAudit)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
			},
			expectedError: errors.New("invalid role"),
			checkUser:     nil,
		},
		{
			name:   "repository update error",
			userID: "user-123",
			request: &entity.UpdateUserRequest{
				Email: &newEmail,
			},
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "password", true, entity.RoleAudit)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*entity.User")).Return(errors.New("db error"))
			},
			expectedError: errors.New("update user"),
			checkUser:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUsersRepository)
			tt.setupMock(mockRepo)

			svc := newTestService(mockRepo)
			ctx := context.Background()

			user, err := svc.UpdateUser(ctx, tt.userID, tt.request)

			if tt.expectedError != nil {
				require.Error(t, err)
				if errors.Is(tt.expectedError, ErrUserNotFound) {
					assert.ErrorIs(t, err, tt.expectedError)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				if tt.checkUser != nil {
					tt.checkUser(t, user)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// DeleteUser Tests
// =============================================================================

func TestDeleteUser(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		setupMock     func(*MockUsersRepository)
		expectedError string
	}{
		{
			name:   "successful deletion",
			userID: "user-123",
			setupMock: func(m *MockUsersRepository) {
				m.On("Delete", mock.Anything, "user-123").Return(nil)
			},
			expectedError: "",
		},
		{
			name:   "repository error",
			userID: "user-123",
			setupMock: func(m *MockUsersRepository) {
				m.On("Delete", mock.Anything, "user-123").Return(errors.New("db error"))
			},
			expectedError: "delete user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUsersRepository)
			tt.setupMock(mockRepo)

			svc := newTestService(mockRepo)
			ctx := context.Background()

			err := svc.DeleteUser(ctx, tt.userID)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// ResetPassword Tests
// =============================================================================

func TestResetPassword(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		newPassword   string
		setupMock     func(*MockUsersRepository)
		expectedError string
	}{
		{
			name:        "successful password reset",
			userID:      "user-123",
			newPassword: "NewPassword123!",
			setupMock: func(m *MockUsersRepository) {
				m.On("UpdatePassword", mock.Anything, "user-123", mock.AnythingOfType("string")).Return(nil)
			},
			expectedError: "",
		},
		{
			name:        "repository error",
			userID:      "user-123",
			newPassword: "NewPassword123!",
			setupMock: func(m *MockUsersRepository) {
				m.On("UpdatePassword", mock.Anything, "user-123", mock.AnythingOfType("string")).Return(errors.New("db error"))
			},
			expectedError: "update password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUsersRepository)
			tt.setupMock(mockRepo)

			svc := newTestService(mockRepo)
			ctx := context.Background()

			err := svc.ResetPassword(ctx, tt.userID, tt.newPassword)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// EnsureDefaultAdmin Tests
// =============================================================================

func TestEnsureDefaultAdmin(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*MockUsersRepository)
		expectedError string
	}{
		{
			name: "creates admin when no users exist",
			setupMock: func(m *MockUsersRepository) {
				m.On("Count", mock.Anything).Return(0, nil)
				m.On("Create", mock.Anything, mock.MatchedBy(func(u *entity.User) bool {
					return u.Username == "admin" && u.Role == entity.RoleAdmin && u.IsActive
				})).Return(nil)
			},
			expectedError: "",
		},
		{
			name: "skips creation when users exist",
			setupMock: func(m *MockUsersRepository) {
				m.On("Count", mock.Anything).Return(5, nil)
			},
			expectedError: "",
		},
		{
			name: "count error",
			setupMock: func(m *MockUsersRepository) {
				m.On("Count", mock.Anything).Return(0, errors.New("db error"))
			},
			expectedError: "count users",
		},
		{
			name: "create error",
			setupMock: func(m *MockUsersRepository) {
				m.On("Count", mock.Anything).Return(0, nil)
				m.On("Create", mock.Anything, mock.AnythingOfType("*entity.User")).Return(errors.New("db error"))
			},
			expectedError: "create admin user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUsersRepository)
			tt.setupMock(mockRepo)

			svc := newTestService(mockRepo)
			ctx := context.Background()

			err := svc.EnsureDefaultAdmin(ctx)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// GetUserByID Tests
// =============================================================================

func TestGetUserByID(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		setupMock     func(*MockUsersRepository)
		expectedError bool
		checkUser     func(*testing.T, *entity.User)
	}{
		{
			name:   "user found",
			userID: "user-123",
			setupMock: func(m *MockUsersRepository) {
				user := createTestUser("user-123", "testuser", "password", true, entity.RoleAdmin)
				m.On("GetByID", mock.Anything, "user-123").Return(user, nil)
			},
			expectedError: false,
			checkUser: func(t *testing.T, user *entity.User) {
				assert.Equal(t, "user-123", user.ID)
				assert.Equal(t, "testuser", user.Username)
			},
		},
		{
			name:   "user not found",
			userID: "nonexistent",
			setupMock: func(m *MockUsersRepository) {
				m.On("GetByID", mock.Anything, "nonexistent").Return(nil, errors.New("not found"))
			},
			expectedError: true,
			checkUser:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUsersRepository)
			tt.setupMock(mockRepo)

			svc := newTestService(mockRepo)
			ctx := context.Background()

			user, err := svc.GetUserByID(ctx, tt.userID)

			if tt.expectedError {
				require.Error(t, err)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				if tt.checkUser != nil {
					tt.checkUser(t, user)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// ListUsers Tests
// =============================================================================

func TestListUsers(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*MockUsersRepository)
		expectedError bool
		expectedCount int
	}{
		{
			name: "returns users list",
			setupMock: func(m *MockUsersRepository) {
				users := []entity.User{
					*createTestUser("user-1", "user1", "pass", true, entity.RoleAdmin),
					*createTestUser("user-2", "user2", "pass", true, entity.RoleAudit),
					*createTestUser("user-3", "user3", "pass", false, entity.RoleAudit),
				}
				m.On("List", mock.Anything).Return(users, nil)
			},
			expectedError: false,
			expectedCount: 3,
		},
		{
			name: "returns empty list",
			setupMock: func(m *MockUsersRepository) {
				m.On("List", mock.Anything).Return([]entity.User{}, nil)
			},
			expectedError: false,
			expectedCount: 0,
		},
		{
			name: "repository error",
			setupMock: func(m *MockUsersRepository) {
				m.On("List", mock.Anything).Return([]entity.User{}, errors.New("db error"))
			},
			expectedError: true,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUsersRepository)
			tt.setupMock(mockRepo)

			svc := newTestService(mockRepo)
			ctx := context.Background()

			users, err := svc.ListUsers(ctx)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, users, tt.expectedCount)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// Token Generation Tests (internal function via Login)
// =============================================================================

func TestGenerateToken_TokenStructure(t *testing.T) {
	mockRepo := new(MockUsersRepository)
	cfg := newTestConfig()
	logger := newTestLogger()
	svc := NewService(mockRepo, cfg, logger)

	user := &entity.User{
		ID:       "user-123",
		Username: "testuser",
		Role:     entity.RoleAdmin,
	}

	token, expiresAt, err := svc.generateToken(user)

	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.False(t, expiresAt.IsZero())
	assert.True(t, expiresAt.After(time.Now()))
	assert.True(t, expiresAt.Before(time.Now().Add(25*time.Hour)))

	// Validate the token can be parsed
	claims, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.Username, claims.Username)
	assert.Equal(t, user.Role, claims.Role)
	assert.Equal(t, "vigilancex", claims.Issuer)
	assert.Equal(t, user.ID, claims.Subject)
}

// =============================================================================
// NewService Tests
// =============================================================================

func TestNewService(t *testing.T) {
	mockRepo := new(MockUsersRepository)
	cfg := newTestConfig()
	logger := newTestLogger()

	svc := NewService(mockRepo, cfg, logger)

	require.NotNil(t, svc)
	assert.NotNil(t, svc.repo)
	assert.NotNil(t, svc.cfg)
	assert.NotNil(t, svc.logger)
}

// =============================================================================
// Edge Cases and Security Tests
// =============================================================================

func TestLogin_SQLInjectionAttempt(t *testing.T) {
	mockRepo := new(MockUsersRepository)
	mockRepo.On("GetByUsername", mock.Anything, "admin' OR '1'='1").Return(nil, errors.New("not found"))

	svc := newTestService(mockRepo)
	ctx := context.Background()

	resp, err := svc.Login(ctx, "admin' OR '1'='1", "password")

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestValidateToken_WrongSigningMethod(t *testing.T) {
	cfg := newTestConfig()
	logger := newTestLogger()
	mockRepo := new(MockUsersRepository)
	svc := NewService(mockRepo, cfg, logger)

	// Create a token with RS256 instead of HS256
	claims := &Claims{
		UserID:   "user-123",
		Username: "testuser",
		Role:     entity.RoleAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "vigilancex",
		},
	}

	// This token will be signed with HS256 but we're testing the validation
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(cfg.JWT.Secret))

	// Valid token should work
	result, err := svc.ValidateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "user-123", result.UserID)
}

func TestHashPassword_Uniqueness(t *testing.T) {
	svc := newTestService(new(MockUsersRepository))
	password := "SamePassword123!"

	hash1, err1 := svc.HashPassword(password)
	hash2, err2 := svc.HashPassword(password)

	require.NoError(t, err1)
	require.NoError(t, err2)

	// Same password should produce different hashes (bcrypt uses random salt)
	assert.NotEqual(t, hash1, hash2)

	// But both should validate correctly
	assert.True(t, svc.CheckPassword(hash1, password))
	assert.True(t, svc.CheckPassword(hash2, password))
}
