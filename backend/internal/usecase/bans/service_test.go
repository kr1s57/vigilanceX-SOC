package bans

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/sophos"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock Repository - implements BansRepository interface
// =============================================================================

type MockBansRepository struct {
	mock.Mock
}

func (m *MockBansRepository) GetActiveBans(ctx context.Context) ([]entity.BanStatus, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.BanStatus), args.Error(1)
}

func (m *MockBansRepository) GetBanByIP(ctx context.Context, ip string) (*entity.BanStatus, error) {
	args := m.Called(ctx, ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.BanStatus), args.Error(1)
}

func (m *MockBansRepository) UpsertBan(ctx context.Context, ban *entity.BanStatus) error {
	args := m.Called(ctx, ban)
	return args.Error(0)
}

func (m *MockBansRepository) UpdateSyncStatus(ctx context.Context, ip string, synced bool) error {
	args := m.Called(ctx, ip, synced)
	return args.Error(0)
}

func (m *MockBansRepository) RecordBanHistory(ctx context.Context, history *entity.BanHistory) error {
	args := m.Called(ctx, history)
	return args.Error(0)
}

func (m *MockBansRepository) GetBanHistory(ctx context.Context, ip string, limit int) ([]entity.BanHistory, error) {
	args := m.Called(ctx, ip, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.BanHistory), args.Error(1)
}

func (m *MockBansRepository) GetBanStats(ctx context.Context) (*entity.BanStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.BanStats), args.Error(1)
}

func (m *MockBansRepository) GetExpiredBans(ctx context.Context) ([]entity.BanStatus, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.BanStatus), args.Error(1)
}

func (m *MockBansRepository) GetUnsyncedBans(ctx context.Context) ([]entity.BanStatus, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.BanStatus), args.Error(1)
}

func (m *MockBansRepository) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	args := m.Called(ctx, ip)
	return args.Bool(0), args.Error(1)
}

func (m *MockBansRepository) CheckWhitelistV2(ctx context.Context, ip string) (*entity.WhitelistCheckResult, error) {
	args := m.Called(ctx, ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.WhitelistCheckResult), args.Error(1)
}

func (m *MockBansRepository) GetWhitelist(ctx context.Context) ([]entity.WhitelistEntry, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.WhitelistEntry), args.Error(1)
}

func (m *MockBansRepository) GetWhitelistByType(ctx context.Context, whitelistType string) ([]entity.WhitelistEntry, error) {
	args := m.Called(ctx, whitelistType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.WhitelistEntry), args.Error(1)
}

func (m *MockBansRepository) GetWhitelistStats(ctx context.Context) (map[string]int, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int), args.Error(1)
}

func (m *MockBansRepository) AddToWhitelist(ctx context.Context, entry *entity.WhitelistEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *MockBansRepository) UpdateWhitelistEntry(ctx context.Context, entry *entity.WhitelistEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *MockBansRepository) RemoveFromWhitelist(ctx context.Context, ip string) error {
	args := m.Called(ctx, ip)
	return args.Error(0)
}

func (m *MockBansRepository) GetExpiredWhitelistEntries(ctx context.Context) ([]entity.WhitelistEntry, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.WhitelistEntry), args.Error(1)
}

// =============================================================================
// Mock Sophos Client - implements SophosClient interface
// =============================================================================

type MockSophosClient struct {
	mock.Mock
}

func (m *MockSophosClient) EnsureBlocklistGroupExists() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockSophosClient) AddIPToBlocklist(ip, reason string) error {
	args := m.Called(ip, reason)
	return args.Error(0)
}

func (m *MockSophosClient) GetBlocklistIPs() ([]string, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockSophosClient) RemoveIPFromBlocklist(ip string) error {
	args := m.Called(ip)
	return args.Error(0)
}

func (m *MockSophosClient) GetSyncStatus() (*sophos.SyncStatus, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sophos.SyncStatus), args.Error(1)
}

// =============================================================================
// Test Helpers
// =============================================================================

func notWhitelistedResult() *entity.WhitelistCheckResult {
	return &entity.WhitelistCheckResult{
		IsWhitelisted: false,
		EffectiveType: "none",
		ScoreModifier: 0,
		AllowAutoBan:  true,
		AlertRequired: false,
	}
}

func hardWhitelistedResult() *entity.WhitelistCheckResult {
	return &entity.WhitelistCheckResult{
		IsWhitelisted: true,
		EffectiveType: entity.WhitelistTypeHard,
		ScoreModifier: 100,
		AllowAutoBan:  false,
		AlertRequired: false,
		Entry: &entity.WhitelistEntry{
			IP:       "192.168.1.100",
			Type:     entity.WhitelistTypeHard,
			Reason:   "Internal server",
			IsActive: true,
		},
	}
}

func softWhitelistedResult(alertOnly bool) *entity.WhitelistCheckResult {
	return &entity.WhitelistCheckResult{
		IsWhitelisted: true,
		EffectiveType: entity.WhitelistTypeSoft,
		ScoreModifier: 50,
		AllowAutoBan:  !alertOnly,
		AlertRequired: true,
		Entry: &entity.WhitelistEntry{
			IP:            "10.0.0.50",
			Type:          entity.WhitelistTypeSoft,
			Reason:        "Partner IP",
			AlertOnly:     alertOnly,
			ScoreModifier: 50,
			IsActive:      true,
		},
	}
}

func monitorWhitelistedResult() *entity.WhitelistCheckResult {
	return &entity.WhitelistCheckResult{
		IsWhitelisted: true,
		EffectiveType: entity.WhitelistTypeMonitor,
		ScoreModifier: 0,
		AllowAutoBan:  true,
		AlertRequired: true,
		Entry: &entity.WhitelistEntry{
			IP:       "172.16.0.1",
			Type:     entity.WhitelistTypeMonitor,
			Reason:   "Monitoring",
			IsActive: true,
		},
	}
}

func createTestBan(ip string, banCount uint8, status string, expiresAt *time.Time) *entity.BanStatus {
	now := time.Now()
	return &entity.BanStatus{
		IP:        ip,
		Status:    status,
		BanCount:  banCount,
		FirstBan:  now.Add(-24 * time.Hour),
		LastBan:   now,
		ExpiresAt: expiresAt,
		Reason:    "Test ban",
		Source:    "manual",
		SyncedXGS: false,
		UpdatedAt: now,
	}
}

func durationPtr(d time.Duration) *time.Duration {
	return &d
}

func createTestService(repo *MockBansRepository, sophosClient *MockSophosClient) *Service {
	if sophosClient == nil {
		return NewServiceWithInterfaces(repo, nil)
	}
	return NewServiceWithInterfaces(repo, sophosClient)
}

// createTestServiceNoSophos creates a test service without Sophos client (avoids async calls)
func createTestServiceNoSophos(repo *MockBansRepository) *Service {
	return NewServiceWithInterfaces(repo, nil)
}

// =============================================================================
// BanIP Tests - Tests the real service with mocked dependencies
// =============================================================================

func TestBanIP(t *testing.T) {
	tests := []struct {
		name          string
		request       *entity.BanRequest
		setupMock     func(*MockBansRepository, *MockSophosClient)
		expectedError string
		checkResult   func(*testing.T, *entity.BanStatus)
	}{
		{
			name: "successful first ban - progressive duration 1h",
			request: &entity.BanRequest{
				IP:          "192.168.1.50",
				Reason:      "Malicious activity",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository, sophos *MockSophosClient) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.50").Return(notWhitelistedResult(), nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.50").Return(nil, errors.New("not found"))
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil)
			},
			expectedError: "",
			checkResult: func(t *testing.T, ban *entity.BanStatus) {
				assert.Equal(t, "192.168.1.50", ban.IP)
				assert.Equal(t, uint8(1), ban.BanCount)
				assert.Equal(t, entity.BanStatusActive, ban.Status)
				assert.NotNil(t, ban.ExpiresAt)
				// First ban should be ~1 hour
				duration := ban.ExpiresAt.Sub(ban.LastBan)
				assert.InDelta(t, time.Hour.Seconds(), duration.Seconds(), 60)
			},
		},
		{
			name: "second ban - progressive duration 4h",
			request: &entity.BanRequest{
				IP:          "192.168.1.51",
				Reason:      "Repeat offense",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository, sophos *MockSophosClient) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.51").Return(notWhitelistedResult(), nil)
				existingBan := createTestBan("192.168.1.51", 1, entity.BanStatusExpired, nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.51").Return(existingBan, nil)
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil)
			},
			expectedError: "",
			checkResult: func(t *testing.T, ban *entity.BanStatus) {
				assert.Equal(t, uint8(2), ban.BanCount)
				assert.Equal(t, entity.BanStatusActive, ban.Status)
				assert.NotNil(t, ban.ExpiresAt)
				// Second ban should be ~4 hours
				duration := ban.ExpiresAt.Sub(ban.LastBan)
				assert.InDelta(t, (4 * time.Hour).Seconds(), duration.Seconds(), 60)
			},
		},
		{
			name: "third ban - progressive duration 24h",
			request: &entity.BanRequest{
				IP:          "192.168.1.52",
				Reason:      "Third offense",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository, sophos *MockSophosClient) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.52").Return(notWhitelistedResult(), nil)
				existingBan := createTestBan("192.168.1.52", 2, entity.BanStatusExpired, nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.52").Return(existingBan, nil)
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil)
			},
			expectedError: "",
			checkResult: func(t *testing.T, ban *entity.BanStatus) {
				assert.Equal(t, uint8(3), ban.BanCount)
				assert.Equal(t, entity.BanStatusActive, ban.Status)
				assert.NotNil(t, ban.ExpiresAt)
				// Third ban should be ~24 hours
				duration := ban.ExpiresAt.Sub(ban.LastBan)
				assert.InDelta(t, (24 * time.Hour).Seconds(), duration.Seconds(), 60)
			},
		},
		{
			name: "fourth ban - recidivism permanent",
			request: &entity.BanRequest{
				IP:          "192.168.1.53",
				Reason:      "Recidivist",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository, sophos *MockSophosClient) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.53").Return(notWhitelistedResult(), nil)
				existingBan := createTestBan("192.168.1.53", 3, entity.BanStatusExpired, nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.53").Return(existingBan, nil)
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil)
			},
			expectedError: "",
			checkResult: func(t *testing.T, ban *entity.BanStatus) {
				assert.Equal(t, uint8(4), ban.BanCount)
				assert.Equal(t, entity.BanStatusPermanent, ban.Status)
				assert.Nil(t, ban.ExpiresAt)
			},
		},
		{
			name: "hard whitelisted IP cannot be banned",
			request: &entity.BanRequest{
				IP:          "192.168.1.100",
				Reason:      "Attempt to ban whitelisted",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository, sophos *MockSophosClient) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.100").Return(hardWhitelistedResult(), nil)
			},
			expectedError: "hard-whitelisted and cannot be banned",
			checkResult:   nil,
		},
		{
			name: "soft whitelisted IP alert-only mode blocks ban",
			request: &entity.BanRequest{
				IP:          "10.0.0.50",
				Reason:      "Attempt to ban soft whitelisted",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository, sophos *MockSophosClient) {
				repo.On("CheckWhitelistV2", mock.Anything, "10.0.0.50").Return(softWhitelistedResult(true), nil)
			},
			expectedError: "soft-whitelisted (alert-only)",
			checkResult:   nil,
		},
		{
			name: "monitor whitelisted IP can be banned",
			request: &entity.BanRequest{
				IP:          "172.16.0.1",
				Reason:      "Monitor whitelist allows ban",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository, sophos *MockSophosClient) {
				repo.On("CheckWhitelistV2", mock.Anything, "172.16.0.1").Return(monitorWhitelistedResult(), nil)
				repo.On("GetBanByIP", mock.Anything, "172.16.0.1").Return(nil, errors.New("not found"))
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil)
			},
			expectedError: "",
			checkResult: func(t *testing.T, ban *entity.BanStatus) {
				assert.Equal(t, "172.16.0.1", ban.IP)
			},
		},
		{
			name: "whitelist check error",
			request: &entity.BanRequest{
				IP:          "192.168.1.70",
				Reason:      "Test",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository, sophos *MockSophosClient) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.70").Return(nil, errors.New("db error"))
			},
			expectedError: "check whitelist",
			checkResult:   nil,
		},
		{
			name: "repository upsert error",
			request: &entity.BanRequest{
				IP:          "192.168.1.71",
				Reason:      "Test",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository, sophos *MockSophosClient) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.71").Return(notWhitelistedResult(), nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.71").Return(nil, errors.New("not found"))
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(errors.New("db error"))
			},
			expectedError: "save ban",
			checkResult:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			mockSophos := new(MockSophosClient)
			tt.setupMock(mockRepo, mockSophos)

			// Use nil sophos to avoid async goroutine calls
			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			ban, err := svc.BanIP(ctx, tt.request)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, ban)
			} else {
				require.NoError(t, err)
				require.NotNil(t, ban)
				if tt.checkResult != nil {
					tt.checkResult(t, ban)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// UnbanIP Tests
// =============================================================================

func TestUnbanIP(t *testing.T) {
	tests := []struct {
		name          string
		request       *entity.UnbanRequest
		setupMock     func(*MockBansRepository)
		expectedError string
	}{
		{
			name: "successful unban",
			request: &entity.UnbanRequest{
				IP:          "192.168.1.50",
				Reason:      "False positive",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository) {
				ban := createTestBan("192.168.1.50", 1, entity.BanStatusActive, nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.50").Return(ban, nil)
				repo.On("UpsertBan", mock.Anything, mock.MatchedBy(func(b *entity.BanStatus) bool {
					return b.IP == "192.168.1.50" && b.Status == entity.BanStatusExpired
				})).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.MatchedBy(func(h *entity.BanHistory) bool {
					return h.Action == entity.BanActionUnban
				})).Return(nil)
			},
			expectedError: "",
		},
		{
			name: "unban non-existent IP",
			request: &entity.UnbanRequest{
				IP:          "192.168.1.99",
				Reason:      "Test",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetBanByIP", mock.Anything, "192.168.1.99").Return(nil, errors.New("not found"))
			},
			expectedError: "ban not found",
		},
		{
			name: "repository upsert error on unban",
			request: &entity.UnbanRequest{
				IP:          "192.168.1.51",
				Reason:      "Test",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository) {
				ban := createTestBan("192.168.1.51", 1, entity.BanStatusActive, nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.51").Return(ban, nil)
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(errors.New("db error"))
			},
			expectedError: "update ban",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			// Use nil sophos to avoid async goroutine calls
			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			err := svc.UnbanIP(ctx, tt.request)

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
// MakePermanent Tests
// =============================================================================

func TestMakePermanent(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		performedBy   string
		setupMock     func(*MockBansRepository)
		expectedError string
		checkResult   func(*testing.T, *entity.BanStatus)
	}{
		{
			name:        "make active ban permanent",
			ip:          "192.168.1.50",
			performedBy: "admin",
			setupMock: func(repo *MockBansRepository) {
				expires := time.Now().Add(2 * time.Hour)
				ban := createTestBan("192.168.1.50", 2, entity.BanStatusActive, &expires)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.50").Return(ban, nil)
				repo.On("UpsertBan", mock.Anything, mock.MatchedBy(func(b *entity.BanStatus) bool {
					return b.Status == entity.BanStatusPermanent && b.ExpiresAt == nil
				})).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.MatchedBy(func(h *entity.BanHistory) bool {
					return h.Action == entity.BanActionPermanent
				})).Return(nil)
			},
			expectedError: "",
			checkResult: func(t *testing.T, ban *entity.BanStatus) {
				assert.Equal(t, entity.BanStatusPermanent, ban.Status)
				assert.Nil(t, ban.ExpiresAt)
			},
		},
		{
			name:        "make non-existent ban permanent",
			ip:          "192.168.1.99",
			performedBy: "admin",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetBanByIP", mock.Anything, "192.168.1.99").Return(nil, errors.New("not found"))
			},
			expectedError: "ban not found",
			checkResult:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			ban, err := svc.MakePermanent(ctx, tt.ip, tt.performedBy)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, ban)
			} else {
				require.NoError(t, err)
				require.NotNil(t, ban)
				if tt.checkResult != nil {
					tt.checkResult(t, ban)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// ListActiveBans Tests
// =============================================================================

func TestListActiveBans(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*MockBansRepository)
		expectedError bool
		expectedCount int
	}{
		{
			name: "returns active bans list",
			setupMock: func(repo *MockBansRepository) {
				bans := []entity.BanStatus{
					*createTestBan("192.168.1.1", 1, entity.BanStatusActive, nil),
					*createTestBan("192.168.1.2", 2, entity.BanStatusActive, nil),
					*createTestBan("192.168.1.3", 4, entity.BanStatusPermanent, nil),
				}
				repo.On("GetActiveBans", mock.Anything).Return(bans, nil)
			},
			expectedError: false,
			expectedCount: 3,
		},
		{
			name: "returns empty list",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetActiveBans", mock.Anything).Return([]entity.BanStatus{}, nil)
			},
			expectedError: false,
			expectedCount: 0,
		},
		{
			name: "repository error",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetActiveBans", mock.Anything).Return(nil, errors.New("db error"))
			},
			expectedError: true,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			bans, err := svc.ListActiveBans(ctx)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, bans, tt.expectedCount)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// GetBan Tests
// =============================================================================

func TestGetBan(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		setupMock     func(*MockBansRepository)
		expectedError bool
		checkBan      func(*testing.T, *entity.BanStatus)
	}{
		{
			name: "ban found",
			ip:   "192.168.1.50",
			setupMock: func(repo *MockBansRepository) {
				ban := createTestBan("192.168.1.50", 2, entity.BanStatusActive, nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.50").Return(ban, nil)
			},
			expectedError: false,
			checkBan: func(t *testing.T, ban *entity.BanStatus) {
				assert.Equal(t, "192.168.1.50", ban.IP)
				assert.Equal(t, uint8(2), ban.BanCount)
			},
		},
		{
			name: "ban not found",
			ip:   "192.168.1.99",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetBanByIP", mock.Anything, "192.168.1.99").Return(nil, errors.New("not found"))
			},
			expectedError: true,
			checkBan:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			ban, err := svc.GetBan(ctx, tt.ip)

			if tt.expectedError {
				require.Error(t, err)
				assert.Nil(t, ban)
			} else {
				require.NoError(t, err)
				require.NotNil(t, ban)
				if tt.checkBan != nil {
					tt.checkBan(t, ban)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// GetStats Tests
// =============================================================================

func TestGetStats(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*MockBansRepository)
		expectedError bool
		checkStats    func(*testing.T, *entity.BanStats)
	}{
		{
			name: "returns statistics",
			setupMock: func(repo *MockBansRepository) {
				stats := &entity.BanStats{
					TotalActiveBans:    100,
					TotalPermanentBans: 25,
					TotalExpiredBans:   500,
					BansLast24h:        10,
					UnbansLast24h:      5,
					RecidivistIPs:      15,
					PendingSync:        3,
				}
				repo.On("GetBanStats", mock.Anything).Return(stats, nil)
			},
			expectedError: false,
			checkStats: func(t *testing.T, stats *entity.BanStats) {
				assert.Equal(t, uint64(100), stats.TotalActiveBans)
				assert.Equal(t, uint64(25), stats.TotalPermanentBans)
				assert.Equal(t, uint64(15), stats.RecidivistIPs)
			},
		},
		{
			name: "repository error",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetBanStats", mock.Anything).Return(nil, errors.New("db error"))
			},
			expectedError: true,
			checkStats:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			stats, err := svc.GetStats(ctx)

			if tt.expectedError {
				require.Error(t, err)
				assert.Nil(t, stats)
			} else {
				require.NoError(t, err)
				require.NotNil(t, stats)
				if tt.checkStats != nil {
					tt.checkStats(t, stats)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// GetHistory Tests
// =============================================================================

func TestGetHistory(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		limit         int
		setupMock     func(*MockBansRepository)
		expectedError bool
		expectedCount int
	}{
		{
			name:  "returns history",
			ip:    "192.168.1.50",
			limit: 10,
			setupMock: func(repo *MockBansRepository) {
				history := []entity.BanHistory{
					{IP: "192.168.1.50", Action: entity.BanActionBan},
					{IP: "192.168.1.50", Action: entity.BanActionUnban},
					{IP: "192.168.1.50", Action: entity.BanActionBan},
				}
				repo.On("GetBanHistory", mock.Anything, "192.168.1.50", 10).Return(history, nil)
			},
			expectedError: false,
			expectedCount: 3,
		},
		{
			name:  "empty history",
			ip:    "192.168.1.99",
			limit: 10,
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetBanHistory", mock.Anything, "192.168.1.99", 10).Return([]entity.BanHistory{}, nil)
			},
			expectedError: false,
			expectedCount: 0,
		},
		{
			name:  "repository error",
			ip:    "192.168.1.50",
			limit: 10,
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetBanHistory", mock.Anything, "192.168.1.50", 10).Return(nil, errors.New("db error"))
			},
			expectedError: true,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			history, err := svc.GetHistory(ctx, tt.ip, tt.limit)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, history, tt.expectedCount)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// Whitelist Tests
// =============================================================================

func TestCheckWhitelist(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		setupMock     func(*MockBansRepository)
		expectedError bool
		checkResult   func(*testing.T, *entity.WhitelistCheckResult)
	}{
		{
			name: "not whitelisted",
			ip:   "192.168.1.200",
			setupMock: func(repo *MockBansRepository) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.200").Return(notWhitelistedResult(), nil)
			},
			expectedError: false,
			checkResult: func(t *testing.T, result *entity.WhitelistCheckResult) {
				assert.False(t, result.IsWhitelisted)
				assert.Equal(t, "none", result.EffectiveType)
				assert.True(t, result.AllowAutoBan)
			},
		},
		{
			name: "hard whitelisted",
			ip:   "192.168.1.100",
			setupMock: func(repo *MockBansRepository) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.100").Return(hardWhitelistedResult(), nil)
			},
			expectedError: false,
			checkResult: func(t *testing.T, result *entity.WhitelistCheckResult) {
				assert.True(t, result.IsWhitelisted)
				assert.Equal(t, entity.WhitelistTypeHard, result.EffectiveType)
				assert.False(t, result.AllowAutoBan)
				assert.Equal(t, int32(100), result.ScoreModifier)
			},
		},
		{
			name: "soft whitelisted",
			ip:   "10.0.0.50",
			setupMock: func(repo *MockBansRepository) {
				repo.On("CheckWhitelistV2", mock.Anything, "10.0.0.50").Return(softWhitelistedResult(true), nil)
			},
			expectedError: false,
			checkResult: func(t *testing.T, result *entity.WhitelistCheckResult) {
				assert.True(t, result.IsWhitelisted)
				assert.Equal(t, entity.WhitelistTypeSoft, result.EffectiveType)
				assert.True(t, result.AlertRequired)
				assert.Equal(t, int32(50), result.ScoreModifier)
			},
		},
		{
			name: "repository error",
			ip:   "192.168.1.201",
			setupMock: func(repo *MockBansRepository) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.201").Return(nil, errors.New("db error"))
			},
			expectedError: true,
			checkResult:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			result, err := svc.CheckWhitelist(ctx, tt.ip)

			if tt.expectedError {
				require.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.checkResult != nil {
					tt.checkResult(t, result)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestGetWhitelist(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*MockBansRepository)
		expectedError bool
		expectedCount int
	}{
		{
			name: "returns whitelist entries",
			setupMock: func(repo *MockBansRepository) {
				entries := []entity.WhitelistEntry{
					{IP: "192.168.1.100", Type: entity.WhitelistTypeHard},
					{IP: "10.0.0.50", Type: entity.WhitelistTypeSoft},
					{IP: "172.16.0.1", Type: entity.WhitelistTypeMonitor},
				}
				repo.On("GetWhitelist", mock.Anything).Return(entries, nil)
			},
			expectedError: false,
			expectedCount: 3,
		},
		{
			name: "empty whitelist",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetWhitelist", mock.Anything).Return([]entity.WhitelistEntry{}, nil)
			},
			expectedError: false,
			expectedCount: 0,
		},
		{
			name: "repository error",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetWhitelist", mock.Anything).Return(nil, errors.New("db error"))
			},
			expectedError: true,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			entries, err := svc.GetWhitelist(ctx)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, entries, tt.expectedCount)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// ExtendBan Tests
// =============================================================================

func TestExtendBan(t *testing.T) {
	tests := []struct {
		name          string
		request       *entity.ExtendBanRequest
		setupMock     func(*MockBansRepository)
		expectedError string
		checkResult   func(*testing.T, *entity.BanStatus)
	}{
		{
			name: "extend active ban",
			request: &entity.ExtendBanRequest{
				IP:           "192.168.1.50",
				DurationDays: 7,
				Reason:       "Extended for review",
				PerformedBy:  "admin",
			},
			setupMock: func(repo *MockBansRepository) {
				expires := time.Now().Add(2 * time.Hour)
				ban := createTestBan("192.168.1.50", 2, entity.BanStatusActive, &expires)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.50").Return(ban, nil)
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.MatchedBy(func(h *entity.BanHistory) bool {
					return h.Action == entity.BanActionExtend
				})).Return(nil)
			},
			expectedError: "",
			checkResult: func(t *testing.T, ban *entity.BanStatus) {
				assert.NotNil(t, ban.ExpiresAt)
			},
		},
		{
			name: "extend non-existent ban",
			request: &entity.ExtendBanRequest{
				IP:           "192.168.1.99",
				DurationDays: 7,
				Reason:       "Test",
				PerformedBy:  "admin",
			},
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetBanByIP", mock.Anything, "192.168.1.99").Return(nil, errors.New("not found"))
			},
			expectedError: "ban not found",
			checkResult:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			ban, err := svc.ExtendBan(ctx, tt.request)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, ban)
				if tt.checkResult != nil {
					tt.checkResult(t, ban)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// ProcessExpiredBans Tests
// =============================================================================

func TestProcessExpiredBans(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*MockBansRepository)
		expectedError bool
		expectedCount int
	}{
		{
			name: "process expired bans",
			setupMock: func(repo *MockBansRepository) {
				expired := []entity.BanStatus{
					*createTestBan("192.168.1.1", 1, entity.BanStatusActive, nil),
					*createTestBan("192.168.1.2", 2, entity.BanStatusActive, nil),
				}
				repo.On("GetExpiredBans", mock.Anything).Return(expired, nil)
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(nil).Times(2)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil).Times(2)
			},
			expectedError: false,
			expectedCount: 2,
		},
		{
			name: "no expired bans",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetExpiredBans", mock.Anything).Return([]entity.BanStatus{}, nil)
			},
			expectedError: false,
			expectedCount: 0,
		},
		{
			name: "repository error",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetExpiredBans", mock.Anything).Return(nil, errors.New("db error"))
			},
			expectedError: true,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			// Use nil sophos to avoid async goroutine calls
			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			count, err := svc.ProcessExpiredBans(ctx)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCount, count)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// AddToWhitelist Tests
// =============================================================================

func TestAddToWhitelist(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		reason        string
		addedBy       string
		setupMock     func(*MockBansRepository)
		expectedError bool
	}{
		{
			name:    "add to whitelist successfully",
			ip:      "192.168.1.100",
			reason:  "Internal server",
			addedBy: "admin",
			setupMock: func(repo *MockBansRepository) {
				repo.On("GetBanByIP", mock.Anything, "192.168.1.100").Return(nil, errors.New("not found"))
				repo.On("AddToWhitelist", mock.Anything, mock.AnythingOfType("*entity.WhitelistEntry")).Return(nil)
			},
			expectedError: false,
		},
		{
			name:    "add to whitelist and unban existing",
			ip:      "192.168.1.101",
			reason:  "False positive",
			addedBy: "admin",
			setupMock: func(repo *MockBansRepository) {
				ban := createTestBan("192.168.1.101", 1, entity.BanStatusActive, nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.101").Return(ban, nil)
				repo.On("UpsertBan", mock.Anything, mock.MatchedBy(func(b *entity.BanStatus) bool {
					return b.Status == entity.BanStatusExpired
				})).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil)
				repo.On("AddToWhitelist", mock.Anything, mock.AnythingOfType("*entity.WhitelistEntry")).Return(nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			// Use nil sophos to avoid async goroutine calls
			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			err := svc.AddToWhitelist(ctx, tt.ip, tt.reason, tt.addedBy)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// RemoveFromWhitelist Tests
// =============================================================================

func TestRemoveFromWhitelist(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		setupMock     func(*MockBansRepository)
		expectedError bool
	}{
		{
			name: "remove from whitelist successfully",
			ip:   "192.168.1.100",
			setupMock: func(repo *MockBansRepository) {
				repo.On("RemoveFromWhitelist", mock.Anything, "192.168.1.100").Return(nil)
			},
			expectedError: false,
		},
		{
			name: "repository error",
			ip:   "192.168.1.101",
			setupMock: func(repo *MockBansRepository) {
				repo.On("RemoveFromWhitelist", mock.Anything, "192.168.1.101").Return(errors.New("db error"))
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			err := svc.RemoveFromWhitelist(ctx, tt.ip)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// =============================================================================
// GetXGSStatus Tests
// =============================================================================

func TestGetXGSStatus(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*MockSophosClient)
		sophosNil     bool
		expectedError bool
		checkResult   func(*testing.T, *sophos.SyncStatus)
	}{
		{
			name: "returns connected status",
			setupMock: func(m *MockSophosClient) {
				m.On("GetSyncStatus").Return(&sophos.SyncStatus{
					Connected:    true,
					GroupExists:  true,
					TotalInGroup: 100,
				}, nil)
			},
			sophosNil:     false,
			expectedError: false,
			checkResult: func(t *testing.T, status *sophos.SyncStatus) {
				assert.True(t, status.Connected)
				assert.Equal(t, 100, status.TotalInGroup)
			},
		},
		{
			name:          "sophos client nil",
			setupMock:     func(m *MockSophosClient) {},
			sophosNil:     true,
			expectedError: false,
			checkResult: func(t *testing.T, status *sophos.SyncStatus) {
				assert.False(t, status.Connected)
				assert.Contains(t, status.LastSyncError, "not configured")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			var svc *Service

			if tt.sophosNil {
				svc = NewServiceWithInterfaces(mockRepo, nil)
			} else {
				mockSophos := new(MockSophosClient)
				tt.setupMock(mockSophos)
				svc = createTestService(mockRepo, mockSophos)
			}

			ctx := context.Background()
			status, err := svc.GetXGSStatus(ctx)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, status)
				if tt.checkResult != nil {
					tt.checkResult(t, status)
				}
			}
		})
	}
}

// =============================================================================
// Progressive Ban Duration Tests
// =============================================================================

func TestGetNextBanDuration(t *testing.T) {
	tests := []struct {
		name             string
		banCount         uint8
		expectedDuration *time.Duration
	}{
		{
			name:             "first ban - 1 hour",
			banCount:         0,
			expectedDuration: durationPtr(1 * time.Hour),
		},
		{
			name:             "second ban - 4 hours",
			banCount:         1,
			expectedDuration: durationPtr(4 * time.Hour),
		},
		{
			name:             "third ban - 24 hours",
			banCount:         2,
			expectedDuration: durationPtr(24 * time.Hour),
		},
		{
			name:             "fourth ban - permanent (nil)",
			banCount:         3,
			expectedDuration: nil,
		},
		{
			name:             "fifth ban - permanent (nil)",
			banCount:         4,
			expectedDuration: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := entity.GetNextBanDuration(tt.banCount)

			if tt.expectedDuration == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, *tt.expectedDuration, *result)
			}
		})
	}
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestBanIP_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		request       *entity.BanRequest
		setupMock     func(*MockBansRepository)
		expectedError string
	}{
		{
			name: "empty reason still works",
			request: &entity.BanRequest{
				IP:          "192.168.1.50",
				Reason:      "",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.50").Return(notWhitelistedResult(), nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.50").Return(nil, errors.New("not found"))
				repo.On("UpsertBan", mock.Anything, mock.AnythingOfType("*entity.BanStatus")).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil)
			},
			expectedError: "",
		},
		{
			name: "high ban count (beyond threshold)",
			request: &entity.BanRequest{
				IP:          "192.168.1.52",
				Reason:      "Chronic offender",
				PerformedBy: "admin",
			},
			setupMock: func(repo *MockBansRepository) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.52").Return(notWhitelistedResult(), nil)
				existingBan := createTestBan("192.168.1.52", 10, entity.BanStatusExpired, nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.52").Return(existingBan, nil)
				repo.On("UpsertBan", mock.Anything, mock.MatchedBy(func(b *entity.BanStatus) bool {
					return b.Status == entity.BanStatusPermanent && b.BanCount == 11
				})).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil)
			},
			expectedError: "",
		},
		{
			name: "explicit permanent ban request",
			request: &entity.BanRequest{
				IP:          "192.168.1.55",
				Reason:      "Immediate permanent",
				PerformedBy: "admin",
				Permanent:   true,
			},
			setupMock: func(repo *MockBansRepository) {
				repo.On("CheckWhitelistV2", mock.Anything, "192.168.1.55").Return(notWhitelistedResult(), nil)
				repo.On("GetBanByIP", mock.Anything, "192.168.1.55").Return(nil, errors.New("not found"))
				repo.On("UpsertBan", mock.Anything, mock.MatchedBy(func(b *entity.BanStatus) bool {
					return b.Status == entity.BanStatusPermanent && b.ExpiresAt == nil
				})).Return(nil)
				repo.On("RecordBanHistory", mock.Anything, mock.AnythingOfType("*entity.BanHistory")).Return(nil)
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockBansRepository)
			tt.setupMock(mockRepo)

			// Use nil sophos to avoid async goroutine calls
			svc := createTestServiceNoSophos(mockRepo)
			ctx := context.Background()
			ban, err := svc.BanIP(ctx, tt.request)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, ban)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
