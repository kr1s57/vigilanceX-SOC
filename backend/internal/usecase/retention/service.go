package retention

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// Repository defines the interface for retention data access
type Repository interface {
	GetRetentionSettings(ctx context.Context) (*entity.RetentionSettings, error)
	SaveRetentionSettings(ctx context.Context, settings *entity.RetentionSettings, updatedBy string) error
	UpdateLastCleanup(ctx context.Context) error
	GetTableRowCount(ctx context.Context, tableName string) (int64, error)
	DeleteOldRecords(ctx context.Context, tableName string, timestampColumn string, retentionDays int) (int64, error)
	GetStorageStats(ctx context.Context) (*entity.StorageStats, error)
}

// Service handles retention logic and cleanup operations
type Service struct {
	repo   Repository
	logger *slog.Logger

	// Background cleanup worker
	stopCh  chan struct{}
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// NewService creates a new retention service
func NewService(repo Repository, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		repo:   repo,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Start starts the background cleanup worker
func (s *Service) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return
	}

	s.running = true
	s.wg.Add(1)
	go s.cleanupWorker()
	s.logger.Info("[RETENTION] Background cleanup worker started")
}

// Stop stops the background cleanup worker
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	s.wg.Wait()
	s.running = false
	s.logger.Info("[RETENTION] Background cleanup worker stopped")
}

// cleanupWorker runs periodic cleanup based on settings
func (s *Service) cleanupWorker() {
	defer s.wg.Done()

	// Check every 5 minutes if cleanup is needed
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Run initial check after 1 minute
	time.Sleep(1 * time.Minute)
	s.checkAndRunCleanup()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkAndRunCleanup()
		}
	}
}

// checkAndRunCleanup checks if cleanup is needed and runs it
func (s *Service) checkAndRunCleanup() {
	ctx := context.Background()

	settings, err := s.repo.GetRetentionSettings(ctx)
	if err != nil {
		s.logger.Error("[RETENTION] Failed to get settings", "error", err)
		return
	}

	if !settings.RetentionEnabled {
		s.logger.Debug("[RETENTION] Cleanup disabled, skipping")
		return
	}

	// Check if enough time has passed since last cleanup
	nextCleanup := settings.LastCleanup.Add(time.Duration(settings.CleanupIntervalHours) * time.Hour)
	if time.Now().Before(nextCleanup) {
		s.logger.Debug("[RETENTION] Cleanup not due yet",
			"last_cleanup", settings.LastCleanup,
			"next_cleanup", nextCleanup)
		return
	}

	s.logger.Info("[RETENTION] Starting scheduled cleanup")
	result := s.RunCleanup(ctx, settings)
	s.logger.Info("[RETENTION] Scheduled cleanup completed",
		"success", result.Success,
		"total_deleted", result.TotalDeleted)
}

// GetSettings returns the current retention settings
func (s *Service) GetSettings(ctx context.Context) (*entity.RetentionSettings, error) {
	return s.repo.GetRetentionSettings(ctx)
}

// UpdateSettings updates the retention settings
func (s *Service) UpdateSettings(ctx context.Context, settings *entity.RetentionSettings, updatedBy string) error {
	// Validate retention days (minimum 1 day, maximum 3650 days / 10 years)
	if settings.EventsRetentionDays < 1 || settings.EventsRetentionDays > 3650 {
		settings.EventsRetentionDays = 30
	}
	if settings.ModsecLogsRetentionDays < 1 || settings.ModsecLogsRetentionDays > 3650 {
		settings.ModsecLogsRetentionDays = 30
	}
	if settings.FirewallEventsRetentionDays < 1 || settings.FirewallEventsRetentionDays > 3650 {
		settings.FirewallEventsRetentionDays = 30
	}
	if settings.VpnEventsRetentionDays < 1 || settings.VpnEventsRetentionDays > 3650 {
		settings.VpnEventsRetentionDays = 30
	}
	if settings.HeartbeatEventsRetentionDays < 1 || settings.HeartbeatEventsRetentionDays > 3650 {
		settings.HeartbeatEventsRetentionDays = 30
	}
	if settings.AtpEventsRetentionDays < 1 || settings.AtpEventsRetentionDays > 3650 {
		settings.AtpEventsRetentionDays = 90
	}
	if settings.AntivirusEventsRetentionDays < 1 || settings.AntivirusEventsRetentionDays > 3650 {
		settings.AntivirusEventsRetentionDays = 90
	}
	if settings.BanHistoryRetentionDays < 1 || settings.BanHistoryRetentionDays > 3650 {
		settings.BanHistoryRetentionDays = 365
	}
	if settings.AuditLogRetentionDays < 1 || settings.AuditLogRetentionDays > 3650 {
		settings.AuditLogRetentionDays = 365
	}
	if settings.CleanupIntervalHours < 1 || settings.CleanupIntervalHours > 168 {
		settings.CleanupIntervalHours = 6
	}

	return s.repo.SaveRetentionSettings(ctx, settings, updatedBy)
}

// RunCleanup performs cleanup on all tables based on settings
func (s *Service) RunCleanup(ctx context.Context, settings *entity.RetentionSettings) *entity.CleanupResult {
	result := &entity.CleanupResult{
		StartTime:  time.Now(),
		TableStats: []entity.RetentionStats{},
	}

	if settings == nil {
		var err error
		settings, err = s.repo.GetRetentionSettings(ctx)
		if err != nil {
			result.Error = err.Error()
			result.EndTime = time.Now()
			return result
		}
	}

	// Define cleanup tasks
	cleanupTasks := []struct {
		tableName       string
		timestampColumn string
		retentionDays   int
	}{
		{"events", "timestamp", settings.EventsRetentionDays},
		{"modsec_logs", "timestamp", settings.ModsecLogsRetentionDays},
		{"firewall_events", "timestamp", settings.FirewallEventsRetentionDays},
		{"vpn_events", "timestamp", settings.VpnEventsRetentionDays},
		{"heartbeat_events", "timestamp", settings.HeartbeatEventsRetentionDays},
		{"atp_events", "timestamp", settings.AtpEventsRetentionDays},
		{"antivirus_events", "timestamp", settings.AntivirusEventsRetentionDays},
		{"ban_history", "timestamp", settings.BanHistoryRetentionDays},
		{"audit_log", "timestamp", settings.AuditLogRetentionDays},
	}

	for _, task := range cleanupTasks {
		start := time.Now()

		rowsBefore, _ := s.repo.GetTableRowCount(ctx, task.tableName)
		deleted, err := s.repo.DeleteOldRecords(ctx, task.tableName, task.timestampColumn, task.retentionDays)

		stat := entity.RetentionStats{
			TableName:     task.tableName,
			RowsBefore:    rowsBefore,
			RetentionDays: task.retentionDays,
			Duration:      float64(time.Since(start).Milliseconds()),
			CleanupTime:   time.Now(),
		}

		if err != nil {
			s.logger.Error("[RETENTION] Cleanup failed for table",
				"table", task.tableName,
				"error", err)
			stat.RowsDeleted = 0
		} else {
			// Note: ClickHouse deletes are async, so we estimate
			stat.RowsDeleted = deleted
			result.TotalDeleted += deleted
		}

		result.TableStats = append(result.TableStats, stat)
	}

	// Update last cleanup timestamp
	if err := s.repo.UpdateLastCleanup(ctx); err != nil {
		s.logger.Error("[RETENTION] Failed to update last cleanup time", "error", err)
	}

	result.Success = true
	result.EndTime = time.Now()

	s.logger.Info("[RETENTION] Cleanup completed",
		"duration_ms", result.EndTime.Sub(result.StartTime).Milliseconds(),
		"tables_processed", len(result.TableStats),
		"total_deleted_estimate", result.TotalDeleted)

	return result
}

// GetStorageStats returns storage usage statistics
func (s *Service) GetStorageStats(ctx context.Context) (*entity.StorageStats, error) {
	return s.repo.GetStorageStats(ctx)
}

// IsRunning returns whether the cleanup worker is running
func (s *Service) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
