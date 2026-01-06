package modsec

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	modsecclient "github.com/kr1s57/vigilancex/internal/adapter/external/modsec"
	"github.com/kr1s57/vigilancex/internal/config"
)

// Service manages ModSec log synchronization
type Service struct {
	client       *modsecclient.Client
	correlator   *modsecclient.Correlator
	syncInterval time.Duration
	logger       *slog.Logger
	mu           sync.Mutex
	running      bool
	stopCh       chan struct{}
	lastSync     time.Time
	stats        SyncStats
}

// SyncStats tracks synchronization statistics
type SyncStats struct {
	LastSync       time.Time `json:"last_sync"`
	EntriesFetched int       `json:"entries_fetched"`
	EventsUpdated  int       `json:"events_updated"`
	LastError      string    `json:"last_error,omitempty"`
	IsRunning      bool      `json:"is_running"`
}

// NewService creates a new ModSec synchronization service
func NewService(cfg config.SophosSSHConfig, db driver.Conn, logger *slog.Logger) *Service {
	client := modsecclient.NewClient(modsecclient.Config{
		Host:    cfg.Host,
		Port:    cfg.Port,
		User:    cfg.User,
		KeyPath: cfg.KeyPath,
		LogPath: cfg.LogPath,
	}, logger)

	correlator := modsecclient.NewCorrelator(db, logger)

	return &Service{
		client:       client,
		correlator:   correlator,
		syncInterval: cfg.SyncInterval,
		logger:       logger,
		stopCh:       make(chan struct{}),
	}
}

// Start begins the background synchronization
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	s.logger.Info("Starting ModSec log sync service", "interval", s.syncInterval)

	// Initial sync
	s.sync(ctx)

	ticker := time.NewTicker(s.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("ModSec sync service stopped (context cancelled)")
			return
		case <-s.stopCh:
			s.logger.Info("ModSec sync service stopped")
			return
		case <-ticker.C:
			s.sync(ctx)
		}
	}
}

// Stop stops the background synchronization
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		close(s.stopCh)
		s.running = false
	}
}

// sync performs a single synchronization cycle
func (s *Service) sync(ctx context.Context) {
	s.logger.Debug("Starting ModSec sync cycle")
	s.stats.IsRunning = true

	// Determine the time window
	var since time.Time
	if s.lastSync.IsZero() {
		// Initial sync: look back 24 hours to capture historical data
		since = time.Now().Add(-24 * time.Hour)
		s.logger.Info("Initial ModSec sync - looking back 24 hours")
	} else {
		// Subsequent syncs: look back to last sync with 1 minute overlap
		since = s.lastSync.Add(-1 * time.Minute)
	}

	// Fetch logs from XGS
	entries, err := s.client.FetchModSecLogs(ctx, since, 2000)
	if err != nil {
		s.logger.Error("Failed to fetch ModSec logs", "error", err)
		s.stats.LastError = err.Error()
		s.stats.IsRunning = false
		return
	}

	s.stats.EntriesFetched = len(entries)
	s.logger.Info("Fetched ModSec log entries", "count", len(entries))

	if len(entries) == 0 {
		s.logger.Info("No ModSec entries to correlate")
		s.stats.LastSync = time.Now()
		s.stats.IsRunning = false
		s.lastSync = time.Now()
		return
	}

	// Correlate and update events
	updated, err := s.correlator.CorrelateAndUpdate(ctx, entries)
	if err != nil {
		s.logger.Error("Failed to correlate events", "error", err)
		s.stats.LastError = err.Error()
		s.stats.IsRunning = false
		return
	}

	s.stats.EventsUpdated = updated
	s.stats.LastSync = time.Now()
	s.stats.LastError = ""
	s.stats.IsRunning = false
	s.lastSync = time.Now()

	s.logger.Info("ModSec sync completed", "entries_fetched", len(entries), "events_updated", updated)
}

// SyncNow triggers an immediate synchronization
func (s *Service) SyncNow(ctx context.Context) error {
	s.sync(ctx)
	if s.stats.LastError != "" {
		return context.DeadlineExceeded // Return an error to indicate sync failed
	}
	return nil
}

// GetStats returns current synchronization statistics
func (s *Service) GetStats() SyncStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// IsConfigured returns true if SSH config is properly set
func (s *Service) IsConfigured() bool {
	return s.client != nil
}

// TestConnection tests the SSH connection
func (s *Service) TestConnection(ctx context.Context) error {
	return s.client.TestConnection(ctx)
}
