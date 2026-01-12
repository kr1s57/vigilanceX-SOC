package wafwatcher

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ModSecSyncer is the interface for triggering ModSec synchronization
type ModSecSyncer interface {
	SyncNow(ctx context.Context) error
}

// WAFEventChecker is the interface for checking recent WAF events
type WAFEventChecker interface {
	// GetRecentWAFBlockEvents returns the count of WAF blocking events since the given time
	GetRecentWAFBlockEvents(ctx context.Context, since time.Time) (int, error)
}

// Config holds the watcher configuration
type Config struct {
	// PollInterval is how often to check for new WAF events
	PollInterval time.Duration
	// SyncCooldown is the minimum time between ModSec syncs
	SyncCooldown time.Duration
	// MinEventsToTrigger is the minimum number of new events to trigger a sync
	MinEventsToTrigger int
}

// DefaultConfig returns a sensible default configuration
func DefaultConfig() Config {
	return Config{
		PollInterval:       15 * time.Second, // Check every 15 seconds
		SyncCooldown:       60 * time.Second, // Don't sync more than once per minute
		MinEventsToTrigger: 1,                // Trigger on any new blocking event
	}
}

// Service monitors ClickHouse for new WAF events and triggers ModSec sync
type Service struct {
	config       Config
	eventChecker WAFEventChecker
	modsecSyncer ModSecSyncer
	logger       *slog.Logger

	mu            sync.Mutex
	running       bool
	stopCh        chan struct{}
	lastCheck     time.Time
	lastSync      time.Time
	triggeredSync int64 // Total number of triggered syncs
	eventsChecked int64 // Total events checked
}

// NewService creates a new WAF event watcher service
func NewService(config Config, eventChecker WAFEventChecker, modsecSyncer ModSecSyncer, logger *slog.Logger) *Service {
	if config.PollInterval == 0 {
		config = DefaultConfig()
	}

	return &Service{
		config:       config,
		eventChecker: eventChecker,
		modsecSyncer: modsecSyncer,
		logger:       logger,
		stopCh:       make(chan struct{}),
	}
}

// Start begins the background monitoring
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.lastCheck = time.Now()
	s.mu.Unlock()

	s.logger.Info("Starting WAF Event Watcher service",
		"poll_interval", s.config.PollInterval,
		"sync_cooldown", s.config.SyncCooldown,
		"min_events", s.config.MinEventsToTrigger)

	ticker := time.NewTicker(s.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("WAF Event Watcher stopped (context cancelled)")
			return
		case <-s.stopCh:
			s.logger.Info("WAF Event Watcher stopped")
			return
		case <-ticker.C:
			s.checkAndTrigger(ctx)
		}
	}
}

// Stop stops the background monitoring
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		close(s.stopCh)
		s.running = false
	}
}

// checkAndTrigger checks for new WAF events and triggers ModSec sync if needed
func (s *Service) checkAndTrigger(ctx context.Context) {
	s.mu.Lock()
	checkSince := s.lastCheck
	s.lastCheck = time.Now()
	lastSyncTime := s.lastSync
	s.mu.Unlock()

	// Check if we're still in cooldown
	if time.Since(lastSyncTime) < s.config.SyncCooldown {
		s.logger.Debug("WAF watcher: still in sync cooldown",
			"remaining", s.config.SyncCooldown-time.Since(lastSyncTime))
		return
	}

	// Query ClickHouse for recent WAF blocking events
	count, err := s.eventChecker.GetRecentWAFBlockEvents(ctx, checkSince)
	if err != nil {
		s.logger.Error("Failed to check WAF events", "error", err)
		return
	}

	s.mu.Lock()
	s.eventsChecked += int64(count)
	s.mu.Unlock()

	if count < s.config.MinEventsToTrigger {
		s.logger.Debug("WAF watcher: no new blocking events", "since", checkSince, "count", count)
		return
	}

	// New WAF blocking events detected! Trigger ModSec sync
	s.logger.Info("WAF blocking events detected, triggering ModSec sync",
		"events", count,
		"since", checkSince)

	if s.modsecSyncer == nil {
		s.logger.Warn("ModSec syncer not configured, cannot trigger sync")
		return
	}

	// Trigger async sync to not block the watcher
	go func() {
		syncCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		if err := s.modsecSyncer.SyncNow(syncCtx); err != nil {
			s.logger.Error("ModSec sync triggered by WAF watcher failed", "error", err)
		} else {
			s.logger.Info("ModSec sync triggered by WAF watcher completed successfully")
		}
	}()

	s.mu.Lock()
	s.lastSync = time.Now()
	s.triggeredSync++
	s.mu.Unlock()
}

// Stats returns watcher statistics
type Stats struct {
	Running        bool          `json:"running"`
	LastCheck      time.Time     `json:"last_check"`
	LastSync       time.Time     `json:"last_sync"`
	TriggeredSyncs int64         `json:"triggered_syncs"`
	EventsChecked  int64         `json:"events_checked"`
	PollInterval   time.Duration `json:"poll_interval"`
	SyncCooldown   time.Duration `json:"sync_cooldown"`
}

// GetStats returns current watcher statistics
func (s *Service) GetStats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()

	return Stats{
		Running:        s.running,
		LastCheck:      s.lastCheck,
		LastSync:       s.lastSync,
		TriggeredSyncs: s.triggeredSync,
		EventsChecked:  s.eventsChecked,
		PollInterval:   s.config.PollInterval,
		SyncCooldown:   s.config.SyncCooldown,
	}
}

// IsRunning returns whether the watcher is currently running
func (s *Service) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
