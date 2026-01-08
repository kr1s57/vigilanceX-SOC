package license

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"
)

// HeartbeatService manages periodic license validation
type HeartbeatService struct {
	client      *Client
	interval    time.Duration
	maxBackoff  time.Duration
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
	running     bool
	lastSuccess time.Time
	failCount   int
}

// NewHeartbeatService creates a new heartbeat service
func NewHeartbeatService(client *Client, interval time.Duration) *HeartbeatService {
	if interval == 0 {
		interval = 12 * time.Hour
	}

	return &HeartbeatService{
		client:     client,
		interval:   interval,
		maxBackoff: 1 * time.Hour, // Max retry delay
		stopCh:     make(chan struct{}),
	}
}

// Start begins the heartbeat loop
func (s *HeartbeatService) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	s.wg.Add(1)
	go s.run()

	slog.Info("License heartbeat service started",
		"interval", s.interval)
}

// Stop stops the heartbeat service
func (s *HeartbeatService) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()

	close(s.stopCh)
	s.wg.Wait()

	slog.Info("License heartbeat service stopped")
}

// run is the main heartbeat loop
func (s *HeartbeatService) run() {
	defer s.wg.Done()

	// Initial heartbeat after short delay
	select {
	case <-time.After(30 * time.Second):
		s.performHeartbeat()
	case <-s.stopCh:
		return
	}

	// Regular heartbeat loop
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.performHeartbeat()
		case <-s.stopCh:
			return
		}
	}
}

// performHeartbeat executes a single heartbeat with retry logic
func (s *HeartbeatService) performHeartbeat() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err := s.client.Heartbeat(ctx)

	if err != nil {
		s.handleFailure(err)
	} else {
		s.handleSuccess()
	}
}

// handleSuccess resets failure counters
func (s *HeartbeatService) handleSuccess() {
	s.mu.Lock()
	s.failCount = 0
	s.lastSuccess = time.Now()
	s.mu.Unlock()

	status := s.client.GetStatus()
	slog.Info("License heartbeat successful",
		"status", status.Status,
		"days_remaining", status.DaysRemaining,
		"grace_mode", status.GraceMode)
}

// handleFailure implements exponential backoff retry
func (s *HeartbeatService) handleFailure(err error) {
	s.mu.Lock()
	s.failCount++
	failCount := s.failCount
	s.mu.Unlock()

	// Calculate backoff delay
	backoff := s.calculateBackoff(failCount)

	status := s.client.GetStatus()
	slog.Warn("License heartbeat failed",
		"error", err,
		"fail_count", failCount,
		"next_retry", backoff,
		"grace_mode", status.GraceMode,
		"licensed", status.Licensed)

	// Schedule retry if not in graceful shutdown
	go func() {
		select {
		case <-time.After(backoff):
			s.performHeartbeat()
		case <-s.stopCh:
			return
		}
	}()
}

// calculateBackoff returns the backoff duration based on failure count
func (s *HeartbeatService) calculateBackoff(failCount int) time.Duration {
	// Exponential backoff: 30s, 1m, 2m, 4m, 8m, 16m, 32m, 60m (max)
	baseDelay := 30 * time.Second
	delay := time.Duration(float64(baseDelay) * math.Pow(2, float64(failCount-1)))

	if delay > s.maxBackoff {
		delay = s.maxBackoff
	}

	return delay
}

// GetStats returns heartbeat statistics
func (s *HeartbeatService) GetStats() HeartbeatStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	return HeartbeatStats{
		Running:     s.running,
		Interval:    s.interval,
		LastSuccess: s.lastSuccess,
		FailCount:   s.failCount,
	}
}

// HeartbeatStats contains heartbeat service statistics
type HeartbeatStats struct {
	Running     bool          `json:"running"`
	Interval    time.Duration `json:"interval"`
	LastSuccess time.Time     `json:"last_success"`
	FailCount   int           `json:"fail_count"`
}

// ForceHeartbeat triggers an immediate heartbeat (for testing/admin)
func (s *HeartbeatService) ForceHeartbeat() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	return s.client.Heartbeat(ctx)
}
