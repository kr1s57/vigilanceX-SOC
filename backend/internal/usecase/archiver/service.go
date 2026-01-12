package archiver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/storage"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// EventFetcher interface for fetching events from repository
type EventFetcher interface {
	GetEvents(ctx context.Context, filters entity.EventFilters, limit, offset int) ([]entity.Event, uint64, error)
}

// Service handles archiving events to external storage
type Service struct {
	storage      *storage.Manager
	eventFetcher EventFetcher
	mu           sync.Mutex

	// Watermark to track last archived event
	lastArchived time.Time
	archiveCount int64
}

// NewService creates a new archiver service
func NewService(storageManager *storage.Manager, eventFetcher EventFetcher) *Service {
	return &Service{
		storage:      storageManager,
		eventFetcher: eventFetcher,
		lastArchived: time.Now().Add(-24 * time.Hour), // Start from 24h ago
	}
}

// Start begins the archiving loop
func (s *Service) Start(ctx context.Context, interval time.Duration) {
	slog.Info("[ARCHIVER] Starting archiver service", "interval", interval)

	// Initial archive run
	s.archiveRecent(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("[ARCHIVER] Archiver service stopped")
			return
		case <-ticker.C:
			s.archiveRecent(ctx)
		}
	}
}

// archiveRecent fetches and archives events since last watermark
func (s *Service) archiveRecent(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if storage is connected
	if !s.storage.IsConnected() {
		return
	}

	// Get config to check if archiving is enabled
	config := s.storage.GetConfig()
	if config == nil || !config.Enabled || config.Archive == nil || !config.Archive.Enabled {
		return
	}

	// Fetch events since last archived timestamp
	filters := entity.EventFilters{
		StartTime: s.lastArchived,
		EndTime:   time.Now(),
	}

	events, total, err := s.eventFetcher.GetEvents(ctx, filters, 10000, 0)
	if err != nil {
		slog.Warn("[ARCHIVER] Failed to fetch events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Info("[ARCHIVER] Archiving events", "count", len(events), "total_available", total)

	// Convert to storage LogEntry format and archive
	for _, event := range events {
		entry := storage.LogEntry{
			Timestamp: event.Timestamp,
			LogType:   event.LogType,
			SrcIP:     event.SrcIP,
			DstIP:     event.DstIP,
			Action:    event.Action,
			RawLog:    event.RawLog,
		}

		if err := s.storage.ArchiveLog(entry); err != nil {
			slog.Warn("[ARCHIVER] Failed to archive log", "error", err)
		}
	}

	// Update watermark to latest event timestamp
	if len(events) > 0 {
		latestTimestamp := events[0].Timestamp
		for _, e := range events {
			if e.Timestamp.After(latestTimestamp) {
				latestTimestamp = e.Timestamp
			}
		}
		s.lastArchived = latestTimestamp
		s.archiveCount += int64(len(events))
	}

	// Flush to storage
	if err := s.storage.Flush(ctx); err != nil {
		slog.Warn("[ARCHIVER] Failed to flush to storage", "error", err)
	}

	slog.Info("[ARCHIVER] Archive batch complete", "archived", len(events), "total_archived", s.archiveCount)
}

// GetStatus returns the current archiver status
func (s *Service) GetStatus() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	return map[string]interface{}{
		"last_archived":  s.lastArchived,
		"total_archived": s.archiveCount,
		"connected":      s.storage.IsConnected(),
	}
}

// ArchiveNow triggers an immediate archive run
func (s *Service) ArchiveNow(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.storage.IsConnected() {
		return 0, fmt.Errorf("storage not connected")
	}

	filters := entity.EventFilters{
		StartTime: s.lastArchived,
		EndTime:   time.Now(),
	}

	events, _, err := s.eventFetcher.GetEvents(ctx, filters, 10000, 0)
	if err != nil {
		return 0, err
	}

	archived := 0
	for _, event := range events {
		entry := storage.LogEntry{
			Timestamp: event.Timestamp,
			LogType:   event.LogType,
			SrcIP:     event.SrcIP,
			DstIP:     event.DstIP,
			Action:    event.Action,
			RawLog:    event.RawLog,
		}

		if err := s.storage.ArchiveLog(entry); err == nil {
			archived++
		}
	}

	if err := s.storage.Flush(ctx); err != nil {
		return archived, err
	}

	if len(events) > 0 {
		latestTimestamp := events[0].Timestamp
		for _, e := range events {
			if e.Timestamp.After(latestTimestamp) {
				latestTimestamp = e.Timestamp
			}
		}
		s.lastArchived = latestTimestamp
		s.archiveCount += int64(archived)
	}

	return archived, nil
}

// WriteTestFile writes a test file to verify storage is working
func (s *Service) WriteTestFile(ctx context.Context) error {
	if !s.storage.IsConnected() {
		return fmt.Errorf("storage not connected")
	}

	testData := map[string]interface{}{
		"test":      true,
		"timestamp": time.Now().Format(time.RFC3339),
		"message":   "VIGILANCE X Storage Test - Connection verified",
		"version":   "3.51",
	}

	data, _ := json.MarshalIndent(testData, "", "  ")
	filename := fmt.Sprintf("test/vigilancex_test_%s.json", time.Now().Format("2006-01-02_15-04-05"))

	// Access the provider directly through manager
	return s.storage.WriteFile(ctx, filename, data)
}
