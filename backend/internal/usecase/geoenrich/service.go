package geoenrich

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/geoip"
	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
)

// Service handles geo enrichment for events
type Service struct {
	eventsRepo *clickhouse.EventsRepository
	geoClient  *geoip.Client
	logger     *slog.Logger
	mu         sync.Mutex
	running    bool
	stopCh     chan struct{}
}

// NewService creates a new geo enrichment service
func NewService(eventsRepo *clickhouse.EventsRepository, geoClient *geoip.Client, logger *slog.Logger) *Service {
	return &Service{
		eventsRepo: eventsRepo,
		geoClient:  geoClient,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}
}

// Start begins the geo enrichment background service
func (s *Service) Start(ctx context.Context, interval time.Duration) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	s.logger.Info("Starting geo enrichment service", "interval", interval)

	// Run initial enrichment
	go func() {
		s.logger.Info("Running initial geo enrichment")
		if err := s.EnrichPendingEvents(ctx); err != nil {
			s.logger.Error("Initial geo enrichment failed", "error", err)
		}
	}()

	// Start periodic enrichment
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := s.EnrichPendingEvents(ctx); err != nil {
					s.logger.Error("Periodic geo enrichment failed", "error", err)
				}
			case <-s.stopCh:
				s.logger.Info("Geo enrichment service stopped")
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop stops the geo enrichment service
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		close(s.stopCh)
		s.running = false
	}
}

// EnrichPendingEvents enriches events that need geo data
func (s *Service) EnrichPendingEvents(ctx context.Context) error {
	// Get unique IPs needing enrichment (limit to avoid rate limiting)
	ips, err := s.eventsRepo.GetUniqueIPsNeedingGeo(ctx, 40) // ip-api.com: 45 req/min
	if err != nil {
		return err
	}

	if len(ips) == 0 {
		s.logger.Debug("No IPs need geo enrichment")
		return nil
	}

	s.logger.Info("Enriching IPs with geolocation", "count", len(ips))

	// Lookup geo data for each IP
	ipToCountry := make(map[string]string)
	enriched := 0
	failed := 0

	for _, ip := range ips {
		// Rate limit: wait between requests to avoid hitting ip-api.com limits
		time.Sleep(1500 * time.Millisecond) // ~40 req/min

		geo, err := s.geoClient.Lookup(ctx, ip)
		if err != nil {
			s.logger.Debug("Failed to lookup geo for IP", "ip", ip, "error", err)
			failed++
			continue
		}

		if geo.CountryCode != "" {
			ipToCountry[ip] = geo.CountryCode
			enriched++
			s.logger.Debug("Geo lookup successful", "ip", ip, "country", geo.CountryCode)
		}
	}

	// Update events in batch
	if len(ipToCountry) > 0 {
		if err := s.eventsRepo.UpdateEventsGeoBatch(ctx, ipToCountry); err != nil {
			s.logger.Error("Failed to update events with geo data", "error", err)
			return err
		}
		s.logger.Info("Geo enrichment completed", "enriched", enriched, "failed", failed)
	}

	return nil
}

// EnrichIP enriches a single IP address and returns the country code
func (s *Service) EnrichIP(ctx context.Context, ip string) (string, error) {
	geo, err := s.geoClient.Lookup(ctx, ip)
	if err != nil {
		return "", err
	}
	return geo.CountryCode, nil
}

// GetStats returns enrichment statistics
func (s *Service) GetStats(ctx context.Context) (pending int, err error) {
	ips, err := s.eventsRepo.GetUniqueIPsNeedingGeo(ctx, 10000)
	if err != nil {
		return 0, err
	}
	return len(ips), nil
}
