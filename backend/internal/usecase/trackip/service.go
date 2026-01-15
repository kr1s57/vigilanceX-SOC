package trackip

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// Repository defines the interface for TrackIP data access
type Repository interface {
	SearchEvents(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPWAFEvent, int64, error)
	SearchWAFSophos(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPWAFEvent, int64, error)
	SearchModSec(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPModSecEvent, int64, error)
	SearchFirewall(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPFirewallEvent, int64, error)
	SearchVPN(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPVPNEvent, int64, error)
	SearchATP(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPATPEvent, int64, error)
	SearchAntivirus(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPAntivirusEvent, int64, error)
	SearchHeartbeat(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPHeartbeatEvent, int64, error)
	GetSummaryStats(ctx context.Context, query *entity.TrackIPQuery) (*entity.TrackIPSummary, error)
}

// GeoIPProvider defines the interface for GeoIP lookups
type GeoIPProvider interface {
	Lookup(ctx context.Context, ip string) (*entity.GeoLocation, error)
}

// Service handles TrackIP business logic
type Service struct {
	repo   Repository
	geoIP  GeoIPProvider
	logger *slog.Logger
}

// NewService creates a new TrackIP service
func NewService(repo Repository, logger *slog.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
	}
}

// SetGeoIPProvider sets the GeoIP provider for IP lookups
func (s *Service) SetGeoIPProvider(geoIP GeoIPProvider) {
	s.geoIP = geoIP
}

// Search performs parallel searches across all log tables
func (s *Service) Search(ctx context.Context, query *entity.TrackIPQuery) (*entity.TrackIPResponse, error) {
	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Validate and determine query type
	if net.ParseIP(query.Query) != nil {
		query.QueryType = "ip"
	} else {
		query.QueryType = "hostname"
	}

	// Set default limit
	if query.Limit <= 0 {
		query.Limit = 100
	}
	if query.Limit > 500 {
		query.Limit = 500
	}

	// Set default time range if not provided
	now := time.Now()
	if query.StartTime == nil {
		defaultStart := now.AddDate(0, 0, -7) // Default to last 7 days
		query.StartTime = &defaultStart
	}
	if query.EndTime == nil {
		query.EndTime = &now
	}

	// Prepare response
	response := &entity.TrackIPResponse{
		Query:      query.Query,
		QueryType:  query.QueryType,
		Categories: make(map[string]*entity.TrackIPCategoryResult),
		TimeRange: entity.TrackIPTimeRange{
			Start: *query.StartTime,
			End:   *query.EndTime,
		},
		Summary: entity.TrackIPSummary{
			SeverityBreakdown: make(map[string]int64),
			UniqueHostnames:   []string{},
			UniqueDstIPs:      []string{},
			TopPorts:          []uint16{},
		},
	}

	// Execute all queries in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Define search functions
	type searchFunc struct {
		name   string
		search func(context.Context, *entity.TrackIPQuery) (interface{}, int64, error)
	}

	searches := []searchFunc{
		{"events", func(ctx context.Context, q *entity.TrackIPQuery) (interface{}, int64, error) {
			return s.repo.SearchEvents(ctx, q)
		}},
		{"waf", func(ctx context.Context, q *entity.TrackIPQuery) (interface{}, int64, error) {
			return s.repo.SearchWAFSophos(ctx, q)
		}},
		{"modsec", func(ctx context.Context, q *entity.TrackIPQuery) (interface{}, int64, error) {
			return s.repo.SearchModSec(ctx, q)
		}},
		{"firewall", func(ctx context.Context, q *entity.TrackIPQuery) (interface{}, int64, error) {
			return s.repo.SearchFirewall(ctx, q)
		}},
		{"vpn", func(ctx context.Context, q *entity.TrackIPQuery) (interface{}, int64, error) {
			return s.repo.SearchVPN(ctx, q)
		}},
		{"atp", func(ctx context.Context, q *entity.TrackIPQuery) (interface{}, int64, error) {
			return s.repo.SearchATP(ctx, q)
		}},
		{"antivirus", func(ctx context.Context, q *entity.TrackIPQuery) (interface{}, int64, error) {
			return s.repo.SearchAntivirus(ctx, q)
		}},
		{"heartbeat", func(ctx context.Context, q *entity.TrackIPQuery) (interface{}, int64, error) {
			return s.repo.SearchHeartbeat(ctx, q)
		}},
	}

	// Execute searches in parallel
	for _, search := range searches {
		wg.Add(1)
		go func(name string, searchFn func(context.Context, *entity.TrackIPQuery) (interface{}, int64, error)) {
			defer wg.Done()

			events, count, err := searchFn(ctx, query)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				s.logger.Warn("TrackIP search failed",
					"category", name,
					"query", query.Query,
					"error", err,
				)
				// Still add empty result for failed category
				response.Categories[name] = &entity.TrackIPCategoryResult{
					Count:  0,
					Events: []interface{}{},
				}
				return
			}

			response.Categories[name] = &entity.TrackIPCategoryResult{
				Count:  count,
				Events: events,
			}
		}(search.name, search.search)
	}

	// Get summary stats in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()

		summary, err := s.repo.GetSummaryStats(ctx, query)

		mu.Lock()
		defer mu.Unlock()

		if err != nil {
			s.logger.Warn("TrackIP summary failed",
				"query", query.Query,
				"error", err,
			)
			return
		}

		response.Summary = *summary
	}()

	// Get GeoIP info for IP queries
	if query.QueryType == "ip" && s.geoIP != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			geoResult, err := s.geoIP.Lookup(ctx, query.Query)
			if err != nil {
				s.logger.Debug("GeoIP lookup failed",
					"ip", query.Query,
					"error", err,
				)
				return
			}
			if geoResult == nil {
				return
			}

			mu.Lock()
			response.GeoInfo = &entity.TrackIPGeoInfo{
				CountryCode: geoResult.CountryCode,
				CountryName: geoResult.CountryName,
				City:        geoResult.City,
				ASN:         geoResult.ASN,
				Org:         geoResult.ASOrg,
			}
			mu.Unlock()
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Calculate categories found and total events
	categoriesFound := 0
	var totalEvents int64 = 0
	for _, cat := range response.Categories {
		if cat.Count > 0 {
			categoriesFound++
			totalEvents += cat.Count
		}
	}
	response.Summary.CategoriesFound = categoriesFound

	// If summary query failed, use the sum of category counts
	if response.Summary.TotalEvents == 0 {
		response.Summary.TotalEvents = totalEvents
	}

	return response, nil
}
