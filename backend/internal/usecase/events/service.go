package events

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// GeoProvider interface for geolocation lookups
type GeoProvider interface {
	LookupBatch(ctx context.Context, ips []string) (map[string]*GeoInfo, error)
}

// GeoInfo represents basic geolocation info
type GeoInfo struct {
	IP          string
	CountryCode string
	CountryName string
}

// Repository defines the interface for event data operations
type Repository interface {
	GetEvents(ctx context.Context, filters entity.EventFilters, limit, offset int) ([]entity.Event, uint64, error)
	GetEventByID(ctx context.Context, eventID uuid.UUID) (*entity.Event, error)
	GetTimeline(ctx context.Context, period string, interval string) ([]entity.TimelinePoint, error)
	GetStats(ctx context.Context, period string) (*entity.EventStats, error)
	GetTopAttackers(ctx context.Context, period string, limit int) ([]entity.TopAttacker, error)
	GetTopTargets(ctx context.Context, period string, limit int) ([]entity.TopTarget, error)
	GetStatsByLogType(ctx context.Context, period string) (map[string]uint64, error)
	GetGeoHeatmap(ctx context.Context, period string) ([]map[string]interface{}, error)
	GetGeoHeatmapFiltered(ctx context.Context, period string, attackTypes []string) ([]map[string]interface{}, error)
	GetGeoHeatmapFilteredRange(ctx context.Context, startTime, endTime time.Time, attackTypes []string) ([]map[string]interface{}, error)
	GetUniqueHostnames(ctx context.Context, logType string) ([]string, error)
	GetSyslogStatus(ctx context.Context) (*entity.SyslogStatus, error)
	GetCriticalAlerts(ctx context.Context, limit int, period string) ([]entity.CriticalAlert, error)
	GetZoneTraffic(ctx context.Context, period string, limit int) (*entity.ZoneTrafficStats, error)
}

// Service handles event business logic
type Service struct {
	repo        Repository
	logger      *slog.Logger
	geoProvider GeoProvider
}

// NewService creates a new events service
func NewService(repo Repository, logger *slog.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
	}
}

// SetGeoProvider sets the geolocation provider for enriching IP data
func (s *Service) SetGeoProvider(gp GeoProvider) {
	s.geoProvider = gp
}

// ListEventsRequest represents a request to list events
type ListEventsRequest struct {
	LogType    string    `json:"log_type"`
	Category   string    `json:"category"`
	Severity   string    `json:"severity"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	Hostname   string    `json:"hostname"`
	RuleID     string    `json:"rule_id"`
	Action     string    `json:"action"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	SearchTerm string    `json:"search_term"`
	Limit      int       `json:"limit"`
	Offset     int       `json:"offset"`
}

// ListEventsResponse represents the response for listing events
type ListEventsResponse struct {
	Data       []entity.Event `json:"data"`
	Pagination Pagination     `json:"pagination"`
}

// Pagination represents pagination information
type Pagination struct {
	Total   uint64 `json:"total"`
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
	HasMore bool   `json:"has_more"`
}

// ListEvents retrieves events with filters
func (s *Service) ListEvents(ctx context.Context, req ListEventsRequest) (*ListEventsResponse, error) {
	// Set defaults
	if req.Limit <= 0 || req.Limit > 1000 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	filters := entity.EventFilters{
		LogType:    req.LogType,
		Category:   req.Category,
		Severity:   req.Severity,
		SrcIP:      req.SrcIP,
		DstIP:      req.DstIP,
		Hostname:   req.Hostname,
		RuleID:     req.RuleID,
		Action:     req.Action,
		StartTime:  req.StartTime,
		EndTime:    req.EndTime,
		SearchTerm: req.SearchTerm,
	}

	events, total, err := s.repo.GetEvents(ctx, filters, req.Limit, req.Offset)
	if err != nil {
		s.logger.Error("Failed to list events", "error", err)
		return nil, err
	}

	return &ListEventsResponse{
		Data: events,
		Pagination: Pagination{
			Total:   total,
			Limit:   req.Limit,
			Offset:  req.Offset,
			HasMore: uint64(req.Offset+len(events)) < total,
		},
	}, nil
}

// GetEvent retrieves a single event by ID
func (s *Service) GetEvent(ctx context.Context, eventID uuid.UUID) (*entity.Event, error) {
	event, err := s.repo.GetEventByID(ctx, eventID)
	if err != nil {
		s.logger.Error("Failed to get event", "event_id", eventID, "error", err)
		return nil, err
	}
	return event, nil
}

// TimelineRequest represents a request for timeline data
type TimelineRequest struct {
	Period   string `json:"period"`   // 24h, 7d, 30d
	Interval string `json:"interval"` // hour, day
}

// GetTimeline retrieves event timeline data
func (s *Service) GetTimeline(ctx context.Context, req TimelineRequest) ([]entity.TimelinePoint, error) {
	// Set defaults
	if req.Period == "" {
		req.Period = "24h"
	}
	if req.Interval == "" {
		req.Interval = "hour"
	}

	timeline, err := s.repo.GetTimeline(ctx, req.Period, req.Interval)
	if err != nil {
		s.logger.Error("Failed to get timeline", "error", err)
		return nil, err
	}

	return timeline, nil
}

// OverviewResponse represents the dashboard overview data
type OverviewResponse struct {
	Stats        *entity.EventStats   `json:"stats"`
	ByLogType    map[string]uint64    `json:"by_log_type"`
	TopAttackers []entity.TopAttacker `json:"top_attackers"`
	TopTargets   []entity.TopTarget   `json:"top_targets"`
}

// GetOverview retrieves dashboard overview data
func (s *Service) GetOverview(ctx context.Context, period string) (*OverviewResponse, error) {
	if period == "" {
		period = "24h"
	}

	// Get stats
	stats, err := s.repo.GetStats(ctx, period)
	if err != nil {
		s.logger.Error("Failed to get stats", "error", err)
		return nil, err
	}

	// Get by log type
	byLogType, err := s.repo.GetStatsByLogType(ctx, period)
	if err != nil {
		s.logger.Error("Failed to get stats by log type", "error", err)
		return nil, err
	}

	// Get top attackers
	topAttackers, err := s.repo.GetTopAttackers(ctx, period, 10)
	if err != nil {
		s.logger.Error("Failed to get top attackers", "error", err)
		return nil, err
	}

	// Enrich top attackers with geolocation
	if s.geoProvider != nil {
		topAttackers = s.enrichAttackersGeo(ctx, topAttackers)
	}

	// Get top targets
	topTargets, err := s.repo.GetTopTargets(ctx, period, 10)
	if err != nil {
		s.logger.Error("Failed to get top targets", "error", err)
		return nil, err
	}

	return &OverviewResponse{
		Stats:        stats,
		ByLogType:    byLogType,
		TopAttackers: topAttackers,
		TopTargets:   topTargets,
	}, nil
}

// GetTopAttackers retrieves top attacking IPs with geolocation enrichment
func (s *Service) GetTopAttackers(ctx context.Context, period string, limit int) ([]entity.TopAttacker, error) {
	if period == "" {
		period = "24h"
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	attackers, err := s.repo.GetTopAttackers(ctx, period, limit)
	if err != nil {
		return nil, err
	}

	// Enrich IPs with missing geolocation
	if s.geoProvider != nil {
		attackers = s.enrichAttackersGeo(ctx, attackers)
	}

	return attackers, nil
}

// enrichAttackersGeo enriches top attackers with geolocation data
func (s *Service) enrichAttackersGeo(ctx context.Context, attackers []entity.TopAttacker) []entity.TopAttacker {
	// Collect IPs that need enrichment
	var ipsToEnrich []string
	for _, a := range attackers {
		if a.Country == "" {
			ipsToEnrich = append(ipsToEnrich, a.IP)
		}
	}

	if len(ipsToEnrich) == 0 {
		return attackers
	}

	s.logger.Debug("Enriching top attackers with geolocation", "count", len(ipsToEnrich))

	// Lookup geolocation for missing IPs
	geoData, err := s.geoProvider.LookupBatch(ctx, ipsToEnrich)
	if err != nil {
		s.logger.Warn("Failed to enrich geolocation", "error", err)
		return attackers
	}

	// Update attackers with geo data
	for i, a := range attackers {
		if a.Country == "" {
			if geo, ok := geoData[a.IP]; ok && geo != nil {
				attackers[i].Country = geo.CountryCode
			}
		}
	}

	return attackers
}

// GetTopTargets retrieves top targeted hosts
func (s *Service) GetTopTargets(ctx context.Context, period string, limit int) ([]entity.TopTarget, error) {
	if period == "" {
		period = "24h"
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	return s.repo.GetTopTargets(ctx, period, limit)
}

// GetGeoHeatmap retrieves geographic distribution data
func (s *Service) GetGeoHeatmap(ctx context.Context, period string) ([]map[string]interface{}, error) {
	if period == "" {
		period = "24h"
	}

	return s.repo.GetGeoHeatmap(ctx, period)
}

// GetGeoHeatmapFiltered retrieves geographic distribution filtered by attack types
// attackTypes can include: waf, ips, malware, bruteforce, ddos
func (s *Service) GetGeoHeatmapFiltered(ctx context.Context, period string, attackTypes []string) ([]map[string]interface{}, error) {
	if period == "" {
		period = "24h"
	}

	// If no filters, use the original method but exclude Firewall Allowed
	if len(attackTypes) == 0 {
		return s.repo.GetGeoHeatmapFiltered(ctx, period, nil)
	}

	return s.repo.GetGeoHeatmapFiltered(ctx, period, attackTypes)
}

// GetGeoHeatmapFilteredRange retrieves geographic distribution for explicit time range (v3.53.105)
// Used for custom date selection in Attack Map
func (s *Service) GetGeoHeatmapFilteredRange(ctx context.Context, startTime, endTime time.Time, attackTypes []string) ([]map[string]interface{}, error) {
	return s.repo.GetGeoHeatmapFilteredRange(ctx, startTime, endTime, attackTypes)
}

// GetUniqueHostnames retrieves unique hostnames for a log type
func (s *Service) GetUniqueHostnames(ctx context.Context, logType string) ([]string, error) {
	return s.repo.GetUniqueHostnames(ctx, logType)
}

// GetSyslogStatus retrieves the current syslog ingestion status
func (s *Service) GetSyslogStatus(ctx context.Context) (*entity.SyslogStatus, error) {
	return s.repo.GetSyslogStatus(ctx)
}

// GetCriticalAlerts retrieves recent critical and high severity alerts
func (s *Service) GetCriticalAlerts(ctx context.Context, limit int, period string) ([]entity.CriticalAlert, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if period == "" {
		period = "24h"
	}
	return s.repo.GetCriticalAlerts(ctx, limit, period)
}

// GetZoneTraffic retrieves traffic flow between network zones
func (s *Service) GetZoneTraffic(ctx context.Context, period string, limit int) (*entity.ZoneTrafficStats, error) {
	if period == "" {
		period = "24h"
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	return s.repo.GetZoneTraffic(ctx, period, limit)
}
