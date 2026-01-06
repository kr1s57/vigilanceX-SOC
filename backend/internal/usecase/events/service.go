package events

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kr1s57/vigilancex/internal/entity"
)

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
	GetUniqueHostnames(ctx context.Context, logType string) ([]string, error)
}

// Service handles event business logic
type Service struct {
	repo   Repository
	logger *slog.Logger
}

// NewService creates a new events service
func NewService(repo Repository, logger *slog.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
	}
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

// GetTopAttackers retrieves top attacking IPs
func (s *Service) GetTopAttackers(ctx context.Context, period string, limit int) ([]entity.TopAttacker, error) {
	if period == "" {
		period = "24h"
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	return s.repo.GetTopAttackers(ctx, period, limit)
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

// GetUniqueHostnames retrieves unique hostnames for a log type
func (s *Service) GetUniqueHostnames(ctx context.Context, logType string) ([]string, error) {
	return s.repo.GetUniqueHostnames(ctx, logType)
}
