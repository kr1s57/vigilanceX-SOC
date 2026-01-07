package blocklists

import (
	"context"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/blocklist"
)

// Service handles blocklist business logic
type Service struct {
	ingester *blocklist.FeedIngester
}

// NewService creates a new blocklist service
func NewService(ingester *blocklist.FeedIngester) *Service {
	return &Service{
		ingester: ingester,
	}
}

// Start starts the automatic feed synchronization
func (s *Service) Start(ctx context.Context) {
	s.ingester.Start(ctx)
}

// Stop stops the automatic feed synchronization
func (s *Service) Stop() {
	s.ingester.Stop()
}

// FeedStatusResponse represents feed status for API response
type FeedStatusResponse struct {
	Source       string    `json:"source"`
	DisplayName  string    `json:"display_name"`
	URL          string    `json:"url"`
	LastSync     time.Time `json:"last_sync"`
	LastSuccess  time.Time `json:"last_success"`
	IPCount      int       `json:"ip_count"`
	ActiveCount  int       `json:"active_count"`
	AddedCount   int       `json:"added_count"`
	RemovedCount int       `json:"removed_count"`
	Status       string    `json:"status"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// GetFeedStatuses returns the status of all configured feeds
func (s *Service) GetFeedStatuses(ctx context.Context) ([]FeedStatusResponse, error) {
	statuses, err := s.ingester.GetFeedStatuses(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]FeedStatusResponse, 0, len(statuses))
	for _, status := range statuses {
		result = append(result, FeedStatusResponse{
			Source:       status.Source,
			DisplayName:  status.DisplayName,
			URL:          status.URL,
			LastSync:     status.LastSync,
			LastSuccess:  status.LastSuccess,
			IPCount:      status.IPCount,
			ActiveCount:  status.ActiveCount,
			AddedCount:   status.AddedCount,
			RemovedCount: status.RemovedCount,
			Status:       status.SyncStatus,
			ErrorMessage: status.ErrorMessage,
		})
	}

	return result, nil
}

// SyncAllFeeds triggers a manual sync of all feeds
func (s *Service) SyncAllFeeds(ctx context.Context) ([]SyncResultResponse, error) {
	results := s.ingester.SyncAll(ctx)

	response := make([]SyncResultResponse, 0, len(results))
	for _, r := range results {
		var errMsg string
		if r.Error != nil {
			errMsg = r.Error.Error()
		}
		response = append(response, SyncResultResponse{
			Source:       r.Source,
			Success:      r.Success,
			IPCount:      r.IPCount,
			AddedCount:   r.AddedCount,
			RemovedCount: r.RemovedCount,
			Duration:     r.Duration.String(),
			Error:        errMsg,
		})
	}

	return response, nil
}

// SyncResultResponse represents sync result for API response
type SyncResultResponse struct {
	Source       string `json:"source"`
	Success      bool   `json:"success"`
	IPCount      int    `json:"ip_count"`
	AddedCount   int    `json:"added_count"`
	RemovedCount int    `json:"removed_count"`
	Duration     string `json:"duration"`
	Error        string `json:"error,omitempty"`
}

// SyncFeed triggers a manual sync of a specific feed
func (s *Service) SyncFeed(ctx context.Context, feedName string) (*SyncResultResponse, error) {
	result, err := s.ingester.SyncFeed(ctx, feedName)
	if err != nil {
		return nil, err
	}

	var errMsg string
	if result.Error != nil {
		errMsg = result.Error.Error()
	}

	return &SyncResultResponse{
		Source:       result.Source,
		Success:      result.Success,
		IPCount:      result.IPCount,
		AddedCount:   result.AddedCount,
		RemovedCount: result.RemovedCount,
		Duration:     result.Duration.String(),
		Error:        errMsg,
	}, nil
}

// IPBlocklistInfo represents blocklist info for an IP
type IPBlocklistInfo struct {
	IP            string     `json:"ip"`
	IsBlocked     bool       `json:"is_blocked"`
	SourceCount   int        `json:"source_count"`
	Sources       []string   `json:"sources"`
	Categories    []string   `json:"categories"`
	MaxConfidence int        `json:"max_confidence"`
	FirstSeen     *time.Time `json:"first_seen,omitempty"`
	LastSeen      *time.Time `json:"last_seen,omitempty"`
}

// CheckIP checks if an IP is in any blocklist
func (s *Service) CheckIP(ctx context.Context, ip string) (*IPBlocklistInfo, error) {
	blocked, summary, err := s.ingester.IsIPBlocked(ctx, ip)
	if err != nil {
		return nil, err
	}

	if !blocked || summary == nil {
		return &IPBlocklistInfo{
			IP:        ip,
			IsBlocked: false,
		}, nil
	}

	return &IPBlocklistInfo{
		IP:            ip,
		IsBlocked:     true,
		SourceCount:   summary.SourceCount,
		Sources:       summary.Sources,
		Categories:    summary.Categories,
		MaxConfidence: summary.MaxConfidence,
		FirstSeen:     &summary.FirstSeen,
		LastSeen:      &summary.LastSeen,
	}, nil
}

// GetHighRiskIPs returns IPs that appear in multiple blocklists
func (s *Service) GetHighRiskIPs(ctx context.Context, minLists int) ([]IPBlocklistInfo, error) {
	summaries, err := s.ingester.GetHighRiskIPs(ctx, minLists)
	if err != nil {
		return nil, err
	}

	result := make([]IPBlocklistInfo, 0, len(summaries))
	for _, s := range summaries {
		firstSeen := s.FirstSeen
		lastSeen := s.LastSeen
		result = append(result, IPBlocklistInfo{
			IP:            s.IP,
			IsBlocked:     s.IsActive,
			SourceCount:   s.SourceCount,
			Sources:       s.Sources,
			Categories:    s.Categories,
			MaxConfidence: s.MaxConfidence,
			FirstSeen:     &firstSeen,
			LastSeen:      &lastSeen,
		})
	}

	return result, nil
}

// BlocklistStats represents overall blocklist statistics
type BlocklistStats struct {
	TotalBlockedIPs int64                `json:"total_blocked_ips"`
	FeedCount       int                  `json:"feed_count"`
	FeedStats       []FeedStatusResponse `json:"feed_stats"`
}

// GetStats returns overall blocklist statistics
func (s *Service) GetStats(ctx context.Context) (*BlocklistStats, error) {
	totalIPs, err := s.ingester.GetTotalBlockedIPs(ctx)
	if err != nil {
		return nil, err
	}

	statuses, err := s.GetFeedStatuses(ctx)
	if err != nil {
		return nil, err
	}

	return &BlocklistStats{
		TotalBlockedIPs: totalIPs,
		FeedCount:       len(statuses),
		FeedStats:       statuses,
	}, nil
}

// GetConfiguredFeeds returns list of configured feed names
func (s *Service) GetConfiguredFeeds() []string {
	feeds := blocklist.GetEnabledFeeds()
	names := make([]string, 0, len(feeds))
	for _, f := range feeds {
		names = append(names, f.Name)
	}
	return names
}
