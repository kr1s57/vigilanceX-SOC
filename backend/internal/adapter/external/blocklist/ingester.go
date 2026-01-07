package blocklist

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// FeedIngester manages blocklist feed synchronization
type FeedIngester struct {
	repo       Repository
	httpClient *http.Client
	parser     *Parser
	feeds      []FeedSource
	logger     *slog.Logger
	mu         sync.RWMutex
	running    bool
	stopCh     chan struct{}
}

// Repository interface for blocklist persistence
type Repository interface {
	// IP operations
	UpsertBlocklistIP(ctx context.Context, ip BlocklistIP) error
	BulkUpsertBlocklistIPs(ctx context.Context, ips []BlocklistIP) error
	DeactivateIPsNotInList(ctx context.Context, source string, activeIPs []string) (int64, error)
	GetBlocklistIPsBySource(ctx context.Context, source string) ([]BlocklistIP, error)
	GetIPBlocklistSummary(ctx context.Context, ip string) (*BlocklistSummary, error)
	GetActiveBlocklistCount(ctx context.Context) (int64, error)

	// Feed status operations
	UpdateFeedStatus(ctx context.Context, status FeedStatus) error
	GetFeedStatuses(ctx context.Context) ([]FeedStatus, error)

	// Summary operations
	RefreshIPSummaries(ctx context.Context) error
	GetIPsInMultipleLists(ctx context.Context, minLists int) ([]BlocklistSummary, error)
}

// BlocklistIP represents an IP in a blocklist
type BlocklistIP struct {
	IP             string    `json:"ip"`
	Source         string    `json:"source"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	IsActive       bool      `json:"is_active"`
	ThreatCategory string    `json:"threat_category"`
	Confidence     int       `json:"confidence"`
}

// BlocklistSummary represents aggregated blocklist data for an IP
type BlocklistSummary struct {
	IP            string    `json:"ip"`
	SourceCount   int       `json:"source_count"`
	Sources       []string  `json:"sources"`
	Categories    []string  `json:"categories"`
	MaxConfidence int       `json:"max_confidence"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	IsActive      bool      `json:"is_active"`
}

// FeedStatus represents the sync status of a feed
type FeedStatus struct {
	Source       string    `json:"source"`
	DisplayName  string    `json:"display_name"`
	URL          string    `json:"url"`
	LastSync     time.Time `json:"last_sync"`
	LastSuccess  time.Time `json:"last_success"`
	IPCount      int       `json:"ip_count"`
	ActiveCount  int       `json:"active_count"`
	AddedCount   int       `json:"added_count"`
	RemovedCount int       `json:"removed_count"`
	SyncStatus   string    `json:"sync_status"` // success, error, pending, syncing
	ErrorMessage string    `json:"error_message,omitempty"`
}

// SyncResult represents the result of a feed sync
type SyncResult struct {
	Source       string
	Success      bool
	IPCount      int
	AddedCount   int
	RemovedCount int
	Duration     time.Duration
	Error        error
}

// IngesterConfig holds configuration for the feed ingester
type IngesterConfig struct {
	HTTPTimeout     time.Duration
	MaxConcurrent   int
	DefaultInterval time.Duration
}

// NewFeedIngester creates a new feed ingester
func NewFeedIngester(repo Repository, cfg IngesterConfig) *FeedIngester {
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 3
	}
	if cfg.DefaultInterval == 0 {
		cfg.DefaultInterval = 1 * time.Hour
	}

	return &FeedIngester{
		repo: repo,
		httpClient: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
		parser: NewParser(),
		feeds:  GetEnabledFeeds(),
		logger: slog.Default(),
		stopCh: make(chan struct{}),
	}
}

// Start begins the feed ingestion loop
func (fi *FeedIngester) Start(ctx context.Context) {
	fi.mu.Lock()
	if fi.running {
		fi.mu.Unlock()
		return
	}
	fi.running = true
	fi.mu.Unlock()

	fi.logger.Info("Feed Ingester started", "feeds", len(fi.feeds))

	// Initial sync
	go fi.syncAllFeeds(ctx)

	// Schedule periodic syncs for each feed
	for _, feed := range fi.feeds {
		go fi.scheduleFeed(ctx, feed)
	}
}

// Stop stops the feed ingestion loop
func (fi *FeedIngester) Stop() {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	if !fi.running {
		return
	}

	close(fi.stopCh)
	fi.running = false
	fi.logger.Info("Feed Ingester stopped")
}

// scheduleFeed schedules periodic sync for a specific feed
func (fi *FeedIngester) scheduleFeed(ctx context.Context, feed FeedSource) {
	ticker := time.NewTicker(feed.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-fi.stopCh:
			return
		case <-ticker.C:
			result := fi.syncFeed(ctx, feed)
			if result.Error != nil {
				fi.logger.Error("Feed sync failed",
					"feed", feed.Name,
					"error", result.Error,
				)
			} else {
				fi.logger.Info("Feed synced",
					"feed", feed.Name,
					"ips", result.IPCount,
					"added", result.AddedCount,
					"removed", result.RemovedCount,
					"duration", result.Duration,
				)
			}
		}
	}
}

// syncAllFeeds syncs all enabled feeds
func (fi *FeedIngester) syncAllFeeds(ctx context.Context) []SyncResult {
	var results []SyncResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Semaphore for concurrency control
	sem := make(chan struct{}, 3)

	for _, feed := range fi.feeds {
		wg.Add(1)
		go func(f FeedSource) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			result := fi.syncFeed(ctx, f)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(feed)
	}

	wg.Wait()

	// Refresh IP summaries after all syncs
	if err := fi.repo.RefreshIPSummaries(ctx); err != nil {
		fi.logger.Error("Failed to refresh IP summaries", "error", err)
	}

	return results
}

// SyncAll triggers a manual sync of all feeds
func (fi *FeedIngester) SyncAll(ctx context.Context) []SyncResult {
	return fi.syncAllFeeds(ctx)
}

// SyncFeed triggers a manual sync of a specific feed
func (fi *FeedIngester) SyncFeed(ctx context.Context, feedName string) (*SyncResult, error) {
	feed := GetFeedByName(feedName)
	if feed == nil {
		return nil, fmt.Errorf("feed not found: %s", feedName)
	}

	result := fi.syncFeed(ctx, *feed)
	return &result, result.Error
}

// syncFeed performs the actual sync for a single feed
func (fi *FeedIngester) syncFeed(ctx context.Context, feed FeedSource) SyncResult {
	start := time.Now()
	result := SyncResult{
		Source: feed.Name,
	}

	// Update status to syncing
	fi.repo.UpdateFeedStatus(ctx, FeedStatus{
		Source:      feed.Name,
		DisplayName: feed.DisplayName,
		URL:         feed.URL,
		LastSync:    time.Now(),
		SyncStatus:  "syncing",
	})

	// Download feed
	content, err := fi.downloadFeed(ctx, feed.URL)
	if err != nil {
		result.Error = fmt.Errorf("download failed: %w", err)
		fi.updateFeedError(ctx, feed, result.Error.Error())
		return result
	}

	// Parse IPs
	parsedIPs := fi.parser.Parse(content, feed.Format)
	if len(parsedIPs) == 0 {
		result.Error = fmt.Errorf("no IPs parsed from feed")
		fi.updateFeedError(ctx, feed, result.Error.Error())
		return result
	}

	result.IPCount = len(parsedIPs)

	// Prepare IPs for bulk insert
	now := time.Now()
	activeIPs := make([]string, 0, len(parsedIPs))
	blocklistIPs := make([]BlocklistIP, 0, len(parsedIPs))

	for _, parsed := range parsedIPs {
		activeIPs = append(activeIPs, parsed.IP)
		blocklistIPs = append(blocklistIPs, BlocklistIP{
			IP:             parsed.IP,
			Source:         feed.Name,
			FirstSeen:      now,
			LastSeen:       now,
			IsActive:       true,
			ThreatCategory: feed.Category,
			Confidence:     feed.Confidence,
		})
	}

	// Bulk upsert IPs (this handles both new and existing IPs)
	if err := fi.repo.BulkUpsertBlocklistIPs(ctx, blocklistIPs); err != nil {
		result.Error = fmt.Errorf("bulk upsert failed: %w", err)
		fi.updateFeedError(ctx, feed, result.Error.Error())
		return result
	}

	// Deactivate IPs that are no longer in the list
	// This is the key for dynamic sync - IPs removed from source are deactivated
	removedCount, err := fi.repo.DeactivateIPsNotInList(ctx, feed.Name, activeIPs)
	if err != nil {
		fi.logger.Warn("Failed to deactivate removed IPs",
			"feed", feed.Name,
			"error", err,
		)
	}

	result.RemovedCount = int(removedCount)
	result.AddedCount = len(parsedIPs) // Approximate, includes updates
	result.Success = true
	result.Duration = time.Since(start)

	// Update feed status
	fi.repo.UpdateFeedStatus(ctx, FeedStatus{
		Source:       feed.Name,
		DisplayName:  feed.DisplayName,
		URL:          feed.URL,
		LastSync:     now,
		LastSuccess:  now,
		IPCount:      result.IPCount,
		ActiveCount:  result.IPCount,
		AddedCount:   result.AddedCount,
		RemovedCount: result.RemovedCount,
		SyncStatus:   "success",
	})

	return result
}

// downloadFeed downloads feed content from URL
func (fi *FeedIngester) downloadFeed(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "VIGILANCE-X/1.6 BlocklistFetcher")
	req.Header.Set("Accept", "text/plain, */*")

	resp, err := fi.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	// Limit read to 50MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	return string(body), nil
}

// updateFeedError updates feed status with error
func (fi *FeedIngester) updateFeedError(ctx context.Context, feed FeedSource, errorMsg string) {
	fi.repo.UpdateFeedStatus(ctx, FeedStatus{
		Source:       feed.Name,
		DisplayName:  feed.DisplayName,
		URL:          feed.URL,
		LastSync:     time.Now(),
		SyncStatus:   "error",
		ErrorMessage: errorMsg,
	})
}

// GetFeedStatuses returns the status of all feeds
func (fi *FeedIngester) GetFeedStatuses(ctx context.Context) ([]FeedStatus, error) {
	return fi.repo.GetFeedStatuses(ctx)
}

// GetIPBlocklistInfo returns blocklist information for a specific IP
func (fi *FeedIngester) GetIPBlocklistInfo(ctx context.Context, ip string) (*BlocklistSummary, error) {
	return fi.repo.GetIPBlocklistSummary(ctx, ip)
}

// GetHighRiskIPs returns IPs that appear in multiple blocklists
func (fi *FeedIngester) GetHighRiskIPs(ctx context.Context, minLists int) ([]BlocklistSummary, error) {
	if minLists < 2 {
		minLists = 2
	}
	return fi.repo.GetIPsInMultipleLists(ctx, minLists)
}

// GetTotalBlockedIPs returns the total count of active blocked IPs
func (fi *FeedIngester) GetTotalBlockedIPs(ctx context.Context) (int64, error) {
	return fi.repo.GetActiveBlocklistCount(ctx)
}

// IsIPBlocked checks if an IP is in any active blocklist
func (fi *FeedIngester) IsIPBlocked(ctx context.Context, ip string) (bool, *BlocklistSummary, error) {
	summary, err := fi.repo.GetIPBlocklistSummary(ctx, ip)
	if err != nil {
		return false, nil, err
	}

	if summary == nil || !summary.IsActive {
		return false, nil, nil
	}

	return true, summary, nil
}
