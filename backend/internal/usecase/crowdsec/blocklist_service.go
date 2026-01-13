package crowdsec

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/crowdsec"
	"github.com/kr1s57/vigilancex/internal/adapter/external/sophos"
)

// BlocklistService manages CrowdSec blocklist synchronization
type BlocklistService struct {
	client       *crowdsec.BlocklistClient
	sophosClient *sophos.Client
	repo         BlocklistRepository
	mu           sync.RWMutex
	lastSync     time.Time
	syncRunning  bool
	config       *BlocklistConfig
}

// BlocklistConfig holds the service configuration
type BlocklistConfig struct {
	Enabled           bool      `json:"enabled"`
	APIKey            string    `json:"api_key"`
	SyncIntervalHours int       `json:"sync_interval_hours"`
	XGSGroupName      string    `json:"xgs_group_name"`
	EnabledLists      []string  `json:"enabled_lists"` // List of blocklist IDs to sync
	LastSync          time.Time `json:"last_sync"`
	TotalIPs          int       `json:"total_ips"`
}

// BlocklistRepository interface for persistence
type BlocklistRepository interface {
	GetConfig(ctx context.Context) (*BlocklistConfig, error)
	SaveConfig(ctx context.Context, config *BlocklistConfig) error
	GetSyncedIPs(ctx context.Context) ([]string, error)
	SaveSyncedIPs(ctx context.Context, ips []string, blocklistID string) error
	GetSyncHistory(ctx context.Context, limit int) ([]SyncHistoryEntry, error)
	SaveSyncHistory(ctx context.Context, entry *SyncHistoryEntry) error
}

// SyncHistoryEntry represents a sync operation record
type SyncHistoryEntry struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	BlocklistID   string    `json:"blocklist_id"`
	BlocklistName string    `json:"blocklist_name"`
	IPsDownloaded int       `json:"ips_downloaded"`
	IPsAdded      int       `json:"ips_added"`
	IPsRemoved    int       `json:"ips_removed"`
	DurationMs    int64     `json:"duration_ms"`
	Success       bool      `json:"success"`
	Error         string    `json:"error,omitempty"`
}

// NewBlocklistService creates a new blocklist service
func NewBlocklistService(client *crowdsec.BlocklistClient, sophosClient *sophos.Client, repo BlocklistRepository) *BlocklistService {
	return &BlocklistService{
		client:       client,
		sophosClient: sophosClient,
		repo:         repo,
		config: &BlocklistConfig{
			Enabled:           false,
			SyncIntervalHours: 6,
			XGSGroupName:      "grp_VGX-CrowdSec",
			EnabledLists:      []string{},
		},
	}
}

// SetSophosClient updates the Sophos client (for hot-reload)
func (s *BlocklistService) SetSophosClient(client *sophos.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sophosClient = client
}

// GetConfig returns the current configuration
func (s *BlocklistService) GetConfig(ctx context.Context) (*BlocklistConfig, error) {
	if s.repo != nil {
		config, err := s.repo.GetConfig(ctx)
		if err == nil && config != nil {
			s.mu.Lock()
			s.config = config
			s.mu.Unlock()
			return config, nil
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, nil
}

// UpdateConfig updates the configuration
func (s *BlocklistService) UpdateConfig(ctx context.Context, config *BlocklistConfig) error {
	s.mu.Lock()
	s.config = config
	s.mu.Unlock()

	// Update client API key if changed
	if config.APIKey != "" {
		s.client.SetAPIKey(config.APIKey)
	}

	if s.repo != nil {
		return s.repo.SaveConfig(ctx, config)
	}
	return nil
}

// TestConnection tests the CrowdSec API connection
func (s *BlocklistService) TestConnection(ctx context.Context) error {
	return s.client.TestConnection(ctx)
}

// ListAvailableBlocklists returns all blocklists available to the account
func (s *BlocklistService) ListAvailableBlocklists(ctx context.Context) ([]crowdsec.BlocklistInfo, error) {
	return s.client.ListBlocklists(ctx)
}

// ListSubscribedBlocklists returns blocklists the user is subscribed to
func (s *BlocklistService) ListSubscribedBlocklists(ctx context.Context) ([]crowdsec.BlocklistInfo, error) {
	return s.client.GetSubscribedBlocklists(ctx)
}

// SyncBlocklist downloads a blocklist and syncs to Sophos XGS
func (s *BlocklistService) SyncBlocklist(ctx context.Context, blocklistID, blocklistName string) (*crowdsec.BlocklistSyncResult, error) {
	s.mu.Lock()
	if s.syncRunning {
		s.mu.Unlock()
		return nil, fmt.Errorf("sync already in progress")
	}
	s.syncRunning = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.syncRunning = false
		s.mu.Unlock()
	}()

	startTime := time.Now()
	result := &crowdsec.BlocklistSyncResult{
		BlocklistID:   blocklistID,
		BlocklistName: blocklistName,
		SyncedAt:      startTime,
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Starting sync",
		"blocklist_id", blocklistID,
		"blocklist_name", blocklistName)

	// Download blocklist from CrowdSec
	ips, err := s.client.DownloadBlocklist(ctx, blocklistID)
	if err != nil {
		result.Error = err.Error()
		s.saveSyncHistory(ctx, result, false)
		return result, fmt.Errorf("download failed: %w", err)
	}

	result.IPsDownloaded = len(ips)

	// Get current IPs in XGS group for comparison
	s.mu.RLock()
	sophosClient := s.sophosClient
	groupName := s.config.XGSGroupName
	s.mu.RUnlock()

	if sophosClient == nil {
		result.Error = "Sophos XGS client not configured"
		s.saveSyncHistory(ctx, result, false)
		return result, fmt.Errorf("sophos client not configured")
	}

	// Ensure the CrowdSec group exists in XGS
	if err := s.ensureXGSGroup(ctx, groupName); err != nil {
		result.Error = fmt.Sprintf("failed to ensure XGS group: %v", err)
		s.saveSyncHistory(ctx, result, false)
		return result, err
	}

	// Sync IPs to XGS (batch operation)
	synced, added, removed, err := s.syncIPsToXGS(ctx, ips, groupName)
	if err != nil {
		result.Error = err.Error()
		s.saveSyncHistory(ctx, result, false)
		return result, err
	}

	result.IPsSynced = synced
	result.IPsNew = added
	result.IPsRemoved = removed
	result.Duration = float64(time.Since(startTime).Milliseconds())

	// Update last sync time
	s.mu.Lock()
	s.lastSync = time.Now()
	if s.config != nil {
		s.config.LastSync = s.lastSync
		s.config.TotalIPs = synced
	}
	s.mu.Unlock()

	// Save sync history
	s.saveSyncHistory(ctx, result, true)

	// Persist synced IPs for tracking
	if s.repo != nil {
		s.repo.SaveSyncedIPs(ctx, ips, blocklistID)
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Sync completed",
		"blocklist_id", blocklistID,
		"downloaded", result.IPsDownloaded,
		"synced", result.IPsSynced,
		"added", result.IPsNew,
		"removed", result.IPsRemoved,
		"duration_ms", result.Duration)

	return result, nil
}

// SyncAllEnabled syncs all enabled blocklists
func (s *BlocklistService) SyncAllEnabled(ctx context.Context) ([]*crowdsec.BlocklistSyncResult, error) {
	s.mu.RLock()
	enabledLists := s.config.EnabledLists
	s.mu.RUnlock()

	if len(enabledLists) == 0 {
		return nil, fmt.Errorf("no blocklists enabled for sync")
	}

	// Get blocklist info for names
	available, err := s.client.ListBlocklists(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list blocklists: %w", err)
	}

	// Map ID to name
	nameMap := make(map[string]string)
	for _, bl := range available {
		nameMap[bl.ID] = bl.Name
	}

	var results []*crowdsec.BlocklistSyncResult
	for _, listID := range enabledLists {
		name := nameMap[listID]
		if name == "" {
			name = listID
		}

		result, err := s.SyncBlocklist(ctx, listID, name)
		if err != nil {
			slog.Error("[CROWDSEC_BLOCKLIST] Failed to sync blocklist",
				"blocklist_id", listID,
				"error", err)
		}
		results = append(results, result)
	}

	return results, nil
}

// ensureXGSGroup creates the CrowdSec group in XGS if it doesn't exist
func (s *BlocklistService) ensureXGSGroup(ctx context.Context, groupName string) error {
	s.mu.RLock()
	sophosClient := s.sophosClient
	s.mu.RUnlock()

	if sophosClient == nil {
		return fmt.Errorf("sophos client not configured")
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Ensuring XGS group exists", "group", groupName)

	err := sophosClient.EnsureGroupExists(groupName, "CrowdSec Premium Blocklist - Managed by VIGILANCE X")
	if err != nil {
		slog.Error("[CROWDSEC_BLOCKLIST] Failed to create XGS group", "group", groupName, "error", err)
		return err
	}

	slog.Info("[CROWDSEC_BLOCKLIST] XGS group ensured", "group", groupName)
	return nil
}

// syncIPsToXGS syncs the IP list to Sophos XGS
func (s *BlocklistService) syncIPsToXGS(ctx context.Context, newIPs []string, groupName string) (synced, added, removed int, err error) {
	s.mu.RLock()
	sophosClient := s.sophosClient
	s.mu.RUnlock()

	if sophosClient == nil {
		return 0, 0, 0, fmt.Errorf("sophos client not configured")
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Syncing IPs to XGS",
		"group", groupName,
		"ip_count", len(newIPs))

	// Use the Sophos client to sync IPs with "crowdsec" host prefix
	added, removed, err = sophosClient.SyncGroupIPs(groupName, "crowdsec", newIPs)
	if err != nil {
		slog.Error("[CROWDSEC_BLOCKLIST] XGS sync failed", "error", err)
		return 0, 0, 0, err
	}

	synced = len(newIPs)

	slog.Info("[CROWDSEC_BLOCKLIST] XGS sync completed",
		"group", groupName,
		"synced", synced,
		"added", added,
		"removed", removed)

	return synced, added, removed, nil
}

// saveSyncHistory saves sync operation to history
func (s *BlocklistService) saveSyncHistory(ctx context.Context, result *crowdsec.BlocklistSyncResult, success bool) {
	if s.repo == nil {
		return
	}

	entry := &SyncHistoryEntry{
		Timestamp:     result.SyncedAt,
		BlocklistID:   result.BlocklistID,
		BlocklistName: result.BlocklistName,
		IPsDownloaded: result.IPsDownloaded,
		IPsAdded:      result.IPsNew,
		IPsRemoved:    result.IPsRemoved,
		DurationMs:    int64(result.Duration),
		Success:       success,
		Error:         result.Error,
	}

	if err := s.repo.SaveSyncHistory(ctx, entry); err != nil {
		slog.Error("[CROWDSEC_BLOCKLIST] Failed to save sync history", "error", err)
	}
}

// GetStatus returns the current service status
func (s *BlocklistService) GetStatus(ctx context.Context) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := map[string]interface{}{
		"configured":   s.client.IsConfigured(),
		"enabled":      s.config.Enabled,
		"sync_running": s.syncRunning,
		"last_sync":    s.lastSync,
		"total_ips":    s.config.TotalIPs,
		"group_name":   s.config.XGSGroupName,
	}

	if len(s.config.EnabledLists) > 0 {
		status["enabled_lists"] = s.config.EnabledLists
	}

	return status
}

// GetSyncHistory returns recent sync history
func (s *BlocklistService) GetSyncHistory(ctx context.Context, limit int) ([]SyncHistoryEntry, error) {
	if s.repo == nil {
		return nil, nil
	}
	return s.repo.GetSyncHistory(ctx, limit)
}

// IsRunning returns true if a sync is in progress
func (s *BlocklistService) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.syncRunning
}
