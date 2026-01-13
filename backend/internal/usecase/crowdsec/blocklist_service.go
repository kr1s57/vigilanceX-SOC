package crowdsec

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/crowdsec"
)

const (
	// BlocklistDataDir is the directory where blocklist files are stored
	BlocklistDataDir = "/app/data/crowdsec_blocklists"
	// DefaultSyncInterval is the default sync interval (2 hours)
	DefaultSyncInterval = 2 * time.Hour
)

// BlocklistService manages CrowdSec blocklist download, storage and XGS sync
type BlocklistService struct {
	client         *crowdsec.BlocklistClient
	repo           BlocklistRepository
	geoIP          GeoIPLookup
	xgs            XGSClient
	mu             sync.RWMutex
	config         *BlocklistConfig
	worker         *syncWorker
	stopChan       chan struct{}
	syncInProgress bool
	syncMu         sync.Mutex
	xgsGroupReady  bool // Track if XGS group has been verified/created
}

// BlocklistConfig holds the service configuration
type BlocklistConfig struct {
	Enabled             bool      `json:"enabled"`
	APIKey              string    `json:"api_key"`
	SyncIntervalMinutes int       `json:"sync_interval_minutes"`
	LastSync            time.Time `json:"last_sync"`
	TotalIPs            int       `json:"total_ips"`
	TotalBlocklists     int       `json:"total_blocklists"`
}

// BlocklistRepository interface for persistence
type BlocklistRepository interface {
	GetConfig(ctx context.Context) (*BlocklistConfig, error)
	SaveConfig(ctx context.Context, config *BlocklistConfig) error
	GetIPsForBlocklist(ctx context.Context, blocklistID string) ([]string, error)
	GetAllIPs(ctx context.Context) ([]BlocklistIP, error)
	AddIPs(ctx context.Context, ips []BlocklistIP) error
	RemoveIPs(ctx context.Context, blocklistID string, ips []string) error
	ClearBlocklist(ctx context.Context, blocklistID string) error
	ClearAllIPs(ctx context.Context) error
	GetSyncHistory(ctx context.Context, limit int) ([]SyncHistoryEntry, error)
	SaveSyncHistory(ctx context.Context, entry *SyncHistoryEntry) error
	GetStats(ctx context.Context) (totalIPs int, totalBlocklists int, err error)
	GetExistingBlocklistIDs(ctx context.Context) ([]struct{ ID, Label string }, error)
}

// GeoIPLookup interface for country enrichment
type GeoIPLookup interface {
	LookupCountry(ctx context.Context, ip string) (string, error)
}

// XGSClient interface for Sophos XGS integration
type XGSClient interface {
	EnsureGroupExists(groupName, description string) error
	GetGroupIPs(groupName string) ([]string, error)
	SyncGroupIPs(groupName, hostPrefix string, targetIPs []string) (int, int, error)
}

// XGS Group configuration
const (
	XGSGroupName        = "grp_VGX-CrowdSBlockL"
	XGSGroupDescription = "CrowdSec Blocklist IPs - Managed by VIGILANCE X Neural-Sync"
	XGSHostPrefix       = "CS" // Prefix for IP host names: CS_1.2.3.4
)

// BlocklistIP represents an IP entry in the database
type BlocklistIP struct {
	IP             string    `json:"ip"`
	BlocklistID    string    `json:"blocklist_id"`
	BlocklistLabel string    `json:"blocklist_label"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	CountryCode    string    `json:"country_code"`
}

// SyncHistoryEntry represents a sync operation record
type SyncHistoryEntry struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	BlocklistID    string    `json:"blocklist_id"`
	BlocklistLabel string    `json:"blocklist_label"`
	IPsInFile      int       `json:"ips_in_file"`
	IPsAdded       int       `json:"ips_added"`
	IPsRemoved     int       `json:"ips_removed"`
	DurationMs     int64     `json:"duration_ms"`
	Success        bool      `json:"success"`
	Error          string    `json:"error,omitempty"`
}

// SyncResult represents the result of syncing a blocklist
type SyncResult struct {
	BlocklistID    string    `json:"blocklist_id"`
	BlocklistLabel string    `json:"blocklist_label"`
	IPsInFile      int       `json:"ips_in_file"`
	IPsAdded       int       `json:"ips_added"`
	IPsRemoved     int       `json:"ips_removed"`
	DurationMs     int64     `json:"duration_ms"`
	SyncedAt       time.Time `json:"synced_at"`
	Error          string    `json:"error,omitempty"`
}

// syncWorker handles periodic sync
type syncWorker struct {
	service  *BlocklistService
	interval time.Duration
	stopChan chan struct{}
	running  bool
	mu       sync.Mutex
}

// NewBlocklistService creates a new blocklist service
func NewBlocklistService(client *crowdsec.BlocklistClient, repo BlocklistRepository) *BlocklistService {
	s := &BlocklistService{
		client:   client,
		repo:     repo,
		stopChan: make(chan struct{}),
		config: &BlocklistConfig{
			Enabled:             false,
			SyncIntervalMinutes: 120, // 2 hours
		},
	}

	// Ensure data directory exists
	if err := os.MkdirAll(BlocklistDataDir, 0755); err != nil {
		slog.Error("[CROWDSEC_BL] Failed to create data directory", "error", err)
	}

	return s
}

// SetGeoIPClient sets the GeoIP client for country enrichment
func (s *BlocklistService) SetGeoIPClient(geoIP GeoIPLookup) {
	s.geoIP = geoIP
}

// SetXGSClient sets the Sophos XGS client for firewall sync
func (s *BlocklistService) SetXGSClient(xgs XGSClient) {
	s.xgs = xgs
	slog.Info("[CROWDSEC_BL] XGS client configured for Neural-Sync")
}

// EnsureXGSGroup ensures the XGS group exists, creates it if not
func (s *BlocklistService) EnsureXGSGroup() error {
	if s.xgs == nil {
		return fmt.Errorf("XGS client not configured")
	}

	slog.Info("[CROWDSEC_BL] Checking XGS group", "group", XGSGroupName)

	// Try to create the group - EnsureGroupExists handles "already exists"
	err := s.xgs.EnsureGroupExists(XGSGroupName, XGSGroupDescription)
	if err != nil {
		// Check if error is "already exists" which is OK
		if err.Error() != "" && (err.Error() == "Configuration already present" ||
			err.Error() == "already exists" ||
			contains(err.Error(), "already") ||
			contains(err.Error(), "exists")) {
			slog.Info("[CROWDSEC_BL] XGS group already exists", "group", XGSGroupName)
			s.xgsGroupReady = true
			return nil
		}
		return fmt.Errorf("failed to ensure XGS group: %w", err)
	}

	slog.Info("[CROWDSEC_BL] XGS group created successfully", "group", XGSGroupName)
	s.xgsGroupReady = true
	return nil
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsCI(s, substr))
}

func containsCI(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFoldASCII(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFoldASCII(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		sr := s[i]
		tr := t[i]
		if sr >= 'A' && sr <= 'Z' {
			sr = sr + 32
		}
		if tr >= 'A' && tr <= 'Z' {
			tr = tr + 32
		}
		if sr != tr {
			return false
		}
	}
	return true
}

// SyncToXGS synchronizes all blocklist IPs to the XGS group
func (s *BlocklistService) SyncToXGS(ctx context.Context) (added, removed int, err error) {
	if s.xgs == nil {
		return 0, 0, fmt.Errorf("XGS client not configured")
	}

	// Ensure group exists first
	if !s.xgsGroupReady {
		if err := s.EnsureXGSGroup(); err != nil {
			return 0, 0, err
		}
	}

	// Get all IPs from database
	allIPs, err := s.repo.GetAllIPs(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get IPs from DB: %w", err)
	}

	// Extract just the IP addresses
	ipList := make([]string, 0, len(allIPs))
	for _, ip := range allIPs {
		ipList = append(ipList, ip.IP)
	}

	slog.Info("[CROWDSEC_BL] Syncing to XGS",
		"group", XGSGroupName,
		"ip_count", len(ipList))

	// Sync to XGS
	added, removed, err = s.xgs.SyncGroupIPs(XGSGroupName, XGSHostPrefix, ipList)
	if err != nil {
		return 0, 0, fmt.Errorf("XGS sync failed: %w", err)
	}

	slog.Info("[CROWDSEC_BL] XGS sync completed",
		"group", XGSGroupName,
		"added", added,
		"removed", removed)

	return added, removed, nil
}

// Initialize loads config and starts worker if enabled
func (s *BlocklistService) Initialize(ctx context.Context) error {
	config, err := s.repo.GetConfig(ctx)
	if err != nil {
		slog.Warn("[CROWDSEC_BL] Failed to load config, using defaults", "error", err)
		config = s.config
	}

	s.mu.Lock()
	s.config = config
	s.mu.Unlock()

	// Update client API key
	if config.APIKey != "" {
		s.client.SetAPIKey(config.APIKey)
	}

	// Start worker if enabled
	if config.Enabled && config.APIKey != "" {
		s.StartWorker()
	}

	return nil
}

// GetConfig returns the current configuration (returns a copy to avoid mutation)
func (s *BlocklistService) GetConfig(ctx context.Context) (*BlocklistConfig, error) {
	if s.repo != nil {
		config, err := s.repo.GetConfig(ctx)
		if err == nil && config != nil {
			s.mu.Lock()
			s.config = config
			s.mu.Unlock()
			// Return a copy to prevent callers from modifying our internal state
			configCopy := *config
			return &configCopy, nil
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy
	configCopy := *s.config
	return &configCopy, nil
}

// UpdateConfig updates the configuration
func (s *BlocklistService) UpdateConfig(ctx context.Context, config *BlocklistConfig) error {
	s.mu.Lock()
	wasEnabled := s.config.Enabled
	s.config = config
	s.mu.Unlock()

	// Update client API key if changed
	if config.APIKey != "" {
		s.client.SetAPIKey(config.APIKey)
	}

	// Handle enable/disable transitions
	if config.Enabled && !wasEnabled {
		// Just enabled - start worker and trigger initial sync
		slog.Info("[CROWDSEC_BL] Service enabled, starting worker")
		s.StartWorker()
		go func() {
			if _, err := s.SyncAll(context.Background()); err != nil {
				slog.Error("[CROWDSEC_BL] Initial sync failed", "error", err)
			}
		}()
	} else if !config.Enabled && wasEnabled {
		// Just disabled - stop worker and cleanup
		slog.Info("[CROWDSEC_BL] Service disabled, cleaning up")
		s.StopWorker()
		if err := s.Cleanup(ctx); err != nil {
			slog.Error("[CROWDSEC_BL] Cleanup failed", "error", err)
		}
	}

	if s.repo != nil {
		return s.repo.SaveConfig(ctx, config)
	}
	return nil
}

// StartWorker starts the periodic sync worker
func (s *BlocklistService) StartWorker() {
	if s.worker != nil {
		s.worker.mu.Lock()
		if s.worker.running {
			s.worker.mu.Unlock()
			return
		}
		s.worker.mu.Unlock()
	}

	s.mu.RLock()
	interval := time.Duration(s.config.SyncIntervalMinutes) * time.Minute
	if interval < time.Minute {
		interval = DefaultSyncInterval
	}
	s.mu.RUnlock()

	s.worker = &syncWorker{
		service:  s,
		interval: interval,
		stopChan: make(chan struct{}),
	}

	go s.worker.run()
	slog.Info("[CROWDSEC_BL] Sync worker started", "interval", interval)
}

// StopWorker stops the periodic sync worker
func (s *BlocklistService) StopWorker() {
	if s.worker != nil {
		s.worker.stop()
		s.worker = nil
	}
}

func (w *syncWorker) run() {
	w.mu.Lock()
	w.running = true
	w.mu.Unlock()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx := context.Background()
			slog.Info("[CROWDSEC_BL] Worker triggered sync")
			if _, err := w.service.SyncAll(ctx); err != nil {
				slog.Error("[CROWDSEC_BL] Worker sync failed", "error", err)
			}
		case <-w.stopChan:
			w.mu.Lock()
			w.running = false
			w.mu.Unlock()
			slog.Info("[CROWDSEC_BL] Worker stopped")
			return
		}
	}
}

func (w *syncWorker) stop() {
	w.mu.Lock()
	if w.running {
		close(w.stopChan)
	}
	w.mu.Unlock()
}

// TestConnection tests the CrowdSec API connection
func (s *BlocklistService) TestConnection(ctx context.Context) error {
	return s.client.TestConnection(ctx)
}

// ListBlocklists returns available and subscribed blocklists
func (s *BlocklistService) ListBlocklists(ctx context.Context) (available []crowdsec.BlocklistInfo, subscribed []crowdsec.BlocklistInfo, err error) {
	available, err = s.client.ListBlocklists(ctx)
	if err != nil {
		return nil, nil, err
	}

	subscribed, _ = s.client.GetSubscribedBlocklists(ctx)
	return available, subscribed, nil
}

// SyncAll syncs all subscribed blocklists
// Uses existing blocklist IDs from DB (instead of querying CrowdSec API which may return 403)
func (s *BlocklistService) SyncAll(ctx context.Context) ([]*SyncResult, error) {
	// Check if sync already in progress
	s.syncMu.Lock()
	if s.syncInProgress {
		s.syncMu.Unlock()
		return nil, fmt.Errorf("sync already in progress")
	}
	s.syncInProgress = true
	s.syncMu.Unlock()
	defer func() {
		s.syncMu.Lock()
		s.syncInProgress = false
		s.syncMu.Unlock()
	}()

	s.mu.RLock()
	if !s.config.Enabled {
		s.mu.RUnlock()
		return nil, fmt.Errorf("service is disabled")
	}
	s.mu.RUnlock()

	// Get existing blocklist IDs from DB (instead of CrowdSec API)
	blocklists, err := s.repo.GetExistingBlocklistIDs(ctx)
	if err != nil {
		slog.Warn("[CROWDSEC_BL] Failed to get blocklist IDs from DB, trying API", "error", err)
		// Fallback to API
		apiBlocklists, apiErr := s.client.GetSubscribedBlocklists(ctx)
		if apiErr != nil {
			return nil, fmt.Errorf("failed to get blocklists from DB or API: %w", apiErr)
		}
		for _, bl := range apiBlocklists {
			blocklists = append(blocklists, struct{ ID, Label string }{ID: bl.ID, Label: bl.Label})
		}
	}

	if len(blocklists) == 0 {
		slog.Info("[CROWDSEC_BL] No blocklists found to sync")
		return []*SyncResult{}, nil
	}

	slog.Info("[CROWDSEC_BL] Starting sync for blocklists", "count", len(blocklists))

	var results []*SyncResult
	for _, bl := range blocklists {
		result, err := s.SyncBlocklist(ctx, bl.ID, bl.Label)
		if err != nil {
			slog.Error("[CROWDSEC_BL] Failed to sync blocklist",
				"blocklist_id", bl.ID,
				"label", bl.Label,
				"error", err)
			results = append(results, &SyncResult{
				BlocklistID:    bl.ID,
				BlocklistLabel: bl.Label,
				Error:          err.Error(),
				SyncedAt:       time.Now(),
			})
		} else {
			results = append(results, result)
		}
	}

	// Update stats
	s.updateStats(ctx)

	// Sync to XGS if client is configured
	if s.xgs != nil {
		xgsAdded, xgsRemoved, xgsErr := s.SyncToXGS(ctx)
		if xgsErr != nil {
			slog.Error("[CROWDSEC_BL] XGS sync failed", "error", xgsErr)
		} else {
			slog.Info("[CROWDSEC_BL] XGS sync completed",
				"added", xgsAdded,
				"removed", xgsRemoved)
		}
	}

	return results, nil
}

// SyncBlocklist downloads a blocklist and syncs with DB
func (s *BlocklistService) SyncBlocklist(ctx context.Context, blocklistID, blocklistLabel string) (*SyncResult, error) {
	startTime := time.Now()
	result := &SyncResult{
		BlocklistID:    blocklistID,
		BlocklistLabel: blocklistLabel,
		SyncedAt:       startTime,
	}

	slog.Info("[CROWDSEC_BL] Syncing blocklist",
		"blocklist_id", blocklistID,
		"label", blocklistLabel)

	// Step 1: Download blocklist from CrowdSec
	ips, err := s.client.DownloadBlocklist(ctx, blocklistID)
	if err != nil {
		result.Error = err.Error()
		s.saveHistory(ctx, result, false)
		return result, fmt.Errorf("download failed: %w", err)
	}

	result.IPsInFile = len(ips)

	// Step 2: Save to file (overwrite existing)
	filePath := filepath.Join(BlocklistDataDir, blocklistID+".txt")
	if err := s.saveToFile(filePath, ips); err != nil {
		result.Error = fmt.Sprintf("failed to save file: %v", err)
		s.saveHistory(ctx, result, false)
		return result, err
	}

	slog.Info("[CROWDSEC_BL] Saved blocklist to file",
		"path", filePath,
		"ip_count", len(ips))

	// Step 3: Compare with DB and sync
	added, removed, err := s.syncWithDB(ctx, blocklistID, blocklistLabel, ips)
	if err != nil {
		result.Error = fmt.Sprintf("failed to sync with DB: %v", err)
		s.saveHistory(ctx, result, false)
		return result, err
	}

	result.IPsAdded = added
	result.IPsRemoved = removed
	result.DurationMs = time.Since(startTime).Milliseconds()

	// Save history
	s.saveHistory(ctx, result, true)

	slog.Info("[CROWDSEC_BL] Sync completed",
		"blocklist_id", blocklistID,
		"ips_in_file", result.IPsInFile,
		"added", result.IPsAdded,
		"removed", result.IPsRemoved,
		"duration_ms", result.DurationMs)

	return result, nil
}

// saveToFile saves IPs to a file (one per line)
func (s *BlocklistService) saveToFile(filePath string, ips []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	for _, ip := range ips {
		if _, err := file.WriteString(ip + "\n"); err != nil {
			return fmt.Errorf("write to file: %w", err)
		}
	}

	return nil
}

// syncWithDB compares downloaded IPs with DB and syncs
// Enriches new IPs with country code using GeoIP lookup
func (s *BlocklistService) syncWithDB(ctx context.Context, blocklistID, blocklistLabel string, downloadedIPs []string) (added, removed int, err error) {
	if s.repo == nil {
		return 0, 0, nil
	}

	// Get current IPs from DB for this blocklist
	currentIPs, err := s.repo.GetIPsForBlocklist(ctx, blocklistID)
	if err != nil {
		return 0, 0, fmt.Errorf("get current IPs: %w", err)
	}

	// Build sets for comparison
	currentSet := make(map[string]bool)
	for _, ip := range currentIPs {
		currentSet[ip] = true
	}

	downloadedSet := make(map[string]bool)
	for _, ip := range downloadedIPs {
		downloadedSet[ip] = true
	}

	// Find IPs to add (in downloaded but not in current)
	var toAdd []BlocklistIP
	now := time.Now()
	for _, ip := range downloadedIPs {
		if !currentSet[ip] {
			blIP := BlocklistIP{
				IP:             ip,
				BlocklistID:    blocklistID,
				BlocklistLabel: blocklistLabel,
				FirstSeen:      now,
				LastSeen:       now,
			}

			// Enrich with country code if GeoIP client is available
			if s.geoIP != nil {
				country, geoErr := s.geoIP.LookupCountry(ctx, ip)
				if geoErr == nil && country != "" {
					blIP.CountryCode = country
				}
			}

			toAdd = append(toAdd, blIP)
		}
	}

	// Find IPs to remove (in current but not in downloaded)
	var toRemove []string
	for _, ip := range currentIPs {
		if !downloadedSet[ip] {
			toRemove = append(toRemove, ip)
		}
	}

	// Add new IPs
	if len(toAdd) > 0 {
		if err := s.repo.AddIPs(ctx, toAdd); err != nil {
			return 0, 0, fmt.Errorf("add IPs: %w", err)
		}
		added = len(toAdd)
		slog.Info("[CROWDSEC_BL] Added IPs with GeoIP enrichment", "count", added)
	}

	// Remove old IPs
	if len(toRemove) > 0 {
		if err := s.repo.RemoveIPs(ctx, blocklistID, toRemove); err != nil {
			return added, 0, fmt.Errorf("remove IPs: %w", err)
		}
		removed = len(toRemove)
	}

	slog.Debug("[CROWDSEC_BL] DB sync completed",
		"blocklist_id", blocklistID,
		"current", len(currentIPs),
		"downloaded", len(downloadedIPs),
		"added", added,
		"removed", removed)

	return added, removed, nil
}

// Cleanup removes all blocklist files and clears DB
// Called when API is disconnected
func (s *BlocklistService) Cleanup(ctx context.Context) error {
	slog.Info("[CROWDSEC_BL] Starting cleanup")

	// Step 1: Delete all blocklist files
	files, err := filepath.Glob(filepath.Join(BlocklistDataDir, "*.txt"))
	if err != nil {
		slog.Error("[CROWDSEC_BL] Failed to list blocklist files", "error", err)
	} else {
		for _, f := range files {
			if err := os.Remove(f); err != nil {
				slog.Error("[CROWDSEC_BL] Failed to delete file", "path", f, "error", err)
			} else {
				slog.Info("[CROWDSEC_BL] Deleted blocklist file", "path", f)
			}
		}
	}

	// Step 2: Clear all IPs from DB
	if s.repo != nil {
		if err := s.repo.ClearAllIPs(ctx); err != nil {
			slog.Error("[CROWDSEC_BL] Failed to clear DB", "error", err)
			return err
		}
		slog.Info("[CROWDSEC_BL] Cleared all IPs from DB")
	}

	// Reset stats
	s.mu.Lock()
	s.config.TotalIPs = 0
	s.config.TotalBlocklists = 0
	s.mu.Unlock()

	slog.Info("[CROWDSEC_BL] Cleanup completed")
	return nil
}

// updateStats updates the total IPs and blocklists count and persists to DB
func (s *BlocklistService) updateStats(ctx context.Context) {
	if s.repo == nil {
		return
	}

	totalIPs, totalBlocklists, err := s.repo.GetStats(ctx)
	if err != nil {
		slog.Error("[CROWDSEC_BL] Failed to get stats", "error", err)
		return
	}

	s.mu.Lock()
	s.config.TotalIPs = totalIPs
	s.config.TotalBlocklists = totalBlocklists
	s.config.LastSync = time.Now()
	configCopy := *s.config
	s.mu.Unlock()

	// Persist to database
	if err := s.repo.SaveConfig(ctx, &configCopy); err != nil {
		slog.Error("[CROWDSEC_BL] Failed to save config after stats update", "error", err)
	}

	slog.Info("[CROWDSEC_BL] Stats updated",
		"total_ips", totalIPs,
		"total_blocklists", totalBlocklists)
}

// saveHistory saves sync operation to history
func (s *BlocklistService) saveHistory(ctx context.Context, result *SyncResult, success bool) {
	if s.repo == nil {
		return
	}

	entry := &SyncHistoryEntry{
		Timestamp:      result.SyncedAt,
		BlocklistID:    result.BlocklistID,
		BlocklistLabel: result.BlocklistLabel,
		IPsInFile:      result.IPsInFile,
		IPsAdded:       result.IPsAdded,
		IPsRemoved:     result.IPsRemoved,
		DurationMs:     result.DurationMs,
		Success:        success,
		Error:          result.Error,
	}

	if err := s.repo.SaveSyncHistory(ctx, entry); err != nil {
		slog.Error("[CROWDSEC_BL] Failed to save sync history", "error", err)
	}
}

// GetStatus returns the current service status
func (s *BlocklistService) GetStatus(ctx context.Context) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	workerRunning := false
	if s.worker != nil {
		s.worker.mu.Lock()
		workerRunning = s.worker.running
		s.worker.mu.Unlock()
	}

	s.syncMu.Lock()
	syncInProgress := s.syncInProgress
	s.syncMu.Unlock()

	// Get XGS group IP count if available
	xgsIPCount := 0
	xgsConfigured := s.xgs != nil
	if xgsConfigured && s.xgsGroupReady {
		if ips, err := s.xgs.GetGroupIPs(XGSGroupName); err == nil {
			xgsIPCount = len(ips)
		}
	}

	return map[string]interface{}{
		"configured":       s.client.IsConfigured(),
		"enabled":          s.config.Enabled,
		"worker_running":   workerRunning,
		"sync_in_progress": syncInProgress,
		"sync_running":     syncInProgress, // Alias for frontend compatibility
		"last_sync":        s.config.LastSync,
		"total_ips":        s.config.TotalIPs,
		"total_blocklists": s.config.TotalBlocklists,
		"sync_interval":    fmt.Sprintf("%dm", s.config.SyncIntervalMinutes),
		"data_dir":         BlocklistDataDir,
		"group_name":       XGSGroupName,
		"xgs_configured":   xgsConfigured,
		"xgs_group_ready":  s.xgsGroupReady,
		"xgs_ip_count":     xgsIPCount,
	}
}

// GetSyncHistory returns recent sync history
func (s *BlocklistService) GetSyncHistory(ctx context.Context, limit int) ([]SyncHistoryEntry, error) {
	if s.repo == nil {
		return nil, nil
	}
	return s.repo.GetSyncHistory(ctx, limit)
}

// GetAllIPs returns all IPs from the database
func (s *BlocklistService) GetAllIPs(ctx context.Context) ([]BlocklistIP, error) {
	if s.repo == nil {
		return nil, nil
	}
	return s.repo.GetAllIPs(ctx)
}

// ReadBlocklistFile reads IPs from a downloaded blocklist file
func (s *BlocklistService) ReadBlocklistFile(blocklistID string) ([]string, error) {
	filePath := filepath.Join(BlocklistDataDir, blocklistID+".txt")

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			ips = append(ips, line)
		}
	}

	return ips, scanner.Err()
}

// ListBlocklistFiles returns all downloaded blocklist files
func (s *BlocklistService) ListBlocklistFiles() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(BlocklistDataDir, "*.txt"))
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, f := range files {
		base := filepath.Base(f)
		id := base[:len(base)-4] // Remove .txt
		ids = append(ids, id)
	}

	return ids, nil
}

// IsRunning returns true if a sync operation is in progress
func (s *BlocklistService) IsRunning() bool {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	return s.syncInProgress
}
