package bans

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/sophos"
	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// Service handles ban business logic with recidivism and XGS sync
type Service struct {
	repo   *clickhouse.BansRepository
	sophos *sophos.Client
	mu     sync.Mutex
}

// NewService creates a new bans service
func NewService(repo *clickhouse.BansRepository, sophosClient *sophos.Client) *Service {
	return &Service{
		repo:   repo,
		sophos: sophosClient,
	}
}

// ListActiveBans returns all active bans
func (s *Service) ListActiveBans(ctx context.Context) ([]entity.BanStatus, error) {
	return s.repo.GetActiveBans(ctx)
}

// GetBan returns a specific ban by IP
func (s *Service) GetBan(ctx context.Context, ip string) (*entity.BanStatus, error) {
	return s.repo.GetBanByIP(ctx, ip)
}

// GetStats returns ban statistics
func (s *Service) GetStats(ctx context.Context) (*entity.BanStats, error) {
	return s.repo.GetBanStats(ctx)
}

// GetHistory returns ban history for an IP
func (s *Service) GetHistory(ctx context.Context, ip string, limit int) ([]entity.BanHistory, error) {
	return s.repo.GetBanHistory(ctx, ip, limit)
}

// BanIP bans an IP address with progressive duration based on recidivism
func (s *Service) BanIP(ctx context.Context, req *entity.BanRequest) (*entity.BanStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check whitelist
	whitelisted, err := s.repo.IsWhitelisted(ctx, req.IP)
	if err != nil {
		return nil, fmt.Errorf("check whitelist: %w", err)
	}
	if whitelisted {
		return nil, fmt.Errorf("IP %s is whitelisted and cannot be banned", req.IP)
	}

	// Get existing ban status (if any)
	existing, err := s.repo.GetBanByIP(ctx, req.IP)
	isNewBan := err != nil // Assume error means not found

	now := time.Now()
	ban := &entity.BanStatus{
		IP:        req.IP,
		Reason:    req.Reason,
		Source:    "manual",
		SyncedXGS: false,
		UpdatedAt: now,
	}

	if req.PerformedBy != "" {
		ban.CreatedBy = req.PerformedBy
	}

	if isNewBan {
		// First time ban
		ban.BanCount = 1
		ban.FirstBan = now
		ban.LastBan = now
	} else {
		// Recidivist - increment ban count
		ban.BanCount = existing.BanCount + 1
		ban.FirstBan = existing.FirstBan
		ban.LastBan = now
	}

	// Determine ban duration
	if req.Permanent || ban.BanCount >= entity.RecidivismThreshold {
		// Permanent ban (4th offense or explicit permanent request)
		ban.Status = entity.BanStatusPermanent
		ban.ExpiresAt = nil
		log.Printf("[BAN] Permanent ban for IP %s (ban count: %d)", req.IP, ban.BanCount)
	} else if req.DurationDays != nil {
		// Explicit duration
		if *req.DurationDays == 0 {
			ban.Status = entity.BanStatusPermanent
			ban.ExpiresAt = nil
		} else {
			expires := now.Add(time.Duration(*req.DurationDays) * 24 * time.Hour)
			ban.Status = entity.BanStatusActive
			ban.ExpiresAt = &expires
		}
	} else {
		// Progressive duration based on recidivism
		duration := entity.GetNextBanDuration(ban.BanCount - 1)
		if duration == nil {
			// Should not happen with threshold check, but fallback to permanent
			ban.Status = entity.BanStatusPermanent
			ban.ExpiresAt = nil
		} else {
			expires := now.Add(*duration)
			ban.Status = entity.BanStatusActive
			ban.ExpiresAt = &expires
			log.Printf("[BAN] Progressive ban for IP %s: %v (ban count: %d)", req.IP, *duration, ban.BanCount)
		}
	}

	// Save to database
	if err := s.repo.UpsertBan(ctx, ban); err != nil {
		return nil, fmt.Errorf("save ban: %w", err)
	}

	// Record history
	durationHours := 0
	if ban.ExpiresAt != nil {
		durationHours = int(ban.ExpiresAt.Sub(now).Hours())
	}

	history := &entity.BanHistory{
		IP:            req.IP,
		Action:        entity.BanActionBan,
		Reason:        req.Reason,
		DurationHours: durationHours,
		Source:        "manual",
		PerformedBy:   req.PerformedBy,
		SyncedXGS:     false,
		CreatedAt:     now,
	}

	if err := s.repo.RecordBanHistory(ctx, history); err != nil {
		log.Printf("[WARN] Failed to record ban history: %v", err)
	}

	// Sync to Sophos XGS (async, don't block)
	go s.syncBanToXGS(ban)

	return ban, nil
}

// UnbanIP removes a ban from an IP address
func (s *Service) UnbanIP(ctx context.Context, req *entity.UnbanRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get existing ban
	existing, err := s.repo.GetBanByIP(ctx, req.IP)
	if err != nil {
		return fmt.Errorf("ban not found: %w", err)
	}

	now := time.Now()

	// Update ban status
	existing.Status = entity.BanStatusExpired
	existing.UpdatedAt = now

	if err := s.repo.UpsertBan(ctx, existing); err != nil {
		return fmt.Errorf("update ban: %w", err)
	}

	// Record history
	history := &entity.BanHistory{
		IP:          req.IP,
		Action:      entity.BanActionUnban,
		Reason:      req.Reason,
		Source:      "manual",
		PerformedBy: req.PerformedBy,
		SyncedXGS:   false,
		CreatedAt:   now,
	}

	if err := s.repo.RecordBanHistory(ctx, history); err != nil {
		log.Printf("[WARN] Failed to record unban history: %v", err)
	}

	// Remove from Sophos XGS (async)
	go s.syncUnbanToXGS(req.IP)

	return nil
}

// ExtendBan extends an existing ban duration
func (s *Service) ExtendBan(ctx context.Context, req *entity.ExtendBanRequest) (*entity.BanStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get existing ban
	existing, err := s.repo.GetBanByIP(ctx, req.IP)
	if err != nil {
		return nil, fmt.Errorf("ban not found: %w", err)
	}

	now := time.Now()

	// Calculate new expiry
	baseTime := now
	if existing.ExpiresAt != nil && existing.ExpiresAt.After(now) {
		baseTime = *existing.ExpiresAt
	}

	newExpiry := baseTime.Add(time.Duration(req.DurationDays) * 24 * time.Hour)
	existing.ExpiresAt = &newExpiry
	existing.UpdatedAt = now

	if err := s.repo.UpsertBan(ctx, existing); err != nil {
		return nil, fmt.Errorf("update ban: %w", err)
	}

	// Record history
	history := &entity.BanHistory{
		IP:            req.IP,
		Action:        entity.BanActionExtend,
		Reason:        req.Reason,
		DurationHours: req.DurationDays * 24,
		Source:        "manual",
		PerformedBy:   req.PerformedBy,
		CreatedAt:     now,
	}

	if err := s.repo.RecordBanHistory(ctx, history); err != nil {
		log.Printf("[WARN] Failed to record extend history: %v", err)
	}

	return existing, nil
}

// MakePermanent makes a ban permanent
func (s *Service) MakePermanent(ctx context.Context, ip, performedBy string) (*entity.BanStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get existing ban
	existing, err := s.repo.GetBanByIP(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("ban not found: %w", err)
	}

	now := time.Now()

	// Update to permanent
	existing.Status = entity.BanStatusPermanent
	existing.ExpiresAt = nil
	existing.UpdatedAt = now

	if err := s.repo.UpsertBan(ctx, existing); err != nil {
		return nil, fmt.Errorf("update ban: %w", err)
	}

	// Record history
	history := &entity.BanHistory{
		IP:          ip,
		Action:      entity.BanActionPermanent,
		Reason:      "Escalated to permanent ban",
		Source:      "manual",
		PerformedBy: performedBy,
		CreatedAt:   now,
	}

	if err := s.repo.RecordBanHistory(ctx, history); err != nil {
		log.Printf("[WARN] Failed to record permanent history: %v", err)
	}

	return existing, nil
}

// SyncToXGS performs bidirectional sync with Sophos XGS:
// 1. Push unsynced bans from VIGILANCE X to Sophos
// 2. Import IPs from Sophos that aren't in our database
func (s *Service) SyncToXGS(ctx context.Context) (*SyncResult, error) {
	if s.sophos == nil {
		return nil, fmt.Errorf("Sophos client not configured")
	}

	// Ensure blocklist group exists
	if err := s.sophos.EnsureBlocklistGroupExists(); err != nil {
		log.Printf("[WARN] Failed to ensure blocklist group: %v", err)
	}

	result := &SyncResult{}

	// PHASE 1: Push unsynced bans to Sophos XGS
	unsynced, err := s.repo.GetUnsyncedBans(ctx)
	if err != nil {
		return nil, fmt.Errorf("get unsynced bans: %w", err)
	}

	result.Total = len(unsynced)

	for _, ban := range unsynced {
		if err := s.sophos.AddIPToBlocklist(ban.IP, ban.Reason); err != nil {
			log.Printf("[ERROR] Failed to sync ban %s to XGS: %v", ban.IP, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", ban.IP, err))
			continue
		}

		// Mark as synced
		if err := s.repo.UpdateSyncStatus(ctx, ban.IP, true); err != nil {
			log.Printf("[WARN] Failed to update sync status for %s: %v", ban.IP, err)
		}

		result.Synced++
	}

	// PHASE 2: Import IPs from Sophos XGS that aren't in our database
	xgsIPs, err := s.sophos.GetBlocklistIPs()
	if err != nil {
		log.Printf("[WARN] Failed to get IPs from XGS: %v", err)
		result.Errors = append(result.Errors, fmt.Sprintf("XGS import: %v", err))
	} else {
		for _, ip := range xgsIPs {
			// Check if this IP is already in our database
			_, err := s.repo.GetBanByIP(ctx, ip)
			if err == nil {
				// Already exists, ensure it's marked as synced
				if err := s.repo.UpdateSyncStatus(ctx, ip, true); err != nil {
					log.Printf("[WARN] Failed to update sync status for existing %s: %v", ip, err)
				}
				continue
			}

			// Check if IP is whitelisted
			whitelisted, _ := s.repo.IsWhitelisted(ctx, ip)
			if whitelisted {
				log.Printf("[SYNC] Skipping whitelisted IP from XGS: %s", ip)
				continue
			}

			// Import this IP as a new ban (it exists in Sophos but not in our DB)
			now := time.Now()
			ban := &entity.BanStatus{
				IP:        ip,
				Status:    entity.BanStatusPermanent, // Assume permanent since we don't know expiry
				BanCount:  1,
				FirstBan:  now,
				LastBan:   now,
				Reason:    "Imported from Sophos XGS",
				Source:    "xgs_import",
				SyncedXGS: true,
				UpdatedAt: now,
			}

			if err := s.repo.UpsertBan(ctx, ban); err != nil {
				log.Printf("[ERROR] Failed to import ban %s from XGS: %v", ip, err)
				result.Errors = append(result.Errors, fmt.Sprintf("import %s: %v", ip, err))
				continue
			}

			// Record history
			history := &entity.BanHistory{
				IP:        ip,
				Action:    entity.BanActionBan,
				Reason:    "Imported from Sophos XGS",
				Source:    "xgs_import",
				SyncedXGS: true,
				CreatedAt: now,
			}
			s.repo.RecordBanHistory(ctx, history)

			result.Imported++
			log.Printf("[SYNC] Imported ban from XGS: %s", ip)
		}
	}

	return result, nil
}

// SyncResult represents the result of a sync operation
type SyncResult struct {
	Total    int      `json:"total"`
	Synced   int      `json:"synced"`
	Failed   int      `json:"failed"`
	Imported int      `json:"imported"`
	Errors   []string `json:"errors,omitempty"`
}

// GetXGSStatus returns the current Sophos XGS sync status
func (s *Service) GetXGSStatus(ctx context.Context) (*sophos.SyncStatus, error) {
	if s.sophos == nil {
		return &sophos.SyncStatus{
			Connected:     false,
			LastSyncError: "Sophos client not configured",
		}, nil
	}

	return s.sophos.GetSyncStatus()
}

// syncBanToXGS syncs a single ban to Sophos XGS (called async)
func (s *Service) syncBanToXGS(ban *entity.BanStatus) {
	if s.sophos == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.sophos.AddIPToBlocklist(ban.IP, ban.Reason); err != nil {
		log.Printf("[ERROR] Failed to sync ban %s to XGS: %v", ban.IP, err)
		return
	}

	if err := s.repo.UpdateSyncStatus(ctx, ban.IP, true); err != nil {
		log.Printf("[WARN] Failed to update sync status for %s: %v", ban.IP, err)
	}

	log.Printf("[SYNC] Ban synced to XGS: %s", ban.IP)
}

// syncUnbanToXGS removes an IP from Sophos XGS blocklist (called async)
func (s *Service) syncUnbanToXGS(ip string) {
	if s.sophos == nil {
		return
	}

	if err := s.sophos.RemoveIPFromBlocklist(ip); err != nil {
		log.Printf("[ERROR] Failed to remove %s from XGS: %v", ip, err)
		return
	}

	log.Printf("[SYNC] IP removed from XGS blocklist: %s", ip)
}

// ProcessExpiredBans checks for expired bans and marks them as expired
func (s *Service) ProcessExpiredBans(ctx context.Context) (int, error) {
	expired, err := s.repo.GetExpiredBans(ctx)
	if err != nil {
		return 0, fmt.Errorf("get expired bans: %w", err)
	}

	count := 0
	for _, ban := range expired {
		ban.Status = entity.BanStatusExpired
		ban.UpdatedAt = time.Now()

		if err := s.repo.UpsertBan(ctx, &ban); err != nil {
			log.Printf("[ERROR] Failed to expire ban %s: %v", ban.IP, err)
			continue
		}

		// Record history
		history := &entity.BanHistory{
			IP:        ban.IP,
			Action:    entity.BanActionExpire,
			Reason:    "Ban expired",
			Source:    "system",
			CreatedAt: time.Now(),
		}
		s.repo.RecordBanHistory(ctx, history)

		// Remove from XGS
		go s.syncUnbanToXGS(ban.IP)

		count++
	}

	return count, nil
}

// Whitelist management

// GetWhitelist returns all whitelisted IPs
func (s *Service) GetWhitelist(ctx context.Context) ([]entity.WhitelistEntry, error) {
	return s.repo.GetWhitelist(ctx)
}

// AddToWhitelist adds an IP to the whitelist
func (s *Service) AddToWhitelist(ctx context.Context, ip, reason, addedBy string) error {
	// If currently banned, unban first
	ban, err := s.repo.GetBanByIP(ctx, ip)
	if err == nil && (ban.Status == entity.BanStatusActive || ban.Status == entity.BanStatusPermanent) {
		if err := s.UnbanIP(ctx, &entity.UnbanRequest{
			IP:          ip,
			Reason:      "Added to whitelist",
			PerformedBy: addedBy,
		}); err != nil {
			log.Printf("[WARN] Failed to unban %s when adding to whitelist: %v", ip, err)
		}
	}

	entry := &entity.WhitelistEntry{
		IP:        ip,
		Reason:    reason,
		AddedBy:   addedBy,
		CreatedAt: time.Now(),
	}

	return s.repo.AddToWhitelist(ctx, entry)
}

// RemoveFromWhitelist removes an IP from the whitelist
func (s *Service) RemoveFromWhitelist(ctx context.Context, ip string) error {
	return s.repo.RemoveFromWhitelist(ctx, ip)
}
