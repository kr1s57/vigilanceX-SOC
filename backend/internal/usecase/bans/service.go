package bans

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/sophos"
	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// ProtectedNetworks defines IP ranges that should NEVER be banned
// These are local/internal networks and critical infrastructure IPs
var ProtectedNetworks = []string{
	"10.0.0.0/8",     // Private Class A
	"192.168.0.0/16", // Private Class C
	"172.16.0.0/12",  // Private Class B (172.16.x.x - 172.31.x.x)
	"127.0.0.0/8",    // Loopback
	"169.254.0.0/16", // Link-local
	"0.0.0.0/32",     // Invalid
}

// ProtectedIPs defines specific IPs that should NEVER be banned
// Critical infrastructure IPs (XGS interfaces, gateways, etc.)
var ProtectedIPs = []string{
	"192.168.1.13", // Sophos XGS WAN interface
	"192.168.1.1",  // Sophos XGS gateway/router
	"0.0.0.0",
	"127.0.0.1",
}

// parsedProtectedNetworks holds parsed CIDR networks (initialized once)
var parsedProtectedNetworks []*net.IPNet

func init() {
	for _, cidr := range ProtectedNetworks {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedProtectedNetworks = append(parsedProtectedNetworks, network)
		}
	}
}

// IsProtectedIP checks if an IP should never be banned
// Returns true for local/internal IPs and critical infrastructure
func IsProtectedIP(ipStr string) bool {
	// Check specific protected IPs first
	for _, protectedIP := range ProtectedIPs {
		if ipStr == protectedIP {
			return true
		}
	}

	// Parse the IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Invalid IP, let it through (will fail later)
	}

	// Check against protected networks
	for _, network := range parsedProtectedNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// GetProtectionReason returns why an IP is protected (for logging)
func GetProtectionReason(ipStr string) string {
	// Check specific protected IPs
	switch ipStr {
	case "192.168.1.13":
		return "Sophos XGS WAN interface"
	case "192.168.1.1":
		return "Sophos XGS gateway"
	case "0.0.0.0", "127.0.0.1":
		return "Loopback/Invalid"
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	// Check networks
	if ip.IsLoopback() {
		return "Loopback address"
	}
	if ip.IsPrivate() {
		return "Private/Internal network"
	}
	if ip.IsLinkLocalUnicast() {
		return "Link-local address"
	}

	for _, network := range parsedProtectedNetworks {
		if network.Contains(ip) {
			return fmt.Sprintf("Protected network %s", network.String())
		}
	}

	return ""
}

// BansRepository interface for ban data access (enables unit testing)
type BansRepository interface {
	GetActiveBans(ctx context.Context) ([]entity.BanStatus, error)
	GetBanByIP(ctx context.Context, ip string) (*entity.BanStatus, error)
	UpsertBan(ctx context.Context, ban *entity.BanStatus) error
	UpdateSyncStatus(ctx context.Context, ip string, synced bool) error
	RecordBanHistory(ctx context.Context, history *entity.BanHistory) error
	GetBanHistory(ctx context.Context, ip string, limit int) ([]entity.BanHistory, error)
	GetBanStats(ctx context.Context) (*entity.BanStats, error)
	GetExpiredBans(ctx context.Context) ([]entity.BanStatus, error)
	GetUnsyncedBans(ctx context.Context) ([]entity.BanStatus, error)
	IsWhitelisted(ctx context.Context, ip string) (bool, error)
	IsIPImmune(ctx context.Context, ip string) (bool, *time.Time, error)
	CheckWhitelistV2(ctx context.Context, ip string) (*entity.WhitelistCheckResult, error)
	GetWhitelist(ctx context.Context) ([]entity.WhitelistEntry, error)
	GetWhitelistByType(ctx context.Context, whitelistType string) ([]entity.WhitelistEntry, error)
	GetWhitelistStats(ctx context.Context) (map[string]int, error)
	AddToWhitelist(ctx context.Context, entry *entity.WhitelistEntry) error
	UpdateWhitelistEntry(ctx context.Context, entry *entity.WhitelistEntry) error
	RemoveFromWhitelist(ctx context.Context, ip string) error
	GetExpiredWhitelistEntries(ctx context.Context) ([]entity.WhitelistEntry, error)
}

// SophosClient interface for Sophos XGS operations (enables unit testing)
type SophosClient interface {
	EnsureBlocklistGroupExists() error
	AddIPToBlocklist(ip, reason string) error
	GetBlocklistIPs() ([]string, error)
	RemoveIPFromBlocklist(ip string) error
	GetSyncStatus() (*sophos.SyncStatus, error)
}

// Service handles ban business logic with recidivism and XGS sync
type Service struct {
	repo   BansRepository
	sophos SophosClient
	mu     sync.Mutex
}

// NewService creates a new bans service
func NewService(repo *clickhouse.BansRepository, sophosClient *sophos.Client) *Service {
	return &Service{
		repo:   repo,
		sophos: sophosClient,
	}
}

// NewServiceWithInterfaces creates a new bans service with interface dependencies (for testing)
func NewServiceWithInterfaces(repo BansRepository, sophosClient SophosClient) *Service {
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

// IsIPImmune checks if an IP has active immunity from auto-ban
// Returns true if the IP is immune, along with the expiration time
func (s *Service) IsIPImmune(ctx context.Context, ip string) (bool, *time.Time, error) {
	return s.repo.IsIPImmune(ctx, ip)
}

// BanIP bans an IP address with progressive duration based on recidivism
// v2.0: Supports soft whitelist - soft whitelisted IPs generate alerts but may still be banned
// v3.5: Added protection for local/internal IPs - external threats only
func (s *Service) BanIP(ctx context.Context, req *entity.BanRequest) (*entity.BanStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// CRITICAL: Check if IP is protected (local/internal/infrastructure)
	// Never ban internal network IPs or critical infrastructure
	if IsProtectedIP(req.IP) {
		reason := GetProtectionReason(req.IP)
		log.Printf("[BAN] REJECTED: Cannot ban protected IP %s - %s", req.IP, reason)
		return nil, fmt.Errorf("cannot ban protected IP %s: %s", req.IP, reason)
	}

	// Check whitelist (v2.0 with soft whitelist support)
	whitelistResult, err := s.repo.CheckWhitelistV2(ctx, req.IP)
	if err != nil {
		return nil, fmt.Errorf("check whitelist: %w", err)
	}

	// Handle whitelist based on type
	if whitelistResult.IsWhitelisted {
		switch whitelistResult.EffectiveType {
		case entity.WhitelistTypeHard:
			// Hard whitelist: never ban
			return nil, fmt.Errorf("IP %s is hard-whitelisted and cannot be banned", req.IP)
		case entity.WhitelistTypeSoft:
			// Soft whitelist: alert required, check if auto-ban is allowed
			if !whitelistResult.AllowAutoBan {
				log.Printf("[WHITELIST] Soft-whitelisted IP %s triggered ban attempt (alert-only mode)", req.IP)
				return nil, fmt.Errorf("IP %s is soft-whitelisted (alert-only): %s", req.IP, whitelistResult.Entry.Reason)
			}
			// Allow ban but log warning
			log.Printf("[WHITELIST] Soft-whitelisted IP %s being banned (alert generated)", req.IP)
		case entity.WhitelistTypeMonitor:
			// Monitor only: allow ban but log for tracking
			log.Printf("[WHITELIST] Monitor-only IP %s being banned (logged for tracking)", req.IP)
		}
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
// If ImmunityHours > 0, grants temporary immunity from auto-ban (Detect2Ban)
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

	// Set immunity if requested
	if req.ImmunityHours > 0 {
		immuneUntil := now.Add(time.Duration(req.ImmunityHours) * time.Hour)
		existing.ImmuneUntil = &immuneUntil
		log.Printf("[BAN] IP %s unbanned with %dh immunity (until %v)", req.IP, req.ImmunityHours, immuneUntil)
	}

	if err := s.repo.UpsertBan(ctx, existing); err != nil {
		return fmt.Errorf("update ban: %w", err)
	}

	// Record history
	action := entity.BanActionUnban
	reason := req.Reason
	if req.ImmunityHours > 0 {
		action = entity.BanActionUnbanImmunity
		if reason == "" {
			reason = fmt.Sprintf("Unbanned with %dh immunity", req.ImmunityHours)
		} else {
			reason = fmt.Sprintf("%s (with %dh immunity)", reason, req.ImmunityHours)
		}
	}

	history := &entity.BanHistory{
		IP:            req.IP,
		Action:        action,
		Reason:        reason,
		DurationHours: req.ImmunityHours, // Store immunity duration
		Source:        "manual",
		PerformedBy:   req.PerformedBy,
		SyncedXGS:     false,
		CreatedAt:     now,
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
// 3. Remove bans from VIGILANCE X that are no longer in Sophos (reconciliation)
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

	// Get all IPs from XGS for Phase 2 and 3
	xgsIPs, err := s.sophos.GetBlocklistIPs()
	if err != nil {
		log.Printf("[WARN] Failed to get IPs from XGS: %v", err)
		result.Errors = append(result.Errors, fmt.Sprintf("XGS fetch: %v", err))
		return result, nil // Can't proceed with reconciliation without XGS data
	}

	// Build a set of XGS IPs for fast lookup
	xgsIPSet := make(map[string]bool)
	for _, ip := range xgsIPs {
		xgsIPSet[ip] = true
	}

	// PHASE 2: Import IPs from Sophos XGS that aren't in our database
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

	// PHASE 3: Reconciliation - Remove bans from VIGILANCE X that are no longer in XGS
	// This handles the case where an IP was removed directly from XGS
	activeBans, err := s.repo.GetActiveBans(ctx)
	if err != nil {
		log.Printf("[WARN] Failed to get active bans for reconciliation: %v", err)
	} else {
		for _, ban := range activeBans {
			// Only reconcile bans that were synced to XGS
			if !ban.SyncedXGS {
				continue
			}

			// Check if this IP still exists in XGS
			if xgsIPSet[ban.IP] {
				continue // Still in XGS, keep it
			}

			// IP was removed from XGS, remove from VIGILANCE X too
			log.Printf("[SYNC] Reconciliation: IP %s removed from XGS, unbanning in VIGILANCE X", ban.IP)

			now := time.Now()
			ban.Status = entity.BanStatusExpired
			ban.Reason = "Unbanned by XGS"
			ban.UpdatedAt = now

			if err := s.repo.UpsertBan(ctx, &ban); err != nil {
				log.Printf("[ERROR] Failed to unban %s during reconciliation: %v", ban.IP, err)
				result.Errors = append(result.Errors, fmt.Sprintf("reconcile %s: %v", ban.IP, err))
				continue
			}

			// Record history
			history := &entity.BanHistory{
				IP:        ban.IP,
				Action:    entity.BanActionUnban,
				Reason:    "Unbanned by XGS",
				Source:    "xgs_reconcile",
				SyncedXGS: true,
				CreatedAt: now,
			}
			s.repo.RecordBanHistory(ctx, history)

			result.Removed++
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
	Removed  int      `json:"removed"`
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

// Whitelist management (v2.0 with soft whitelist support)

// GetWhitelist returns all whitelisted IPs
func (s *Service) GetWhitelist(ctx context.Context) ([]entity.WhitelistEntry, error) {
	return s.repo.GetWhitelist(ctx)
}

// GetWhitelistByType returns whitelisted IPs filtered by type (v2.0)
func (s *Service) GetWhitelistByType(ctx context.Context, whitelistType string) ([]entity.WhitelistEntry, error) {
	return s.repo.GetWhitelistByType(ctx, whitelistType)
}

// GetWhitelistStats returns whitelist statistics by type (v2.0)
func (s *Service) GetWhitelistStats(ctx context.Context) (map[string]int, error) {
	return s.repo.GetWhitelistStats(ctx)
}

// CheckWhitelist performs a full whitelist check with soft whitelist support (v2.0)
func (s *Service) CheckWhitelist(ctx context.Context, ip string) (*entity.WhitelistCheckResult, error) {
	return s.repo.CheckWhitelistV2(ctx, ip)
}

// AddToWhitelist adds an IP to the whitelist (legacy - defaults to hard whitelist)
func (s *Service) AddToWhitelist(ctx context.Context, ip, reason, addedBy string) error {
	req := &entity.WhitelistRequest{
		IP:      ip,
		Type:    entity.WhitelistTypeHard,
		Reason:  reason,
		AddedBy: addedBy,
	}
	return s.AddToWhitelistV2(ctx, req)
}

// AddToWhitelistV2 adds an IP to the whitelist with full v2.0 support
func (s *Service) AddToWhitelistV2(ctx context.Context, req *entity.WhitelistRequest) error {
	// Validate whitelist type
	validTypes := map[string]bool{
		entity.WhitelistTypeHard:    true,
		entity.WhitelistTypeSoft:    true,
		entity.WhitelistTypeMonitor: true,
	}
	if !validTypes[req.Type] {
		return fmt.Errorf("invalid whitelist type: %s (must be hard, soft, or monitor)", req.Type)
	}

	// For hard whitelist, unban if currently banned
	if req.Type == entity.WhitelistTypeHard {
		ban, err := s.repo.GetBanByIP(ctx, req.IP)
		if err == nil && (ban.Status == entity.BanStatusActive || ban.Status == entity.BanStatusPermanent) {
			if err := s.UnbanIP(ctx, &entity.UnbanRequest{
				IP:          req.IP,
				Reason:      "Added to hard whitelist",
				PerformedBy: req.AddedBy,
			}); err != nil {
				log.Printf("[WARN] Failed to unban %s when adding to whitelist: %v", req.IP, err)
			}
		}
	}

	// Build whitelist entry
	entry := &entity.WhitelistEntry{
		IP:            req.IP,
		CIDRMask:      req.CIDRMask,
		Type:          req.Type,
		Reason:        req.Reason,
		Description:   req.Description,
		ScoreModifier: req.ScoreModifier,
		AlertOnly:     req.AlertOnly,
		Tags:          req.Tags,
		AddedBy:       req.AddedBy,
		IsActive:      true,
		CreatedAt:     time.Now(),
	}

	// Set defaults based on type
	if entry.Type == entity.WhitelistTypeSoft {
		if entry.ScoreModifier == 0 {
			entry.ScoreModifier = 50 // Default 50% reduction
		}
		if !entry.AlertOnly {
			entry.AlertOnly = true // Default to alert-only for soft whitelist
		}
	}

	// Set expiration if duration specified
	if req.DurationDays != nil && *req.DurationDays > 0 {
		expires := time.Now().Add(time.Duration(*req.DurationDays) * 24 * time.Hour)
		entry.ExpiresAt = &expires
	}

	log.Printf("[WHITELIST] Adding %s whitelist entry for IP %s (reason: %s)", req.Type, req.IP, req.Reason)
	return s.repo.AddToWhitelist(ctx, entry)
}

// UpdateWhitelistEntry updates an existing whitelist entry (v2.0)
func (s *Service) UpdateWhitelistEntry(ctx context.Context, entry *entity.WhitelistEntry) error {
	return s.repo.UpdateWhitelistEntry(ctx, entry)
}

// RemoveFromWhitelist removes an IP from the whitelist
func (s *Service) RemoveFromWhitelist(ctx context.Context, ip string) error {
	log.Printf("[WHITELIST] Removing IP %s from whitelist", ip)
	return s.repo.RemoveFromWhitelist(ctx, ip)
}

// ProcessExpiredWhitelist checks for expired whitelist entries and deactivates them (v2.0)
func (s *Service) ProcessExpiredWhitelist(ctx context.Context) (int, error) {
	expired, err := s.repo.GetExpiredWhitelistEntries(ctx)
	if err != nil {
		return 0, fmt.Errorf("get expired whitelist: %w", err)
	}

	count := 0
	for _, entry := range expired {
		entry.IsActive = false
		if err := s.repo.UpdateWhitelistEntry(ctx, &entry); err != nil {
			log.Printf("[ERROR] Failed to expire whitelist entry %s: %v", entry.IP, err)
			continue
		}
		log.Printf("[WHITELIST] Expired whitelist entry for IP %s (type: %s)", entry.IP, entry.Type)
		count++
	}

	return count, nil
}

// ApplyWhitelistScoreModifier applies whitelist score modifier to a threat score (v2.0)
// Returns the modified score and whether the IP is whitelisted
func (s *Service) ApplyWhitelistScoreModifier(ctx context.Context, ip string, originalScore int) (int, *entity.WhitelistCheckResult, error) {
	result, err := s.repo.CheckWhitelistV2(ctx, ip)
	if err != nil {
		return originalScore, nil, err
	}

	if !result.IsWhitelisted || result.ScoreModifier == 0 {
		return originalScore, result, nil
	}

	// Apply score reduction
	reduction := float64(originalScore) * float64(result.ScoreModifier) / 100.0
	modifiedScore := originalScore - int(reduction)
	if modifiedScore < 0 {
		modifiedScore = 0
	}

	log.Printf("[WHITELIST] Score modified for IP %s: %d -> %d (-%d%% %s whitelist)",
		ip, originalScore, modifiedScore, result.ScoreModifier, result.EffectiveType)

	return modifiedScore, result, nil
}
