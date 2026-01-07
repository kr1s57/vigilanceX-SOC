package entity

import (
	"time"

	"github.com/google/uuid"
)

// BanStatus represents the current ban status of an IP
type BanStatus struct {
	IP           string     `json:"ip" ch:"ip"`
	Status       string     `json:"status" ch:"status"`
	BanCount     uint8      `json:"ban_count" ch:"ban_count"`
	FirstBan     time.Time  `json:"first_ban" ch:"first_ban"`
	LastBan      time.Time  `json:"last_ban" ch:"last_ban"`
	ExpiresAt    *time.Time `json:"expires_at" ch:"expires_at"`
	Reason       string     `json:"reason" ch:"reason"`
	Source       string     `json:"source" ch:"source"` // manual, detect2ban, threat_intel
	TriggerRule  string     `json:"trigger_rule" ch:"trigger_rule"`
	TriggerEvent uuid.UUID  `json:"trigger_event_id" ch:"trigger_event_id"`
	SyncedXGS    bool       `json:"synced_xgs" ch:"synced_xgs"`
	CreatedBy    string     `json:"created_by" ch:"created_by"`
	UpdatedAt    time.Time  `json:"updated_at" ch:"updated_at"`
	Version      uint64     `json:"-" ch:"version"`
}

// BanHistory represents a ban/unban action in the audit trail
type BanHistory struct {
	ID             uuid.UUID `json:"id" ch:"id"`
	Timestamp      time.Time `json:"timestamp" ch:"timestamp"`
	IP             string    `json:"ip" ch:"ip"`
	Action         string    `json:"action" ch:"action"`
	PreviousStatus string    `json:"previous_status" ch:"previous_status"`
	NewStatus      string    `json:"new_status" ch:"new_status"`
	DurationHours  int       `json:"duration_hours" ch:"duration_hours"`
	Reason         string    `json:"reason" ch:"reason"`
	Source         string    `json:"source" ch:"source"`
	PerformedBy    string    `json:"performed_by" ch:"performed_by"`
	SyncedXGS      bool      `json:"synced_xgs" ch:"synced_xgs"`
	CreatedAt      time.Time `json:"created_at" ch:"created_at"`
	Metadata       string    `json:"metadata" ch:"metadata"`
}

// WhitelistEntry represents a whitelisted IP with soft whitelist support (v2.0)
type WhitelistEntry struct {
	IP            string     `json:"ip" ch:"ip"`
	CIDRMask      uint8      `json:"cidr_mask" ch:"cidr_mask"`
	Type          string     `json:"type" ch:"type"` // hard, soft, monitor
	Reason        string     `json:"reason" ch:"reason"`
	Description   string     `json:"description" ch:"description"`
	ScoreModifier int32      `json:"score_modifier" ch:"score_modifier"` // % reduction (0-100) for soft
	AlertOnly     bool       `json:"alert_only" ch:"alert_only"`         // Alert but don't auto-ban
	ExpiresAt     *time.Time `json:"expires_at" ch:"expires_at"`         // TTL for temporary whitelist
	Tags          []string   `json:"tags" ch:"tags"`                     // CDN, partner, pentest, etc.
	AddedBy       string     `json:"added_by" ch:"added_by"`
	CreatedAt     time.Time  `json:"created_at" ch:"created_at"`
	CreatedBy     string     `json:"created_by" ch:"created_by"`
	IsActive      bool       `json:"is_active" ch:"is_active"`
	Version       uint64     `json:"-" ch:"version"`
}

// WhitelistType constants for soft whitelist (v2.0)
const (
	WhitelistTypeHard    = "hard"    // Full bypass - never banned, score ignored
	WhitelistTypeSoft    = "soft"    // Score reduced, alert only (no auto-ban)
	WhitelistTypeMonitor = "monitor" // Logging only, no impact on score or bans
)

// WhitelistRequest represents a request to add an IP to the whitelist (v2.0)
type WhitelistRequest struct {
	IP            string   `json:"ip" validate:"required"`
	CIDRMask      uint8    `json:"cidr_mask"`                // 0 = single IP, 24-32 for ranges
	Type          string   `json:"type" validate:"required"` // hard, soft, monitor
	Reason        string   `json:"reason" validate:"required"`
	Description   string   `json:"description"`
	ScoreModifier int32    `json:"score_modifier"` // 0-100, default 50 for soft
	AlertOnly     bool     `json:"alert_only"`     // Default true for soft
	DurationDays  *int     `json:"duration_days"`  // nil = permanent
	Tags          []string `json:"tags"`
	AddedBy       string   `json:"added_by"`
}

// WhitelistCheckResult represents the result of checking an IP against the whitelist (v2.0)
type WhitelistCheckResult struct {
	IsWhitelisted bool            `json:"is_whitelisted"`
	Entry         *WhitelistEntry `json:"entry,omitempty"`
	EffectiveType string          `json:"effective_type"` // none, hard, soft, monitor
	ScoreModifier int32           `json:"score_modifier"` // % to reduce score
	AllowAutoBan  bool            `json:"allow_auto_ban"` // Can auto-ban proceed?
	AlertRequired bool            `json:"alert_required"` // Should generate alert?
}

// BanRequest represents a request to ban an IP
type BanRequest struct {
	IP           string `json:"ip" validate:"required,ip"`
	Reason       string `json:"reason" validate:"required"`
	DurationDays *int   `json:"duration_days"` // nil = use progressive, 0 = permanent
	Permanent    bool   `json:"permanent"`
	TriggerRule  string `json:"trigger_rule"`
	TriggerEvent string `json:"trigger_event_id"`
	PerformedBy  string `json:"performed_by"`
}

// UnbanRequest represents a request to unban an IP
type UnbanRequest struct {
	IP          string `json:"ip" validate:"required,ip"`
	Reason      string `json:"reason"`
	PerformedBy string `json:"performed_by"`
}

// ExtendBanRequest represents a request to extend a ban
type ExtendBanRequest struct {
	IP           string `json:"ip" validate:"required,ip"`
	DurationDays int    `json:"duration_days" validate:"required,min=1"`
	Reason       string `json:"reason"`
	PerformedBy  string `json:"performed_by"`
}

// BanStats represents ban statistics
type BanStats struct {
	TotalActiveBans    uint64 `json:"total_active_bans"`
	TotalPermanentBans uint64 `json:"total_permanent_bans"`
	TotalExpiredBans   uint64 `json:"total_expired_bans"`
	BansLast24h        uint64 `json:"bans_last_24h"`
	UnbansLast24h      uint64 `json:"unbans_last_24h"`
	RecidivistIPs      uint64 `json:"recidivist_ips"` // IPs banned more than once
	PendingSync        uint64 `json:"pending_sync"`   // Bans not yet synced to XGS
}

// BanFilters for querying bans
type BanFilters struct {
	Status    string `json:"status"`
	SyncedXGS *bool  `json:"synced_xgs"`
}

// Ban status constants
const (
	BanStatusActive    = "active"
	BanStatusExpired   = "expired"
	BanStatusPermanent = "permanent"
)

// Ban action constants (for history)
const (
	BanActionBan       = "ban"
	BanActionUnban     = "unban"
	BanActionExtend    = "extend"
	BanActionPermanent = "permanent"
	BanActionExpire    = "expire"
)

// Progressive ban durations
var ProgressiveBanDurations = []time.Duration{
	1 * time.Hour,  // 1st ban
	4 * time.Hour,  // 2nd ban
	24 * time.Hour, // 3rd ban
	// 4th+ = permanent
}

// RecidivismThreshold is the number of bans after which an IP becomes permanently banned
const RecidivismThreshold = 4

// IsPermanent returns true if the ban is permanent (no expiry)
func (b *BanStatus) IsPermanent() bool {
	return b.ExpiresAt == nil || b.Status == BanStatusPermanent
}

// IsExpired returns true if the ban has expired
func (b *BanStatus) IsExpired() bool {
	if b.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*b.ExpiresAt)
}

// IsRecidivist returns true if the IP has been banned multiple times
func (b *BanStatus) IsRecidivist() bool {
	return b.BanCount >= RecidivismThreshold
}

// GetNextBanDuration returns the duration for the next ban based on recidivism
func GetNextBanDuration(banCount uint8) *time.Duration {
	if int(banCount) >= len(ProgressiveBanDurations) {
		return nil // Permanent
	}
	duration := ProgressiveBanDurations[banCount]
	return &duration
}

// IsHard returns true if the whitelist entry is a hard whitelist (full bypass)
func (w *WhitelistEntry) IsHard() bool {
	return w.Type == WhitelistTypeHard
}

// IsSoft returns true if the whitelist entry is a soft whitelist (reduced score)
func (w *WhitelistEntry) IsSoft() bool {
	return w.Type == WhitelistTypeSoft
}

// IsMonitor returns true if the whitelist entry is monitor-only
func (w *WhitelistEntry) IsMonitor() bool {
	return w.Type == WhitelistTypeMonitor
}

// IsExpired returns true if the whitelist entry has expired
func (w *WhitelistEntry) IsExpired() bool {
	if w.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*w.ExpiresAt)
}

// GetEffectiveScoreModifier returns the score modifier percentage
func (w *WhitelistEntry) GetEffectiveScoreModifier() int32 {
	switch w.Type {
	case WhitelistTypeHard:
		return 100 // 100% reduction = score becomes 0
	case WhitelistTypeSoft:
		if w.ScoreModifier > 0 {
			return w.ScoreModifier
		}
		return 50 // Default 50% reduction for soft whitelist
	case WhitelistTypeMonitor:
		return 0 // No score modification
	default:
		return 0
	}
}

// CheckWhitelist evaluates an IP against a whitelist entry and returns the check result
func (w *WhitelistEntry) CheckWhitelist() *WhitelistCheckResult {
	if !w.IsActive || w.IsExpired() {
		return &WhitelistCheckResult{
			IsWhitelisted: false,
			EffectiveType: "none",
			AllowAutoBan:  true,
			AlertRequired: false,
		}
	}

	result := &WhitelistCheckResult{
		IsWhitelisted: true,
		Entry:         w,
		EffectiveType: w.Type,
		ScoreModifier: w.GetEffectiveScoreModifier(),
	}

	switch w.Type {
	case WhitelistTypeHard:
		result.AllowAutoBan = false
		result.AlertRequired = false
	case WhitelistTypeSoft:
		result.AllowAutoBan = !w.AlertOnly // Only allow if not alert-only
		result.AlertRequired = true
	case WhitelistTypeMonitor:
		result.AllowAutoBan = true
		result.AlertRequired = true
	}

	return result
}
