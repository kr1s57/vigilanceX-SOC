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
	TriggerRule  string     `json:"trigger_rule" ch:"trigger_rule"`
	TriggerEvent uuid.UUID  `json:"trigger_event_id" ch:"trigger_event_id"`
	SyncedXGS    bool       `json:"synced_xgs" ch:"synced_xgs"`
	CreatedBy    string     `json:"created_by" ch:"created_by"`
	Version      uint64     `json:"-" ch:"version"`
}

// BanHistory represents a ban/unban action in the audit trail
type BanHistory struct {
	ID             uuid.UUID  `json:"id" ch:"id"`
	Timestamp      time.Time  `json:"timestamp" ch:"timestamp"`
	IP             string     `json:"ip" ch:"ip"`
	Action         string     `json:"action" ch:"action"`
	PreviousStatus string     `json:"previous_status" ch:"previous_status"`
	NewStatus      string     `json:"new_status" ch:"new_status"`
	DurationHours  *uint32    `json:"duration_hours" ch:"duration_hours"`
	Reason         string     `json:"reason" ch:"reason"`
	PerformedBy    string     `json:"performed_by" ch:"performed_by"`
	Metadata       string     `json:"metadata" ch:"metadata"`
}

// WhitelistEntry represents a whitelisted IP
type WhitelistEntry struct {
	IP          string    `json:"ip" ch:"ip"`
	CIDRMask    uint8     `json:"cidr_mask" ch:"cidr_mask"`
	Description string    `json:"description" ch:"description"`
	CreatedAt   time.Time `json:"created_at" ch:"created_at"`
	CreatedBy   string    `json:"created_by" ch:"created_by"`
	IsActive    bool      `json:"is_active" ch:"is_active"`
	Version     uint64    `json:"-" ch:"version"`
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
	TotalActiveBans    int64 `json:"total_active_bans"`
	TotalPermanentBans int64 `json:"total_permanent_bans"`
	TotalExpiredBans   int64 `json:"total_expired_bans"`
	BansLast24h        int64 `json:"bans_last_24h"`
	UnbansLast24h      int64 `json:"unbans_last_24h"`
	RecidivistIPs      int64 `json:"recidivist_ips"` // IPs banned more than once
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
	1 * time.Hour,   // 1st ban
	4 * time.Hour,   // 2nd ban
	24 * time.Hour,  // 3rd ban
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
