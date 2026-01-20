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
	ImmuneUntil  *time.Time `json:"immune_until" ch:"immune_until"` // Immunity from auto-ban until this time
	CreatedBy    string     `json:"created_by" ch:"created_by"`
	UpdatedAt    time.Time  `json:"updated_at" ch:"updated_at"`
	Version      uint64     `json:"-" ch:"version"`
	Country      string     `json:"country,omitempty"` // Country code (enriched via GeoIP, not stored in DB)

	// D2B v2 Fields (v3.52)
	CurrentTier      uint8      `json:"current_tier" ch:"current_tier"`               // 0=initial, 1=1st recidiv, 2=2nd recidiv, 3+=permanent
	ConditionalUntil *time.Time `json:"conditional_until" ch:"conditional_until"`     // End of conditional survey period
	GeoZone          string     `json:"geo_zone" ch:"geo_zone"`                       // authorized, hostile, neutral
	ThreatScoreAtBan int        `json:"threat_score_at_ban" ch:"threat_score_at_ban"` // Threat score when banned
	XGSGroup         string     `json:"xgs_group" ch:"xgs_group"`                     // grp_VGX-BannedIP or grp_VGX-BannedPerm
}

// BanHistory represents a ban/unban action in the audit trail
type BanHistory struct {
	ID            uuid.UUID `json:"id" ch:"id"`
	Timestamp     time.Time `json:"timestamp" ch:"timestamp"`
	IP            string    `json:"ip" ch:"ip"`
	Action        string    `json:"action" ch:"action"`
	DurationHours int       `json:"duration_hours" ch:"duration_hours"`
	Reason        string    `json:"reason" ch:"reason"`
	Source        string    `json:"source" ch:"source"` // manual, detect2ban, threat_intel, policy
	PerformedBy   string    `json:"performed_by" ch:"performed_by"`
	SyncedXGS     bool      `json:"synced_xgs" ch:"synced_xgs"`
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
	IP            string `json:"ip" validate:"required,ip"`
	Reason        string `json:"reason"`
	PerformedBy   string `json:"performed_by"`
	ImmunityHours int    `json:"immunity_hours"` // Hours of immunity from auto-ban (0 = no immunity)
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

	// D2B v2 Status (v3.52)
	BanStatusConditional   = "conditional"      // Under post-unban surveillance
	BanStatusPending       = "pending_approval" // Awaiting admin review
	BanStatusBanWAFHzone   = "ban_waf_hzone"    // WAF ban from hostile zone
	BanStatusBanWAFZone    = "ban_waf_zone"     // WAF ban from authorized zone (threat confirmed)
	BanStatusBanWAFPending = "ban_waf_pending"  // WAF detection from authorized zone, awaiting review
)

// Ban action constants (for history)
const (
	BanActionBan           = "ban"
	BanActionUnban         = "unban"
	BanActionUnbanImmunity = "unban_immunity" // Unban with temporary immunity from auto-ban
	BanActionExtend        = "extend"
	BanActionPermanent     = "permanent"
	BanActionExpire        = "expire"

	// D2B v2 Actions (v3.52)
	BanActionUnbanConditional = "unban_conditional" // Unban with conditional surveillance
	BanActionEscalate         = "escalate"          // Tier escalation due to recidive
	BanActionApprove          = "approve"           // Admin approved pending ban
	BanActionReject           = "reject"            // Admin rejected pending ban
)

// GeoZone constants (D2B v2)
const (
	GeoZoneAuthorized = "authorized" // Trusted countries
	GeoZoneHostile    = "hostile"    // Untrusted countries - immediate ban
	GeoZoneNeutral    = "neutral"    // Default - standard processing
)

// XGS Group constants (D2B v2)
const (
	XGSGroupTempBan = "grp_VGX-BannedIP"   // Temporary bans (Tier 0-2)
	XGSGroupPermBan = "grp_VGX-BannedPerm" // Permanent bans (Tier 3+)
)

// Progressive ban durations by tier (D2B v2)
var TierBanDurations = map[uint8]time.Duration{
	0: 4 * time.Hour,      // Tier 0: Initial ban
	1: 24 * time.Hour,     // Tier 1: 1st recidive
	2: 7 * 24 * time.Hour, // Tier 2: 2nd recidive
	// Tier 3+ = Permanent
}

// ConditionalSurveyDuration is the surveillance period after unban (D2B v2)
const ConditionalSurveyDuration = 30 * 24 * time.Hour // 30 days

// PermanentTierThreshold is the tier at which bans become permanent
const PermanentTierThreshold uint8 = 3

// Legacy progressive ban durations (kept for backward compatibility)
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

// IsImmune returns true if the IP has active immunity from auto-ban
func (b *BanStatus) IsImmune() bool {
	if b.ImmuneUntil == nil {
		return false
	}
	return time.Now().Before(*b.ImmuneUntil)
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

// ============================================================================
// D2B v2 - GeoZone Configuration (v3.52)
// ============================================================================

// GeoZoneConfig holds geographic zone configuration for ban decisions
type GeoZoneConfig struct {
	Enabled              bool     `json:"enabled"`
	AuthorizedCountries  []string `json:"authorized_countries"`   // ISO 3166-1 alpha-2 codes (FR, BE, LU, DE, CH...)
	HostileCountries     []string `json:"hostile_countries"`      // Explicit blocklist (optional)
	DefaultPolicy        string   `json:"default_policy"`         // "hostile" or "neutral" for unlisted countries
	WAFThresholdHzone    int      `json:"waf_threshold_hzone"`    // Events before ban for hostile zone (default: 1)
	WAFThresholdZone     int      `json:"waf_threshold_zone"`     // Events before TI check for authorized zone (default: 3)
	ThreatScoreThreshold int      `json:"threat_score_threshold"` // Min score to auto-ban in authorized zone (default: 50)
}

// DefaultGeoZoneConfig returns sensible defaults
func DefaultGeoZoneConfig() *GeoZoneConfig {
	return &GeoZoneConfig{
		Enabled: false,
		AuthorizedCountries: []string{
			"FR", "BE", "LU", "DE", "CH", "NL", "GB", "ES", "IT", "PT", "AT",
		},
		HostileCountries:     []string{},
		DefaultPolicy:        GeoZoneNeutral,
		WAFThresholdHzone:    1,  // Immediate ban for hostile zone
		WAFThresholdZone:     3,  // 3 events before TI check
		ThreatScoreThreshold: 50, // 50% threat score to auto-ban
	}
}

// ClassifyCountry determines the zone for a country code
func (c *GeoZoneConfig) ClassifyCountry(countryCode string) string {
	if !c.Enabled {
		return GeoZoneNeutral
	}

	// Check hostile list first
	for _, cc := range c.HostileCountries {
		if cc == countryCode {
			return GeoZoneHostile
		}
	}

	// Check authorized list
	for _, cc := range c.AuthorizedCountries {
		if cc == countryCode {
			return GeoZoneAuthorized
		}
	}

	// Return default policy
	return c.DefaultPolicy
}

// PendingBan represents a ban awaiting admin approval (D2B v2)
// v3.57.116: Changed ThreatScore and EventCount to int32 for ClickHouse compatibility
// v3.57.118: Added PendingType to distinguish country_policy vs false_positive
type PendingBan struct {
	ID            string     `json:"id" ch:"id"`
	IP            string     `json:"ip" ch:"ip"`
	Country       string     `json:"country" ch:"country"`
	GeoZone       string     `json:"geo_zone" ch:"geo_zone"`
	ThreatScore   int32      `json:"threat_score" ch:"threat_score"`
	ThreatSources []string   `json:"threat_sources" ch:"threat_sources"`
	EventCount    uint32     `json:"event_count" ch:"event_count"`
	FirstEvent    time.Time  `json:"first_event" ch:"first_event"`
	LastEvent     time.Time  `json:"last_event" ch:"last_event"`
	TriggerRule   string     `json:"trigger_rule" ch:"trigger_rule"`
	Reason        string     `json:"reason" ch:"reason"`
	Status        string     `json:"status" ch:"status"` // pending, approved, rejected, expired
	CreatedAt     time.Time  `json:"created_at" ch:"created_at"`
	ReviewedAt    *time.Time `json:"reviewed_at" ch:"reviewed_at"`
	ReviewedBy    string     `json:"reviewed_by" ch:"reviewed_by"`
	ReviewNote    string     `json:"review_note" ch:"review_note"`
	// v3.57.118: False Positive detection fields
	PendingType  string `json:"pending_type" ch:"pending_type"`     // country_policy, false_positive
	FPRuleID     string `json:"fp_rule_id" ch:"fp_rule_id"`         // Rule ID causing false positive
	FPURI        string `json:"fp_uri" ch:"fp_uri"`                 // URI pattern causing false positive
	FPHostname   string `json:"fp_hostname" ch:"fp_hostname"`       // Target hostname
	FPMatchCount uint32 `json:"fp_match_count" ch:"fp_match_count"` // Identical pattern occurrences
}

// PendingType constants (v3.57.118)
const (
	PendingTypeCountryPolicy = "country_policy" // From authorized country requiring approval
	PendingTypeFalsePositive = "false_positive" // Detected as potential false positive
)

// False positive detection threshold (v3.57.118)
// If same IP triggers 10+ identical attacks (same rule_id + same URI), it's likely a FP
const FalsePositiveThreshold = 10

// PendingBanStats for dashboard widgets
// v3.57.117: Changed to uint64 for ClickHouse count() compatibility
// v3.57.118: Added FalsePositiveCount for FP detection
type PendingBanStats struct {
	TotalPending       uint64     `json:"total_pending"`
	HighThreat         uint64     `json:"high_threat"`   // Score >= 70
	MediumThreat       uint64     `json:"medium_threat"` // Score 30-69
	LowThreat          uint64     `json:"low_threat"`    // Score < 30
	OldestPending      *time.Time `json:"oldest_pending"`
	FalsePositiveCount uint64     `json:"false_positive_count"` // v3.57.118: FP detections
	CountryPolicyCount uint64     `json:"country_policy_count"` // v3.57.118: Country policy detections
}

// ============================================================================
// D2B v2 - Additional BanStatus Methods (v3.52)
// ============================================================================

// IsConditional returns true if the IP is under conditional surveillance
func (b *BanStatus) IsConditional() bool {
	if b.Status != BanStatusConditional {
		return false
	}
	if b.ConditionalUntil == nil {
		return false
	}
	return time.Now().Before(*b.ConditionalUntil)
}

// IsPendingApproval returns true if the ban is awaiting admin review
func (b *BanStatus) IsPendingApproval() bool {
	return b.Status == BanStatusPending || b.Status == BanStatusBanWAFPending
}

// GetTierDuration returns the ban duration for the current tier
func (b *BanStatus) GetTierDuration() *time.Duration {
	if b.CurrentTier >= PermanentTierThreshold {
		return nil // Permanent
	}
	if duration, ok := TierBanDurations[b.CurrentTier]; ok {
		return &duration
	}
	// Fallback to tier 0
	duration := TierBanDurations[0]
	return &duration
}

// ShouldEscalate returns true if recidive during conditional survey
func (b *BanStatus) ShouldEscalate() bool {
	return b.IsConditional()
}

// GetNextTier returns the next tier after escalation
func (b *BanStatus) GetNextTier() uint8 {
	next := b.CurrentTier + 1
	if next > PermanentTierThreshold {
		return PermanentTierThreshold
	}
	return next
}

// GetXGSGroup returns the appropriate XGS group based on tier
func (b *BanStatus) GetXGSGroup() string {
	if b.CurrentTier >= PermanentTierThreshold || b.Status == BanStatusPermanent {
		return XGSGroupPermBan
	}
	return XGSGroupTempBan
}
