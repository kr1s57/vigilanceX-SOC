package entity

import (
	"time"
)

// GeoBlockRule represents a geoblocking rule (v2.0)
type GeoBlockRule struct {
	ID            string    `json:"id" ch:"id"`
	RuleType      string    `json:"rule_type" ch:"rule_type"`           // country_block, country_watch, asn_block, asn_watch
	Target        string    `json:"target" ch:"target"`                 // Country code (FR, US, RU) or ASN number
	Action        string    `json:"action" ch:"action"`                 // block, watch, boost
	ScoreModifier int32     `json:"score_modifier" ch:"score_modifier"` // Points to add (positive) or subtract (negative)
	Reason        string    `json:"reason" ch:"reason"`
	IsActive      bool      `json:"is_active" ch:"is_active"`
	CreatedBy     string    `json:"created_by" ch:"created_by"`
	CreatedAt     time.Time `json:"created_at" ch:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" ch:"updated_at"`
}

// GeoBlockRuleType constants
const (
	GeoRuleTypeCountryBlock = "country_block" // Auto-ban IPs from this country
	GeoRuleTypeCountryWatch = "country_watch" // Score boost for IPs from this country
	GeoRuleTypeASNBlock     = "asn_block"     // Auto-ban IPs from this ASN
	GeoRuleTypeASNWatch     = "asn_watch"     // Score boost for IPs from this ASN
)

// GeoBlockAction constants
const (
	GeoActionBlock = "block" // Auto-ban
	GeoActionWatch = "watch" // Increased monitoring / score boost
	GeoActionBoost = "boost" // Only boost score, no auto-action
)

// GeoLocation represents geolocation data for an IP (v2.0)
type GeoLocation struct {
	IP           string    `json:"ip" ch:"ip"`
	CountryCode  string    `json:"country_code" ch:"country_code"`
	CountryName  string    `json:"country_name" ch:"country_name"`
	City         string    `json:"city" ch:"city"`
	Region       string    `json:"region" ch:"region"`
	ASN          uint32    `json:"asn" ch:"asn"`
	ASOrg        string    `json:"as_org" ch:"as_org"`
	IsVPN        bool      `json:"is_vpn" ch:"is_vpn"`
	IsProxy      bool      `json:"is_proxy" ch:"is_proxy"`
	IsTor        bool      `json:"is_tor" ch:"is_tor"`
	IsDatacenter bool      `json:"is_datacenter" ch:"is_datacenter"`
	Latitude     float64   `json:"latitude" ch:"latitude"`
	Longitude    float64   `json:"longitude" ch:"longitude"`
	LastUpdated  time.Time `json:"last_updated" ch:"last_updated"`
}

// GeoBlockRequest represents a request to create/update a geoblocking rule
type GeoBlockRequest struct {
	RuleType      string `json:"rule_type" validate:"required"`
	Target        string `json:"target" validate:"required"` // Country code or ASN
	Action        string `json:"action" validate:"required"`
	ScoreModifier int32  `json:"score_modifier"`
	Reason        string `json:"reason"`
	CreatedBy     string `json:"created_by"`
}

// GeoCheckResult represents the result of checking an IP against geoblocking rules
type GeoCheckResult struct {
	IP              string         `json:"ip"`
	GeoLocation     *GeoLocation   `json:"geo_location,omitempty"`
	MatchedRules    []GeoBlockRule `json:"matched_rules"`
	TotalScoreBoost int32          `json:"total_score_boost"`
	ShouldBlock     bool           `json:"should_block"`
	BlockReason     string         `json:"block_reason,omitempty"`
	RiskFactors     []string       `json:"risk_factors"`
}

// CountryRiskLevel defines risk levels for countries
type CountryRiskLevel struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	RiskLevel   string `json:"risk_level"` // low, medium, high, critical
	BaseScore   int    `json:"base_score"` // 0-100 base score for this country
	Reason      string `json:"reason"`
}

// DefaultHighRiskCountries returns a list of typically high-risk countries
// This is used as default configuration, can be overridden by rules
func DefaultHighRiskCountries() []CountryRiskLevel {
	return []CountryRiskLevel{
		{CountryCode: "KP", CountryName: "North Korea", RiskLevel: "critical", BaseScore: 90, Reason: "Sanctioned country"},
		{CountryCode: "IR", CountryName: "Iran", RiskLevel: "high", BaseScore: 70, Reason: "High threat activity"},
		{CountryCode: "RU", CountryName: "Russia", RiskLevel: "high", BaseScore: 60, Reason: "High threat activity"},
		{CountryCode: "CN", CountryName: "China", RiskLevel: "medium", BaseScore: 40, Reason: "Elevated threat activity"},
		{CountryCode: "BY", CountryName: "Belarus", RiskLevel: "medium", BaseScore: 40, Reason: "Elevated threat activity"},
	}
}

// ASNRiskProfile represents risk assessment for an ASN
type ASNRiskProfile struct {
	ASN             uint32 `json:"asn"`
	ASOrg           string `json:"as_org"`
	RiskLevel       string `json:"risk_level"`
	BaseScore       int    `json:"base_score"`
	IsBulletproof   bool   `json:"is_bulletproof"` // Known bulletproof hosting
	IsCloudProvider bool   `json:"is_cloud_provider"`
	Reason          string `json:"reason"`
}

// GeoBlockStats represents geoblocking statistics
type GeoBlockStats struct {
	TotalRules       int            `json:"total_rules"`
	ActiveRules      int            `json:"active_rules"`
	RulesByType      map[string]int `json:"rules_by_type"`
	RulesByAction    map[string]int `json:"rules_by_action"`
	BlockedCountries []string       `json:"blocked_countries"`
	WatchedCountries []string       `json:"watched_countries"`
	BlockedASNs      []uint32       `json:"blocked_asns"`
}

// IsCountryBlocked checks if a country code is in the blocked list
func IsCountryBlocked(countryCode string, rules []GeoBlockRule) bool {
	for _, rule := range rules {
		if rule.IsActive && rule.RuleType == GeoRuleTypeCountryBlock && rule.Target == countryCode {
			return true
		}
	}
	return false
}

// GetCountryScoreModifier returns the score modifier for a country
func GetCountryScoreModifier(countryCode string, rules []GeoBlockRule) int32 {
	var modifier int32 = 0
	for _, rule := range rules {
		if rule.IsActive && rule.Target == countryCode {
			modifier += rule.ScoreModifier
		}
	}
	return modifier
}

// IsASNBlocked checks if an ASN is in the blocked list
func IsASNBlocked(asn uint32, rules []GeoBlockRule) bool {
	asnStr := string(rune(asn)) // Convert to string for comparison
	for _, rule := range rules {
		if rule.IsActive && rule.RuleType == GeoRuleTypeASNBlock && rule.Target == asnStr {
			return true
		}
	}
	return false
}
