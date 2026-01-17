package entity

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// WAFMonitoredServer represents a web server monitored for WAF events
// with optional country access policy
type WAFMonitoredServer struct {
	ID          uuid.UUID `json:"id" ch:"id"`
	Hostname    string    `json:"hostname" ch:"hostname"`
	DisplayName string    `json:"display_name" ch:"display_name"`
	Description string    `json:"description" ch:"description"`

	// Country Access Policy
	PolicyEnabled  bool     `json:"policy_enabled" ch:"policy_enabled"`
	PolicyMode     string   `json:"policy_mode" ch:"policy_mode"` // none, whitecountry, blockcountry
	WhiteCountries []string `json:"white_countries" ch:"white_countries"`
	BlockCountries []string `json:"block_countries" ch:"block_countries"`

	// WAF Settings
	WAFThreshold    uint8  `json:"waf_threshold" ch:"waf_threshold"`
	CustomBanReason string `json:"custom_ban_reason" ch:"custom_ban_reason"`

	// Status
	Enabled bool `json:"enabled" ch:"enabled"`

	// Audit
	CreatedAt time.Time `json:"created_at" ch:"created_at"`
	CreatedBy string    `json:"created_by" ch:"created_by"`
	UpdatedAt time.Time `json:"updated_at" ch:"updated_at"`
	Version   uint64    `json:"-" ch:"version"`
}

// WAFServerRequest represents a request to create or update a WAF server
type WAFServerRequest struct {
	Hostname        string   `json:"hostname" validate:"required"`
	DisplayName     string   `json:"display_name"`
	Description     string   `json:"description"`
	PolicyEnabled   bool     `json:"policy_enabled"`
	PolicyMode      string   `json:"policy_mode"`
	WhiteCountries  []string `json:"white_countries"`
	BlockCountries  []string `json:"block_countries"`
	WAFThreshold    uint8    `json:"waf_threshold"`
	CustomBanReason string   `json:"custom_ban_reason"`
	Enabled         bool     `json:"enabled"`
}

// PolicyCheckResult represents the result of a country policy check
type PolicyCheckResult struct {
	ShouldBan bool   `json:"should_ban"`
	BanReason string `json:"ban_reason"`
	PolicyHit string `json:"policy_hit"` // whitecountry, blockcountry, or empty
}

// Policy mode constants
const (
	PolicyModeNone         = "none"
	PolicyModeWhiteCountry = "whitecountry"
	PolicyModeBlockCountry = "blockcountry"
)

// CheckCountryPolicy evaluates whether an IP from a given country should be banned
// based on the server's country access policy
func (s *WAFMonitoredServer) CheckCountryPolicy(countryCode string) *PolicyCheckResult {
	result := &PolicyCheckResult{
		ShouldBan: false,
		BanReason: "",
		PolicyHit: "",
	}

	// Skip if policy not enabled or no mode set
	if !s.PolicyEnabled || s.PolicyMode == PolicyModeNone || s.PolicyMode == "" {
		return result
	}

	switch s.PolicyMode {
	case PolicyModeWhiteCountry:
		// Check if country is in whitelist
		inWhitelist := false
		for _, cc := range s.WhiteCountries {
			if cc == countryCode {
				inWhitelist = true
				break
			}
		}
		if !inWhitelist {
			result.ShouldBan = true
			result.PolicyHit = PolicyModeWhiteCountry
			if s.CustomBanReason != "" {
				result.BanReason = s.CustomBanReason
			} else {
				result.BanReason = fmt.Sprintf("CountryPolicy: %s - Country %s not in whitelist", s.Hostname, countryCode)
			}
		}

	case PolicyModeBlockCountry:
		// Check if country is in blocklist
		for _, cc := range s.BlockCountries {
			if cc == countryCode {
				result.ShouldBan = true
				result.PolicyHit = PolicyModeBlockCountry
				if s.CustomBanReason != "" {
					result.BanReason = s.CustomBanReason
				} else {
					result.BanReason = fmt.Sprintf("CountryPolicy: %s - Country %s is blocked", s.Hostname, countryCode)
				}
				break
			}
		}
	}

	return result
}

// IsValid validates the WAF server request
func (r *WAFServerRequest) IsValid() error {
	if r.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	// Validate policy mode
	if r.PolicyMode != "" {
		switch r.PolicyMode {
		case PolicyModeNone, PolicyModeWhiteCountry, PolicyModeBlockCountry:
			// Valid
		default:
			return fmt.Errorf("invalid policy_mode: must be 'none', 'whitecountry', or 'blockcountry'")
		}
	}

	// Validate country codes (must be 2 letters)
	for _, cc := range r.WhiteCountries {
		if len(cc) != 2 {
			return fmt.Errorf("invalid country code in white_countries: %s (must be 2 letters)", cc)
		}
	}
	for _, cc := range r.BlockCountries {
		if len(cc) != 2 {
			return fmt.Errorf("invalid country code in block_countries: %s (must be 2 letters)", cc)
		}
	}

	// Validate WAF threshold
	if r.WAFThreshold == 0 {
		r.WAFThreshold = 5 // Default threshold
	}

	return nil
}

// ToEntity converts a request to a WAFMonitoredServer entity
func (r *WAFServerRequest) ToEntity(createdBy string) *WAFMonitoredServer {
	now := time.Now()
	policyMode := r.PolicyMode
	if policyMode == "" {
		policyMode = PolicyModeNone
	}

	wafThreshold := r.WAFThreshold
	if wafThreshold == 0 {
		wafThreshold = 5
	}

	return &WAFMonitoredServer{
		ID:              uuid.New(),
		Hostname:        r.Hostname,
		DisplayName:     r.DisplayName,
		Description:     r.Description,
		PolicyEnabled:   r.PolicyEnabled,
		PolicyMode:      policyMode,
		WhiteCountries:  r.WhiteCountries,
		BlockCountries:  r.BlockCountries,
		WAFThreshold:    wafThreshold,
		CustomBanReason: r.CustomBanReason,
		Enabled:         r.Enabled,
		CreatedAt:       now,
		CreatedBy:       createdBy,
		UpdatedAt:       now,
		Version:         uint64(now.UnixNano()),
	}
}

// ApplyUpdate applies a request update to an existing server
func (s *WAFMonitoredServer) ApplyUpdate(r *WAFServerRequest) {
	if r.DisplayName != "" {
		s.DisplayName = r.DisplayName
	}
	if r.Description != "" {
		s.Description = r.Description
	}
	s.PolicyEnabled = r.PolicyEnabled
	if r.PolicyMode != "" {
		s.PolicyMode = r.PolicyMode
	}
	if r.WhiteCountries != nil {
		s.WhiteCountries = r.WhiteCountries
	}
	if r.BlockCountries != nil {
		s.BlockCountries = r.BlockCountries
	}
	if r.WAFThreshold > 0 {
		s.WAFThreshold = r.WAFThreshold
	}
	s.CustomBanReason = r.CustomBanReason
	s.Enabled = r.Enabled
	s.UpdatedAt = time.Now()
	s.Version = uint64(time.Now().UnixNano())
}

// WAFServerWithStats extends WAFMonitoredServer with runtime statistics
type WAFServerWithStats struct {
	WAFMonitoredServer
	EventCount24h    int64      `json:"event_count_24h"`
	LastEventTime    *time.Time `json:"last_event_time,omitempty"`
	IsAutoDiscovered bool       `json:"is_auto_discovered"` // True if discovered from logs, not manually added
}
