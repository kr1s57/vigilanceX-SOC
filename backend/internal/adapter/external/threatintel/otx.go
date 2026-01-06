package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OTXClient handles communication with AlienVault OTX API
type OTXClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// OTXConfig holds OTX client configuration
type OTXConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewOTXClient creates a new AlienVault OTX client
func NewOTXClient(cfg OTXConfig) *OTXClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	return &OTXClient{
		apiKey:  cfg.APIKey,
		baseURL: "https://otx.alienvault.com/api/v1",
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// OTXGeneralResponse represents the general info response
type OTXGeneralResponse struct {
	Indicator      string   `json:"indicator"`
	Type           string   `json:"type"`
	TypeTitle      string   `json:"type_title"`
	PulseInfo      OTXPulseInfo `json:"pulse_info"`
	BaseIndicator  OTXBaseIndicator `json:"base_indicator"`
	Reputation     int      `json:"reputation"`
	Country        string   `json:"country_name"`
	CountryCode    string   `json:"country_code"`
	City           string   `json:"city"`
	ASN            string   `json:"asn"`
}

// OTXPulseInfo contains pulse (threat feed) information
type OTXPulseInfo struct {
	Count   int        `json:"count"`
	Pulses  []OTXPulse `json:"pulses"`
	Related OTXRelated `json:"related"`
}

// OTXPulse represents a single threat feed entry
type OTXPulse struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Created        string   `json:"created"`
	Modified       string   `json:"modified"`
	Tags           []string `json:"tags"`
	TLP            string   `json:"TLP"`
	Adversary      string   `json:"adversary"`
	TargetedCountries []string `json:"targeted_countries"`
	Industries     []string `json:"industries"`
	MalwareFamilies []string `json:"malware_families"`
	AttackIDs      []OTXAttackID `json:"attack_ids"`
}

// OTXAttackID represents MITRE ATT&CK mapping
type OTXAttackID struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// OTXRelated contains related indicators info
type OTXRelated struct {
	Alienvault OTXAlienvaultRelated `json:"alienvault"`
	Other      OTXOtherRelated      `json:"other"`
}

// OTXAlienvaultRelated contains AlienVault internal data
type OTXAlienvaultRelated struct {
	Adversary       []string `json:"adversary"`
	MalwareFamilies []string `json:"malware_families"`
	Industries      []string `json:"industries"`
}

// OTXOtherRelated contains external data
type OTXOtherRelated struct {
	Adversary       []string `json:"adversary"`
	MalwareFamilies []string `json:"malware_families"`
	Industries      []string `json:"industries"`
}

// OTXBaseIndicator contains base indicator info
type OTXBaseIndicator struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	Indicator   string `json:"indicator"`
	Description string `json:"description"`
	Title       string `json:"title"`
	AccessType  string `json:"access_type"`
}

// OTXReputationResponse represents the reputation endpoint response
type OTXReputationResponse struct {
	Reputation OTXReputationData `json:"reputation"`
}

// OTXReputationData contains reputation details
type OTXReputationData struct {
	ThreatScore  int      `json:"threat_score"`
	Counts       OTXCounts `json:"counts"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
	Activities   []OTXActivity `json:"activities"`
}

// OTXCounts contains activity counts
type OTXCounts struct {
	Activities int `json:"activities"`
	Pulses     int `json:"pulses"`
}

// OTXActivity represents a malicious activity
type OTXActivity struct {
	Name     string `json:"name"`
	LastSeen string `json:"last_seen"`
}

// OTXResult represents the processed result
type OTXResult struct {
	IP              string   `json:"ip"`
	PulseCount      int      `json:"pulse_count"`
	Reputation      int      `json:"reputation"`
	Country         string   `json:"country"`
	CountryCode     string   `json:"country_code"`
	ASN             string   `json:"asn"`
	ThreatScore     int      `json:"threat_score"`
	MalwareFamilies []string `json:"malware_families"`
	Adversaries     []string `json:"adversaries"`
	Industries      []string `json:"industries"`
	Tags            []string `json:"tags"`
	Activities      []string `json:"activities"`
	FirstSeen       string   `json:"first_seen"`
	LastSeen        string   `json:"last_seen"`
	RawScore        int      `json:"raw_score"`
	NormalizedScore int      `json:"normalized_score"` // 0-100 scale
}

// CheckIP queries AlienVault OTX for IP reputation
func (c *OTXClient) CheckIP(ctx context.Context, ip string) (*OTXResult, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("OTX API key not configured")
	}

	// Get general info
	generalURL := fmt.Sprintf("%s/indicators/IPv4/%s/general", c.baseURL, ip)
	general, err := c.fetchGeneral(ctx, generalURL)
	if err != nil {
		return nil, err
	}

	// Get reputation info
	reputationURL := fmt.Sprintf("%s/indicators/IPv4/%s/reputation", c.baseURL, ip)
	reputation, _ := c.fetchReputation(ctx, reputationURL) // Don't fail if reputation not available

	// Build result
	result := &OTXResult{
		IP:          ip,
		PulseCount:  general.PulseInfo.Count,
		Reputation:  general.Reputation,
		Country:     general.Country,
		CountryCode: general.CountryCode,
		ASN:         general.ASN,
	}

	// Extract malware families and adversaries from pulses
	malwareSet := make(map[string]bool)
	adversarySet := make(map[string]bool)
	industrySet := make(map[string]bool)
	tagSet := make(map[string]bool)

	for _, pulse := range general.PulseInfo.Pulses {
		for _, mf := range pulse.MalwareFamilies {
			malwareSet[mf] = true
		}
		if pulse.Adversary != "" {
			adversarySet[pulse.Adversary] = true
		}
		for _, ind := range pulse.Industries {
			industrySet[ind] = true
		}
		for _, tag := range pulse.Tags {
			tagSet[tag] = true
		}
	}

	// Add related data
	for _, mf := range general.PulseInfo.Related.Alienvault.MalwareFamilies {
		malwareSet[mf] = true
	}
	for _, adv := range general.PulseInfo.Related.Alienvault.Adversary {
		adversarySet[adv] = true
	}

	// Convert sets to slices
	for mf := range malwareSet {
		result.MalwareFamilies = append(result.MalwareFamilies, mf)
	}
	for adv := range adversarySet {
		result.Adversaries = append(result.Adversaries, adv)
	}
	for ind := range industrySet {
		result.Industries = append(result.Industries, ind)
	}
	for tag := range tagSet {
		result.Tags = append(result.Tags, tag)
	}

	// Add reputation data if available
	if reputation != nil {
		result.ThreatScore = reputation.Reputation.ThreatScore
		result.FirstSeen = reputation.Reputation.FirstSeen
		result.LastSeen = reputation.Reputation.LastSeen

		for _, act := range reputation.Reputation.Activities {
			result.Activities = append(result.Activities, act.Name)
		}
	}

	// Calculate normalized score (0-100)
	// Based on pulse count, threat score, and reputation
	normalizedScore := 0

	// Pulse count contribution (max 50 points)
	if result.PulseCount > 0 {
		pulseScore := result.PulseCount * 5
		if pulseScore > 50 {
			pulseScore = 50
		}
		normalizedScore += pulseScore
	}

	// Threat score contribution (max 30 points)
	if result.ThreatScore > 0 {
		threatContrib := result.ThreatScore * 3 / 10
		if threatContrib > 30 {
			threatContrib = 30
		}
		normalizedScore += threatContrib
	}

	// Malware families contribution (max 20 points)
	if len(result.MalwareFamilies) > 0 {
		malwareScore := len(result.MalwareFamilies) * 5
		if malwareScore > 20 {
			malwareScore = 20
		}
		normalizedScore += malwareScore
	}

	// Cap at 100
	if normalizedScore > 100 {
		normalizedScore = 100
	}

	result.RawScore = result.PulseCount
	result.NormalizedScore = normalizedScore

	return result, nil
}

// fetchGeneral fetches general indicator info
func (c *OTXClient) fetchGeneral(ctx context.Context, url string) (*OTXGeneralResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-OTX-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	var result OTXGeneralResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

// fetchReputation fetches reputation info
func (c *OTXClient) fetchReputation(ctx context.Context, url string) (*OTXReputationResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-OTX-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var result OTXReputationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetProviderName returns the provider name
func (c *OTXClient) GetProviderName() string {
	return "AlienVault OTX"
}

// IsConfigured returns true if the client has an API key
func (c *OTXClient) IsConfigured() bool {
	return c.apiKey != ""
}
