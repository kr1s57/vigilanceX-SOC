package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// PulsediveClient handles communication with Pulsedive API
// Pulsedive excels at IOC correlation and threat context
// Key value: Links IPs to threat actors, campaigns, and related indicators
type PulsediveClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// PulsediveConfig holds Pulsedive client configuration
type PulsediveConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewPulsediveClient creates a new Pulsedive client
func NewPulsediveClient(cfg PulsediveConfig) *PulsediveClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	return &PulsediveClient{
		apiKey:  cfg.APIKey,
		baseURL: "https://pulsedive.com/api",
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// PulsediveResponse represents the API response for indicator info
type PulsediveResponse struct {
	IID         int64               `json:"iid"`         // Indicator ID
	Indicator   string              `json:"indicator"`   // The IP address
	Type        string              `json:"type"`        // "ip"
	Risk        string              `json:"risk"`        // "none", "low", "medium", "high", "critical", "unknown"
	RiskFactors []PulsediveRisk     `json:"riskfactors"` // Why it's risky
	Threats     []PulsediveThreat   `json:"threats"`     // Associated threats
	Feeds       []PulsediveFeed     `json:"feeds"`       // Threat feeds containing this IP
	Attributes  PulsediveAttrs      `json:"attributes"`  // Technical attributes
	Summary     PulsediveSummary    `json:"summary"`     // Summary stats
	Stamp       string              `json:"stamp_seen"`  // Last seen timestamp
	StampAdded  string              `json:"stamp_added"` // When added to Pulsedive
}

// PulsediveRisk represents a risk factor
type PulsediveRisk struct {
	RFid        int    `json:"rfid"`
	Description string `json:"description"`
	Risk        string `json:"risk"` // Risk level this factor contributes
}

// PulsediveThreat represents an associated threat
type PulsediveThreat struct {
	TID         int    `json:"tid"`
	Name        string `json:"name"`
	Category    string `json:"category"` // "malware", "actor", "campaign"
	Risk        string `json:"risk"`
	Description string `json:"description"`
}

// PulsediveFeed represents a threat feed
type PulsediveFeed struct {
	FID         int    `json:"fid"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Organization string `json:"organization"`
}

// PulsediveAttrs contains technical attributes
type PulsediveAttrs struct {
	Port     []string `json:"port"`
	Protocol []string `json:"protocol"`
	Technology []string `json:"technology"`
}

// PulsediveSummary contains summary statistics
type PulsediveSummary struct {
	Properties PulsediveProperties `json:"properties"`
}

// PulsediveProperties contains property counts
type PulsediveProperties struct {
	Geo       map[string]interface{} `json:"geo"`
	Whois     map[string]interface{} `json:"whois"`
}

// PulsediveResult represents the processed result
type PulsediveResult struct {
	IP              string   `json:"ip"`
	Risk            string   `json:"risk"`              // none, low, medium, high, critical
	RiskFactors     []string `json:"risk_factors"`      // List of risk factor descriptions
	ThreatCount     int      `json:"threat_count"`      // Number of associated threats
	ThreatNames     []string `json:"threat_names"`      // Names of associated threats
	ThreatActors    []string `json:"threat_actors"`     // Associated threat actors
	Campaigns       []string `json:"campaigns"`         // Associated campaigns
	MalwareFamilies []string `json:"malware_families"`  // Associated malware
	FeedCount       int      `json:"feed_count"`        // Number of feeds containing this IP
	FeedNames       []string `json:"feed_names"`        // Feed names
	LastSeen        string   `json:"last_seen"`
	Technologies    []string `json:"technologies"`      // Detected technologies
	RawScore        int      `json:"raw_score"`
	NormalizedScore int      `json:"normalized_score"`  // 0-100 scale
}

// CheckIP queries Pulsedive for IP information
func (c *PulsediveClient) CheckIP(ctx context.Context, ip string) (*PulsediveResult, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("Pulsedive API key not configured")
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/info.php?indicator=%s&key=%s",
		c.baseURL, url.QueryEscape(ip), c.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// 404 means IP not found in Pulsedive - this is normal
	if resp.StatusCode == 404 {
		return &PulsediveResult{
			IP:              ip,
			Risk:            "unknown",
			ThreatCount:     0,
			FeedCount:       0,
			RawScore:        0,
			NormalizedScore: 0,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	var apiResp PulsediveResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Process threats by category
	threatNames := make([]string, 0)
	threatActors := make([]string, 0)
	campaigns := make([]string, 0)
	malware := make([]string, 0)

	for _, t := range apiResp.Threats {
		threatNames = append(threatNames, t.Name)
		switch t.Category {
		case "actor":
			threatActors = append(threatActors, t.Name)
		case "campaign":
			campaigns = append(campaigns, t.Name)
		case "malware":
			malware = append(malware, t.Name)
		}
	}

	// Extract risk factors
	riskFactors := make([]string, 0, len(apiResp.RiskFactors))
	for _, rf := range apiResp.RiskFactors {
		riskFactors = append(riskFactors, rf.Description)
	}

	// Extract feed names
	feedNames := make([]string, 0, len(apiResp.Feeds))
	for _, f := range apiResp.Feeds {
		feedNames = append(feedNames, f.Name)
	}

	// Calculate score
	score := c.calculateScore(apiResp)

	result := &PulsediveResult{
		IP:              apiResp.Indicator,
		Risk:            apiResp.Risk,
		RiskFactors:     riskFactors,
		ThreatCount:     len(apiResp.Threats),
		ThreatNames:     threatNames,
		ThreatActors:    threatActors,
		Campaigns:       campaigns,
		MalwareFamilies: malware,
		FeedCount:       len(apiResp.Feeds),
		FeedNames:       feedNames,
		LastSeen:        apiResp.Stamp,
		Technologies:    apiResp.Attributes.Technology,
		RawScore:        score,
		NormalizedScore: score,
	}

	return result, nil
}

// calculateScore determines threat score based on Pulsedive data
func (c *PulsediveClient) calculateScore(resp PulsediveResponse) int {
	score := 0

	// Base score from risk level
	switch resp.Risk {
	case "critical":
		score = 90
	case "high":
		score = 70
	case "medium":
		score = 45
	case "low":
		score = 20
	case "none", "unknown":
		score = 0
	default:
		score = 0
	}

	// Add points for threat associations
	for _, threat := range resp.Threats {
		switch threat.Category {
		case "actor":
			score += 15 // Associated with threat actor = very bad
		case "campaign":
			score += 10 // Part of a campaign
		case "malware":
			score += 12 // Associated with malware
		default:
			score += 5
		}
	}

	// Add points for feed presence (more feeds = more confidence)
	feedBonus := len(resp.Feeds) * 3
	if feedBonus > 20 {
		feedBonus = 20 // Cap feed bonus
	}
	score += feedBonus

	// Add points for risk factors
	score += len(resp.RiskFactors) * 5

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// GetProviderName returns the provider name
func (c *PulsediveClient) GetProviderName() string {
	return "Pulsedive"
}

// IsConfigured returns true if the client has an API key
func (c *PulsediveClient) IsConfigured() bool {
	return c.apiKey != ""
}
