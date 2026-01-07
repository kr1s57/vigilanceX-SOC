package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// VirusTotalClient handles communication with VirusTotal API
type VirusTotalClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// VirusTotalConfig holds VirusTotal client configuration
type VirusTotalConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewVirusTotalClient creates a new VirusTotal client
func NewVirusTotalClient(cfg VirusTotalConfig) *VirusTotalClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}

	return &VirusTotalClient{
		apiKey:  cfg.APIKey,
		baseURL: "https://www.virustotal.com/api/v3",
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// VirusTotalIPResponse represents the API response for IP lookup
type VirusTotalIPResponse struct {
	Data VirusTotalIPData `json:"data"`
}

// VirusTotalIPData contains the IP attributes
type VirusTotalIPData struct {
	Type       string                 `json:"type"`
	ID         string                 `json:"id"`
	Attributes VirusTotalIPAttributes `json:"attributes"`
}

// VirusTotalIPAttributes contains detailed IP information
type VirusTotalIPAttributes struct {
	ASN                      int                               `json:"asn"`
	ASOwner                  string                            `json:"as_owner"`
	Country                  string                            `json:"country"`
	Continent                string                            `json:"continent"`
	Network                  string                            `json:"network"`
	RegionalInternetRegistry string                            `json:"regional_internet_registry"`
	Reputation               int                               `json:"reputation"`
	LastAnalysisStats        VirusTotalAnalysisStats           `json:"last_analysis_stats"`
	LastAnalysisResults      map[string]VirusTotalEngineResult `json:"last_analysis_results"`
	Tags                     []string                          `json:"tags"`
	TotalVotes               VirusTotalVotes                   `json:"total_votes"`
	LastModificationDate     int64                             `json:"last_modification_date"`
	LastAnalysisDate         int64                             `json:"last_analysis_date"`
}

// VirusTotalAnalysisStats contains detection statistics
type VirusTotalAnalysisStats struct {
	Harmless   int `json:"harmless"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Timeout    int `json:"timeout"`
	Undetected int `json:"undetected"`
}

// VirusTotalEngineResult contains individual engine results
type VirusTotalEngineResult struct {
	Category   string `json:"category"`
	Result     string `json:"result"`
	Method     string `json:"method"`
	EngineName string `json:"engine_name"`
}

// VirusTotalVotes contains community votes
type VirusTotalVotes struct {
	Harmless  int `json:"harmless"`
	Malicious int `json:"malicious"`
}

// VirusTotalResult represents the processed result
type VirusTotalResult struct {
	IP              string   `json:"ip"`
	ASN             int      `json:"asn"`
	ASOwner         string   `json:"as_owner"`
	Country         string   `json:"country"`
	Network         string   `json:"network"`
	Reputation      int      `json:"reputation"`
	MaliciousCount  int      `json:"malicious_count"`
	SuspiciousCount int      `json:"suspicious_count"`
	HarmlessCount   int      `json:"harmless_count"`
	TotalEngines    int      `json:"total_engines"`
	Tags            []string `json:"tags"`
	VotesHarmless   int      `json:"votes_harmless"`
	VotesMalicious  int      `json:"votes_malicious"`
	LastAnalysis    int64    `json:"last_analysis"`
	RawScore        int      `json:"raw_score"`
	NormalizedScore int      `json:"normalized_score"` // 0-100 scale
}

// CheckIP queries VirusTotal for IP reputation
func (c *VirusTotalClient) CheckIP(ctx context.Context, ip string) (*VirusTotalResult, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not configured")
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/ip_addresses/%s", c.baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	if resp.StatusCode == 404 {
		// IP not found in VT database - return zero score
		return &VirusTotalResult{
			IP:              ip,
			NormalizedScore: 0,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	var apiResp VirusTotalIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	attrs := apiResp.Data.Attributes

	// Calculate total engines
	totalEngines := attrs.LastAnalysisStats.Harmless +
		attrs.LastAnalysisStats.Malicious +
		attrs.LastAnalysisStats.Suspicious +
		attrs.LastAnalysisStats.Undetected

	// Calculate normalized score (0-100)
	// Based on malicious + suspicious detections vs total
	normalizedScore := 0
	if totalEngines > 0 {
		maliciousRatio := float64(attrs.LastAnalysisStats.Malicious+attrs.LastAnalysisStats.Suspicious) / float64(totalEngines)
		normalizedScore = int(maliciousRatio * 100)
	}

	// Adjust score based on reputation (VT reputation is -100 to 100, negative = bad)
	if attrs.Reputation < 0 {
		reputationPenalty := -attrs.Reputation // Convert to positive
		if reputationPenalty > 50 {
			reputationPenalty = 50
		}
		normalizedScore += reputationPenalty
	}

	// Cap at 100
	if normalizedScore > 100 {
		normalizedScore = 100
	}

	result := &VirusTotalResult{
		IP:              ip,
		ASN:             attrs.ASN,
		ASOwner:         attrs.ASOwner,
		Country:         attrs.Country,
		Network:         attrs.Network,
		Reputation:      attrs.Reputation,
		MaliciousCount:  attrs.LastAnalysisStats.Malicious,
		SuspiciousCount: attrs.LastAnalysisStats.Suspicious,
		HarmlessCount:   attrs.LastAnalysisStats.Harmless,
		TotalEngines:    totalEngines,
		Tags:            attrs.Tags,
		VotesHarmless:   attrs.TotalVotes.Harmless,
		VotesMalicious:  attrs.TotalVotes.Malicious,
		LastAnalysis:    attrs.LastAnalysisDate,
		RawScore:        attrs.LastAnalysisStats.Malicious + attrs.LastAnalysisStats.Suspicious,
		NormalizedScore: normalizedScore,
	}

	return result, nil
}

// GetProviderName returns the provider name
func (c *VirusTotalClient) GetProviderName() string {
	return "VirusTotal"
}

// IsConfigured returns true if the client has an API key
func (c *VirusTotalClient) IsConfigured() bool {
	return c.apiKey != ""
}
