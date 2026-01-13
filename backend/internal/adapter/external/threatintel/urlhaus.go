package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// URLhausConfig holds configuration for URLhaus client
type URLhausConfig struct {
	APIKey string // Auth-Key from auth.abuse.ch (same as ThreatFox)
}

// URLhausClient queries abuse.ch URLhaus API for malicious URLs/hosts
// Requires Auth-Key header (free key from auth.abuse.ch)
// Tier 1 provider (unlimited)
type URLhausClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// URLhausHostResponse represents the host lookup response
type URLhausHostResponse struct {
	QueryStatus     string            `json:"query_status"`
	Host            string            `json:"host"`
	FirstSeen       string            `json:"firstseen"`
	URLCount        int               `json:"url_count"`
	BlacklistsCount int               `json:"blacklists"`
	Blacklists      URLhausBlacklists `json:"blacklists"`
	URLs            []URLhausURL      `json:"urls"`
}

// URLhausBlacklists contains blacklist status
type URLhausBlacklists struct {
	SpamhausDbl string `json:"spamhaus_dbl"`
	SurblMulti  string `json:"surbl_multi"`
}

// URLhausURL represents a malicious URL entry
type URLhausURL struct {
	ID          string   `json:"id"`
	URL         string   `json:"url"`
	URLStatus   string   `json:"url_status"`
	DateAdded   string   `json:"date_added"`
	Threat      string   `json:"threat"`
	Tags        []string `json:"tags"`
	URLhausLink string   `json:"urlhaus_link"`
	Reporter    string   `json:"reporter"`
}

// URLhausResult represents the processed result
type URLhausResult struct {
	Found       bool     `json:"found"`
	Host        string   `json:"host,omitempty"`
	FirstSeen   string   `json:"first_seen,omitempty"`
	URLCount    int      `json:"url_count,omitempty"`
	ActiveURLs  int      `json:"active_urls,omitempty"`
	ThreatTypes []string `json:"threat_types,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	SpamhausDbl bool     `json:"spamhaus_dbl"`
	SurblListed bool     `json:"surbl_listed"`
	Score       int      `json:"score"`
}

// NewURLhausClient creates a new URLhaus client
func NewURLhausClient(cfg URLhausConfig) *URLhausClient {
	return &URLhausClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		baseURL: "https://urlhaus-api.abuse.ch/v1/",
		apiKey:  cfg.APIKey,
	}
}

// IsConfigured returns true if Auth-Key is configured
func (c *URLhausClient) IsConfigured() bool {
	return c.apiKey != ""
}

// GetProviderName returns the provider name
func (c *URLhausClient) GetProviderName() string {
	return "URLhaus"
}

// GetTier returns the provider tier (1 = unlimited)
func (c *URLhausClient) GetTier() int {
	return 1
}

// CheckIP queries URLhaus for an IP/host
func (c *URLhausClient) CheckIP(ctx context.Context, ip string) (*URLhausResult, error) {
	// URLhaus expects form-encoded data for host lookup
	data := url.Values{}
	data.Set("host", ip)

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"host/", bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", c.apiKey) // Required by abuse.ch

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var uhResp URLhausHostResponse
	if err := json.NewDecoder(resp.Body).Decode(&uhResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.processResponse(&uhResp), nil
}

// processResponse converts URLhaus response to our result format
func (c *URLhausClient) processResponse(resp *URLhausHostResponse) *URLhausResult {
	result := &URLhausResult{
		Found: false,
		Score: 0,
	}

	// no_results means IP not found in URLhaus
	if resp.QueryStatus == "no_results" {
		return result
	}

	if resp.QueryStatus != "ok" {
		return result
	}

	result.Found = true
	result.Host = resp.Host
	result.FirstSeen = resp.FirstSeen
	result.URLCount = resp.URLCount

	// Check blacklist status
	result.SpamhausDbl = resp.Blacklists.SpamhausDbl == "listed"
	result.SurblListed = resp.Blacklists.SurblMulti == "listed"

	// Process URLs to extract threat types and tags
	threatTypes := make(map[string]bool)
	tagSet := make(map[string]bool)
	activeCount := 0

	for _, u := range resp.URLs {
		if u.URLStatus == "online" {
			activeCount++
		}
		if u.Threat != "" {
			threatTypes[u.Threat] = true
		}
		for _, tag := range u.Tags {
			tagSet[tag] = true
		}
	}

	result.ActiveURLs = activeCount

	for t := range threatTypes {
		result.ThreatTypes = append(result.ThreatTypes, t)
	}
	for t := range tagSet {
		result.Tags = append(result.Tags, t)
	}

	// Calculate score
	result.Score = c.calculateScore(result)

	return result
}

// calculateScore calculates threat score based on URLhaus data
func (c *URLhausClient) calculateScore(result *URLhausResult) int {
	if !result.Found {
		return 0
	}

	// Base score for being in URLhaus
	score := 50

	// Active malicious URLs are more dangerous
	if result.ActiveURLs > 0 {
		score += min(result.ActiveURLs*10, 30)
	}

	// Total URL count
	if result.URLCount > 5 {
		score += 10
	}

	// Blacklist bonus
	if result.SpamhausDbl {
		score += 10
	}
	if result.SurblListed {
		score += 10
	}

	// Threat type bonuses
	for _, t := range result.ThreatTypes {
		switch t {
		case "malware_download":
			score += 15
		case "phishing":
			score += 10
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
