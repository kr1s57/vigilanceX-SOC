package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AbuseIPDBClient handles communication with AbuseIPDB API
type AbuseIPDBClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// AbuseIPDBConfig holds AbuseIPDB client configuration
type AbuseIPDBConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewAbuseIPDBClient creates a new AbuseIPDB client
func NewAbuseIPDBClient(cfg AbuseIPDBConfig) *AbuseIPDBClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	return &AbuseIPDBClient{
		apiKey:  cfg.APIKey,
		baseURL: "https://api.abuseipdb.com/api/v2",
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// AbuseIPDBResponse represents the API response for IP check
type AbuseIPDBResponse struct {
	Data AbuseIPDBData `json:"data"`
}

// AbuseIPDBData contains the IP information
type AbuseIPDBData struct {
	IPAddress            string   `json:"ipAddress"`
	IsPublic             bool     `json:"isPublic"`
	IPVersion            int      `json:"ipVersion"`
	IsWhitelisted        bool     `json:"isWhitelisted"`
	AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
	CountryCode          string   `json:"countryCode"`
	CountryName          string   `json:"countryName"`
	UsageType            string   `json:"usageType"`
	ISP                  string   `json:"isp"`
	Domain               string   `json:"domain"`
	Hostnames            []string `json:"hostnames"`
	TotalReports         int      `json:"totalReports"`
	NumDistinctUsers     int      `json:"numDistinctUsers"`
	LastReportedAt       string   `json:"lastReportedAt"`
	IsTor                bool     `json:"isTor"`
}

// AbuseIPDBResult represents the processed result
type AbuseIPDBResult struct {
	IP                   string   `json:"ip"`
	AbuseConfidenceScore int      `json:"abuse_confidence_score"`
	TotalReports         int      `json:"total_reports"`
	NumDistinctUsers     int      `json:"num_distinct_users"`
	CountryCode          string   `json:"country_code"`
	CountryName          string   `json:"country_name"`
	ISP                  string   `json:"isp"`
	Domain               string   `json:"domain"`
	UsageType            string   `json:"usage_type"`
	IsTor                bool     `json:"is_tor"`
	IsWhitelisted        bool     `json:"is_whitelisted"`
	LastReportedAt       string   `json:"last_reported_at"`
	Categories           []string `json:"categories"`
	RawScore             int      `json:"raw_score"`
	NormalizedScore      int      `json:"normalized_score"` // 0-100 scale
}

// CheckIP queries AbuseIPDB for IP reputation
func (c *AbuseIPDBClient) CheckIP(ctx context.Context, ip string) (*AbuseIPDBResult, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("AbuseIPDB API key not configured")
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/check?ipAddress=%s&maxAgeInDays=90&verbose=true",
		c.baseURL, url.QueryEscape(ip))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Key", c.apiKey)
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

	var apiResp AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Convert to result
	result := &AbuseIPDBResult{
		IP:                   apiResp.Data.IPAddress,
		AbuseConfidenceScore: apiResp.Data.AbuseConfidenceScore,
		TotalReports:         apiResp.Data.TotalReports,
		NumDistinctUsers:     apiResp.Data.NumDistinctUsers,
		CountryCode:          apiResp.Data.CountryCode,
		CountryName:          apiResp.Data.CountryName,
		ISP:                  apiResp.Data.ISP,
		Domain:               apiResp.Data.Domain,
		UsageType:            apiResp.Data.UsageType,
		IsTor:                apiResp.Data.IsTor,
		IsWhitelisted:        apiResp.Data.IsWhitelisted,
		LastReportedAt:       apiResp.Data.LastReportedAt,
		RawScore:             apiResp.Data.AbuseConfidenceScore,
		NormalizedScore:      apiResp.Data.AbuseConfidenceScore, // Already 0-100
	}

	return result, nil
}

// GetProviderName returns the provider name
func (c *AbuseIPDBClient) GetProviderName() string {
	return "AbuseIPDB"
}

// IsConfigured returns true if the client has an API key
func (c *AbuseIPDBClient) IsConfigured() bool {
	return c.apiKey != ""
}
