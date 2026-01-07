package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GreyNoiseClient handles communication with GreyNoise Community API
// GreyNoise identifies IPs that are mass-scanning the internet
// Key value: Reduces false positives by identifying benign scanners (Shodan, Googlebot, etc.)
type GreyNoiseClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// GreyNoiseConfig holds GreyNoise client configuration
type GreyNoiseConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewGreyNoiseClient creates a new GreyNoise client
func NewGreyNoiseClient(cfg GreyNoiseConfig) *GreyNoiseClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	return &GreyNoiseClient{
		apiKey:  cfg.APIKey,
		baseURL: "https://api.greynoise.io/v3/community",
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// GreyNoiseResponse represents the Community API response
type GreyNoiseResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`          // Is the IP scanning the internet?
	Riot           bool   `json:"riot"`           // Is it a known benign service (RIOT dataset)?
	Classification string `json:"classification"` // "benign", "malicious", "unknown"
	Name           string `json:"name"`           // Name of benign service (if riot=true)
	Link           string `json:"link"`           // Link to GreyNoise visualizer
	LastSeen       string `json:"last_seen"`      // Last seen timestamp
	Message        string `json:"message"`        // Human readable message
}

// GreyNoiseResult represents the processed result
type GreyNoiseResult struct {
	IP              string `json:"ip"`
	Noise           bool   `json:"noise"`          // Scanning the internet
	Riot            bool   `json:"riot"`           // Known benign service
	Classification  string `json:"classification"` // benign, malicious, unknown
	Name            string `json:"name"`           // Service name if benign
	LastSeen        string `json:"last_seen"`
	Message         string `json:"message"`
	IsBenign        bool   `json:"is_benign"` // Computed: should reduce threat score
	RawScore        int    `json:"raw_score"`
	NormalizedScore int    `json:"normalized_score"` // 0-100 scale (can be negative modifier)
}

// CheckIP queries GreyNoise for IP information
// Returns special scoring: benign IPs get LOW scores to reduce false positives
func (c *GreyNoiseClient) CheckIP(ctx context.Context, ip string) (*GreyNoiseResult, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("GreyNoise API key not configured")
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/%s", c.baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// 404 means IP not found in GreyNoise database - this is normal
	if resp.StatusCode == 404 {
		return &GreyNoiseResult{
			IP:              ip,
			Noise:           false,
			Riot:            false,
			Classification:  "unknown",
			IsBenign:        false,
			RawScore:        0,
			NormalizedScore: 0, // No data = neutral score
			Message:         "IP not observed by GreyNoise",
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	var apiResp GreyNoiseResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Calculate score based on classification
	// GreyNoise is unique: it can REDUCE threat scores for benign IPs
	score := c.calculateScore(apiResp)
	isBenign := apiResp.Riot || apiResp.Classification == "benign"

	result := &GreyNoiseResult{
		IP:              apiResp.IP,
		Noise:           apiResp.Noise,
		Riot:            apiResp.Riot,
		Classification:  apiResp.Classification,
		Name:            apiResp.Name,
		LastSeen:        apiResp.LastSeen,
		Message:         apiResp.Message,
		IsBenign:        isBenign,
		RawScore:        score,
		NormalizedScore: score,
	}

	return result, nil
}

// calculateScore determines threat score based on GreyNoise classification
// Key insight: GreyNoise helps REDUCE false positives
func (c *GreyNoiseClient) calculateScore(resp GreyNoiseResponse) int {
	// RIOT = Rule It Out - known benign services (Googlebot, Microsoft, etc.)
	if resp.Riot {
		return 0 // Definitely benign - should not be banned
	}

	switch resp.Classification {
	case "benign":
		// Known benign scanner (Shodan, Censys, security researchers)
		return 5
	case "malicious":
		// Known malicious actor
		return 85
	case "unknown":
		if resp.Noise {
			// Scanning the internet but intent unknown
			return 30
		}
		// Never seen scanning - neutral
		return 0
	default:
		return 0
	}
}

// GetProviderName returns the provider name
func (c *GreyNoiseClient) GetProviderName() string {
	return "GreyNoise"
}

// IsConfigured returns true if the client has an API key
func (c *GreyNoiseClient) IsConfigured() bool {
	return c.apiKey != ""
}

// IsBenignIP is a helper to check if an IP is known benign
// This can be used by the aggregator to apply negative weight
func (c *GreyNoiseClient) IsBenignIP(result *GreyNoiseResult) bool {
	if result == nil {
		return false
	}
	return result.Riot || result.Classification == "benign"
}
