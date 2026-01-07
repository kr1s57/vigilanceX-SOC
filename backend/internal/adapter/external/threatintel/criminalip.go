package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CriminalIPClient handles communication with Criminal IP API
// Criminal IP specializes in detecting C2 servers, VPNs, proxies, and hosting abuse
// Key value: Excellent detection of infrastructure used by attackers
type CriminalIPClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// CriminalIPConfig holds Criminal IP client configuration
type CriminalIPConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewCriminalIPClient creates a new Criminal IP client
func NewCriminalIPClient(cfg CriminalIPConfig) *CriminalIPClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	return &CriminalIPClient{
		apiKey:  cfg.APIKey,
		baseURL: "https://api.criminalip.io/v1",
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// CriminalIPResponse represents the actual API response structure
// Note: CriminalIP returns data at root level, not wrapped in "data" object
type CriminalIPResponse struct {
	IP              string                `json:"ip"`
	Tags            CriminalIPTags        `json:"tags"`
	Score           CriminalIPScore       `json:"score"`
	UserSearchCount int                   `json:"user_search_count"`
	Issues          CriminalIPIssueData   `json:"issues,omitempty"`
	CurrentOpenPort CriminalIPPortData    `json:"current_open_port,omitempty"`
}

// CriminalIPTags contains boolean flags about the IP
type CriminalIPTags struct {
	IsVPN     bool `json:"is_vpn"`
	IsCloud   bool `json:"is_cloud"`
	IsTor     bool `json:"is_tor"`
	IsProxy   bool `json:"is_proxy"`
	IsHosting bool `json:"is_hosting"`
	IsMobile  bool `json:"is_mobile"`
	IsDarkweb bool `json:"is_darkweb"`
	IsScanner bool `json:"is_scanner"`
	IsSnort   bool `json:"is_snort"`
}

// CriminalIPScore contains threat scoring (0-5 scale: 0=safe, 5=critical)
type CriminalIPScore struct {
	Inbound  int `json:"inbound"`
	Outbound int `json:"outbound"`
}

// CriminalIPIssueData contains security issues
type CriminalIPIssueData struct {
	Count int                 `json:"count"`
	Data  []CriminalIPIssue   `json:"data"`
}

// CriminalIPIssue represents a detected security issue
type CriminalIPIssue struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// CriminalIPPortData contains open port information
type CriminalIPPortData struct {
	Count int                `json:"count"`
	Data  []CriminalIPPort   `json:"data"`
}

// CriminalIPPort represents an open port
type CriminalIPPort struct {
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Service    string `json:"service_name"`
	Banner     string `json:"banner"`
	AppName    string `json:"app_name"`
	AppVersion string `json:"app_version"`
}

// CriminalIPResult represents the processed result
type CriminalIPResult struct {
	IP              string   `json:"ip"`
	InboundScore    string   `json:"inbound_score"`    // Threat level for incoming attacks
	OutboundScore   string   `json:"outbound_score"`   // Threat level for outgoing attacks
	IsVPN           bool     `json:"is_vpn"`
	IsProxy         bool     `json:"is_proxy"`
	IsTor           bool     `json:"is_tor"`
	IsHosting       bool     `json:"is_hosting"`
	IsCloud         bool     `json:"is_cloud"`
	IsDarkweb       bool     `json:"is_darkweb"`
	IsScanner       bool     `json:"is_scanner"`
	IssueCount      int      `json:"issue_count"`
	CriticalIssues  int      `json:"critical_issues"`
	HighIssues      int      `json:"high_issues"`
	Country         string   `json:"country"`
	ASN             string   `json:"asn"`
	OpenPorts       int      `json:"open_ports"`
	Categories      []string `json:"categories"` // Aggregated from issues
	RawScore        int      `json:"raw_score"`
	NormalizedScore int      `json:"normalized_score"` // 0-100 scale
}

// CheckIP queries Criminal IP for IP information
func (c *CriminalIPClient) CheckIP(ctx context.Context, ip string) (*CriminalIPResult, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("Criminal IP API key not configured")
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/ip/data?ip=%s", c.baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("x-api-key", c.apiKey)
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

	var apiResp CriminalIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Count issues by severity
	criticalCount := 0
	highCount := 0
	categories := make([]string, 0)
	for _, issue := range apiResp.Issues.Data {
		switch issue.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
		categories = append(categories, issue.Type)
	}

	// Calculate score based on new structure
	score := c.calculateScore(apiResp, criticalCount, highCount)

	// Convert inbound/outbound scores to level strings
	inboundLevel := c.scoreToLevel(apiResp.Score.Inbound)
	outboundLevel := c.scoreToLevel(apiResp.Score.Outbound)

	result := &CriminalIPResult{
		IP:              apiResp.IP,
		InboundScore:    inboundLevel,
		OutboundScore:   outboundLevel,
		IsVPN:           apiResp.Tags.IsVPN,
		IsProxy:         apiResp.Tags.IsProxy,
		IsTor:           apiResp.Tags.IsTor,
		IsHosting:       apiResp.Tags.IsHosting,
		IsCloud:         apiResp.Tags.IsCloud,
		IsDarkweb:       apiResp.Tags.IsDarkweb,
		IsScanner:       apiResp.Tags.IsScanner,
		IssueCount:      apiResp.Issues.Count,
		CriticalIssues:  criticalCount,
		HighIssues:      highCount,
		Country:         "", // Not directly available in this endpoint
		ASN:             "",
		OpenPorts:       apiResp.CurrentOpenPort.Count,
		Categories:      categories,
		RawScore:        score,
		NormalizedScore: score,
	}

	return result, nil
}

// scoreToLevel converts numeric score (0-5) to level string
func (c *CriminalIPClient) scoreToLevel(score int) string {
	switch score {
	case 5:
		return "critical"
	case 4:
		return "dangerous"
	case 3:
		return "moderate"
	case 2:
		return "low"
	case 1:
		return "low"
	default:
		return "safe"
	}
}

// calculateScore determines threat score based on Criminal IP data
// Score scale: 0=safe to 5=critical, converted to 0-100
func (c *CriminalIPClient) calculateScore(data CriminalIPResponse, critical, high int) int {
	score := 0

	// Score based on inbound threat level (0-5 scale -> 0-50 points)
	score += data.Score.Inbound * 10

	// Add points for infrastructure flags (used by attackers)
	if data.Tags.IsVPN {
		score += 10 // VPNs commonly used to hide origin
	}
	if data.Tags.IsProxy {
		score += 15 // Proxies often used for attacks
	}
	if data.Tags.IsTor {
		score += 20 // Tor exit nodes = high anonymity
	}
	if data.Tags.IsDarkweb {
		score += 25 // Darkweb association = very suspicious
	}
	if data.Tags.IsScanner {
		score += 15 // Known scanner
	}

	// Add points for security issues
	score += critical * 10 // Each critical issue
	score += high * 5      // Each high issue

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// GetProviderName returns the provider name
func (c *CriminalIPClient) GetProviderName() string {
	return "CriminalIP"
}

// IsConfigured returns true if the client has an API key
func (c *CriminalIPClient) IsConfigured() bool {
	return c.apiKey != ""
}
