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

// CriminalIPResponse represents the API response
type CriminalIPResponse struct {
	Status  int              `json:"status"`
	Message string           `json:"message"`
	Data    CriminalIPData   `json:"data"`
}

// CriminalIPData contains the IP information
type CriminalIPData struct {
	IP           string               `json:"ip"`
	Score        CriminalIPScore      `json:"score"`
	Issues       []CriminalIPIssue    `json:"issues"`
	Whois        CriminalIPWhois      `json:"whois"`
	IsVPN        bool                 `json:"is_vpn"`
	IsProxy      bool                 `json:"is_proxy"`
	IsTor        bool                 `json:"is_tor"`
	IsHosting    bool                 `json:"is_hosting"`
	IsCloud      bool                 `json:"is_cloud"`
	IsDarkweb    bool                 `json:"is_darkweb"`
	IsScanner    bool                 `json:"is_scanner"`
	IsMobile     bool                 `json:"is_mobile"`
	Country      string               `json:"country"`
	City         string               `json:"city"`
	ASN          string               `json:"as_name"`
	ASNNumber    int                  `json:"asn"`
	Ports        []CriminalIPPort     `json:"ports"`
}

// CriminalIPScore contains threat scoring
type CriminalIPScore struct {
	Inbound  string `json:"inbound"`  // "critical", "dangerous", "moderate", "low", "safe"
	Outbound string `json:"outbound"` // Same levels
}

// CriminalIPIssue represents a detected security issue
type CriminalIPIssue struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // "critical", "high", "medium", "low"
}

// CriminalIPWhois contains WHOIS information
type CriminalIPWhois struct {
	ASN      string `json:"as_name"`
	Country  string `json:"country"`
	City     string `json:"city"`
	Org      string `json:"org_name"`
}

// CriminalIPPort represents an open port
type CriminalIPPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Banner   string `json:"banner"`
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

	if apiResp.Status != 200 {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	// Count issues by severity
	criticalCount := 0
	highCount := 0
	categories := make([]string, 0)
	for _, issue := range apiResp.Data.Issues {
		switch issue.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
		categories = append(categories, issue.Type)
	}

	// Calculate score
	score := c.calculateScore(apiResp.Data, criticalCount, highCount)

	result := &CriminalIPResult{
		IP:              apiResp.Data.IP,
		InboundScore:    apiResp.Data.Score.Inbound,
		OutboundScore:   apiResp.Data.Score.Outbound,
		IsVPN:           apiResp.Data.IsVPN,
		IsProxy:         apiResp.Data.IsProxy,
		IsTor:           apiResp.Data.IsTor,
		IsHosting:       apiResp.Data.IsHosting,
		IsCloud:         apiResp.Data.IsCloud,
		IsDarkweb:       apiResp.Data.IsDarkweb,
		IsScanner:       apiResp.Data.IsScanner,
		IssueCount:      len(apiResp.Data.Issues),
		CriticalIssues:  criticalCount,
		HighIssues:      highCount,
		Country:         apiResp.Data.Country,
		ASN:             apiResp.Data.ASN,
		OpenPorts:       len(apiResp.Data.Ports),
		Categories:      categories,
		RawScore:        score,
		NormalizedScore: score,
	}

	return result, nil
}

// calculateScore determines threat score based on Criminal IP data
func (c *CriminalIPClient) calculateScore(data CriminalIPData, critical, high int) int {
	score := 0

	// Score based on inbound threat level
	switch data.Score.Inbound {
	case "critical":
		score += 50
	case "dangerous":
		score += 35
	case "moderate":
		score += 20
	case "low":
		score += 10
	}

	// Add points for infrastructure flags (used by attackers)
	if data.IsVPN {
		score += 10 // VPNs commonly used to hide origin
	}
	if data.IsProxy {
		score += 15 // Proxies often used for attacks
	}
	if data.IsTor {
		score += 20 // Tor exit nodes = high anonymity
	}
	if data.IsDarkweb {
		score += 25 // Darkweb association = very suspicious
	}
	if data.IsScanner {
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
