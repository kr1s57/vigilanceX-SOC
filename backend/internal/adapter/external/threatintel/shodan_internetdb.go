package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ShodanInternetDBClient queries Shodan's free InternetDB API
// Free API - no authentication required
// Tier 1 provider (unlimited)
// Provides: open ports, hostnames, tags, CPEs, vulnerabilities
type ShodanInternetDBClient struct {
	httpClient *http.Client
	baseURL    string
}

// ShodanInternetDBResponse represents the API response
type ShodanInternetDBResponse struct {
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	CPEs      []string `json:"cpes"`
	Vulns     []string `json:"vulns"`
}

// ShodanInternetDBResult represents the processed result
type ShodanInternetDBResult struct {
	Found         bool     `json:"found"`
	IP            string   `json:"ip,omitempty"`
	Hostnames     []string `json:"hostnames,omitempty"`
	Ports         []int    `json:"ports,omitempty"`
	OpenPortCount int      `json:"open_port_count,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	CPEs          []string `json:"cpes,omitempty"`
	Vulns         []string `json:"vulns,omitempty"`
	VulnCount     int      `json:"vuln_count,omitempty"`
	HasCritical   bool     `json:"has_critical_vulns"`
	IsVPN         bool     `json:"is_vpn"`
	IsProxy       bool     `json:"is_proxy"`
	IsTor         bool     `json:"is_tor"`
	IsHoneypot    bool     `json:"is_honeypot"`
	Score         int      `json:"score"`
}

// Suspicious ports that might indicate malicious activity
var suspiciousPorts = map[int]int{
	4444:  20, // Metasploit default
	5555:  15, // Android debug / common backdoor
	6666:  15, // IRC / common backdoor
	6667:  15, // IRC
	31337: 20, // Elite / common backdoor
	1337:  15, // Common backdoor
	9001:  10, // Tor
	9050:  10, // Tor
	3389:  5,  // RDP (not suspicious alone, but worth noting)
	5900:  5,  // VNC
	4443:  10, // Common C2 port
	8443:  5,  // Alternative HTTPS
	8888:  10, // Common proxy/backdoor
}

// NewShodanInternetDBClient creates a new Shodan InternetDB client
func NewShodanInternetDBClient() *ShodanInternetDBClient {
	return &ShodanInternetDBClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		baseURL: "https://internetdb.shodan.io/",
	}
}

// IsConfigured returns true (InternetDB is always available - no API key needed)
func (c *ShodanInternetDBClient) IsConfigured() bool {
	return true
}

// GetTier returns the provider tier (1 = unlimited)
func (c *ShodanInternetDBClient) GetTier() int {
	return 1
}

// CheckIP queries Shodan InternetDB for an IP address
func (c *ShodanInternetDBClient) CheckIP(ctx context.Context, ip string) (*ShodanInternetDBResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+ip, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// 404 means IP not found in InternetDB (not an error, just no data)
	if resp.StatusCode == http.StatusNotFound {
		return &ShodanInternetDBResult{Found: false, Score: 0}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var shodanResp ShodanInternetDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&shodanResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.processResponse(&shodanResp), nil
}

// processResponse converts Shodan response to our result format
func (c *ShodanInternetDBClient) processResponse(resp *ShodanInternetDBResponse) *ShodanInternetDBResult {
	result := &ShodanInternetDBResult{
		Found:         true,
		IP:            resp.IP,
		Hostnames:     resp.Hostnames,
		Ports:         resp.Ports,
		OpenPortCount: len(resp.Ports),
		Tags:          resp.Tags,
		CPEs:          resp.CPEs,
		Vulns:         resp.Vulns,
		VulnCount:     len(resp.Vulns),
	}

	// Check tags for specific indicators
	for _, tag := range resp.Tags {
		tagLower := strings.ToLower(tag)
		switch {
		case strings.Contains(tagLower, "vpn"):
			result.IsVPN = true
		case strings.Contains(tagLower, "proxy"):
			result.IsProxy = true
		case strings.Contains(tagLower, "tor"):
			result.IsTor = true
		case strings.Contains(tagLower, "honeypot"):
			result.IsHoneypot = true
		}
	}

	// Check for critical vulnerabilities
	for _, vuln := range resp.Vulns {
		// Check for known critical CVEs (simplified - in production would check CVSS)
		if strings.Contains(vuln, "2021-44228") || // Log4Shell
			strings.Contains(vuln, "2021-26855") || // ProxyLogon
			strings.Contains(vuln, "2017-0144") || // EternalBlue
			strings.Contains(vuln, "2019-19781") || // Citrix
			strings.Contains(vuln, "2023-") { // Recent CVEs
			result.HasCritical = true
			break
		}
	}

	// Calculate score
	result.Score = c.calculateScore(result)

	return result
}

// calculateScore calculates a threat score based on Shodan data
func (c *ShodanInternetDBClient) calculateScore(result *ShodanInternetDBResult) int {
	if !result.Found {
		return 0
	}

	score := 0

	// Check for suspicious ports
	for _, port := range result.Ports {
		if points, ok := suspiciousPorts[port]; ok {
			score += points
		}
	}

	// Many open ports can indicate a compromised system or scanner
	if len(result.Ports) > 20 {
		score += 15
	} else if len(result.Ports) > 10 {
		score += 10
	}

	// Vulnerabilities
	if result.VulnCount > 0 {
		score += min(result.VulnCount*5, 25)
	}
	if result.HasCritical {
		score += 20
	}

	// Tags indicators
	if result.IsVPN {
		score += 10 // VPNs are often used to hide origin
	}
	if result.IsProxy {
		score += 15
	}
	if result.IsTor {
		score += 20 // Tor exit nodes are high risk
	}
	// Honeypots are actually benign (security research)
	if result.IsHoneypot {
		score -= 20
	}

	// Clamp to 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
