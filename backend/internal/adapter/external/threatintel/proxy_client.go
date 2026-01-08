package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ProxyConfig holds configuration for the OSINT proxy client
type ProxyConfig struct {
	ServerURL  string
	LicenseKey string
	HardwareID string
	Timeout    time.Duration
	RateLimit  int // requests per minute
}

// OSINTProxyClient routes OSINT queries through a central proxy server
type OSINTProxyClient struct {
	serverURL   string
	licenseKey  string
	hardwareID  string
	httpClient  *http.Client
	rateLimiter *rate.Limiter
	mu          sync.RWMutex
}

// ProxyRequest is sent to the OSINT proxy server
type ProxyRequest struct {
	IP         string `json:"ip"`
	HardwareID string `json:"hardware_id"`
	LicenseKey string `json:"license_key"`
}

// ProxyResponse is received from the OSINT proxy server
type ProxyResponse struct {
	Success bool              `json:"success"`
	Error   string            `json:"error,omitempty"`
	Result  *AggregatedResult `json:"result,omitempty"`
}

// NewOSINTProxyClient creates a new OSINT proxy client
func NewOSINTProxyClient(cfg ProxyConfig) *OSINTProxyClient {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	rateLimit := cfg.RateLimit
	if rateLimit == 0 {
		rateLimit = 60 // 60 requests per minute
	}

	// Create rate limiter (requests per second)
	limiter := rate.NewLimiter(rate.Limit(float64(rateLimit)/60.0), 5)

	return &OSINTProxyClient{
		serverURL:  cfg.ServerURL,
		licenseKey: cfg.LicenseKey,
		hardwareID: cfg.HardwareID,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		rateLimiter: limiter,
	}
}

// CheckIP queries the OSINT proxy for threat intelligence
func (c *OSINTProxyClient) CheckIP(ctx context.Context, ip string) (*AggregatedResult, error) {
	// Apply rate limiting
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %w", err)
	}

	c.mu.RLock()
	licenseKey := c.licenseKey
	hardwareID := c.hardwareID
	c.mu.RUnlock()

	req := ProxyRequest{
		IP:         ip,
		HardwareID: hardwareID,
		LicenseKey: licenseKey,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		c.serverURL+"/api/v1/osint/check", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to contact OSINT proxy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("proxy error (%d): %s", resp.StatusCode, errResp.Error)
	}

	var proxyResp ProxyResponse
	if err := json.NewDecoder(resp.Body).Decode(&proxyResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !proxyResp.Success {
		return nil, fmt.Errorf("proxy returned error: %s", proxyResp.Error)
	}

	if proxyResp.Result == nil {
		return nil, fmt.Errorf("proxy returned empty result")
	}

	slog.Debug("OSINT proxy query successful",
		"ip", ip,
		"score", proxyResp.Result.AggregatedScore,
		"threat_level", proxyResp.Result.ThreatLevel)

	return proxyResp.Result, nil
}

// IsConfigured returns true if the proxy client is properly configured
func (c *OSINTProxyClient) IsConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serverURL != "" && c.licenseKey != "" && c.hardwareID != ""
}

// UpdateCredentials updates the license key and hardware ID
func (c *OSINTProxyClient) UpdateCredentials(licenseKey, hardwareID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.licenseKey = licenseKey
	c.hardwareID = hardwareID
}

// GetProviderName returns the provider name
func (c *OSINTProxyClient) GetProviderName() string {
	return "OSINTProxy"
}

// HealthCheck performs a simple health check on the proxy server
func (c *OSINTProxyClient) HealthCheck(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET",
		c.serverURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("proxy unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy unhealthy: status %d", resp.StatusCode)
	}

	return nil
}
