package crowdsec

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// VigilanceKeyClient fetches blocklists from VigilanceKey ProxyAPI
// instead of directly from CrowdSec
type VigilanceKeyClient struct {
	httpClient *http.Client
	baseURL    string
	licenseKey string
	hardwareID string
	mu         sync.RWMutex
}

// VigilanceKeyConfig holds configuration for the VigilanceKey blocklist client
type VigilanceKeyConfig struct {
	ServerURL  string // VigilanceKey server URL (e.g., https://vgxkey.vigilancex.lu)
	LicenseKey string // VGX license key
	HardwareID string // VGX hardware ID
}

// ProxyBlocklistInfo represents blocklist metadata from VigilanceKey
type ProxyBlocklistInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Label       string    `json:"label"`
	Description string    `json:"description"`
	IPCount     int64     `json:"ip_count"`
	LastSync    time.Time `json:"last_sync,omitempty"`
	Enabled     bool      `json:"enabled"`
}

// ProxyBlocklistsResponse represents the response from VigilanceKey
type ProxyBlocklistsResponse struct {
	Blocklists []ProxyBlocklistInfo `json:"blocklists"`
	Total      int                  `json:"total"`
}

// NewVigilanceKeyClient creates a new VigilanceKey blocklist client
func NewVigilanceKeyClient(cfg VigilanceKeyConfig) *VigilanceKeyClient {
	return &VigilanceKeyClient{
		httpClient: &http.Client{
			Timeout: 120 * time.Second, // Longer timeout for large blocklists
		},
		baseURL:    strings.TrimSuffix(cfg.ServerURL, "/"),
		licenseKey: cfg.LicenseKey,
		hardwareID: cfg.HardwareID,
	}
}

// SetCredentials updates the license credentials
func (c *VigilanceKeyClient) SetCredentials(licenseKey, hardwareID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.licenseKey = licenseKey
	c.hardwareID = hardwareID
}

// SetServerURL updates the server URL
func (c *VigilanceKeyClient) SetServerURL(serverURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = strings.TrimSuffix(serverURL, "/")
}

// IsConfigured returns true if credentials are set
func (c *VigilanceKeyClient) IsConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.licenseKey != "" && c.hardwareID != "" && c.baseURL != ""
}

// setHeaders adds authentication headers to requests
func (c *VigilanceKeyClient) setHeaders(req *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	req.Header.Set("X-License-Key", c.licenseKey)
	req.Header.Set("X-Hardware-ID", c.hardwareID)
	req.Header.Set("Accept", "application/json")
}

// TestConnection tests the connection to VigilanceKey
func (c *VigilanceKeyClient) TestConnection(ctx context.Context) error {
	if !c.IsConfigured() {
		return fmt.Errorf("VigilanceKey client not configured")
	}

	url := c.baseURL + "/api/v1/blocklist/status"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	c.setHeaders(req)

	slog.Debug("[VK_BLOCKLIST] Testing connection", "url", url)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("invalid license credentials")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListBlocklists returns available blocklists from VigilanceKey
func (c *VigilanceKeyClient) ListBlocklists(ctx context.Context) ([]BlocklistInfo, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("VigilanceKey client not configured")
	}

	url := c.baseURL + "/api/v1/blocklist/lists"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	c.setHeaders(req)

	slog.Debug("[VK_BLOCKLIST] Fetching blocklists", "url", url)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("invalid license credentials")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result ProxyBlocklistsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Convert to BlocklistInfo format
	blocklists := make([]BlocklistInfo, 0, len(result.Blocklists))
	for _, bl := range result.Blocklists {
		blocklists = append(blocklists, BlocklistInfo{
			ID:          bl.ID,
			Name:        bl.Name,
			Label:       bl.Label,
			Description: bl.Description,
			IPCount:     bl.IPCount,
			IsPrivate:   false, // VigilanceKey serves premium blocklists
		})
	}

	slog.Info("[VK_BLOCKLIST] Fetched blocklists from VigilanceKey",
		"count", len(blocklists))

	return blocklists, nil
}

// GetSubscribedBlocklists returns blocklists with IPs (same as ListBlocklists for proxy)
func (c *VigilanceKeyClient) GetSubscribedBlocklists(ctx context.Context) ([]BlocklistInfo, error) {
	return c.ListBlocklists(ctx)
}

// DownloadBlocklist downloads IPs from a blocklist via VigilanceKey
func (c *VigilanceKeyClient) DownloadBlocklist(ctx context.Context, blocklistID string) ([]string, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("VigilanceKey client not configured")
	}

	url := fmt.Sprintf("%s/api/v1/blocklist/%s/download", c.baseURL, blocklistID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	c.setHeaders(req)
	req.Header.Set("Accept", "text/plain")

	slog.Info("[VK_BLOCKLIST] Downloading blocklist from VigilanceKey",
		"blocklist_id", blocklistID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("invalid license credentials")
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("blocklist not found: %s", blocklistID)
	}

	// 204 No Content = blocklist file not yet downloaded by VigilanceKey
	if resp.StatusCode == http.StatusNoContent {
		slog.Info("[VK_BLOCKLIST] Blocklist not yet available on VigilanceKey",
			"blocklist_id", blocklistID)
		return []string{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// Parse plain text response (one IP per line)
	var ips []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Validate IP format
		if ip := net.ParseIP(line); ip != nil {
			// Only include IPv4 for Sophos XGS compatibility
			if ip.To4() != nil {
				ips = append(ips, line)
			}
		} else if strings.Contains(line, "/") {
			// Handle CIDR notation
			ipStr := strings.Split(line, "/")[0]
			if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
				ips = append(ips, line) // Keep CIDR format
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	slog.Info("[VK_BLOCKLIST] Downloaded blocklist from VigilanceKey",
		"blocklist_id", blocklistID,
		"ip_count", len(ips))

	return ips, nil
}

// SetAPIKey is a no-op for VigilanceKey client (API key is on server side)
func (c *VigilanceKeyClient) SetAPIKey(apiKey string) {
	// No-op - VigilanceKey manages the CrowdSec API key centrally
}

// GetAPIKey returns empty string (API key is on server side)
func (c *VigilanceKeyClient) GetAPIKey() string {
	return ""
}

// GetServerURL returns the configured server URL
func (c *VigilanceKeyClient) GetServerURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baseURL
}
