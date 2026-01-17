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

// BlocklistClient handles CrowdSec Blocklist API interactions
type BlocklistClient struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
	mu         sync.RWMutex
}

// BlocklistConfig holds configuration for the blocklist client
type BlocklistConfig struct {
	APIKey string
}

// BlocklistStats represents blocklist statistics from the API
type BlocklistStats struct {
	Count int64 `json:"count"`
}

// BlocklistInfo represents a blocklist metadata
type BlocklistInfo struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Label       string         `json:"label"`
	Description string         `json:"description"`
	References  []string       `json:"references,omitempty"`
	IsPrivate   bool           `json:"is_private"`
	Subscribers interface{}    `json:"subscribers"` // Can be array or int depending on API version
	Stats       BlocklistStats `json:"stats"`       // Contains count (IP count)
	IPCount     int64          `json:"ip_count"`    // Computed field for convenience
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// BlocklistsResponse represents the API response for listing blocklists
type BlocklistsResponse struct {
	Items      []BlocklistInfo `json:"items"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	TotalItems int             `json:"total_items"`
	TotalPages int             `json:"total_pages"`
}

// SubscribedBlocklist represents a blocklist the user is subscribed to
type SubscribedBlocklist struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Label       string    `json:"label"`
	Description string    `json:"description"`
	IPCount     int64     `json:"ip_count"`
	LastSync    time.Time `json:"last_sync"`
	SyncedToXGS bool      `json:"synced_to_xgs"`
	Enabled     bool      `json:"enabled"`
	Remediation string    `json:"remediation"` // ban, captcha, etc.
}

// BlocklistSyncResult represents the result of syncing a blocklist
type BlocklistSyncResult struct {
	BlocklistID   string    `json:"blocklist_id"`
	BlocklistName string    `json:"blocklist_name"`
	IPsDownloaded int       `json:"ips_downloaded"`
	IPsSynced     int       `json:"ips_synced"`
	IPsNew        int       `json:"ips_new"`
	IPsRemoved    int       `json:"ips_removed"`
	Duration      float64   `json:"duration_ms"`
	SyncedAt      time.Time `json:"synced_at"`
	Error         string    `json:"error,omitempty"`
}

// NewBlocklistClient creates a new CrowdSec Blocklist API client
func NewBlocklistClient(cfg BlocklistConfig) *BlocklistClient {
	return &BlocklistClient{
		httpClient: &http.Client{
			Timeout: 60 * time.Second, // Longer timeout for large blocklists
		},
		apiKey:  cfg.APIKey,
		baseURL: "https://admin.api.crowdsec.net/v1",
	}
}

// SetAPIKey updates the API key (for hot-reload from settings)
func (c *BlocklistClient) SetAPIKey(apiKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiKey = apiKey
}

// IsConfigured returns true if the API key is set
func (c *BlocklistClient) IsConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey != ""
}

// GetAPIKey returns the current API key (for testing)
func (c *BlocklistClient) GetAPIKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey
}

// ListBlocklists returns all blocklists available to the account
func (c *BlocklistClient) ListBlocklists(ctx context.Context) ([]BlocklistInfo, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("blocklist API key not configured")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/blocklists", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	c.mu.RLock()
	req.Header.Set("x-api-key", c.apiKey)
	c.mu.RUnlock()
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid API key")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result BlocklistsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result.Items, nil
}

// GetSubscribedBlocklists returns premium/subscribed blocklists accessible to the API key
// Uses the standard /blocklists endpoint and filters for premium blocklists with IP count > 0
func (c *BlocklistClient) GetSubscribedBlocklists(ctx context.Context) ([]BlocklistInfo, error) {
	// First, get all accessible blocklists using the standard endpoint
	allBlocklists, err := c.ListBlocklists(ctx)
	if err != nil {
		return nil, fmt.Errorf("list blocklists: %w", err)
	}

	// Filter for blocklists with IPs (premium/subscribed blocklists typically have IPs)
	// and populate IPCount from Stats.Count for convenience
	var filtered []BlocklistInfo
	for _, bl := range allBlocklists {
		bl.IPCount = bl.Stats.Count // Copy stats.count to IPCount for convenience
		if bl.Stats.Count > 0 {
			filtered = append(filtered, bl)
		}
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Found premium blocklists",
		"total", len(allBlocklists),
		"with_ips", len(filtered))

	return filtered, nil
}

// DownloadBlocklist downloads the IP list from a blocklist
// Returns a slice of IP addresses (IPv4 strings)
func (c *BlocklistClient) DownloadBlocklist(ctx context.Context, blocklistID string) ([]string, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("blocklist API key not configured")
	}

	url := fmt.Sprintf("%s/blocklists/%s/download", c.baseURL, blocklistID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	c.mu.RLock()
	req.Header.Set("x-api-key", c.apiKey)
	c.mu.RUnlock()
	req.Header.Set("Accept", "text/plain")

	slog.Info("[CROWDSEC_BLOCKLIST] Downloading blocklist", "blocklist_id", blocklistID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid API key")
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("blocklist not found or not subscribed: %s", blocklistID)
	}

	// 204 No Content = blocklist is empty (valid response)
	if resp.StatusCode == http.StatusNoContent {
		slog.Info("[CROWDSEC_BLOCKLIST] Blocklist is empty (204 No Content)", "blocklist_id", blocklistID)
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
			// Handle CIDR notation - extract base IP for now
			// TODO: Expand CIDR to individual IPs or handle ranges
			ipStr := strings.Split(line, "/")[0]
			if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
				ips = append(ips, line) // Keep CIDR format
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	slog.Info("[CROWDSEC_BLOCKLIST] Downloaded blocklist",
		"blocklist_id", blocklistID,
		"ip_count", len(ips))

	return ips, nil
}

// TestConnection tests the API connection
func (c *BlocklistClient) TestConnection(ctx context.Context) error {
	if !c.IsConfigured() {
		return fmt.Errorf("blocklist API key not configured")
	}

	// Try to list blocklists as a connection test
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/blocklists?page_size=1", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	c.mu.RLock()
	apiKey := c.apiKey
	c.mu.RUnlock()

	keyPrefix := apiKey
	if len(keyPrefix) > 8 {
		keyPrefix = keyPrefix[:8]
	}
	slog.Info("[CROWDSEC_CLIENT] Testing connection",
		"api_key_length", len(apiKey),
		"api_key_prefix", keyPrefix+"...")

	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid API key")
	}

	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("API key lacks blocklist permissions. Ensure your CrowdSec Console API key has 'blocklists:read' scope and your organization has blocklist access enabled")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}
