package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IPSumClient handles IP reputation checking against the IPSum aggregated blocklists
// IPSum aggregates 30+ public blocklists (Firehol, Emerging Threats, etc.)
// Key value: If an IP appears in multiple blocklists, it's highly likely malicious
type IPSumClient struct {
	baseURL       string
	httpClient    *http.Client
	cache         map[string]int // IP -> count of blocklists
	cacheMutex    sync.RWMutex
	lastUpdate    time.Time
	refreshPeriod time.Duration
	minListCount  int // Minimum number of lists to consider (default: 3)
}

// IPSumConfig holds IPSum client configuration
type IPSumConfig struct {
	Timeout       time.Duration
	RefreshPeriod time.Duration // How often to refresh the list (default: 6 hours)
	MinListCount  int           // Minimum blocklist count threshold (default: 3)
}

// NewIPSumClient creates a new IPSum client
func NewIPSumClient(cfg IPSumConfig) *IPSumClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.RefreshPeriod == 0 {
		cfg.RefreshPeriod = 6 * time.Hour
	}
	if cfg.MinListCount == 0 {
		cfg.MinListCount = 3
	}

	client := &IPSumClient{
		// IPSum GitHub raw URL - level 3 means IPs in 3+ blocklists
		baseURL: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/%d.txt",
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		cache:         make(map[string]int),
		refreshPeriod: cfg.RefreshPeriod,
		minListCount:  cfg.MinListCount,
	}

	// Initial load (async to not block startup)
	go client.refreshCache()

	return client
}

// IPSumResult represents the processed result
type IPSumResult struct {
	IP              string   `json:"ip"`
	InBlocklists    bool     `json:"in_blocklists"`    // Found in aggregated lists
	BlocklistCount  int      `json:"blocklist_count"`  // Number of lists containing this IP
	Sources         []string `json:"sources"`          // List names (not available in basic IPSum)
	LastUpdated     string   `json:"last_updated"`     // When the list was last fetched
	RawScore        int      `json:"raw_score"`
	NormalizedScore int      `json:"normalized_score"` // 0-100 scale
}

// CheckIP checks if an IP is in the IPSum aggregated blocklists
func (c *IPSumClient) CheckIP(ctx context.Context, ip string) (*IPSumResult, error) {
	// Refresh cache if needed
	if time.Since(c.lastUpdate) > c.refreshPeriod || len(c.cache) == 0 {
		if err := c.refreshCache(); err != nil {
			// Log error but continue with stale cache
			fmt.Printf("IPSum cache refresh failed: %v\n", err)
		}
	}

	c.cacheMutex.RLock()
	count, found := c.cache[ip]
	c.cacheMutex.RUnlock()

	score := c.calculateScore(count, found)

	result := &IPSumResult{
		IP:              ip,
		InBlocklists:    found && count >= c.minListCount,
		BlocklistCount:  count,
		LastUpdated:     c.lastUpdate.Format(time.RFC3339),
		RawScore:        score,
		NormalizedScore: score,
	}

	return result, nil
}

// calculateScore determines threat score based on blocklist count
func (c *IPSumClient) calculateScore(count int, found bool) int {
	if !found || count < c.minListCount {
		return 0 // Not in enough lists
	}

	// Score increases with number of blocklists
	switch {
	case count >= 10:
		return 95 // In 10+ lists = extremely malicious
	case count >= 7:
		return 85 // In 7-9 lists = highly malicious
	case count >= 5:
		return 75 // In 5-6 lists = very suspicious
	case count >= 3:
		return 60 // In 3-4 lists = suspicious
	default:
		return 0
	}
}

// refreshCache downloads and parses the IPSum list
func (c *IPSumClient) refreshCache() error {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	// Download the list for IPs in 3+ blocklists
	url := fmt.Sprintf(c.baseURL, c.minListCount)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("download IPSum list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("IPSum API error: status %d", resp.StatusCode)
	}

	// Parse the list (format: IP<tab>count)
	newCache := make(map[string]int)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 1 {
			ip := parts[0]
			count := c.minListCount // Default to minimum if no count provided
			if len(parts) >= 2 {
				if parsed, err := strconv.Atoi(parts[1]); err == nil {
					count = parsed
				}
			}
			newCache[ip] = count
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse IPSum list: %w", err)
	}

	c.cache = newCache
	c.lastUpdate = time.Now()

	fmt.Printf("IPSum: Loaded %d IPs from blocklists\n", len(newCache))
	return nil
}

// GetProviderName returns the provider name
func (c *IPSumClient) GetProviderName() string {
	return "IPSum"
}

// IsConfigured returns true (IPSum doesn't require an API key)
func (c *IPSumClient) IsConfigured() bool {
	return true // Always configured - uses public GitHub data
}

// GetCacheStats returns statistics about the local cache
func (c *IPSumClient) GetCacheStats() (int, time.Time) {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()
	return len(c.cache), c.lastUpdate
}

// ForceRefresh forces an immediate cache refresh
func (c *IPSumClient) ForceRefresh() error {
	return c.refreshCache()
}
