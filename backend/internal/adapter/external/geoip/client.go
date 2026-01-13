package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// Client provides geolocation lookups for IP addresses
// Uses ip-api.com (free tier: 45 requests/minute) and local caching
type Client struct {
	httpClient *http.Client
	cache      *geoCache
	config     Config
}

// Config holds GeoIP client configuration
type Config struct {
	// CacheTTL is how long to cache geolocation results
	CacheTTL time.Duration
	// Timeout for HTTP requests
	Timeout time.Duration
	// MaxCacheSize is the maximum number of entries in the cache
	MaxCacheSize int
}

// DefaultConfig returns sensible default configuration
func DefaultConfig() Config {
	return Config{
		CacheTTL:     24 * time.Hour,
		Timeout:      5 * time.Second,
		MaxCacheSize: 10000,
	}
}

// geoCache provides thread-safe caching for geolocation results
type geoCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	maxSize int
}

type cacheEntry struct {
	data      *entity.GeoLocation
	expiresAt time.Time
}

func newGeoCache(maxSize int) *geoCache {
	return &geoCache{
		entries: make(map[string]*cacheEntry),
		maxSize: maxSize,
	}
}

func (c *geoCache) Get(ip string) (*entity.GeoLocation, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[ip]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.data, true
}

func (c *geoCache) Set(ip string, data *entity.GeoLocation, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: if at max size, remove oldest 10%
	if len(c.entries) >= c.maxSize {
		count := 0
		toDelete := c.maxSize / 10
		for key := range c.entries {
			delete(c.entries, key)
			count++
			if count >= toDelete {
				break
			}
		}
	}

	c.entries[ip] = &cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *geoCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry)
}

func (c *geoCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// NewClient creates a new GeoIP client
func NewClient(config Config) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		cache:  newGeoCache(config.MaxCacheSize),
		config: config,
	}
}

// NewDefaultClient creates a client with default configuration
func NewDefaultClient() *Client {
	return NewClient(DefaultConfig())
}

// ipAPIResponse represents the response from ip-api.com
type ipAPIResponse struct {
	Status      string  `json:"status"`
	Message     string  `json:"message"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
	// Pro fields (not available in free tier)
	Mobile  bool `json:"mobile"`
	Proxy   bool `json:"proxy"`
	Hosting bool `json:"hosting"`
}

// Lookup performs a geolocation lookup for an IP address
func (c *Client) Lookup(ctx context.Context, ip string) (*entity.GeoLocation, error) {
	// Check cache first
	if cached, ok := c.cache.Get(ip); ok {
		return cached, nil
	}

	// Query ip-api.com
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,query,proxy,hosting", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("geoip lookup failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("geoip api returned status %d", resp.StatusCode)
	}

	var apiResp ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if apiResp.Status != "success" {
		return nil, fmt.Errorf("geoip lookup failed: %s", apiResp.Message)
	}

	// Parse ASN from "AS" field (format: "AS12345 Organization Name")
	var asn uint32
	if apiResp.AS != "" {
		fmt.Sscanf(apiResp.AS, "AS%d", &asn)
	}

	geo := &entity.GeoLocation{
		IP:           ip,
		CountryCode:  apiResp.CountryCode,
		CountryName:  apiResp.Country,
		City:         apiResp.City,
		Region:       apiResp.RegionName,
		ASN:          asn,
		ASOrg:        apiResp.Org,
		IsProxy:      apiResp.Proxy,
		IsDatacenter: apiResp.Hosting,
		Latitude:     apiResp.Lat,
		Longitude:    apiResp.Lon,
		LastUpdated:  time.Now(),
	}

	// Cache the result
	c.cache.Set(ip, geo, c.config.CacheTTL)

	return geo, nil
}

// LookupBatch performs geolocation lookups for multiple IPs
// Note: ip-api.com has a rate limit of 45 requests/minute on free tier
func (c *Client) LookupBatch(ctx context.Context, ips []string) (map[string]*entity.GeoLocation, error) {
	results := make(map[string]*entity.GeoLocation)

	for _, ip := range ips {
		geo, err := c.Lookup(ctx, ip)
		if err != nil {
			// Log error but continue with other IPs
			continue
		}
		results[ip] = geo
	}

	return results, nil
}

// GetCacheStats returns cache statistics
func (c *Client) GetCacheStats() (size int, ttl time.Duration) {
	return c.cache.Size(), c.config.CacheTTL
}

// ClearCache clears the geolocation cache
func (c *Client) ClearCache() {
	c.cache.Clear()
}

// IsConfigured returns true (this client doesn't require API keys)
func (c *Client) IsConfigured() bool {
	return true
}

// GetProviderName returns the provider name
func (c *Client) GetProviderName() string {
	return "ip-api.com"
}

// LookupCountry returns just the country code for an IP address
// Implements the crowdsec.GeoIPLookup interface
func (c *Client) LookupCountry(ctx context.Context, ip string) (string, error) {
	geo, err := c.Lookup(ctx, ip)
	if err != nil {
		return "", err
	}
	if geo == nil {
		return "", nil
	}
	return geo.CountryCode, nil
}
