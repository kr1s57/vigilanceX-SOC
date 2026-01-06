package threatintel

import (
	"sync"
	"time"
)

// ThreatCache provides in-memory caching for threat intel results
type ThreatCache struct {
	data    map[string]*cacheEntry
	ttl     time.Duration
	mu      sync.RWMutex
	hits    int64
	misses  int64
}

type cacheEntry struct {
	result    *AggregatedResult
	expiresAt time.Time
}

// CacheStats contains cache statistics
type CacheStats struct {
	Size   int     `json:"size"`
	Hits   int64   `json:"hits"`
	Misses int64   `json:"misses"`
	HitRate float64 `json:"hit_rate"`
	TTL    string  `json:"ttl"`
}

// NewThreatCache creates a new threat cache
func NewThreatCache(ttl time.Duration) *ThreatCache {
	cache := &ThreatCache{
		data: make(map[string]*cacheEntry),
		ttl:  ttl,
	}

	// Start background cleanup goroutine
	go cache.cleanup()

	return cache
}

// Get retrieves a result from cache
func (c *ThreatCache) Get(ip string) (*AggregatedResult, bool) {
	c.mu.RLock()
	entry, exists := c.data[ip]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.data, ip)
		c.misses++
		c.mu.Unlock()
		return nil, false
	}

	c.mu.Lock()
	c.hits++
	c.mu.Unlock()

	// Return a copy to prevent modification
	result := *entry.result
	return &result, true
}

// Set stores a result in cache
func (c *ThreatCache) Set(ip string, result *AggregatedResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[ip] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Delete removes an entry from cache
func (c *ThreatCache) Delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, ip)
}

// Clear removes all entries from cache
func (c *ThreatCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]*cacheEntry)
	c.hits = 0
	c.misses = 0
}

// Stats returns cache statistics
func (c *ThreatCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(c.hits) / float64(total)
	}

	return CacheStats{
		Size:    len(c.data),
		Hits:    c.hits,
		Misses:  c.misses,
		HitRate: hitRate,
		TTL:     c.ttl.String(),
	}
}

// cleanup periodically removes expired entries
func (c *ThreatCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.removeExpired()
	}
}

// removeExpired removes all expired entries
func (c *ThreatCache) removeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for ip, entry := range c.data {
		if now.After(entry.expiresAt) {
			delete(c.data, ip)
		}
	}
}
