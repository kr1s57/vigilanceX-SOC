package threatintel

import (
	"context"
	"log"
	"sync"
	"time"
)

// ThreatIntelProvider defines the interface for threat intel sources
type ThreatIntelProvider interface {
	GetProviderName() string
	IsConfigured() bool
}

// Aggregator combines multiple threat intelligence sources
type Aggregator struct {
	abuseIPDB   *AbuseIPDBClient
	virusTotal  *VirusTotalClient
	otx         *OTXClient
	cache       *ThreatCache
	weights     AggregationWeights
}

// AggregationWeights defines the weight of each source in final score
type AggregationWeights struct {
	AbuseIPDB  float64 // Default: 0.4 (40%)
	VirusTotal float64 // Default: 0.35 (35%)
	OTX        float64 // Default: 0.25 (25%)
}

// DefaultWeights returns the default aggregation weights
func DefaultWeights() AggregationWeights {
	return AggregationWeights{
		AbuseIPDB:  0.40,
		VirusTotal: 0.35,
		OTX:        0.25,
	}
}

// AggregatorConfig holds configuration for the aggregator
type AggregatorConfig struct {
	AbuseIPDBKey   string
	VirusTotalKey  string
	OTXKey         string
	CacheTTL       time.Duration
	Weights        *AggregationWeights
}

// NewAggregator creates a new threat intel aggregator
func NewAggregator(cfg AggregatorConfig) *Aggregator {
	weights := DefaultWeights()
	if cfg.Weights != nil {
		weights = *cfg.Weights
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 24 * time.Hour
	}

	return &Aggregator{
		abuseIPDB: NewAbuseIPDBClient(AbuseIPDBConfig{
			APIKey: cfg.AbuseIPDBKey,
		}),
		virusTotal: NewVirusTotalClient(VirusTotalConfig{
			APIKey: cfg.VirusTotalKey,
		}),
		otx: NewOTXClient(OTXConfig{
			APIKey: cfg.OTXKey,
		}),
		cache:   NewThreatCache(cacheTTL),
		weights: weights,
	}
}

// AggregatedResult contains the combined threat intelligence
type AggregatedResult struct {
	IP                string            `json:"ip"`
	AggregatedScore   int               `json:"aggregated_score"`   // 0-100 weighted score
	ThreatLevel       string            `json:"threat_level"`       // none, low, medium, high, critical
	Confidence        float64           `json:"confidence"`         // 0-1 based on source availability
	Sources           []SourceResult    `json:"sources"`
	AbuseIPDB         *AbuseIPDBResult  `json:"abuseipdb,omitempty"`
	VirusTotal        *VirusTotalResult `json:"virustotal,omitempty"`
	OTX               *OTXResult        `json:"otx,omitempty"`
	Country           string            `json:"country"`
	ASN               string            `json:"asn"`
	ISP               string            `json:"isp"`
	Tags              []string          `json:"tags"`
	MalwareFamilies   []string          `json:"malware_families,omitempty"`
	Adversaries       []string          `json:"adversaries,omitempty"`
	IsTor             bool              `json:"is_tor"`
	LastChecked       time.Time         `json:"last_checked"`
	CacheHit          bool              `json:"cache_hit"`
}

// SourceResult contains result from a single source
type SourceResult struct {
	Provider        string `json:"provider"`
	Score           int    `json:"score"`
	Weight          float64 `json:"weight"`
	WeightedScore   float64 `json:"weighted_score"`
	Available       bool   `json:"available"`
	Error           string `json:"error,omitempty"`
}

// CheckIP queries all configured threat intel sources and aggregates results
func (a *Aggregator) CheckIP(ctx context.Context, ip string) (*AggregatedResult, error) {
	// Check cache first
	if cached, found := a.cache.Get(ip); found {
		cached.CacheHit = true
		return cached, nil
	}

	result := &AggregatedResult{
		IP:          ip,
		LastChecked: time.Now(),
		Tags:        []string{},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Query AbuseIPDB
	if a.abuseIPDB.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			abuseResult, err := a.abuseIPDB.CheckIP(ctx, ip)

			mu.Lock()
			defer mu.Unlock()

			source := SourceResult{
				Provider:  "AbuseIPDB",
				Weight:    a.weights.AbuseIPDB,
				Available: err == nil,
			}

			if err != nil {
				source.Error = err.Error()
				log.Printf("[TIP] AbuseIPDB error for %s: %v", ip, err)
			} else {
				result.AbuseIPDB = abuseResult
				source.Score = abuseResult.NormalizedScore
				source.WeightedScore = float64(abuseResult.NormalizedScore) * a.weights.AbuseIPDB

				// Extract metadata
				if result.Country == "" && abuseResult.CountryCode != "" {
					result.Country = abuseResult.CountryCode
				}
				if result.ISP == "" && abuseResult.ISP != "" {
					result.ISP = abuseResult.ISP
				}
				if abuseResult.IsTor {
					result.IsTor = true
					result.Tags = append(result.Tags, "tor_exit_node")
				}
			}

			result.Sources = append(result.Sources, source)
		}()
	}

	// Query VirusTotal
	if a.virusTotal.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vtResult, err := a.virusTotal.CheckIP(ctx, ip)

			mu.Lock()
			defer mu.Unlock()

			source := SourceResult{
				Provider:  "VirusTotal",
				Weight:    a.weights.VirusTotal,
				Available: err == nil,
			}

			if err != nil {
				source.Error = err.Error()
				log.Printf("[TIP] VirusTotal error for %s: %v", ip, err)
			} else {
				result.VirusTotal = vtResult
				source.Score = vtResult.NormalizedScore
				source.WeightedScore = float64(vtResult.NormalizedScore) * a.weights.VirusTotal

				// Extract metadata
				if result.Country == "" && vtResult.Country != "" {
					result.Country = vtResult.Country
				}
				if result.ASN == "" && vtResult.ASOwner != "" {
					result.ASN = vtResult.ASOwner
				}

				// Add tags from VT
				result.Tags = append(result.Tags, vtResult.Tags...)
			}

			result.Sources = append(result.Sources, source)
		}()
	}

	// Query AlienVault OTX
	if a.otx.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			otxResult, err := a.otx.CheckIP(ctx, ip)

			mu.Lock()
			defer mu.Unlock()

			source := SourceResult{
				Provider:  "AlienVault OTX",
				Weight:    a.weights.OTX,
				Available: err == nil,
			}

			if err != nil {
				source.Error = err.Error()
				log.Printf("[TIP] OTX error for %s: %v", ip, err)
			} else {
				result.OTX = otxResult
				source.Score = otxResult.NormalizedScore
				source.WeightedScore = float64(otxResult.NormalizedScore) * a.weights.OTX

				// Extract metadata
				if result.Country == "" && otxResult.CountryCode != "" {
					result.Country = otxResult.CountryCode
				}
				if result.ASN == "" && otxResult.ASN != "" {
					result.ASN = otxResult.ASN
				}

				// Add enrichment data
				result.MalwareFamilies = otxResult.MalwareFamilies
				result.Adversaries = otxResult.Adversaries
				result.Tags = append(result.Tags, otxResult.Tags...)
			}

			result.Sources = append(result.Sources, source)
		}()
	}

	// Wait for all queries
	wg.Wait()

	// Calculate aggregated score
	a.calculateAggregatedScore(result)

	// Cache the result
	a.cache.Set(ip, result)

	return result, nil
}

// calculateAggregatedScore computes the weighted average score
func (a *Aggregator) calculateAggregatedScore(result *AggregatedResult) {
	var totalWeight float64
	var weightedSum float64

	for _, source := range result.Sources {
		if source.Available {
			totalWeight += source.Weight
			weightedSum += source.WeightedScore
		}
	}

	if totalWeight > 0 {
		// Normalize by actual available weight
		result.AggregatedScore = int(weightedSum / totalWeight)
		result.Confidence = totalWeight
	} else {
		result.AggregatedScore = 0
		result.Confidence = 0
	}

	// Determine threat level
	result.ThreatLevel = GetThreatLevel(result.AggregatedScore)
}

// GetThreatLevel converts a score to a threat level string
func GetThreatLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 20:
		return "low"
	default:
		return "none"
	}
}

// GetConfiguredProviders returns list of configured providers
func (a *Aggregator) GetConfiguredProviders() []string {
	var providers []string

	if a.abuseIPDB.IsConfigured() {
		providers = append(providers, "AbuseIPDB")
	}
	if a.virusTotal.IsConfigured() {
		providers = append(providers, "VirusTotal")
	}
	if a.otx.IsConfigured() {
		providers = append(providers, "AlienVault OTX")
	}

	return providers
}

// ClearCache clears the threat intel cache
func (a *Aggregator) ClearCache() {
	a.cache.Clear()
}

// GetCacheStats returns cache statistics
func (a *Aggregator) GetCacheStats() CacheStats {
	return a.cache.Stats()
}
