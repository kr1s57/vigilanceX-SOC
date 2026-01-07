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
// v1.6: Added GreyNoise, IPSum, CriminalIP, Pulsedive
type Aggregator struct {
	// Core providers (API-based)
	abuseIPDB  *AbuseIPDBClient
	virusTotal *VirusTotalClient
	otx        *OTXClient
	// New providers v1.6
	greyNoise  *GreyNoiseClient  // Reduces false positives
	ipSum      *IPSumClient      // Aggregated blocklists (no API key needed)
	criminalIP *CriminalIPClient // C2/VPN/Proxy detection
	pulsedive  *PulsediveClient  // IOC correlation
	cache      *ThreatCache
	weights    AggregationWeights
}

// AggregationWeights defines the weight of each source in final score
// v1.6: Rebalanced weights for 7 providers
type AggregationWeights struct {
	AbuseIPDB  float64 // Behavior-based reputation
	VirusTotal float64 // Multi-AV consensus
	OTX        float64 // Threat context
	GreyNoise  float64 // False positive reduction (can apply negative)
	IPSum      float64 // Blocklist aggregation
	CriminalIP float64 // Infrastructure detection
	Pulsedive  float64 // IOC correlation
}

// DefaultWeights returns the default aggregation weights
// Total = 1.0 for normalization
func DefaultWeights() AggregationWeights {
	return AggregationWeights{
		AbuseIPDB:  0.20, // Reduced from 0.40 to accommodate new sources
		VirusTotal: 0.18, // Reduced from 0.35
		OTX:        0.12, // Reduced from 0.25
		GreyNoise:  0.15, // Important for FP reduction
		IPSum:      0.15, // Blocklist presence is strong signal
		CriminalIP: 0.10, // Infrastructure context
		Pulsedive:  0.10, // IOC correlation
	}
}

// AggregatorConfig holds configuration for the aggregator
type AggregatorConfig struct {
	// Core providers
	AbuseIPDBKey  string
	VirusTotalKey string
	OTXKey        string
	// New providers v1.6
	GreyNoiseKey  string
	CriminalIPKey string
	PulsediveKey  string
	// IPSum doesn't need a key (public GitHub data)
	CacheTTL time.Duration
	Weights  *AggregationWeights
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
		// Core providers
		abuseIPDB: NewAbuseIPDBClient(AbuseIPDBConfig{
			APIKey: cfg.AbuseIPDBKey,
		}),
		virusTotal: NewVirusTotalClient(VirusTotalConfig{
			APIKey: cfg.VirusTotalKey,
		}),
		otx: NewOTXClient(OTXConfig{
			APIKey: cfg.OTXKey,
		}),
		// New providers v1.6
		greyNoise: NewGreyNoiseClient(GreyNoiseConfig{
			APIKey: cfg.GreyNoiseKey,
		}),
		ipSum: NewIPSumClient(IPSumConfig{
			MinListCount: 3, // IPs in 3+ blocklists
		}),
		criminalIP: NewCriminalIPClient(CriminalIPConfig{
			APIKey: cfg.CriminalIPKey,
		}),
		pulsedive: NewPulsediveClient(PulsediveConfig{
			APIKey: cfg.PulsediveKey,
		}),
		cache:   NewThreatCache(cacheTTL),
		weights: weights,
	}
}

// AggregatedResult contains the combined threat intelligence
type AggregatedResult struct {
	IP              string         `json:"ip"`
	AggregatedScore int            `json:"aggregated_score"` // 0-100 weighted score
	ThreatLevel     string         `json:"threat_level"`     // none, low, medium, high, critical
	Confidence      float64        `json:"confidence"`       // 0-1 based on source availability
	Sources         []SourceResult `json:"sources"`
	// Core provider results
	AbuseIPDB  *AbuseIPDBResult  `json:"abuseipdb,omitempty"`
	VirusTotal *VirusTotalResult `json:"virustotal,omitempty"`
	OTX        *OTXResult        `json:"otx,omitempty"`
	// New provider results v1.6
	GreyNoise  *GreyNoiseResult  `json:"greynoise,omitempty"`
	IPSum      *IPSumResult      `json:"ipsum,omitempty"`
	CriminalIP *CriminalIPResult `json:"criminalip,omitempty"`
	Pulsedive  *PulsediveResult  `json:"pulsedive,omitempty"`
	// Aggregated metadata
	Country         string    `json:"country"`
	ASN             string    `json:"asn"`
	ISP             string    `json:"isp"`
	Tags            []string  `json:"tags"`
	MalwareFamilies []string  `json:"malware_families,omitempty"`
	Adversaries     []string  `json:"adversaries,omitempty"`
	Campaigns       []string  `json:"campaigns,omitempty"`
	IsTor           bool      `json:"is_tor"`
	IsVPN           bool      `json:"is_vpn"`
	IsProxy         bool      `json:"is_proxy"`
	IsBenign        bool      `json:"is_benign"`     // GreyNoise benign flag
	InBlocklists    int       `json:"in_blocklists"` // IPSum count
	LastChecked     time.Time `json:"last_checked"`
	CacheHit        bool      `json:"cache_hit"`
}

// SourceResult contains result from a single source
type SourceResult struct {
	Provider       string  `json:"provider"`
	Score          int     `json:"score"`
	Weight         float64 `json:"weight"`
	WeightedScore  float64 `json:"weighted_score"`
	Available      bool    `json:"available"`
	Error          string  `json:"error,omitempty"`
	IsBenignSource bool    `json:"is_benign_source,omitempty"` // For GreyNoise
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

	// Query GreyNoise (v1.6)
	if a.greyNoise.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gnResult, err := a.greyNoise.CheckIP(ctx, ip)

			mu.Lock()
			defer mu.Unlock()

			source := SourceResult{
				Provider:  "GreyNoise",
				Weight:    a.weights.GreyNoise,
				Available: err == nil,
			}

			if err != nil {
				source.Error = err.Error()
				log.Printf("[TIP] GreyNoise error for %s: %v", ip, err)
			} else {
				result.GreyNoise = gnResult
				source.Score = gnResult.NormalizedScore
				source.WeightedScore = float64(gnResult.NormalizedScore) * a.weights.GreyNoise
				source.IsBenignSource = gnResult.IsBenign

				// Mark as benign if GreyNoise says so (important for FP reduction)
				if gnResult.IsBenign {
					result.IsBenign = true
					result.Tags = append(result.Tags, "greynoise_benign")
					if gnResult.Name != "" {
						result.Tags = append(result.Tags, "service:"+gnResult.Name)
					}
				}
				if gnResult.Classification == "malicious" {
					result.Tags = append(result.Tags, "greynoise_malicious")
				}
				if gnResult.Noise {
					result.Tags = append(result.Tags, "internet_scanner")
				}
			}

			result.Sources = append(result.Sources, source)
		}()
	}

	// Query IPSum (v1.6) - always available (no API key needed)
	if a.ipSum.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipsResult, err := a.ipSum.CheckIP(ctx, ip)

			mu.Lock()
			defer mu.Unlock()

			source := SourceResult{
				Provider:  "IPSum",
				Weight:    a.weights.IPSum,
				Available: err == nil,
			}

			if err != nil {
				source.Error = err.Error()
				log.Printf("[TIP] IPSum error for %s: %v", ip, err)
			} else {
				result.IPSum = ipsResult
				source.Score = ipsResult.NormalizedScore
				source.WeightedScore = float64(ipsResult.NormalizedScore) * a.weights.IPSum

				// Track blocklist count
				result.InBlocklists = ipsResult.BlocklistCount
				if ipsResult.InBlocklists {
					result.Tags = append(result.Tags, "in_blocklists")
				}
			}

			result.Sources = append(result.Sources, source)
		}()
	}

	// Query Criminal IP (v1.6)
	if a.criminalIP.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cipResult, err := a.criminalIP.CheckIP(ctx, ip)

			mu.Lock()
			defer mu.Unlock()

			source := SourceResult{
				Provider:  "CriminalIP",
				Weight:    a.weights.CriminalIP,
				Available: err == nil,
			}

			if err != nil {
				source.Error = err.Error()
				log.Printf("[TIP] CriminalIP error for %s: %v", ip, err)
			} else {
				result.CriminalIP = cipResult
				source.Score = cipResult.NormalizedScore
				source.WeightedScore = float64(cipResult.NormalizedScore) * a.weights.CriminalIP

				// Extract infrastructure flags
				if cipResult.IsVPN {
					result.IsVPN = true
					result.Tags = append(result.Tags, "vpn")
				}
				if cipResult.IsProxy {
					result.IsProxy = true
					result.Tags = append(result.Tags, "proxy")
				}
				if cipResult.IsTor {
					result.IsTor = true
				}
				if cipResult.IsDarkweb {
					result.Tags = append(result.Tags, "darkweb")
				}
				if cipResult.IsScanner {
					result.Tags = append(result.Tags, "scanner")
				}
				result.Tags = append(result.Tags, cipResult.Categories...)
			}

			result.Sources = append(result.Sources, source)
		}()
	}

	// Query Pulsedive (v1.6)
	if a.pulsedive.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pdResult, err := a.pulsedive.CheckIP(ctx, ip)

			mu.Lock()
			defer mu.Unlock()

			source := SourceResult{
				Provider:  "Pulsedive",
				Weight:    a.weights.Pulsedive,
				Available: err == nil,
			}

			if err != nil {
				source.Error = err.Error()
				log.Printf("[TIP] Pulsedive error for %s: %v", ip, err)
			} else {
				result.Pulsedive = pdResult
				source.Score = pdResult.NormalizedScore
				source.WeightedScore = float64(pdResult.NormalizedScore) * a.weights.Pulsedive

				// Merge threat context
				if len(pdResult.ThreatActors) > 0 {
					result.Adversaries = append(result.Adversaries, pdResult.ThreatActors...)
				}
				if len(pdResult.MalwareFamilies) > 0 {
					result.MalwareFamilies = append(result.MalwareFamilies, pdResult.MalwareFamilies...)
				}
				if len(pdResult.Campaigns) > 0 {
					result.Campaigns = append(result.Campaigns, pdResult.Campaigns...)
				}
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
// v1.6: Handles GreyNoise benign flag for FP reduction
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

	// v1.6: Apply GreyNoise benign modifier
	// If GreyNoise says the IP is benign (RIOT dataset), significantly reduce score
	if result.IsBenign && result.AggregatedScore > 20 {
		// Reduce score by 50% but keep minimum of 10 (still worth monitoring)
		result.AggregatedScore = max(10, result.AggregatedScore/2)
		result.Tags = append(result.Tags, "score_reduced_benign")
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
	// v1.6 providers
	if a.greyNoise.IsConfigured() {
		providers = append(providers, "GreyNoise")
	}
	if a.ipSum.IsConfigured() {
		providers = append(providers, "IPSum")
	}
	if a.criminalIP.IsConfigured() {
		providers = append(providers, "CriminalIP")
	}
	if a.pulsedive.IsConfigured() {
		providers = append(providers, "Pulsedive")
	}

	return providers
}

// GetProviderStatus returns detailed status of all providers
func (a *Aggregator) GetProviderStatus() []ProviderStatus {
	return []ProviderStatus{
		{Name: "AbuseIPDB", Configured: a.abuseIPDB.IsConfigured(), Description: "IP abuse reports & confidence scoring"},
		{Name: "VirusTotal", Configured: a.virusTotal.IsConfigured(), Description: "Multi-AV consensus & reputation"},
		{Name: "AlienVault OTX", Configured: a.otx.IsConfigured(), Description: "Threat context & IOCs"},
		{Name: "GreyNoise", Configured: a.greyNoise.IsConfigured(), Description: "Benign scanner identification (FP reduction)"},
		{Name: "IPSum", Configured: a.ipSum.IsConfigured(), Description: "Aggregated blocklists (30+ sources)"},
		{Name: "CriminalIP", Configured: a.criminalIP.IsConfigured(), Description: "C2/VPN/Proxy infrastructure detection"},
		{Name: "Pulsedive", Configured: a.pulsedive.IsConfigured(), Description: "IOC correlation & threat actors"},
	}
}

// ProviderStatus represents the status of a provider
type ProviderStatus struct {
	Name        string `json:"name"`
	Configured  bool   `json:"configured"`
	Description string `json:"description"`
}

// ClearCache clears the threat intel cache
func (a *Aggregator) ClearCache() {
	a.cache.Clear()
}

// GetCacheStats returns cache statistics
func (a *Aggregator) GetCacheStats() CacheStats {
	return a.cache.Stats()
}

// GetIPSumStats returns IPSum blocklist statistics
func (a *Aggregator) GetIPSumStats() (int, time.Time) {
	return a.ipSum.GetCacheStats()
}

// RefreshIPSum forces a refresh of the IPSum blocklist cache
func (a *Aggregator) RefreshIPSum() error {
	return a.ipSum.ForceRefresh()
}

// max returns the larger of two ints
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
