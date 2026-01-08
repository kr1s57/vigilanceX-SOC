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
// v2.9: Added proxy mode support
// v2.9.5: Added cascade tiers, ThreatFox, URLhaus, Shodan InternetDB
type Aggregator struct {
	// Tier 1 providers (unlimited - always query)
	ipSum      *IPSumClient            // Aggregated blocklists (no API key)
	otx        *OTXClient              // AlienVault OTX (generous limits)
	threatFox  *ThreatFoxClient        // abuse.ch C2/malware IOCs (no API key)
	urlhaus    *URLhausClient          // abuse.ch malicious URLs (no API key)
	shodanIDB  *ShodanInternetDBClient // Shodan passive data (no API key)

	// Tier 2 providers (moderate limits - query if Tier1 score >= threshold)
	abuseIPDB *AbuseIPDBClient // ~1000/day
	greyNoise *GreyNoiseClient // ~500/day, reduces false positives

	// Tier 3 providers (limited - query only if high suspicion)
	virusTotal *VirusTotalClient // ~500/day
	criminalIP *CriminalIPClient // Limited
	pulsedive  *PulsediveClient  // ~30/day

	// v2.9: Proxy support
	proxyClient *OSINTProxyClient
	useProxy    bool

	// Cascade configuration
	cascadeConfig CascadeConfig

	cache   *ThreatCache
	weights AggregationWeights
}

// CascadeConfig defines thresholds for tiered API querying
type CascadeConfig struct {
	Tier2Threshold int  // Score threshold to query Tier 2 (default: 30)
	Tier3Threshold int  // Score threshold to query Tier 3 (default: 60)
	EnableCascade  bool // Enable cascade mode (default: true)
}

// AggregationWeights defines the weight of each source in final score
// v2.9.5: Rebalanced weights for 10 providers with cascade tiers
type AggregationWeights struct {
	// Tier 1 (unlimited)
	IPSum     float64 // Blocklist aggregation
	OTX       float64 // Threat context
	ThreatFox float64 // C2/malware IOCs
	URLhaus   float64 // Malicious URLs
	ShodanIDB float64 // Passive reconnaissance
	// Tier 2 (moderate)
	AbuseIPDB float64 // Behavior-based reputation
	GreyNoise float64 // False positive reduction
	// Tier 3 (limited)
	VirusTotal float64 // Multi-AV consensus
	CriminalIP float64 // Infrastructure detection
	Pulsedive  float64 // IOC correlation
}

// DefaultWeights returns the default aggregation weights
// v2.9.5: 10 providers, weights sum to ~1.0
func DefaultWeights() AggregationWeights {
	return AggregationWeights{
		// Tier 1 - Always queried, moderate weight each
		IPSum:     0.12,
		OTX:       0.10,
		ThreatFox: 0.12, // High value for C2/malware detection
		URLhaus:   0.10,
		ShodanIDB: 0.08, // Contextual data
		// Tier 2 - Queried on suspicion
		AbuseIPDB: 0.15, // Strong behavioral signal
		GreyNoise: 0.12, // Important for FP reduction
		// Tier 3 - Queried on high suspicion
		VirusTotal: 0.10,
		CriminalIP: 0.06,
		Pulsedive:  0.05,
	}
}

// DefaultCascadeConfig returns default cascade thresholds
func DefaultCascadeConfig() CascadeConfig {
	return CascadeConfig{
		Tier2Threshold: 30,  // Query Tier 2 if Tier 1 score >= 30
		Tier3Threshold: 60,  // Query Tier 3 if Tier 2 score >= 60
		EnableCascade:  true,
	}
}

// AggregatorConfig holds configuration for the aggregator
// v2.9.5: Added cascade configuration and new providers
type AggregatorConfig struct {
	// Tier 2 providers (need API keys)
	AbuseIPDBKey  string
	GreyNoiseKey  string
	// Tier 3 providers (need API keys)
	VirusTotalKey string
	CriminalIPKey string
	PulsediveKey  string
	// Tier 1 providers: OTX needs key, others are free
	OTXKey string
	// ThreatFox, URLhaus, ShodanIDB, IPSum don't need keys

	CacheTTL      time.Duration
	Weights       *AggregationWeights
	CascadeConfig *CascadeConfig
}

// NewAggregator creates a new threat intel aggregator
// v2.9.5: With cascade tier support
func NewAggregator(cfg AggregatorConfig) *Aggregator {
	weights := DefaultWeights()
	if cfg.Weights != nil {
		weights = *cfg.Weights
	}

	cascadeConfig := DefaultCascadeConfig()
	if cfg.CascadeConfig != nil {
		cascadeConfig = *cfg.CascadeConfig
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 24 * time.Hour
	}

	return &Aggregator{
		// Tier 1 providers (unlimited - always query)
		ipSum: NewIPSumClient(IPSumConfig{
			MinListCount: 3,
		}),
		otx: NewOTXClient(OTXConfig{
			APIKey: cfg.OTXKey,
		}),
		threatFox: NewThreatFoxClient(),
		urlhaus:   NewURLhausClient(),
		shodanIDB: NewShodanInternetDBClient(),

		// Tier 2 providers (moderate limits)
		abuseIPDB: NewAbuseIPDBClient(AbuseIPDBConfig{
			APIKey: cfg.AbuseIPDBKey,
		}),
		greyNoise: NewGreyNoiseClient(GreyNoiseConfig{
			APIKey: cfg.GreyNoiseKey,
		}),

		// Tier 3 providers (limited)
		virusTotal: NewVirusTotalClient(VirusTotalConfig{
			APIKey: cfg.VirusTotalKey,
		}),
		criminalIP: NewCriminalIPClient(CriminalIPConfig{
			APIKey: cfg.CriminalIPKey,
		}),
		pulsedive: NewPulsediveClient(PulsediveConfig{
			APIKey: cfg.PulsediveKey,
		}),

		cascadeConfig: cascadeConfig,
		cache:         NewThreatCache(cacheTTL),
		weights:       weights,
		useProxy:      false,
	}
}

// NewAggregatorWithProxy creates a new aggregator that routes queries through a proxy
func NewAggregatorWithProxy(proxyClient *OSINTProxyClient, cacheTTL time.Duration) *Aggregator {
	if cacheTTL == 0 {
		cacheTTL = 24 * time.Hour
	}

	return &Aggregator{
		proxyClient: proxyClient,
		useProxy:    true,
		cache:       NewThreatCache(cacheTTL),
		weights:     DefaultWeights(),
	}
}

// AggregatedResult contains the combined threat intelligence
// v2.9.5: Added ThreatFox, URLhaus, ShodanIDB results and cascade info
type AggregatedResult struct {
	IP              string         `json:"ip"`
	AggregatedScore int            `json:"aggregated_score"` // 0-100 weighted score
	ThreatLevel     string         `json:"threat_level"`     // none, low, medium, high, critical
	Confidence      float64        `json:"confidence"`       // 0-1 based on source availability
	Sources         []SourceResult `json:"sources"`
	TiersQueried    []int          `json:"tiers_queried"`    // v2.9.5: Which tiers were queried [1], [1,2], [1,2,3]

	// Tier 1 provider results (always queried)
	IPSum     *IPSumResult            `json:"ipsum,omitempty"`
	OTX       *OTXResult              `json:"otx,omitempty"`
	ThreatFox *ThreatFoxResult        `json:"threatfox,omitempty"`
	URLhaus   *URLhausResult          `json:"urlhaus,omitempty"`
	ShodanIDB *ShodanInternetDBResult `json:"shodan_idb,omitempty"`

	// Tier 2 provider results (queried on suspicion)
	AbuseIPDB *AbuseIPDBResult `json:"abuseipdb,omitempty"`
	GreyNoise *GreyNoiseResult `json:"greynoise,omitempty"`

	// Tier 3 provider results (queried on high suspicion)
	VirusTotal *VirusTotalResult `json:"virustotal,omitempty"`
	CriminalIP *CriminalIPResult `json:"criminalip,omitempty"`
	Pulsedive  *PulsediveResult  `json:"pulsedive,omitempty"`

	// Aggregated metadata
	Country         string   `json:"country"`
	ASN             string   `json:"asn"`
	ISP             string   `json:"isp"`
	Tags            []string `json:"tags"`
	MalwareFamilies []string `json:"malware_families,omitempty"`
	Adversaries     []string `json:"adversaries,omitempty"`
	Campaigns       []string `json:"campaigns,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"` // v2.9.5: From ShodanIDB
	OpenPorts       []int    `json:"open_ports,omitempty"`      // v2.9.5: From ShodanIDB
	IsTor           bool     `json:"is_tor"`
	IsVPN           bool     `json:"is_vpn"`
	IsProxy         bool     `json:"is_proxy"`
	IsBenign        bool     `json:"is_benign"`      // GreyNoise benign flag
	IsC2            bool     `json:"is_c2"`          // v2.9.5: From ThreatFox
	InBlocklists    int      `json:"in_blocklists"`  // IPSum count
	LastChecked     time.Time `json:"last_checked"`
	CacheHit        bool     `json:"cache_hit"`
}

// SourceResult contains result from a single source
type SourceResult struct {
	Provider       string  `json:"provider"`
	Score          int     `json:"score"`
	Weight         float64 `json:"weight"`
	WeightedScore  float64 `json:"weighted_score"`
	Available      bool    `json:"available"`
	Tier           int     `json:"tier"`                       // v2.9.5: Provider tier (1, 2, or 3)
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

	var result *AggregatedResult
	var err error

	// v2.9: Use proxy mode if enabled
	if a.useProxy && a.proxyClient != nil {
		result, err = a.proxyClient.CheckIP(ctx, ip)
		if err != nil {
			return nil, err
		}
		// Cache the result
		a.cache.Set(ip, result)
		return result, nil
	}

	// Local providers mode
	result = a.checkIPLocally(ctx, ip)

	// Cache the result
	a.cache.Set(ip, result)

	return result, nil
}

// checkIPLocally queries threat intel providers using cascade tiers
// v2.9.5: Implements tiered cascade to save API quotas
func (a *Aggregator) checkIPLocally(ctx context.Context, ip string) *AggregatedResult {
	result := &AggregatedResult{
		IP:           ip,
		LastChecked:  time.Now(),
		Tags:         []string{},
		TiersQueried: []int{1},
	}

	var mu sync.Mutex

	// =========================================================================
	// TIER 1: Unlimited providers (always query in parallel)
	// =========================================================================
	a.queryTier1(ctx, ip, result, &mu)

	// Calculate intermediate score after Tier 1
	tier1Score := a.calculateIntermediateScore(result)
	hasCriticalIndicators := a.hasCriticalIndicators(result)

	log.Printf("[CASCADE] %s: Tier 1 score=%d, critical=%v", ip, tier1Score, hasCriticalIndicators)

	// =========================================================================
	// TIER 2: Moderate limits (query if Tier 1 indicates suspicion)
	// =========================================================================
	shouldQueryTier2 := !a.cascadeConfig.EnableCascade ||
		tier1Score >= a.cascadeConfig.Tier2Threshold ||
		hasCriticalIndicators

	if shouldQueryTier2 {
		result.TiersQueried = append(result.TiersQueried, 2)
		a.queryTier2(ctx, ip, result, &mu)

		// Recalculate score after Tier 2
		tier2Score := a.calculateIntermediateScore(result)
		hasHighRiskIndicators := a.hasHighRiskIndicators(result)

		log.Printf("[CASCADE] %s: Tier 2 score=%d, high_risk=%v", ip, tier2Score, hasHighRiskIndicators)

		// =========================================================================
		// TIER 3: Limited providers (query only on high suspicion)
		// =========================================================================
		shouldQueryTier3 := !a.cascadeConfig.EnableCascade ||
			tier2Score >= a.cascadeConfig.Tier3Threshold ||
			hasHighRiskIndicators

		if shouldQueryTier3 {
			result.TiersQueried = append(result.TiersQueried, 3)
			a.queryTier3(ctx, ip, result, &mu)
		}
	}

	// Calculate final aggregated score
	a.calculateAggregatedScore(result)

	return result
}

// queryTier1 queries all Tier 1 (unlimited) providers in parallel
func (a *Aggregator) queryTier1(ctx context.Context, ip string, result *AggregatedResult, mu *sync.Mutex) {
	var wg sync.WaitGroup

	// IPSum (blocklists)
	if a.ipSum != nil && a.ipSum.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipsResult, err := a.ipSum.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "IPSum", Weight: a.weights.IPSum, Available: err == nil, Tier: 1}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.IPSum = ipsResult
				source.Score = ipsResult.NormalizedScore
				source.WeightedScore = float64(ipsResult.NormalizedScore) * a.weights.IPSum
				result.InBlocklists = ipsResult.BlocklistCount
				if ipsResult.InBlocklists {
					result.Tags = append(result.Tags, "in_blocklists")
				}
			}
			result.Sources = append(result.Sources, source)
		}()
	}

	// AlienVault OTX
	if a.otx != nil && a.otx.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			otxResult, err := a.otx.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "AlienVault OTX", Weight: a.weights.OTX, Available: err == nil, Tier: 1}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.OTX = otxResult
				source.Score = otxResult.NormalizedScore
				source.WeightedScore = float64(otxResult.NormalizedScore) * a.weights.OTX
				if result.Country == "" && otxResult.CountryCode != "" {
					result.Country = otxResult.CountryCode
				}
				if result.ASN == "" && otxResult.ASN != "" {
					result.ASN = otxResult.ASN
				}
				result.MalwareFamilies = append(result.MalwareFamilies, otxResult.MalwareFamilies...)
				result.Adversaries = append(result.Adversaries, otxResult.Adversaries...)
				result.Tags = append(result.Tags, otxResult.Tags...)
			}
			result.Sources = append(result.Sources, source)
		}()
	}

	// ThreatFox (abuse.ch)
	if a.threatFox != nil && a.threatFox.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tfResult, err := a.threatFox.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "ThreatFox", Weight: a.weights.ThreatFox, Available: err == nil, Tier: 1}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.ThreatFox = tfResult
				source.Score = tfResult.Score
				source.WeightedScore = float64(tfResult.Score) * a.weights.ThreatFox
				if tfResult.Found {
					result.IsC2 = true
					result.Tags = append(result.Tags, "threatfox_ioc")
					if tfResult.Malware != "" {
						result.MalwareFamilies = append(result.MalwareFamilies, tfResult.Malware)
					}
					result.Tags = append(result.Tags, tfResult.Tags...)
				}
			}
			result.Sources = append(result.Sources, source)
		}()
	}

	// URLhaus (abuse.ch)
	if a.urlhaus != nil && a.urlhaus.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			uhResult, err := a.urlhaus.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "URLhaus", Weight: a.weights.URLhaus, Available: err == nil, Tier: 1}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.URLhaus = uhResult
				source.Score = uhResult.Score
				source.WeightedScore = float64(uhResult.Score) * a.weights.URLhaus
				if uhResult.Found {
					result.Tags = append(result.Tags, "urlhaus_malicious")
					result.Tags = append(result.Tags, uhResult.Tags...)
				}
			}
			result.Sources = append(result.Sources, source)
		}()
	}

	// Shodan InternetDB
	if a.shodanIDB != nil && a.shodanIDB.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sResult, err := a.shodanIDB.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "Shodan InternetDB", Weight: a.weights.ShodanIDB, Available: err == nil, Tier: 1}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.ShodanIDB = sResult
				source.Score = sResult.Score
				source.WeightedScore = float64(sResult.Score) * a.weights.ShodanIDB
				if sResult.Found {
					result.OpenPorts = sResult.Ports
					result.Vulnerabilities = sResult.Vulns
					result.Tags = append(result.Tags, sResult.Tags...)
					if sResult.IsVPN {
						result.IsVPN = true
					}
					if sResult.IsProxy {
						result.IsProxy = true
					}
					if sResult.IsTor {
						result.IsTor = true
					}
				}
			}
			result.Sources = append(result.Sources, source)
		}()
	}

	wg.Wait()
}

// queryTier2 queries Tier 2 (moderate limits) providers in parallel
func (a *Aggregator) queryTier2(ctx context.Context, ip string, result *AggregatedResult, mu *sync.Mutex) {
	var wg sync.WaitGroup

	// AbuseIPDB
	if a.abuseIPDB != nil && a.abuseIPDB.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			abuseResult, err := a.abuseIPDB.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "AbuseIPDB", Weight: a.weights.AbuseIPDB, Available: err == nil, Tier: 2}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.AbuseIPDB = abuseResult
				source.Score = abuseResult.NormalizedScore
				source.WeightedScore = float64(abuseResult.NormalizedScore) * a.weights.AbuseIPDB
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

	// GreyNoise
	if a.greyNoise != nil && a.greyNoise.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gnResult, err := a.greyNoise.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "GreyNoise", Weight: a.weights.GreyNoise, Available: err == nil, Tier: 2}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.GreyNoise = gnResult
				source.Score = gnResult.NormalizedScore
				source.WeightedScore = float64(gnResult.NormalizedScore) * a.weights.GreyNoise
				source.IsBenignSource = gnResult.IsBenign
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
			}
			result.Sources = append(result.Sources, source)
		}()
	}

	wg.Wait()
}

// queryTier3 queries Tier 3 (limited) providers in parallel
func (a *Aggregator) queryTier3(ctx context.Context, ip string, result *AggregatedResult, mu *sync.Mutex) {
	var wg sync.WaitGroup

	// VirusTotal
	if a.virusTotal != nil && a.virusTotal.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vtResult, err := a.virusTotal.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "VirusTotal", Weight: a.weights.VirusTotal, Available: err == nil, Tier: 3}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.VirusTotal = vtResult
				source.Score = vtResult.NormalizedScore
				source.WeightedScore = float64(vtResult.NormalizedScore) * a.weights.VirusTotal
				if result.Country == "" && vtResult.Country != "" {
					result.Country = vtResult.Country
				}
				if result.ASN == "" && vtResult.ASOwner != "" {
					result.ASN = vtResult.ASOwner
				}
				result.Tags = append(result.Tags, vtResult.Tags...)
			}
			result.Sources = append(result.Sources, source)
		}()
	}

	// CriminalIP
	if a.criminalIP != nil && a.criminalIP.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cipResult, err := a.criminalIP.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "CriminalIP", Weight: a.weights.CriminalIP, Available: err == nil, Tier: 3}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.CriminalIP = cipResult
				source.Score = cipResult.NormalizedScore
				source.WeightedScore = float64(cipResult.NormalizedScore) * a.weights.CriminalIP
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
				result.Tags = append(result.Tags, cipResult.Categories...)
			}
			result.Sources = append(result.Sources, source)
		}()
	}

	// Pulsedive
	if a.pulsedive != nil && a.pulsedive.IsConfigured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pdResult, err := a.pulsedive.CheckIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			source := SourceResult{Provider: "Pulsedive", Weight: a.weights.Pulsedive, Available: err == nil, Tier: 3}
			if err != nil {
				source.Error = err.Error()
			} else {
				result.Pulsedive = pdResult
				source.Score = pdResult.NormalizedScore
				source.WeightedScore = float64(pdResult.NormalizedScore) * a.weights.Pulsedive
				result.Adversaries = append(result.Adversaries, pdResult.ThreatActors...)
				result.MalwareFamilies = append(result.MalwareFamilies, pdResult.MalwareFamilies...)
				result.Campaigns = append(result.Campaigns, pdResult.Campaigns...)
			}
			result.Sources = append(result.Sources, source)
		}()
	}

	wg.Wait()
}

// calculateIntermediateScore calculates score from currently available sources
func (a *Aggregator) calculateIntermediateScore(result *AggregatedResult) int {
	var totalWeight float64
	var weightedSum float64

	for _, source := range result.Sources {
		if source.Available {
			totalWeight += source.Weight
			weightedSum += source.WeightedScore
		}
	}

	if totalWeight > 0 {
		return int(weightedSum / totalWeight)
	}
	return 0
}

// hasCriticalIndicators checks for critical indicators that warrant deeper investigation
func (a *Aggregator) hasCriticalIndicators(result *AggregatedResult) bool {
	// C2 or malware IOC found in ThreatFox
	if result.ThreatFox != nil && result.ThreatFox.Found {
		return true
	}
	// Active malicious URLs in URLhaus
	if result.URLhaus != nil && result.URLhaus.Found && result.URLhaus.ActiveURLs > 0 {
		return true
	}
	// High blocklist presence
	if result.InBlocklists >= 5 {
		return true
	}
	// Critical vulnerabilities from Shodan
	if result.ShodanIDB != nil && result.ShodanIDB.HasCritical {
		return true
	}
	return false
}

// hasHighRiskIndicators checks for indicators that warrant Tier 3 investigation
func (a *Aggregator) hasHighRiskIndicators(result *AggregatedResult) bool {
	// AbuseIPDB high confidence
	if result.AbuseIPDB != nil && result.AbuseIPDB.NormalizedScore >= 50 {
		return true
	}
	// GreyNoise says malicious
	if result.GreyNoise != nil && result.GreyNoise.Classification == "malicious" {
		return true
	}
	// Multiple critical indicators from Tier 1
	if result.IsC2 && result.InBlocklists >= 3 {
		return true
	}
	return false
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
// v2.9.5: Added Tier 1 providers (ThreatFox, URLhaus, ShodanIDB)
func (a *Aggregator) GetConfiguredProviders() []string {
	var providers []string

	// v2.9: Handle proxy mode
	if a.useProxy {
		if a.proxyClient != nil && a.proxyClient.IsConfigured() {
			providers = append(providers, "OSINT Proxy")
		}
		return providers
	}

	// Tier 1 providers (unlimited)
	if a.ipSum != nil && a.ipSum.IsConfigured() {
		providers = append(providers, "IPSum")
	}
	if a.otx != nil && a.otx.IsConfigured() {
		providers = append(providers, "AlienVault OTX")
	}
	if a.threatFox != nil && a.threatFox.IsConfigured() {
		providers = append(providers, "ThreatFox")
	}
	if a.urlhaus != nil && a.urlhaus.IsConfigured() {
		providers = append(providers, "URLhaus")
	}
	if a.shodanIDB != nil && a.shodanIDB.IsConfigured() {
		providers = append(providers, "Shodan InternetDB")
	}

	// Tier 2 providers (moderate limits)
	if a.abuseIPDB != nil && a.abuseIPDB.IsConfigured() {
		providers = append(providers, "AbuseIPDB")
	}
	if a.greyNoise != nil && a.greyNoise.IsConfigured() {
		providers = append(providers, "GreyNoise")
	}

	// Tier 3 providers (limited)
	if a.virusTotal != nil && a.virusTotal.IsConfigured() {
		providers = append(providers, "VirusTotal")
	}
	if a.criminalIP != nil && a.criminalIP.IsConfigured() {
		providers = append(providers, "CriminalIP")
	}
	if a.pulsedive != nil && a.pulsedive.IsConfigured() {
		providers = append(providers, "Pulsedive")
	}

	return providers
}

// GetProviderStatus returns detailed status of all providers
// v2.9.5: Added tier information and new providers
func (a *Aggregator) GetProviderStatus() []ProviderStatus {
	// v2.9: Handle proxy mode
	if a.useProxy {
		return []ProviderStatus{
			{Name: "OSINT Proxy", Configured: a.proxyClient != nil && a.proxyClient.IsConfigured(), Description: "Centralized OSINT queries via license server", Tier: 0, RequiresKey: false},
		}
	}

	return []ProviderStatus{
		// Tier 1: Unlimited providers (always queried)
		{Name: "IPSum", Configured: a.ipSum != nil && a.ipSum.IsConfigured(), Description: "Aggregated blocklists (30+ sources)", Tier: 1, RequiresKey: false},
		{Name: "AlienVault OTX", Configured: a.otx != nil && a.otx.IsConfigured(), Description: "Threat context & IOCs", Tier: 1, RequiresKey: true},
		{Name: "ThreatFox", Configured: a.threatFox != nil && a.threatFox.IsConfigured(), Description: "abuse.ch C2/malware IOCs", Tier: 1, RequiresKey: false},
		{Name: "URLhaus", Configured: a.urlhaus != nil && a.urlhaus.IsConfigured(), Description: "abuse.ch malicious URLs database", Tier: 1, RequiresKey: false},
		{Name: "Shodan InternetDB", Configured: a.shodanIDB != nil && a.shodanIDB.IsConfigured(), Description: "Passive ports/vulns/tags reconnaissance", Tier: 1, RequiresKey: false},

		// Tier 2: Moderate limits (queried on suspicion)
		{Name: "AbuseIPDB", Configured: a.abuseIPDB != nil && a.abuseIPDB.IsConfigured(), Description: "IP abuse reports & confidence scoring", Tier: 2, RequiresKey: true},
		{Name: "GreyNoise", Configured: a.greyNoise != nil && a.greyNoise.IsConfigured(), Description: "Benign scanner identification (FP reduction)", Tier: 2, RequiresKey: true},

		// Tier 3: Limited providers (queried on high suspicion)
		{Name: "VirusTotal", Configured: a.virusTotal != nil && a.virusTotal.IsConfigured(), Description: "Multi-AV consensus & reputation", Tier: 3, RequiresKey: true},
		{Name: "CriminalIP", Configured: a.criminalIP != nil && a.criminalIP.IsConfigured(), Description: "C2/VPN/Proxy infrastructure detection", Tier: 3, RequiresKey: true},
		{Name: "Pulsedive", Configured: a.pulsedive != nil && a.pulsedive.IsConfigured(), Description: "IOC correlation & threat actors", Tier: 3, RequiresKey: true},
	}
}

// IsProxyMode returns true if the aggregator is using proxy mode
func (a *Aggregator) IsProxyMode() bool {
	return a.useProxy
}

// ProviderStatus represents the status of a provider
// v2.9.5: Added Tier and RequiresKey fields
type ProviderStatus struct {
	Name        string `json:"name"`
	Configured  bool   `json:"configured"`
	Description string `json:"description"`
	Tier        int    `json:"tier"`         // 1=unlimited, 2=moderate, 3=limited, 0=proxy
	RequiresKey bool   `json:"requires_key"` // Whether API key is required
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
