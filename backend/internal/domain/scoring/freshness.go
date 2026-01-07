package scoring

import (
	"math"
	"time"
)

// FreshnessConfig defines parameters for freshness-based score decay
type FreshnessConfig struct {
	// DecayFactor controls how quickly scores decay over time
	// Lower values = faster decay. Default: 7 (scores halve every 7 days)
	DecayFactor float64

	// MinMultiplier is the minimum freshness multiplier (floor)
	// Default: 0.1 (scores never drop below 10% of original)
	MinMultiplier float64

	// MaxMultiplier is the maximum freshness multiplier (ceiling)
	// Default: 1.5 (recent activity can boost scores up to 150%)
	MaxMultiplier float64

	// RecentActivityBoostDays defines the window for recent activity boost
	// IPs seen within this window get a score boost. Default: 3 days
	RecentActivityBoostDays int

	// RecentActivityBoost is the multiplier for recently active IPs
	// Default: 1.25 (25% boost for IPs active in last 3 days)
	RecentActivityBoost float64

	// StaleThresholdDays marks the threshold after which scores start decaying significantly
	// Default: 30 days
	StaleThresholdDays int
}

// DefaultFreshnessConfig returns sensible defaults for freshness scoring
func DefaultFreshnessConfig() FreshnessConfig {
	return FreshnessConfig{
		DecayFactor:             7.0,
		MinMultiplier:           0.1,
		MaxMultiplier:           1.5,
		RecentActivityBoostDays: 3,
		RecentActivityBoost:     1.25,
		StaleThresholdDays:      30,
	}
}

// FreshnessScorer calculates freshness-based score modifiers
type FreshnessScorer struct {
	config FreshnessConfig
}

// NewFreshnessScorer creates a new freshness scorer with the given config
func NewFreshnessScorer(config FreshnessConfig) *FreshnessScorer {
	return &FreshnessScorer{config: config}
}

// NewDefaultFreshnessScorer creates a freshness scorer with default config
func NewDefaultFreshnessScorer() *FreshnessScorer {
	return &FreshnessScorer{config: DefaultFreshnessConfig()}
}

// FreshnessResult contains the result of a freshness calculation
type FreshnessResult struct {
	// OriginalScore is the input score before freshness adjustment
	OriginalScore int `json:"original_score"`

	// AdjustedScore is the final score after freshness adjustment
	AdjustedScore int `json:"adjusted_score"`

	// Multiplier is the freshness multiplier applied
	Multiplier float64 `json:"multiplier"`

	// DaysSinceLastSeen is the number of days since the IP was last seen
	DaysSinceLastSeen int `json:"days_since_last_seen"`

	// IsRecent indicates if the IP was seen within the recent activity window
	IsRecent bool `json:"is_recent"`

	// IsStale indicates if the IP hasn't been seen in a while
	IsStale bool `json:"is_stale"`

	// Reason explains why the score was adjusted
	Reason string `json:"reason"`
}

// CalculateFreshness calculates the freshness-adjusted score
func (f *FreshnessScorer) CalculateFreshness(score int, lastSeen time.Time) *FreshnessResult {
	result := &FreshnessResult{
		OriginalScore: score,
		AdjustedScore: score,
		Multiplier:    1.0,
	}

	// If lastSeen is zero, treat as unknown (no adjustment)
	if lastSeen.IsZero() {
		result.Reason = "unknown_last_seen"
		return result
	}

	now := time.Now()
	daysSince := int(now.Sub(lastSeen).Hours() / 24)
	result.DaysSinceLastSeen = daysSince

	// Check if recent (within boost window)
	if daysSince <= f.config.RecentActivityBoostDays {
		result.IsRecent = true
		result.Multiplier = f.config.RecentActivityBoost
		result.Reason = "recent_activity_boost"
	} else if daysSince > f.config.StaleThresholdDays {
		// Stale - apply decay
		result.IsStale = true
		daysOverThreshold := float64(daysSince - f.config.StaleThresholdDays)

		// Exponential decay: multiplier = e^(-days/decay_factor)
		result.Multiplier = math.Exp(-daysOverThreshold / f.config.DecayFactor)
		result.Reason = "stale_decay"
	} else {
		// Within normal window - no adjustment
		result.Multiplier = 1.0
		result.Reason = "normal_window"
	}

	// Apply bounds
	if result.Multiplier < f.config.MinMultiplier {
		result.Multiplier = f.config.MinMultiplier
	}
	if result.Multiplier > f.config.MaxMultiplier {
		result.Multiplier = f.config.MaxMultiplier
	}

	// Calculate adjusted score
	result.AdjustedScore = int(float64(score) * result.Multiplier)

	// Ensure score stays within valid range
	if result.AdjustedScore > 100 {
		result.AdjustedScore = 100
	}
	if result.AdjustedScore < 0 {
		result.AdjustedScore = 0
	}

	return result
}

// CalculateMultiSourceFreshness calculates freshness based on multiple last-seen timestamps
// This is useful when aggregating data from multiple blocklists
func (f *FreshnessScorer) CalculateMultiSourceFreshness(score int, lastSeenTimes []time.Time) *FreshnessResult {
	if len(lastSeenTimes) == 0 {
		return &FreshnessResult{
			OriginalScore: score,
			AdjustedScore: score,
			Multiplier:    1.0,
			Reason:        "no_timestamps",
		}
	}

	// Find the most recent last_seen
	var mostRecent time.Time
	for _, t := range lastSeenTimes {
		if t.After(mostRecent) {
			mostRecent = t
		}
	}

	// Calculate base freshness from most recent
	result := f.CalculateFreshness(score, mostRecent)

	// Boost if present in multiple sources recently
	recentCount := 0
	for _, t := range lastSeenTimes {
		daysSince := int(time.Now().Sub(t).Hours() / 24)
		if daysSince <= f.config.RecentActivityBoostDays {
			recentCount++
		}
	}

	if recentCount > 1 {
		// Multi-source recent activity = additional boost
		multiSourceBoost := 1.0 + (0.05 * float64(recentCount-1)) // +5% per additional source
		result.Multiplier *= multiSourceBoost
		if result.Multiplier > f.config.MaxMultiplier {
			result.Multiplier = f.config.MaxMultiplier
		}
		result.AdjustedScore = int(float64(result.OriginalScore) * result.Multiplier)
		if result.AdjustedScore > 100 {
			result.AdjustedScore = 100
		}
		result.Reason = "multi_source_recent_boost"
	}

	return result
}

// ScoringWeights for combining freshness with other factors
type ScoringWeights struct {
	ThreatIntel float64 `json:"threat_intel"` // Weight for threat intel score (0-1)
	Blocklist   float64 `json:"blocklist"`    // Weight for blocklist presence (0-1)
	Freshness   float64 `json:"freshness"`    // Weight for freshness factor (0-1)
	Geolocation float64 `json:"geolocation"`  // Weight for geo-based scoring (0-1)
}

// DefaultScoringWeights returns balanced scoring weights
func DefaultScoringWeights() ScoringWeights {
	return ScoringWeights{
		ThreatIntel: 0.40,
		Blocklist:   0.30,
		Freshness:   0.20,
		Geolocation: 0.10,
	}
}

// CombinedScoreInput contains all inputs for combined score calculation
type CombinedScoreInput struct {
	ThreatIntelScore  int       `json:"threat_intel_score"`
	BlocklistCount    int       `json:"blocklist_count"`
	LastSeen          time.Time `json:"last_seen"`
	GeoScore          int       `json:"geo_score"` // 0-100 based on country risk
	IsWhitelisted     bool      `json:"is_whitelisted"`
	WhitelistModifier int       `json:"whitelist_modifier"` // % reduction for soft whitelist
}

// CombinedScoreResult contains the final combined risk assessment
type CombinedScoreResult struct {
	FinalScore   int             `json:"final_score"`
	RiskLevel    string          `json:"risk_level"`
	Components   ScoreComponents `json:"components"`
	RecommendBan bool            `json:"recommend_ban"`
	Confidence   float64         `json:"confidence"` // 0-1 based on data availability
}

// ScoreComponents breaks down the final score
type ScoreComponents struct {
	ThreatIntel        int     `json:"threat_intel"`
	ThreatIntelWt      float64 `json:"threat_intel_weight"`
	Blocklist          int     `json:"blocklist"`
	BlocklistWt        float64 `json:"blocklist_weight"`
	Freshness          int     `json:"freshness"`
	FreshnessWt        float64 `json:"freshness_weight"`
	Geolocation        int     `json:"geolocation"`
	GeolocationWt      float64 `json:"geolocation_weight"`
	WhitelistReduction int     `json:"whitelist_reduction"`
}

// CombinedScorer combines multiple scoring factors
type CombinedScorer struct {
	freshnessScorer *FreshnessScorer
	weights         ScoringWeights
}

// NewCombinedScorer creates a new combined scorer
func NewCombinedScorer(freshnessConfig FreshnessConfig, weights ScoringWeights) *CombinedScorer {
	return &CombinedScorer{
		freshnessScorer: NewFreshnessScorer(freshnessConfig),
		weights:         weights,
	}
}

// NewDefaultCombinedScorer creates a combined scorer with defaults
func NewDefaultCombinedScorer() *CombinedScorer {
	return &CombinedScorer{
		freshnessScorer: NewDefaultFreshnessScorer(),
		weights:         DefaultScoringWeights(),
	}
}

// CalculateCombinedScore calculates the final risk score from all factors
func (c *CombinedScorer) CalculateCombinedScore(input CombinedScoreInput) *CombinedScoreResult {
	result := &CombinedScoreResult{
		Components: ScoreComponents{
			ThreatIntelWt: c.weights.ThreatIntel,
			BlocklistWt:   c.weights.Blocklist,
			FreshnessWt:   c.weights.Freshness,
			GeolocationWt: c.weights.Geolocation,
		},
	}

	// 1. Threat Intel component
	result.Components.ThreatIntel = input.ThreatIntelScore

	// 2. Blocklist component (convert count to 0-100 score)
	// 1 list = 30, 2 lists = 50, 3+ lists = 70+
	blocklistScore := 0
	if input.BlocklistCount > 0 {
		blocklistScore = 20 + (input.BlocklistCount * 15)
		if blocklistScore > 100 {
			blocklistScore = 100
		}
	}
	result.Components.Blocklist = blocklistScore

	// 3. Freshness component
	freshnessResult := c.freshnessScorer.CalculateFreshness(
		(input.ThreatIntelScore+blocklistScore)/2, // Base on average
		input.LastSeen,
	)
	result.Components.Freshness = int(freshnessResult.Multiplier * 50) // Convert multiplier to 0-75 scale

	// 4. Geolocation component
	result.Components.Geolocation = input.GeoScore

	// Calculate weighted sum
	weightedSum := float64(result.Components.ThreatIntel)*c.weights.ThreatIntel +
		float64(result.Components.Blocklist)*c.weights.Blocklist +
		float64(result.Components.Freshness)*c.weights.Freshness +
		float64(result.Components.Geolocation)*c.weights.Geolocation

	result.FinalScore = int(weightedSum)

	// Apply whitelist reduction if applicable
	if input.IsWhitelisted && input.WhitelistModifier > 0 {
		reduction := float64(result.FinalScore) * float64(input.WhitelistModifier) / 100.0
		result.Components.WhitelistReduction = int(reduction)
		result.FinalScore -= int(reduction)
		if result.FinalScore < 0 {
			result.FinalScore = 0
		}
	}

	// Ensure bounds
	if result.FinalScore > 100 {
		result.FinalScore = 100
	}

	// Determine risk level
	result.RiskLevel = GetRiskLevel(result.FinalScore)

	// Recommendation
	result.RecommendBan = result.FinalScore >= 70

	// Calculate confidence based on data availability
	dataPoints := 0
	if input.ThreatIntelScore > 0 {
		dataPoints++
	}
	if input.BlocklistCount > 0 {
		dataPoints++
	}
	if !input.LastSeen.IsZero() {
		dataPoints++
	}
	if input.GeoScore > 0 {
		dataPoints++
	}
	result.Confidence = float64(dataPoints) / 4.0

	return result
}

// GetRiskLevel converts a score to a risk level string
func GetRiskLevel(score int) string {
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
