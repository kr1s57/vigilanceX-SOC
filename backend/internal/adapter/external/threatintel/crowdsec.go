package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CrowdSecClient queries CrowdSec CTI API for IP reputation
// Free tier: 50 requests/day
// Tier 2 provider (moderate limits)
// Provides: reputation, behaviors, background noise, IP range score, MITRE techniques
type CrowdSecClient struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
}

// CrowdSecConfig holds configuration for CrowdSec client
type CrowdSecConfig struct {
	APIKey string
}

// CrowdSecResponse represents the CTI API response
type CrowdSecResponse struct {
	IP                   string                 `json:"ip"`
	IPRange              string                 `json:"ip_range"`
	IPRangeScore         int                    `json:"ip_range_score"`
	IPRange24            string                 `json:"ip_range_24"`
	IPRange24Reputation  string                 `json:"ip_range_24_reputation"`
	IPRange24Score       int                    `json:"ip_range_24_score"`
	ASName               string                 `json:"as_name"`
	ASNum                int                    `json:"as_num"`
	Reputation           string                 `json:"reputation"` // malicious, suspicious, unknown, known, safe
	BackgroundNoiseScore int                    `json:"background_noise_score"` // 0-10
	BackgroundNoise      string                 `json:"background_noise"`       // low, medium, high, none
	Confidence           string                 `json:"confidence"`             // low, medium, high
	ReverseDNS           string                 `json:"reverse_dns"`
	Behaviors            []CrowdSecBehavior     `json:"behaviors"`
	History              CrowdSecHistory        `json:"history"`
	Location             CrowdSecLocation       `json:"location"`
	Classifications      CrowdSecClassification `json:"classifications"`
	AttackDetails        []CrowdSecAttack       `json:"attack_details"`
	TargetCountries      map[string]float64     `json:"target_countries"`
	Scores               CrowdSecScores         `json:"scores"`
	MitreTechniques      []CrowdSecMitre        `json:"mitre_techniques"`
	CVEs                 []string               `json:"cves"`
	References           []CrowdSecReference    `json:"references"`
}

// CrowdSecBehavior represents an observed attack behavior
type CrowdSecBehavior struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// CrowdSecHistory represents IP history
type CrowdSecHistory struct {
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	FullAge   int    `json:"full_age"`
	DaysAge   int    `json:"days_age"`
}

// CrowdSecLocation represents geolocation
type CrowdSecLocation struct {
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// CrowdSecClassificationItem represents a classification entry
type CrowdSecClassificationItem struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	References  []string `json:"references,omitempty"`
}

// CrowdSecClassification holds false positive and classification info
type CrowdSecClassification struct {
	FalsePositives  []CrowdSecClassificationItem `json:"false_positives"`
	Classifications []CrowdSecClassificationItem `json:"classifications"`
}

// CrowdSecAttack represents attack details
type CrowdSecAttack struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	References  []string `json:"references"`
}

// CrowdSecScores represents multi-timeframe scoring
type CrowdSecScores struct {
	Overall   CrowdSecScoreDetail `json:"overall"`
	LastDay   CrowdSecScoreDetail `json:"last_day"`
	LastWeek  CrowdSecScoreDetail `json:"last_week"`
	LastMonth CrowdSecScoreDetail `json:"last_month"`
}

// CrowdSecScoreDetail represents score breakdown
type CrowdSecScoreDetail struct {
	Aggressiveness int `json:"aggressiveness"`
	Threat         int `json:"threat"`
	Trust          int `json:"trust"`
	Anomaly        int `json:"anomaly"`
	Total          int `json:"total"`
}

// CrowdSecMitre represents MITRE ATT&CK technique
type CrowdSecMitre struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// CrowdSecReference represents external references
type CrowdSecReference struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CrowdSecResult represents the processed result
type CrowdSecResult struct {
	Found                bool     `json:"found"`
	IP                   string   `json:"ip,omitempty"`
	Reputation           string   `json:"reputation,omitempty"`           // malicious, suspicious, unknown, safe
	BackgroundNoiseScore int      `json:"background_noise_score"`         // 0-10 (unique to CrowdSec)
	BackgroundNoise      string   `json:"background_noise,omitempty"`     // low, medium, high
	IPRangeScore         int      `json:"ip_range_score"`                 // 0-5 (unique: subnet reputation)
	IPRange24Reputation  string   `json:"ip_range_24_reputation,omitempty"`
	Confidence           string   `json:"confidence,omitempty"`
	Behaviors            []string `json:"behaviors,omitempty"`
	Classifications      []string `json:"classifications,omitempty"`
	FalsePositives       []string `json:"false_positives,omitempty"`
	MitreTechniques      []string `json:"mitre_techniques,omitempty"`
	CVEs                 []string `json:"cves,omitempty"`
	ASName               string   `json:"as_name,omitempty"`
	Country              string   `json:"country,omitempty"`
	FirstSeen            string   `json:"first_seen,omitempty"`
	LastSeen             string   `json:"last_seen,omitempty"`
	DaysAge              int      `json:"days_age,omitempty"`
	// Multi-timeframe scores (unique to CrowdSec)
	OverallScore   int `json:"overall_score"`
	LastDayScore   int `json:"last_day_score"`
	LastWeekScore  int `json:"last_week_score"`
	LastMonthScore int `json:"last_month_score"`
	// Normalized score for aggregation
	NormalizedScore int `json:"normalized_score"` // 0-100
}

// NewCrowdSecClient creates a new CrowdSec CTI client
func NewCrowdSecClient(cfg CrowdSecConfig) *CrowdSecClient {
	return &CrowdSecClient{
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		apiKey:  cfg.APIKey,
		baseURL: "https://cti.api.crowdsec.net/v2",
	}
}

// IsConfigured returns true if the API key is set
func (c *CrowdSecClient) IsConfigured() bool {
	return c.apiKey != ""
}

// GetTier returns the provider tier (2 = moderate limits)
func (c *CrowdSecClient) GetTier() int {
	return 2
}

// CheckIP queries CrowdSec CTI for an IP address
func (c *CrowdSecClient) CheckIP(ctx context.Context, ip string) (*CrowdSecResult, error) {
	if !c.IsConfigured() {
		return &CrowdSecResult{Found: false, NormalizedScore: 0}, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/smoke/"+ip, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// 404 means IP not found in CrowdSec (not an error, just no data)
	if resp.StatusCode == http.StatusNotFound {
		return &CrowdSecResult{Found: false, NormalizedScore: 0}, nil
	}

	// 429 rate limit exceeded
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("CrowdSec rate limit exceeded (50/day)")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var csResp CrowdSecResponse
	if err := json.NewDecoder(resp.Body).Decode(&csResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.processResponse(&csResp), nil
}

// processResponse converts CrowdSec response to our result format
func (c *CrowdSecClient) processResponse(resp *CrowdSecResponse) *CrowdSecResult {
	result := &CrowdSecResult{
		Found:                true,
		IP:                   resp.IP,
		Reputation:           resp.Reputation,
		BackgroundNoiseScore: resp.BackgroundNoiseScore,
		BackgroundNoise:      resp.BackgroundNoise,
		IPRangeScore:         resp.IPRangeScore,
		IPRange24Reputation:  resp.IPRange24Reputation,
		Confidence:           resp.Confidence,
		ASName:               resp.ASName,
		Country:              resp.Location.Country,
		FirstSeen:            resp.History.FirstSeen,
		LastSeen:             resp.History.LastSeen,
		DaysAge:              resp.History.DaysAge,
		CVEs:                 resp.CVEs,
	}

	// Extract behavior names
	for _, b := range resp.Behaviors {
		result.Behaviors = append(result.Behaviors, b.Name)
	}

	// Extract classification names
	for _, c := range resp.Classifications.Classifications {
		result.Classifications = append(result.Classifications, c.Name)
	}
	for _, fp := range resp.Classifications.FalsePositives {
		result.FalsePositives = append(result.FalsePositives, fp.Name)
	}

	// Extract MITRE technique names
	for _, m := range resp.MitreTechniques {
		result.MitreTechniques = append(result.MitreTechniques, m.Name)
	}

	// Multi-timeframe scores
	result.OverallScore = resp.Scores.Overall.Total
	result.LastDayScore = resp.Scores.LastDay.Total
	result.LastWeekScore = resp.Scores.LastWeek.Total
	result.LastMonthScore = resp.Scores.LastMonth.Total

	// Calculate normalized score
	result.NormalizedScore = c.calculateScore(resp)

	return result
}

// calculateScore calculates a normalized threat score (0-100)
func (c *CrowdSecClient) calculateScore(resp *CrowdSecResponse) int {
	score := 0

	// Base score from reputation
	switch strings.ToLower(resp.Reputation) {
	case "malicious":
		score = 70
	case "suspicious":
		score = 50
	case "known":
		score = 30
	case "unknown":
		score = 10
	case "safe":
		score = 0
	}

	// Adjust based on background noise (0-10 scale)
	// High background noise = more suspicious
	if resp.BackgroundNoiseScore >= 7 {
		score += 15
	} else if resp.BackgroundNoiseScore >= 4 {
		score += 10
	}

	// Adjust based on IP range reputation
	switch strings.ToLower(resp.IPRange24Reputation) {
	case "malicious":
		score += 10
	case "suspicious":
		score += 5
	}

	// Adjust based on IP range score (0-5)
	if resp.IPRangeScore >= 4 {
		score += 10
	} else if resp.IPRangeScore >= 2 {
		score += 5
	}

	// Adjust based on behaviors
	behaviorBonus := min(len(resp.Behaviors)*3, 15)
	score += behaviorBonus

	// Bonus for aggressive behaviors
	for _, b := range resp.Behaviors {
		name := strings.ToLower(b.Name)
		if strings.Contains(name, "exploit") {
			score += 10
		} else if strings.Contains(name, "bruteforce") {
			score += 8
		} else if strings.Contains(name, "scan") {
			score += 3
		}
	}

	// MITRE techniques indicate advanced threats
	if len(resp.MitreTechniques) > 0 {
		score += min(len(resp.MitreTechniques)*2, 10)
	}

	// CVEs associated with the IP
	if len(resp.CVEs) > 0 {
		score += min(len(resp.CVEs)*3, 10)
	}

	// Confidence adjustment
	switch strings.ToLower(resp.Confidence) {
	case "high":
		// Keep score as is
	case "medium":
		score = int(float64(score) * 0.9)
	case "low":
		score = int(float64(score) * 0.7)
	}

	// False positive reduction
	if len(resp.Classifications.FalsePositives) > 0 {
		// Known false positives (CDN, VPN, etc.) reduce score
		score = int(float64(score) * 0.6)
	}

	// Clamp to 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
