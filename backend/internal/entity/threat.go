package entity

import (
	"time"
)

// ThreatScore represents the threat intelligence score for an IP
type ThreatScore struct {
	IP              string    `json:"ip" ch:"ip"`
	TotalScore      uint8     `json:"total_score" ch:"total_score"`
	ReputationScore uint8     `json:"reputation_score" ch:"reputation_score"`
	ActivityScore   uint8     `json:"activity_score" ch:"activity_score"`
	SeverityScore   uint8     `json:"severity_score" ch:"severity_score"`

	IsMalicious  bool     `json:"is_malicious" ch:"is_malicious"`
	ThreatLevel  string   `json:"threat_level" ch:"threat_level"`
	Categories   []string `json:"categories" ch:"categories"`
	Sources      []string `json:"sources" ch:"sources"`

	// Per-source details
	AbuseIPDBScore    uint8  `json:"abuseipdb_score" ch:"abuseipdb_score"`
	AbuseIPDBReports  uint32 `json:"abuseipdb_reports" ch:"abuseipdb_reports"`
	AbuseIPDBIsTor    bool   `json:"abuseipdb_is_tor" ch:"abuseipdb_is_tor"`
	VirusTotalPositives uint8 `json:"virustotal_positives" ch:"virustotal_positives"`
	VirusTotalTotal   uint8  `json:"virustotal_total" ch:"virustotal_total"`
	AlienVaultPulses  uint16 `json:"alienvault_pulses" ch:"alienvault_pulses"`

	FirstSeen    time.Time `json:"first_seen" ch:"first_seen"`
	LastSeen     time.Time `json:"last_seen" ch:"last_seen"`
	LastChecked  time.Time `json:"last_checked" ch:"last_checked"`
	TotalAttacks uint32    `json:"total_attacks" ch:"total_attacks"`
	Version      uint64    `json:"-" ch:"version"`
}

// IPGeolocation represents geolocation data for an IP
type IPGeolocation struct {
	IP          string    `json:"ip" ch:"ip"`
	CountryCode string    `json:"country_code" ch:"country_code"`
	CountryName string    `json:"country_name" ch:"country_name"`
	City        string    `json:"city" ch:"city"`
	Region      string    `json:"region" ch:"region"`
	Latitude    float32   `json:"latitude" ch:"latitude"`
	Longitude   float32   `json:"longitude" ch:"longitude"`
	ASN         uint32    `json:"asn" ch:"asn"`
	Org         string    `json:"org" ch:"org"`
	IsProxy     bool      `json:"is_proxy" ch:"is_proxy"`
	IsHosting   bool      `json:"is_hosting" ch:"is_hosting"`
	IsTor       bool      `json:"is_tor" ch:"is_tor"`
	UpdatedAt   time.Time `json:"updated_at" ch:"updated_at"`
}

// AbuseIPDBResponse represents the response from AbuseIPDB API
type AbuseIPDBResponse struct {
	IPAddress            string   `json:"ipAddress"`
	IsPublic             bool     `json:"isPublic"`
	IPVersion            int      `json:"ipVersion"`
	IsWhitelisted        bool     `json:"isWhitelisted"`
	AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
	CountryCode          string   `json:"countryCode"`
	UsageType            string   `json:"usageType"`
	ISP                  string   `json:"isp"`
	Domain               string   `json:"domain"`
	TotalReports         int      `json:"totalReports"`
	NumDistinctUsers     int      `json:"numDistinctUsers"`
	LastReportedAt       string   `json:"lastReportedAt"`
	IsTor                bool     `json:"isTor"`
	Categories           []int    `json:"reports"`
}

// VirusTotalResponse represents the response from VirusTotal API
type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			Reputation int    `json:"reputation"`
			ASOwner    string `json:"as_owner"`
			ASN        int    `json:"asn"`
			Country    string `json:"country"`
		} `json:"attributes"`
	} `json:"data"`
}

// AlienVaultResponse represents the response from AlienVault OTX API
type AlienVaultResponse struct {
	PulseCount int `json:"pulse_info"`
	General    struct {
		Reputation int      `json:"reputation"`
		Indicator  string   `json:"indicator"`
		Pulses     []Pulse  `json:"pulse_info"`
	} `json:"general"`
}

// Pulse represents an AlienVault OTX pulse
type Pulse struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// ThreatIntelResult represents aggregated threat intel from all sources
type ThreatIntelResult struct {
	IP           string         `json:"ip"`
	AbuseIPDB    *AbuseIPDBData `json:"abuseipdb,omitempty"`
	VirusTotal   *VirusTotalData `json:"virustotal,omitempty"`
	AlienVault   *AlienVaultData `json:"alienvault,omitempty"`
	Geolocation  *IPGeolocation `json:"geolocation,omitempty"`
	ThreatScore  *ThreatScore   `json:"threat_score"`
	CheckedAt    time.Time      `json:"checked_at"`
}

// AbuseIPDBData represents processed AbuseIPDB data
type AbuseIPDBData struct {
	Score        int    `json:"score"`
	TotalReports int    `json:"total_reports"`
	IsTor        bool   `json:"is_tor"`
	CountryCode  string `json:"country_code"`
	ISP          string `json:"isp"`
	UsageType    string `json:"usage_type"`
}

// VirusTotalData represents processed VirusTotal data
type VirusTotalData struct {
	Malicious  int    `json:"malicious"`
	Suspicious int    `json:"suspicious"`
	Harmless   int    `json:"harmless"`
	Reputation int    `json:"reputation"`
	ASOwner    string `json:"as_owner"`
}

// AlienVaultData represents processed AlienVault data
type AlienVaultData struct {
	PulseCount int      `json:"pulse_count"`
	Tags       []string `json:"tags"`
}

// Threat level constants
const (
	ThreatLevelCritical = "critical"
	ThreatLevelHigh     = "high"
	ThreatLevelMedium   = "medium"
	ThreatLevelLow      = "low"
	ThreatLevelMinimal  = "minimal"
)

// Score thresholds
const (
	MaxTotalScore      = 100
	MaxReputationScore = 40
	MaxActivityScore   = 40
	MaxSeverityScore   = 20

	CriticalThreshold = 80
	HighThreshold     = 60
	MediumThreshold   = 40
	LowThreshold      = 20
)

// Score weights for threat intel sources
const (
	AbuseIPDBWeight   = 0.40
	VirusTotalWeight  = 0.35
	AlienVaultWeight  = 0.25
)

// GetThreatLevel returns the threat level based on the total score
func GetThreatLevel(score uint8) string {
	switch {
	case score >= CriticalThreshold:
		return ThreatLevelCritical
	case score >= HighThreshold:
		return ThreatLevelHigh
	case score >= MediumThreshold:
		return ThreatLevelMedium
	case score >= LowThreshold:
		return ThreatLevelLow
	default:
		return ThreatLevelMinimal
	}
}

// IsMaliciousScore returns true if the score indicates malicious activity
func IsMaliciousScore(score uint8) bool {
	return score >= HighThreshold
}
