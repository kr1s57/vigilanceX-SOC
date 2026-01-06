package entity

import (
	"time"

	"github.com/google/uuid"
)

// AnomalySpike represents a detected anomaly in the system
type AnomalySpike struct {
	ID             uuid.UUID `json:"id" ch:"id"`
	DetectedAt     time.Time `json:"detected_at" ch:"detected_at"`
	AnomalyType    string    `json:"anomaly_type" ch:"anomaly_type"`
	MetricName     string    `json:"metric_name" ch:"metric_name"`
	CurrentValue   float64   `json:"current_value" ch:"current_value"`
	BaselineValue  float64   `json:"baseline_value" ch:"baseline_value"`
	DeviationSigma float64   `json:"deviation_sigma" ch:"deviation_sigma"`
	AffectedIPs    []string  `json:"affected_ips" ch:"affected_ips"`
	AffectedRules  []string  `json:"affected_rules" ch:"affected_rules"`
	Description    string    `json:"description" ch:"description"`
	IsAcknowledged bool      `json:"is_acknowledged" ch:"is_acknowledged"`
	AcknowledgedBy string    `json:"acknowledged_by" ch:"acknowledged_by"`
	AcknowledgedAt *time.Time `json:"acknowledged_at" ch:"acknowledged_at"`
}

// NewIPDetected represents a newly detected IP
type NewIPDetected struct {
	IP              string    `json:"ip" ch:"ip"`
	FirstSeen       time.Time `json:"first_seen" ch:"first_seen"`
	DetectionWindow string    `json:"detection_window" ch:"detection_window"`
	FirstLogType    string    `json:"first_log_type" ch:"first_log_type"`
	FirstCategory   string    `json:"first_category" ch:"first_category"`
	FirstSeverity   string    `json:"first_severity" ch:"first_severity"`
	EventCount24h   uint32    `json:"event_count_24h" ch:"event_count_24h"`
	GeoCountry      string    `json:"geo_country" ch:"geo_country"`
	ThreatScore     uint8     `json:"threat_score" ch:"threat_score"`
	IsRisky         bool      `json:"is_risky" ch:"is_risky"`
	Version         uint64    `json:"-" ch:"version"`
}

// AnomalyStats represents anomaly detection statistics
type AnomalyStats struct {
	TotalSpikes       int64 `json:"total_spikes"`
	UnacknowledgedSpikes int64 `json:"unacknowledged_spikes"`
	NewIPsLast24h     int64 `json:"new_ips_last_24h"`
	RiskyNewIPs       int64 `json:"risky_new_ips"`
	PatternDetections int64 `json:"pattern_detections"`
}

// PatternAnomaly represents a detected attack pattern
type PatternAnomaly struct {
	Type           string    `json:"type"`
	Description    string    `json:"description"`
	AffectedIPs    []string  `json:"affected_ips"`
	AffectedHosts  []string  `json:"affected_hosts"`
	DetectedAt     time.Time `json:"detected_at"`
	Severity       string    `json:"severity"`
}

// Spike represents a statistical spike anomaly
type Spike struct {
	ID          uuid.UUID `json:"id" ch:"id"`
	Timestamp   time.Time `json:"timestamp" ch:"timestamp"`
	EventCount  int64     `json:"event_count" ch:"event_count"`
	Baseline    int64     `json:"baseline" ch:"baseline"`
	Threshold   int64     `json:"threshold" ch:"threshold"`
	Deviation   float64   `json:"deviation" ch:"deviation"`
	Severity    string    `json:"severity" ch:"severity"`
	LogType     string    `json:"log_type,omitempty" ch:"log_type"`
	DetectedAt  time.Time `json:"detected_at" ch:"detected_at"`
}

// NewIPAnomaly represents a new IP detection
type NewIPAnomaly struct {
	IP          string    `json:"ip"`
	FirstSeen   time.Time `json:"first_seen"`
	EventCount  int64     `json:"event_count"`
	LogTypes    []string  `json:"log_types"`
	Country     string    `json:"country"`
	ThreatScore int       `json:"threat_score"`
}

// MultiVectorAttack represents an IP attacking via multiple vectors
type MultiVectorAttack struct {
	IP          string    `json:"ip"`
	Vectors     []string  `json:"vectors"` // WAF, IPS, VPN, etc.
	EventCount  int64     `json:"event_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Country     string    `json:"country"`
}

// TargetedCampaign represents multiple IPs targeting the same resource
type TargetedCampaign struct {
	Target      string    `json:"target"` // hostname or URL
	SourceIPs   []string  `json:"source_ips"`
	EventCount  int64     `json:"event_count"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
}

// BruteForcePattern represents a brute force attack pattern
type BruteForcePattern struct {
	IP            string    `json:"ip"`
	Target        string    `json:"target"`
	FailedAttempts int64    `json:"failed_attempts"`
	Window        string    `json:"window"`
	FirstAttempt  time.Time `json:"first_attempt"`
	LastAttempt   time.Time `json:"last_attempt"`
}

// Anomaly is a generic anomaly record
type Anomaly struct {
	ID          uuid.UUID `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	IP          string    `json:"ip,omitempty"`
	Description string    `json:"description"`
	Details     string    `json:"details,omitempty"`
	DetectedAt  time.Time `json:"detected_at"`
	Acknowledged bool     `json:"acknowledged"`
}

// Anomaly type constants
const (
	AnomalyTypeSpike       = "spike"
	AnomalyTypeNewIP       = "new_ip"
	AnomalyTypePattern     = "pattern"
	AnomalyTypeMultiVector = "multi_vector"
	AnomalyTypeCampaign    = "campaign"
	AnomalyTypeScanning    = "scanning"
)

// Detection window constants
const (
	Window24h = "24h"
	Window7d  = "7d"
	Window30d = "30d"
)

// Default spike detection threshold (standard deviations)
const DefaultSpikeThreshold = 3.0

// Thresholds for pattern detection
const (
	MultiVectorThreshold = 3   // Minimum different attack types
	CampaignThreshold    = 5   // Minimum source IPs targeting same host
	ScanningThreshold    = 10  // Minimum different hosts from same IP
)

// Risk thresholds for new IPs
const (
	RiskyThreatScore    = 80
	RiskyEventCount     = 10
	RiskySeverityThreshold = "high"
)

// IsHighRisk determines if a new IP detection is high risk
func (n *NewIPDetected) IsHighRisk() bool {
	return n.ThreatScore >= RiskyThreatScore ||
		n.EventCount24h >= RiskyEventCount ||
		n.FirstSeverity == SeverityCritical ||
		n.FirstSeverity == SeverityHigh
}
