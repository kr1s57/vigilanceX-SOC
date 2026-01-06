package entity

import (
	"time"

	"github.com/google/uuid"
)

// Event represents a security event from Sophos XGS
type Event struct {
	EventID     uuid.UUID `json:"event_id" ch:"event_id"`
	Timestamp   time.Time `json:"timestamp" ch:"timestamp"`

	// Classification
	LogType     string `json:"log_type" ch:"log_type"`
	Category    string `json:"category" ch:"category"`
	SubCategory string `json:"sub_category" ch:"sub_category"`
	Severity    string `json:"severity" ch:"severity"`

	// Network
	SrcIP    string `json:"src_ip" ch:"src_ip"`
	DstIP    string `json:"dst_ip" ch:"dst_ip"`
	SrcPort  uint16 `json:"src_port" ch:"src_port"`
	DstPort  uint16 `json:"dst_port" ch:"dst_port"`
	Protocol string `json:"protocol" ch:"protocol"`

	// Action
	Action   string `json:"action" ch:"action"`
	RuleID   string `json:"rule_id" ch:"rule_id"`
	RuleName string `json:"rule_name" ch:"rule_name"`

	// Context
	Hostname   string `json:"hostname" ch:"hostname"`
	UserName   string `json:"user_name" ch:"user_name"`
	URL        string `json:"url" ch:"url"`
	HTTPMethod string `json:"http_method" ch:"http_method"`
	HTTPStatus uint16 `json:"http_status" ch:"http_status"`
	UserAgent  string `json:"user_agent" ch:"user_agent"`

	// Geo
	GeoCountry string `json:"geo_country" ch:"geo_country"`
	GeoCity    string `json:"geo_city" ch:"geo_city"`
	GeoASN     uint32 `json:"geo_asn" ch:"geo_asn"`
	GeoOrg     string `json:"geo_org" ch:"geo_org"`

	// Message
	Message string `json:"message" ch:"message"`
	RawLog  string `json:"raw_log,omitempty" ch:"raw_log"`

	// Metadata
	SophosID   string    `json:"sophos_id" ch:"sophos_id"`
	IngestedAt time.Time `json:"ingested_at" ch:"ingested_at"`
}

// EventFilters for querying events
type EventFilters struct {
	LogType    string    `json:"log_type"`
	Category   string    `json:"category"`
	Severity   string    `json:"severity"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	Hostname   string    `json:"hostname"`
	RuleID     string    `json:"rule_id"`
	Action     string    `json:"action"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	SearchTerm string    `json:"search_term"`
}

// EventStats represents aggregated event statistics
type EventStats struct {
	TotalEvents      int64   `json:"total_events"`
	BlockedEvents    int64   `json:"blocked_events"`
	BlockRate        float64 `json:"block_rate"`
	UniqueIPs        int64   `json:"unique_ips"`
	CriticalEvents   int64   `json:"critical_events"`
	HighEvents       int64   `json:"high_events"`
	MediumEvents     int64   `json:"medium_events"`
	LowEvents        int64   `json:"low_events"`
}

// TimelinePoint represents a point in the event timeline
type TimelinePoint struct {
	Time          time.Time `json:"time"`
	TotalEvents   int64     `json:"total_events"`
	BlockedEvents int64     `json:"blocked_events"`
	UniqueIPs     int64     `json:"unique_ips"`
}

// TopAttacker represents a top attacking IP
type TopAttacker struct {
	IP           string   `json:"ip"`
	AttackCount  int64    `json:"attack_count"`
	BlockedCount int64    `json:"blocked_count"`
	UniqueRules  int64    `json:"unique_rules"`
	Categories   []string `json:"categories"`
	Country      string   `json:"country"`
	ThreatScore  int      `json:"threat_score,omitempty"`
}

// TopTarget represents a frequently targeted resource
type TopTarget struct {
	Hostname    string `json:"hostname"`
	URL         string `json:"url,omitempty"`
	AttackCount int64  `json:"attack_count"`
	UniqueIPs   int64  `json:"unique_ips"`
}

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Log types
const (
	LogTypeWAF       = "WAF"
	LogTypeIPS       = "IPS"
	LogTypeATP       = "ATP"
	LogTypeAntiVirus = "Anti-Virus"
	LogTypeFirewall  = "Firewall"
	LogTypeVPN       = "VPN"
	LogTypeHeartbeat = "Heartbeat"
)

// Actions
const (
	ActionAllow      = "allow"
	ActionDrop       = "drop"
	ActionReject     = "reject"
	ActionQuarantine = "quarantine"
)
