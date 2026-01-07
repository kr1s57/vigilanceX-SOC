package entity

import (
	"time"

	"github.com/google/uuid"
)

// Event represents a security event from Sophos XGS
type Event struct {
	EventID   uuid.UUID `json:"event_id" ch:"event_id"`
	Timestamp time.Time `json:"timestamp" ch:"timestamp"`

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
	Reason  string `json:"reason" ch:"reason"`
	RawLog  string `json:"raw_log,omitempty" ch:"raw_log"`

	// Metadata
	SophosID   string    `json:"sophos_id" ch:"sophos_id"`
	IngestedAt time.Time `json:"ingested_at" ch:"ingested_at"`

	// ModSec enrichment
	ModSecRuleIDs  []string `json:"modsec_rule_ids,omitempty" ch:"modsec_rule_ids"`
	ModSecMessages []string `json:"modsec_messages,omitempty" ch:"modsec_messages"`

	// Threat enrichment (not stored in DB, added at query time)
	ThreatScore int    `json:"threat_score,omitempty" ch:"-"`
	ThreatLevel string `json:"threat_level,omitempty" ch:"-"`
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
	TotalEvents    uint64  `json:"total_events"`
	BlockedEvents  uint64  `json:"blocked_events"`
	BlockRate      float64 `json:"block_rate"`
	UniqueIPs      uint64  `json:"unique_ips"`
	CriticalEvents uint64  `json:"critical_events"`
	HighEvents     uint64  `json:"high_events"`
	MediumEvents   uint64  `json:"medium_events"`
	LowEvents      uint64  `json:"low_events"`
}

// TimelinePoint represents a point in the event timeline
type TimelinePoint struct {
	Time          time.Time `json:"time"`
	TotalEvents   uint64    `json:"total_events"`
	BlockedEvents uint64    `json:"blocked_events"`
	UniqueIPs     uint64    `json:"unique_ips"`
}

// TopAttacker represents a top attacking IP
type TopAttacker struct {
	IP           string   `json:"ip"`
	AttackCount  uint64   `json:"attack_count"`
	BlockedCount uint64   `json:"blocked_count"`
	UniqueRules  uint64   `json:"unique_rules"`
	Categories   []string `json:"categories"`
	Country      string   `json:"country"`
	ThreatScore  int      `json:"threat_score,omitempty"`
}

// TopTarget represents a frequently targeted resource
type TopTarget struct {
	Hostname    string `json:"hostname"`
	URL         string `json:"url,omitempty"`
	AttackCount uint64 `json:"attack_count"`
	UniqueIPs   uint64 `json:"unique_ips"`
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

// ModSecLog represents a ModSecurity log entry from Sophos XGS
type ModSecLog struct {
	ID            string    `json:"id" ch:"id"`
	Timestamp     time.Time `json:"timestamp" ch:"timestamp"`
	UniqueID      string    `json:"unique_id" ch:"unique_id"` // Links all rules from same request
	SrcIP         string    `json:"src_ip" ch:"src_ip"`
	SrcPort       uint16    `json:"src_port" ch:"src_port"`
	Hostname      string    `json:"hostname" ch:"hostname"`
	URI           string    `json:"uri" ch:"uri"`
	RuleID        string    `json:"rule_id" ch:"rule_id"`
	RuleFile      string    `json:"rule_file" ch:"rule_file"`
	RuleMsg       string    `json:"rule_msg" ch:"rule_msg"`
	RuleSeverity  string    `json:"rule_severity" ch:"rule_severity"`
	RuleData      string    `json:"rule_data" ch:"rule_data"`
	CRSVersion    string    `json:"crs_version" ch:"crs_version"`
	ParanoiaLevel uint8     `json:"paranoia_level" ch:"paranoia_level"`
	AttackType    string    `json:"attack_type" ch:"attack_type"`
	TotalScore    uint16    `json:"total_score" ch:"total_score"`
	IsBlocking    bool      `json:"is_blocking" ch:"is_blocking"`
	Tags          []string  `json:"tags" ch:"tags"`
	RawLog        string    `json:"raw_log,omitempty" ch:"raw_log"`
	IngestedAt    time.Time `json:"ingested_at" ch:"ingested_at"`
}

// ModSecLogFilters for querying ModSec logs
type ModSecLogFilters struct {
	SrcIP      string    `json:"src_ip"`
	Hostname   string    `json:"hostname"`
	RuleID     string    `json:"rule_id"`
	AttackType string    `json:"attack_type"`
	UniqueID   string    `json:"unique_id"`
	Country    string    `json:"country"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	SearchTerm string    `json:"search_term"`
}

// ModSecRequestGroup groups all ModSec logs from same request by unique_id
type ModSecRequestGroup struct {
	UniqueID   string       `json:"unique_id"`
	Timestamp  time.Time    `json:"timestamp"`
	SrcIP      string       `json:"src_ip"`
	Hostname   string       `json:"hostname"`
	URI        string       `json:"uri"`
	TotalScore uint16       `json:"total_score"`
	IsBlocked  bool         `json:"is_blocked"`
	RuleCount  uint64       `json:"rule_count"`
	Rules      []ModSecRule `json:"rules"`
	GeoCountry string       `json:"geo_country,omitempty"`
	GeoCity    string       `json:"geo_city,omitempty"`
}

// ModSecRule represents a single rule within a request group
type ModSecRule struct {
	RuleID        string   `json:"rule_id"`
	RuleMsg       string   `json:"rule_msg"`
	RuleSeverity  string   `json:"rule_severity"`
	RuleFile      string   `json:"rule_file"`
	RuleData      string   `json:"rule_data"`
	AttackType    string   `json:"attack_type"`
	ParanoiaLevel uint8    `json:"paranoia_level"`
	Tags          []string `json:"tags"`
}

// SyslogStatus represents the status of syslog data ingestion
type SyslogStatus struct {
	LastEventTime    time.Time `json:"last_event_time"`
	EventsLastHour   uint64    `json:"events_last_hour"`
	IsReceiving      bool      `json:"is_receiving"`
	SecondsSinceLast int64     `json:"seconds_since_last"`
}

// CriticalAlert represents a critical security alert
type CriticalAlert struct {
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	LogType   string    `json:"log_type"`
	Category  string    `json:"category"`
	Severity  string    `json:"severity"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	Hostname  string    `json:"hostname"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Message   string    `json:"message"`
	Action    string    `json:"action"`
	Country   string    `json:"country"`
}
