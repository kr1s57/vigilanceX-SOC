package entity

import "time"

// TrackIPQuery represents the search parameters for IP/hostname tracking
type TrackIPQuery struct {
	Query     string     `json:"query"`      // IP address or hostname
	QueryType string     `json:"query_type"` // "ip" or "hostname" (auto-detected)
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Limit     int        `json:"limit"` // Per-category limit (default 100)
}

// TrackIPTimeRange represents the time range of the search
type TrackIPTimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// TrackIPSummary contains aggregated statistics across all categories
type TrackIPSummary struct {
	TotalEvents       int64            `json:"total_events"`
	CategoriesFound   int              `json:"categories_found"`
	FirstSeen         *time.Time       `json:"first_seen,omitempty"`
	LastSeen          *time.Time       `json:"last_seen,omitempty"`
	UniqueHostnames   []string         `json:"unique_hostnames"`
	UniqueDstIPs      []string         `json:"unique_dst_ips"`
	TopPorts          []uint16         `json:"top_ports"`
	SeverityBreakdown map[string]int64 `json:"severity_breakdown"`
}

// TrackIPCategoryResult contains results for one category
type TrackIPCategoryResult struct {
	Count  int64       `json:"count"`
	Events interface{} `json:"events"` // Type varies by category
}

// TrackIPGeoInfo contains geolocation data for the IP
type TrackIPGeoInfo struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	City        string `json:"city"`
	ASN         uint32 `json:"asn"`
	Org         string `json:"org"`
}

// TrackIPResponse is the full API response
type TrackIPResponse struct {
	Query      string                            `json:"query"`
	QueryType  string                            `json:"query_type"`
	TimeRange  TrackIPTimeRange                  `json:"time_range"`
	Summary    TrackIPSummary                    `json:"summary"`
	Categories map[string]*TrackIPCategoryResult `json:"categories"`
	GeoInfo    *TrackIPGeoInfo                   `json:"geo_info,omitempty"`
}

// TrackIPEventBase contains common fields for all event types
type TrackIPEventBase struct {
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
}

// TrackIPWAFEvent represents a WAF/IPS event from the events table
type TrackIPWAFEvent struct {
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	LogType   string    `json:"log_type"`
	Category  string    `json:"category"`
	Severity  string    `json:"severity"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	Hostname  string    `json:"hostname"`
	URL       string    `json:"url"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Action    string    `json:"action"`
	Message   string    `json:"message"`
}

// TrackIPModSecEvent represents a ModSecurity event from modsec_logs table
type TrackIPModSecEvent struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	UniqueID   string    `json:"unique_id"`
	SrcIP      string    `json:"src_ip"`
	Hostname   string    `json:"hostname"`
	URI        string    `json:"uri"`
	RuleID     string    `json:"rule_id"`
	RuleMsg    string    `json:"rule_msg"`
	AttackType string    `json:"attack_type"`
	TotalScore uint16    `json:"total_score"`
	IsBlocking bool      `json:"is_blocking"`
}

// TrackIPFirewallEvent represents a firewall event from firewall_events table
type TrackIPFirewallEvent struct {
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	RuleName    string    `json:"rule_name"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	Action      string    `json:"action"`
	SrcZone     string    `json:"src_zone"`
	DstZone     string    `json:"dst_zone"`
	Bytes       uint64    `json:"bytes"`
	Application string    `json:"application"`
}

// TrackIPVPNEvent represents a VPN event from vpn_events table
type TrackIPVPNEvent struct {
	EventID    string    `json:"event_id"`
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"`
	VPNType    string    `json:"vpn_type"`
	UserName   string    `json:"user_name"`
	SrcIP      string    `json:"src_ip"`
	AssignedIP string    `json:"assigned_ip,omitempty"`
	Duration   uint32    `json:"duration_seconds"`
	BytesIn    uint64    `json:"bytes_in"`
	BytesOut   uint64    `json:"bytes_out"`
	GeoCountry string    `json:"geo_country,omitempty"`
}

// TrackIPATPEvent represents an Advanced Threat Protection event
type TrackIPATPEvent struct {
	EventID    string    `json:"event_id"`
	Timestamp  time.Time `json:"timestamp"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	ThreatName string    `json:"threat_name"`
	ThreatType string    `json:"threat_type"`
	Severity   string    `json:"severity"`
	Action     string    `json:"action"`
	URL        string    `json:"url"`
	UserName   string    `json:"user_name,omitempty"`
}

// TrackIPAntivirusEvent represents an antivirus event
type TrackIPAntivirusEvent struct {
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	MalwareName string    `json:"malware_name"`
	MalwareType string    `json:"malware_type"`
	Action      string    `json:"action"`
	FileName    string    `json:"file_name"`
	FilePath    string    `json:"file_path,omitempty"`
}

// TrackIPHeartbeatEvent represents an endpoint heartbeat event
type TrackIPHeartbeatEvent struct {
	EventID      string    `json:"event_id"`
	Timestamp    time.Time `json:"timestamp"`
	EndpointName string    `json:"endpoint_name"`
	EndpointIP   string    `json:"endpoint_ip"`
	HealthStatus string    `json:"health_status"`
	OSType       string    `json:"os_type,omitempty"`
}
