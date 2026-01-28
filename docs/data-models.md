# Modèles de Données

> **Généré**: 2026-01-28 | **Version**: 3.58.108

---

## Vue d'Ensemble

VIGILANCE X utilise ClickHouse comme base de données principale avec un modèle orienté événements temps réel.

---

## Entités Go (`internal/entity/`)

### Event

```go
type Event struct {
    EventID   uuid.UUID `json:"event_id"`
    Timestamp time.Time `json:"timestamp"`

    // Classification
    LogType        string `json:"log_type"`        // WAF, IPS, ATP, Anti-Virus, Firewall, VPN
    Category       string `json:"category"`        // Injection, Scan, Malware, DDoS
    SubCategory    string `json:"sub_category"`
    Severity       string `json:"severity"`        // critical, high, medium, low, info
    MitreTechnique string `json:"mitre_technique"` // T1190, T1059, etc.

    // Network
    SrcIP    string `json:"src_ip"`
    DstIP    string `json:"dst_ip"`
    SrcPort  uint16 `json:"src_port"`
    DstPort  uint16 `json:"dst_port"`
    Protocol string `json:"protocol"`

    // Action
    Action   string `json:"action"`    // allow, drop, reject, quarantine
    RuleID   string `json:"rule_id"`
    RuleName string `json:"rule_name"`

    // Context
    Hostname   string `json:"hostname"`
    UserName   string `json:"user_name"`
    URL        string `json:"url"`
    HTTPMethod string `json:"http_method"`
    HTTPStatus uint16 `json:"http_status"`
    UserAgent  string `json:"user_agent"`

    // Geo
    GeoCountry string `json:"geo_country"`
    GeoCity    string `json:"geo_city"`
    GeoASN     uint32 `json:"geo_asn"`
    GeoOrg     string `json:"geo_org"`

    // Message
    Message string `json:"message"`
    Reason  string `json:"reason"`
    RawLog  string `json:"raw_log,omitempty"`

    // ModSec enrichment
    ModSecRuleIDs  []string `json:"modsec_rule_ids,omitempty"`
    ModSecMessages []string `json:"modsec_messages,omitempty"`
}
```

### BanStatus

```go
type BanStatus struct {
    IP           string     `json:"ip"`
    Status       string     `json:"status"`       // active, expired, permanent, conditional, pending_approval
    BanCount     uint8      `json:"ban_count"`
    FirstBan     time.Time  `json:"first_ban"`
    LastBan      time.Time  `json:"last_ban"`
    ExpiresAt    *time.Time `json:"expires_at"`
    Reason       string     `json:"reason"`
    Source       string     `json:"source"`       // manual, detect2ban, threat_intel
    TriggerRule  string     `json:"trigger_rule"`
    SyncedXGS    bool       `json:"synced_xgs"`
    ImmuneUntil  *time.Time `json:"immune_until"`
    Country      string     `json:"country,omitempty"`

    // D2B v2 Fields
    CurrentTier      uint8      `json:"current_tier"`       // 0=4h, 1=24h, 2=7j, 3+=permanent
    ConditionalUntil *time.Time `json:"conditional_until"`
    GeoZone          string     `json:"geo_zone"`           // authorized, hostile, neutral
    ThreatScoreAtBan int        `json:"threat_score_at_ban"`
    XGSGroup         string     `json:"xgs_group"`          // grp_VGX-BannedIP, grp_VGX-BannedPerm
}
```

### WhitelistEntry

```go
type WhitelistEntry struct {
    IP            string     `json:"ip"`
    CIDRMask      uint8      `json:"cidr_mask"`      // 0 = single IP, 24-32 for ranges
    Type          string     `json:"type"`           // hard, soft, monitor
    Reason        string     `json:"reason"`
    Description   string     `json:"description"`
    ScoreModifier int32      `json:"score_modifier"` // % reduction (0-100)
    AlertOnly     bool       `json:"alert_only"`
    ExpiresAt     *time.Time `json:"expires_at"`
    Tags          []string   `json:"tags"`           // CDN, partner, pentest
    IsActive      bool       `json:"is_active"`
}
```

### GeoZoneConfig

```go
type GeoZoneConfig struct {
    Enabled              bool     `json:"enabled"`
    AuthorizedCountries  []string `json:"authorized_countries"`  // FR, BE, LU, DE, CH...
    HostileCountries     []string `json:"hostile_countries"`
    DefaultPolicy        string   `json:"default_policy"`        // hostile, neutral
    WAFThresholdHzone    int      `json:"waf_threshold_hzone"`   // Default: 1
    WAFThresholdZone     int      `json:"waf_threshold_zone"`    // Default: 3
    ThreatScoreThreshold int      `json:"threat_score_threshold"`// Default: 50
}
```

### PendingBan

```go
type PendingBan struct {
    ID            string     `json:"id"`
    IP            string     `json:"ip"`
    Country       string     `json:"country"`
    GeoZone       string     `json:"geo_zone"`
    ThreatScore   int32      `json:"threat_score"`
    ThreatSources []string   `json:"threat_sources"`
    EventCount    uint32     `json:"event_count"`
    FirstEvent    time.Time  `json:"first_event"`
    LastEvent     time.Time  `json:"last_event"`
    TriggerRule   string     `json:"trigger_rule"`
    Reason        string     `json:"reason"`
    Status        string     `json:"status"`        // pending, approved, rejected, expired
    PendingType   string     `json:"pending_type"`  // country_policy, false_positive
    FPRuleID      string     `json:"fp_rule_id"`
    FPURI         string     `json:"fp_uri"`
    FPHostname    string     `json:"fp_hostname"`
}
```

### ModSecLog

```go
type ModSecLog struct {
    ID            string    `json:"id"`
    Timestamp     time.Time `json:"timestamp"`
    UniqueID      string    `json:"unique_id"`     // Links all rules from same request
    SrcIP         string    `json:"src_ip"`
    Hostname      string    `json:"hostname"`
    URI           string    `json:"uri"`
    RuleID        string    `json:"rule_id"`       // 920320, 930130, 949110
    RuleFile      string    `json:"rule_file"`
    RuleMsg       string    `json:"rule_msg"`
    RuleSeverity  string    `json:"rule_severity"` // NOTICE, WARNING, CRITICAL
    RuleData      string    `json:"rule_data"`
    CRSVersion    string    `json:"crs_version"`   // OWASP_CRS/3.3.3
    ParanoiaLevel uint8     `json:"paranoia_level"`// 1-4
    AttackType    string    `json:"attack_type"`   // sql, xss, lfi, rfi, rce, protocol
    TotalScore    uint16    `json:"total_score"`
    IsBlocking    bool      `json:"is_blocking"`   // True if rule 949110
    Tags          []string  `json:"tags"`
}
```

### User

```go
type User struct {
    ID           uuid.UUID `json:"id"`
    Username     string    `json:"username"`
    Email        string    `json:"email"`
    PasswordHash string    `json:"-"`
    Role         string    `json:"role"`      // admin, audit
    IsActive     bool      `json:"is_active"`
    LastLogin    time.Time `json:"last_login"`
    CreatedAt    time.Time `json:"created_at"`
}
```

### ThreatScore (Cache TI)

```go
type ThreatScore struct {
    IP              string   `json:"ip"`
    AggregatedScore int32    `json:"aggregated_score"` // 0-100
    ThreatLevel     string   `json:"threat_level"`     // critical, high, medium, low
    IsMalicious     bool     `json:"is_malicious"`
    Categories      []string `json:"categories"`
    Sources         []string `json:"sources"`
    Country         string   `json:"country"`
    ASN             string   `json:"asn"`
    IsTor           bool     `json:"is_tor"`

    // Scores par provider (0-100)
    AbuseIPDBScore   int32 `json:"abuseipdb_score"`
    VirusTotalScore  int32 `json:"virustotal_score"`
    OTXScore         int32 `json:"otx_score"`
    GreyNoiseScore   int32 `json:"greynoise_score"`
    CrowdSecScore    int32 `json:"crowdsec_score"`
    CriminalIPScore  int32 `json:"criminalip_score"`
    PulsediveScore   int32 `json:"pulsedive_score"`
}
```

---

## Schéma ClickHouse

### Table: events

```sql
CREATE TABLE IF NOT EXISTS events (
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime CODEC(Delta, ZSTD(1)),

    -- Classification
    log_type LowCardinality(String),
    category LowCardinality(String),
    sub_category LowCardinality(String),
    severity LowCardinality(String),
    mitre_technique LowCardinality(String) DEFAULT '',

    -- Network
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    protocol LowCardinality(String),

    -- Action
    action LowCardinality(String),
    rule_id String,
    rule_name String,

    -- Context
    hostname LowCardinality(String),
    user_name String,
    url String,
    http_method LowCardinality(String),
    http_status UInt16,
    user_agent String,

    -- Geo
    geo_country LowCardinality(String),
    geo_city String,
    geo_asn UInt32,
    geo_org String,

    -- Message
    message String,
    reason String DEFAULT '',
    raw_log String CODEC(ZSTD(3)),

    -- ModSec enrichment
    modsec_rule_ids Array(String) DEFAULT [],
    modsec_messages Array(String) DEFAULT [],

    -- Metadata
    sophos_id String,
    ingested_at DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (log_type, severity, src_ip, timestamp)
SETTINGS index_granularity = 8192;
```

### Table: modsec_logs

```sql
CREATE TABLE IF NOT EXISTS modsec_logs (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(6) CODEC(Delta, ZSTD(1)),
    unique_id String,
    src_ip IPv4,
    src_port UInt16,
    hostname String,
    uri String,
    rule_id String,
    rule_file String,
    rule_msg String,
    rule_severity LowCardinality(String),
    rule_data String,
    crs_version String,
    paranoia_level UInt8,
    attack_type LowCardinality(String),
    anomaly_score UInt16 DEFAULT 0,
    total_score UInt16 DEFAULT 0,
    is_blocking UInt8 DEFAULT 0,
    tags Array(String),
    raw_log String CODEC(ZSTD(3)),
    ingested_at DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, unique_id, rule_id);
```

### Table: bans

```sql
CREATE TABLE IF NOT EXISTS bans (
    ip IPv4,
    status LowCardinality(String),
    ban_count UInt8 DEFAULT 1,
    first_ban DateTime DEFAULT now(),
    last_ban DateTime DEFAULT now(),
    expires_at Nullable(DateTime),
    reason String,
    source LowCardinality(String),
    trigger_rule String DEFAULT '',
    trigger_event_id UUID DEFAULT generateUUIDv4(),
    synced_xgs UInt8 DEFAULT 0,
    immune_until Nullable(DateTime),
    created_by String DEFAULT 'system',
    updated_at DateTime DEFAULT now(),
    version UInt64 DEFAULT 1,
    current_tier UInt8 DEFAULT 0,
    conditional_until Nullable(DateTime),
    geo_zone LowCardinality(String) DEFAULT 'neutral',
    threat_score_at_ban Int32 DEFAULT 0,
    xgs_group LowCardinality(String) DEFAULT 'grp_VGX-BannedIP'
)
ENGINE = ReplacingMergeTree(version)
ORDER BY ip;
```

### Table: ip_threat_scores

```sql
CREATE TABLE IF NOT EXISTS ip_threat_scores (
    ip IPv4,
    aggregated_score Int32 DEFAULT 0,
    total_score UInt8 DEFAULT 0,
    is_malicious UInt8 DEFAULT 0,
    threat_level LowCardinality(String),
    categories Array(LowCardinality(String)),
    sources Array(LowCardinality(String)),
    tags Array(String),
    country LowCardinality(String) DEFAULT '',
    asn String DEFAULT '',
    is_tor UInt8 DEFAULT 0,

    -- Provider scores
    abuseipdb_score Int32 DEFAULT 0,
    virustotal_score Int32 DEFAULT 0,
    otx_score Int32 DEFAULT 0,
    greynoise_score Int32 DEFAULT 0,
    crowdsec_score Int32 DEFAULT 0,
    criminalip_score Int32 DEFAULT 0,
    pulsedive_score Int32 DEFAULT 0,

    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY ip;
```

### Table: users

```sql
CREATE TABLE IF NOT EXISTS users (
    id UUID DEFAULT generateUUIDv4(),
    username String,
    email String,
    password_hash String,
    role LowCardinality(String) DEFAULT 'audit',
    is_active UInt8 DEFAULT 1,
    last_login Nullable(DateTime),
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY id;
```

### Table: pending_bans

```sql
CREATE TABLE IF NOT EXISTS pending_bans (
    id String,
    ip IPv4,
    country LowCardinality(String),
    geo_zone LowCardinality(String),
    threat_score Int32,
    threat_sources Array(String),
    event_count UInt32,
    first_event DateTime,
    last_event DateTime,
    trigger_rule String,
    reason String,
    status LowCardinality(String) DEFAULT 'pending',
    pending_type LowCardinality(String) DEFAULT 'country_policy',
    fp_rule_id String DEFAULT '',
    fp_uri String DEFAULT '',
    fp_hostname String DEFAULT '',
    fp_match_count UInt32 DEFAULT 0,
    created_at DateTime DEFAULT now(),
    reviewed_at Nullable(DateTime),
    reviewed_by String DEFAULT '',
    review_note String DEFAULT ''
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (status, created_at, id);
```

---

## Relations

```
                    ┌──────────────┐
                    │    users     │
                    └──────────────┘
                           │
                           │ performed_by
                           ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   events     │───▶│    bans      │───▶│ ban_history  │
└──────────────┘    └──────────────┘    └──────────────┘
       │                   │
       │                   │ approval
       ▼                   ▼
┌──────────────┐    ┌──────────────┐
│ modsec_logs  │    │ pending_bans │
└──────────────┘    └──────────────┘
       │
       │ TI check
       ▼
┌──────────────────┐
│ ip_threat_scores │
└──────────────────┘
```

---

## Constantes

### Severities

```go
const (
    SeverityCritical = "critical"
    SeverityHigh     = "high"
    SeverityMedium   = "medium"
    SeverityLow      = "low"
    SeverityInfo     = "info"
)
```

### Log Types

```go
const (
    LogTypeWAF       = "WAF"
    LogTypeIPS       = "IPS"
    LogTypeATP       = "ATP"
    LogTypeAntiVirus = "Anti-Virus"
    LogTypeFirewall  = "Firewall"
    LogTypeVPN       = "VPN"
)
```

### Ban Status

```go
const (
    BanStatusActive      = "active"
    BanStatusExpired     = "expired"
    BanStatusPermanent   = "permanent"
    BanStatusConditional = "conditional"
    BanStatusPending     = "pending_approval"
)
```

### Whitelist Types

```go
const (
    WhitelistTypeHard    = "hard"    // Full bypass
    WhitelistTypeSoft    = "soft"    // Score reduced
    WhitelistTypeMonitor = "monitor" // Logging only
)
```

### GeoZone

```go
const (
    GeoZoneAuthorized = "authorized"
    GeoZoneHostile    = "hostile"
    GeoZoneNeutral    = "neutral"
)
```

### Tier Durations

```go
var TierBanDurations = map[uint8]time.Duration{
    0: 4 * time.Hour,      // Initial
    1: 24 * time.Hour,     // 1st recidive
    2: 7 * 24 * time.Hour, // 2nd recidive
    // 3+ = Permanent
}
```

---

*Documentation générée par le workflow document-project*
