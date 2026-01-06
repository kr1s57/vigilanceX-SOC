-- ============================================
-- VIGILANCE X - ClickHouse Schema
-- Optimise pour analytics temps reel SIEM
-- ============================================

-- Base de donnees principale
CREATE DATABASE IF NOT EXISTS vigilance_x;
USE vigilance_x;

-- ============================================
-- TABLE: events (logs principaux)
-- Partitionnement par jour, ORDER BY optimise
-- ============================================
CREATE TABLE IF NOT EXISTS events (
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime CODEC(Delta, ZSTD(1)),

    -- Classification
    log_type LowCardinality(String),          -- WAF, IPS, ATP, Anti-Virus, Firewall
    category LowCardinality(String),          -- Injection, Scan, Malware, DDoS
    sub_category LowCardinality(String),
    severity LowCardinality(String),          -- critical, high, medium, low, info

    -- Reseau
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    protocol LowCardinality(String),

    -- Action
    action LowCardinality(String),            -- allow, drop, reject, quarantine
    rule_id String,
    rule_name String,

    -- Contexte
    hostname LowCardinality(String),
    user_name String,
    url String,
    http_method LowCardinality(String),
    http_status UInt16,
    user_agent String,

    -- Geo (enrichi)
    geo_country LowCardinality(String),
    geo_city String,
    geo_asn UInt32,
    geo_org String,

    -- Message et raw
    message String,
    reason String DEFAULT '',
    raw_log String CODEC(ZSTD(3)),

    -- ModSec enrichment
    modsec_rule_ids Array(String) DEFAULT [],

    -- Metadata
    sophos_id String,
    ingested_at DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (log_type, severity, src_ip, timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Index secondaires pour recherches frequentes
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_src_ip src_ip TYPE bloom_filter GRANULARITY 4;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_rule_id rule_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_category category TYPE set(100) GRANULARITY 4;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_hostname hostname TYPE bloom_filter GRANULARITY 4;

-- ============================================
-- TABLE: ip_geolocation (cache geo)
-- ============================================
CREATE TABLE IF NOT EXISTS ip_geolocation (
    ip IPv4,
    country_code LowCardinality(String),
    country_name String,
    city String,
    region String,
    latitude Float32,
    longitude Float32,
    asn UInt32,
    org String,
    is_proxy UInt8 DEFAULT 0,
    is_hosting UInt8 DEFAULT 0,
    is_tor UInt8 DEFAULT 0,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY ip;

-- ============================================
-- TABLE: ip_threat_scores (cache threat intel)
-- ============================================
CREATE TABLE IF NOT EXISTS ip_threat_scores (
    ip IPv4,
    aggregated_score Int32 DEFAULT 0,         -- Score agrege 0-100
    total_score UInt8 DEFAULT 0,              -- 0-100
    reputation_score UInt8 DEFAULT 0,         -- 0-40
    activity_score UInt8 DEFAULT 0,           -- 0-40
    severity_score UInt8 DEFAULT 0,           -- 0-20
    confidence Float64 DEFAULT 0,             -- Niveau de confiance

    is_malicious UInt8 DEFAULT 0,             -- 0 ou 1
    threat_level LowCardinality(String),      -- critical, high, medium, low
    categories Array(LowCardinality(String)),
    sources Array(LowCardinality(String)),    -- abuseipdb, virustotal, etc.
    tags Array(String),                       -- Tags enrichissement

    -- Geo/Network info
    country LowCardinality(String) DEFAULT '',
    asn String DEFAULT '',
    isp String DEFAULT '',
    is_tor UInt8 DEFAULT 0,

    -- Details par source (scores normalises 0-100)
    abuseipdb_score Int32 DEFAULT 0,
    abuseipdb_reports UInt32 DEFAULT 0,
    abuseipdb_is_tor UInt8 DEFAULT 0,
    virustotal_score Int32 DEFAULT 0,
    virustotal_positives UInt8 DEFAULT 0,
    virustotal_total UInt8 DEFAULT 0,
    otx_score Int32 DEFAULT 0,
    alienvault_pulses UInt16 DEFAULT 0,

    -- Enrichissement threat intel
    malware_families Array(String),
    adversaries Array(String),

    first_seen DateTime DEFAULT now(),
    last_seen DateTime DEFAULT now(),
    last_checked DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    total_attacks UInt32 DEFAULT 0,
    version UInt64 DEFAULT 1                  -- Pour ReplacingMergeTree
)
ENGINE = ReplacingMergeTree(version)
ORDER BY ip
TTL last_checked + INTERVAL 7 DAY;

-- ============================================
-- TABLE: ip_ban_status
-- ============================================
CREATE TABLE IF NOT EXISTS ip_ban_status (
    ip IPv4,
    status LowCardinality(String),            -- active, expired, permanent
    ban_count UInt8,
    first_ban DateTime,
    last_ban DateTime,
    expires_at Nullable(DateTime),            -- NULL = permanent
    reason String,
    trigger_rule String,
    trigger_event_id UUID,
    synced_xgs UInt8,                         -- 0 ou 1
    created_by String,
    version UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY ip;

-- ============================================
-- TABLE: ban_history (audit trail)
-- ============================================
CREATE TABLE IF NOT EXISTS ban_history (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    ip IPv4,
    action LowCardinality(String),            -- ban, unban, extend, permanent
    previous_status String,
    new_status String,
    duration_hours Nullable(UInt32),
    reason String,
    performed_by String,
    metadata String                           -- JSON additionnel
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (ip, timestamp)
TTL timestamp + INTERVAL 365 DAY;

-- ============================================
-- TABLE: ip_whitelist
-- ============================================
CREATE TABLE IF NOT EXISTS ip_whitelist (
    ip IPv4,
    cidr_mask UInt8 DEFAULT 32,               -- Pour /24 etc.
    description String,
    created_at DateTime DEFAULT now(),
    created_by String,
    is_active UInt8 DEFAULT 1,
    version UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY ip;

-- ============================================
-- TABLE: stats_hourly (Materialized View target)
-- ============================================
CREATE TABLE IF NOT EXISTS stats_hourly (
    hour DateTime,
    log_type LowCardinality(String),
    severity LowCardinality(String),
    action LowCardinality(String),
    event_count UInt64,
    unique_ips UInt64,
    unique_rules UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, log_type, severity, action);

-- Materialized View pour stats horaires
CREATE MATERIALIZED VIEW IF NOT EXISTS stats_hourly_mv TO stats_hourly AS
SELECT
    toStartOfHour(timestamp) AS hour,
    log_type,
    severity,
    action,
    count() AS event_count,
    uniqExact(src_ip) AS unique_ips,
    uniqExact(rule_id) AS unique_rules
FROM events
GROUP BY hour, log_type, severity, action;

-- ============================================
-- TABLE: stats_ip_daily
-- ============================================
CREATE TABLE IF NOT EXISTS stats_ip_daily (
    day Date,
    src_ip IPv4,
    log_type LowCardinality(String),
    event_count UInt64,
    blocked_count UInt64,
    high_severity_count UInt64,
    categories Array(LowCardinality(String))
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, src_ip, log_type);

-- Materialized View pour stats IP quotidiennes
CREATE MATERIALIZED VIEW IF NOT EXISTS stats_ip_daily_mv TO stats_ip_daily AS
SELECT
    toDate(timestamp) AS day,
    src_ip,
    log_type,
    count() AS event_count,
    countIf(action = 'drop') AS blocked_count,
    countIf(severity = 'critical' OR severity = 'high') AS high_severity_count,
    groupUniqArray(10)(category) AS categories
FROM events
GROUP BY day, src_ip, log_type;

-- ============================================
-- TABLE: stats_hostname_daily
-- ============================================
CREATE TABLE IF NOT EXISTS stats_hostname_daily (
    day Date,
    hostname LowCardinality(String),
    log_type LowCardinality(String),
    event_count UInt64,
    blocked_count UInt64,
    unique_ips UInt64,
    unique_rules UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, hostname, log_type);

-- Materialized View pour stats hostname quotidiennes
CREATE MATERIALIZED VIEW IF NOT EXISTS stats_hostname_daily_mv TO stats_hostname_daily AS
SELECT
    toDate(timestamp) AS day,
    hostname,
    log_type,
    count() AS event_count,
    countIf(action = 'drop') AS blocked_count,
    uniqExact(src_ip) AS unique_ips,
    uniqExact(rule_id) AS unique_rules
FROM events
GROUP BY day, hostname, log_type;

-- ============================================
-- TABLE: anomaly_spikes (detection anomalies)
-- ============================================
CREATE TABLE IF NOT EXISTS anomaly_spikes (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime,                       -- Heure du spike
    event_count Int64,                        -- Nombre d'evenements
    baseline Int64,                           -- Baseline attendu
    threshold Int64,                          -- Seuil calcule
    deviation Float64,                        -- Ecart en sigma
    severity LowCardinality(String),          -- critical, high, medium, low
    log_type LowCardinality(String),          -- WAF, IPS, etc.
    detected_at DateTime DEFAULT now(),
    is_acknowledged UInt8 DEFAULT 0,
    acknowledged_by String DEFAULT '',
    acknowledged_at Nullable(DateTime)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(detected_at)
ORDER BY (detected_at, severity);

-- ============================================
-- TABLE: new_ips_detected
-- ============================================
CREATE TABLE IF NOT EXISTS new_ips_detected (
    ip IPv4,
    first_seen DateTime,
    detection_window LowCardinality(String),  -- 24h, 7d, 30d
    first_log_type LowCardinality(String),
    first_category LowCardinality(String),
    first_severity LowCardinality(String),
    event_count_24h UInt32,
    geo_country LowCardinality(String),
    threat_score UInt8,
    is_risky UInt8 DEFAULT 0,
    version UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (ip, detection_window);

-- ============================================
-- TABLE: vpn_events
-- ============================================
CREATE TABLE IF NOT EXISTS vpn_events (
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3),
    event_type LowCardinality(String),        -- connect, disconnect, auth_fail
    vpn_type LowCardinality(String),          -- ssl, ipsec, l2tp
    user_name String,
    src_ip IPv4,
    assigned_ip Nullable(IPv4),
    duration_seconds UInt32 DEFAULT 0,
    bytes_in UInt64 DEFAULT 0,
    bytes_out UInt64 DEFAULT 0,
    tunnel_id String,
    auth_method LowCardinality(String),
    failure_reason String,
    geo_country LowCardinality(String),
    geo_city String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (vpn_type, user_name, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- ============================================
-- TABLE: firewall_events (Network Detection)
-- ============================================
CREATE TABLE IF NOT EXISTS firewall_events (
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3),
    rule_id String,
    rule_name String,
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    protocol LowCardinality(String),
    action LowCardinality(String),
    bytes UInt64 DEFAULT 0,
    packets UInt32 DEFAULT 0,
    application LowCardinality(String),
    category LowCardinality(String),
    src_zone LowCardinality(String),
    dst_zone LowCardinality(String),
    nat_src_ip Nullable(IPv4),
    nat_dst_ip Nullable(IPv4),
    interface_in LowCardinality(String),
    interface_out LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (action, protocol, dst_port, timestamp)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- ============================================
-- TABLE: atp_events (Advanced Threat Protection)
-- ============================================
CREATE TABLE IF NOT EXISTS atp_events (
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3),
    src_ip IPv4,
    dst_ip IPv4,
    user_name String,
    threat_name String,
    threat_type LowCardinality(String),       -- c2, malware, botnet, phishing
    severity LowCardinality(String),
    action LowCardinality(String),
    url String,
    file_name String,
    file_hash String,
    detection_method LowCardinality(String),
    message String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (threat_type, severity, timestamp)
TTL toDateTime(timestamp) + INTERVAL 180 DAY;

-- ============================================
-- TABLE: antivirus_events
-- ============================================
CREATE TABLE IF NOT EXISTS antivirus_events (
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3),
    src_ip IPv4,
    dst_ip IPv4,
    user_name String,
    malware_name String,
    malware_type LowCardinality(String),
    action LowCardinality(String),            -- blocked, quarantined, cleaned
    file_name String,
    file_path String,
    file_hash String,
    scan_type LowCardinality(String),         -- realtime, scheduled, manual
    message String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (malware_type, timestamp)
TTL toDateTime(timestamp) + INTERVAL 180 DAY;

-- ============================================
-- TABLE: heartbeat_events (Endpoint Health)
-- ============================================
CREATE TABLE IF NOT EXISTS heartbeat_events (
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3),
    endpoint_id String,
    endpoint_name String,
    endpoint_ip IPv4,
    health_status LowCardinality(String),     -- green, yellow, red
    last_seen DateTime,
    os_type LowCardinality(String),
    os_version String,
    agent_version String,
    message String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (endpoint_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- ============================================
-- TABLE: detect2ban_scenarios (config)
-- ============================================
CREATE TABLE IF NOT EXISTS detect2ban_scenarios (
    id UUID DEFAULT generateUUIDv4(),
    name String,
    description String,
    enabled UInt8 DEFAULT 1,
    priority UInt8 DEFAULT 50,
    conditions String,                        -- JSON des conditions
    actions String,                           -- JSON des actions
    cooldown_minutes UInt32 DEFAULT 60,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    version UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY name;

-- ============================================
-- TABLE: users (authentication)
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id UUID DEFAULT generateUUIDv4(),
    username String,
    email String,
    password_hash String,
    role LowCardinality(String),              -- admin, analyst, viewer
    is_active UInt8 DEFAULT 1,
    last_login Nullable(DateTime),
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    version UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY username;

-- ============================================
-- TABLE: audit_log
-- ============================================
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    user_id UUID,
    username String,
    action LowCardinality(String),
    resource_type LowCardinality(String),
    resource_id String,
    details String,                           -- JSON
    ip_address IPv4,
    user_agent String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, user_id)
TTL timestamp + INTERVAL 365 DAY;

-- ============================================
-- Views utiles pour le dashboard
-- ============================================

-- Vue: Stats overview des dernieres 24h
CREATE VIEW IF NOT EXISTS v_stats_24h AS
SELECT
    log_type,
    count() as total_events,
    countIf(action = 'drop') as blocked_events,
    uniqExact(src_ip) as unique_ips,
    countIf(severity = 'critical') as critical_events,
    countIf(severity = 'high') as high_events
FROM events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY log_type;

-- Vue: Top 10 attaquants derniere 24h
CREATE VIEW IF NOT EXISTS v_top_attackers_24h AS
SELECT
    src_ip,
    count() as attack_count,
    countIf(action = 'drop') as blocked_count,
    uniqExact(rule_id) as unique_rules,
    groupUniqArray(5)(category) as categories,
    any(geo_country) as country
FROM events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY src_ip
ORDER BY attack_count DESC
LIMIT 10;
