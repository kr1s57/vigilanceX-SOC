-- Migration 005: Soft Whitelist Support for VIGILANCE X v2.0
-- Adds soft whitelist types (hard, soft, monitor) with TTL support

-- Drop old ip_whitelist if exists and recreate with new schema
DROP TABLE IF EXISTS ip_whitelist_v2;

CREATE TABLE IF NOT EXISTS ip_whitelist_v2 (
    ip IPv4,
    cidr_mask UInt8 DEFAULT 32,
    type LowCardinality(String) DEFAULT 'hard',  -- hard, soft, monitor
    reason String,
    description String DEFAULT '',
    score_modifier Int32 DEFAULT 50,              -- % reduction for soft whitelist
    alert_only UInt8 DEFAULT 1,                   -- 1 = alert only, 0 = allow auto-ban
    expires_at DateTime DEFAULT toDateTime(0),    -- 0 = permanent
    tags Array(String) DEFAULT [],
    added_by String DEFAULT 'system',
    is_active UInt8 DEFAULT 1,
    created_at DateTime DEFAULT now(),
    version UInt64 DEFAULT toUnixTimestamp(now())
) ENGINE = ReplacingMergeTree(version)
ORDER BY (ip, cidr_mask)
SETTINGS index_granularity = 8192;

-- Migrate data from old table if exists
INSERT INTO ip_whitelist_v2 (ip, cidr_mask, type, reason, added_by, is_active, created_at, version)
SELECT
    ip,
    32 as cidr_mask,
    'hard' as type,
    reason,
    added_by,
    active as is_active,
    created_at,
    toUnixTimestamp(now()) as version
FROM ip_whitelist FINAL
WHERE 1=1;

-- Geoblocking rules table for v2.0
CREATE TABLE IF NOT EXISTS geoblock_rules (
    id UUID DEFAULT generateUUIDv4(),
    rule_type LowCardinality(String),             -- country_block, country_watch, asn_block, asn_watch
    target String,                                 -- Country code (FR, US) or ASN number
    action LowCardinality(String),                -- block, watch, boost
    score_modifier Int32 DEFAULT 0,               -- Points to add/subtract
    reason String DEFAULT '',
    is_active UInt8 DEFAULT 1,
    created_by String DEFAULT 'system',
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    version UInt64 DEFAULT toUnixTimestamp(now())
) ENGINE = ReplacingMergeTree(version)
ORDER BY (rule_type, target)
SETTINGS index_granularity = 8192;

-- IP geolocation cache for enrichment
CREATE TABLE IF NOT EXISTS ip_geolocation (
    ip IPv4,
    country_code LowCardinality(String),
    country_name String DEFAULT '',
    city String DEFAULT '',
    region String DEFAULT '',
    asn UInt32 DEFAULT 0,
    as_org String DEFAULT '',
    is_vpn UInt8 DEFAULT 0,
    is_proxy UInt8 DEFAULT 0,
    is_tor UInt8 DEFAULT 0,
    is_datacenter UInt8 DEFAULT 0,
    latitude Float64 DEFAULT 0,
    longitude Float64 DEFAULT 0,
    last_updated DateTime DEFAULT now(),
    version UInt64 DEFAULT toUnixTimestamp(now())
) ENGINE = ReplacingMergeTree(version)
ORDER BY ip
TTL last_updated + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

-- Whitelist stats view
CREATE VIEW IF NOT EXISTS whitelist_stats AS
SELECT
    type,
    count() as count,
    countIf(is_active = 1) as active_count,
    countIf(expires_at > now() OR expires_at = toDateTime(0)) as valid_count
FROM ip_whitelist_v2 FINAL
GROUP BY type;

-- Geoblocking stats view
CREATE VIEW IF NOT EXISTS geoblock_stats AS
SELECT
    rule_type,
    action,
    count() as count,
    countIf(is_active = 1) as active_count
FROM geoblock_rules FINAL
GROUP BY rule_type, action;
