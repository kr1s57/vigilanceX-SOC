-- Migration 007: D2B v2 - Enhanced Ban System with Tiers and GeoZones
-- Version: 3.52.100
-- Date: 2026-01-12

-- ============================================================================
-- 1. Add new columns to ip_ban_status for D2B v2
-- ============================================================================

-- Add current_tier column (0=initial, 1=1st recidiv, 2=2nd recidiv, 3+=permanent)
ALTER TABLE vigilance_x.ip_ban_status
ADD COLUMN IF NOT EXISTS current_tier UInt8 DEFAULT 0;

-- Add conditional_until for surveillance period after unban
ALTER TABLE vigilance_x.ip_ban_status
ADD COLUMN IF NOT EXISTS conditional_until Nullable(DateTime);

-- Add geo_zone for geographic classification (authorized, hostile, neutral)
ALTER TABLE vigilance_x.ip_ban_status
ADD COLUMN IF NOT EXISTS geo_zone LowCardinality(String) DEFAULT '';

-- Add threat_score_at_ban to record score when banned
ALTER TABLE vigilance_x.ip_ban_status
ADD COLUMN IF NOT EXISTS threat_score_at_ban Int32 DEFAULT 0;

-- Add xgs_group to track which XGS group the IP is in
ALTER TABLE vigilance_x.ip_ban_status
ADD COLUMN IF NOT EXISTS xgs_group LowCardinality(String) DEFAULT 'grp_VGX-BannedIP';

-- ============================================================================
-- 2. Add new columns to ban_history for audit trail
-- ============================================================================

-- Add tier column to track tier at time of action
ALTER TABLE vigilance_x.ban_history
ADD COLUMN IF NOT EXISTS tier UInt8 DEFAULT 0;

-- Add geo_zone to track zone at time of action
ALTER TABLE vigilance_x.ban_history
ADD COLUMN IF NOT EXISTS geo_zone LowCardinality(String) DEFAULT '';

-- Add threat_score to track score at time of action
ALTER TABLE vigilance_x.ban_history
ADD COLUMN IF NOT EXISTS threat_score Int32 DEFAULT 0;

-- Add xgs_group to track group at time of action
ALTER TABLE vigilance_x.ban_history
ADD COLUMN IF NOT EXISTS xgs_group LowCardinality(String) DEFAULT '';

-- ============================================================================
-- 3. Create pending_bans table for awaiting admin approval
-- ============================================================================

CREATE TABLE IF NOT EXISTS vigilance_x.pending_bans (
    id UUID DEFAULT generateUUIDv4(),
    ip IPv4,
    country LowCardinality(String),
    geo_zone LowCardinality(String),
    threat_score Int32 DEFAULT 0,
    threat_sources Array(String) DEFAULT [],
    event_count UInt32 DEFAULT 0,
    first_event DateTime,
    last_event DateTime,
    trigger_rule String DEFAULT '',
    reason String DEFAULT '',
    status LowCardinality(String) DEFAULT 'pending', -- pending, approved, rejected, expired
    created_at DateTime DEFAULT now(),
    reviewed_at Nullable(DateTime),
    reviewed_by String DEFAULT '',
    review_note String DEFAULT ''
) ENGINE = ReplacingMergeTree()
ORDER BY (ip, created_at)
TTL created_at + INTERVAL 30 DAY;

-- ============================================================================
-- 4. Create geozone_config table for settings persistence
-- ============================================================================

CREATE TABLE IF NOT EXISTS vigilance_x.geozone_config (
    id UInt8 DEFAULT 1,
    enabled UInt8 DEFAULT 0,
    authorized_countries Array(String) DEFAULT ['FR', 'BE', 'LU', 'DE', 'CH', 'NL', 'GB', 'ES', 'IT', 'PT', 'AT'],
    hostile_countries Array(String) DEFAULT [],
    default_policy LowCardinality(String) DEFAULT 'neutral',
    waf_threshold_hzone UInt8 DEFAULT 1,
    waf_threshold_zone UInt8 DEFAULT 3,
    threat_score_threshold UInt8 DEFAULT 50,
    updated_at DateTime DEFAULT now(),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY id;

-- Insert default config if not exists
INSERT INTO vigilance_x.geozone_config (id, enabled, version)
SELECT 1, 0, 1
WHERE NOT EXISTS (SELECT 1 FROM vigilance_x.geozone_config WHERE id = 1);

-- ============================================================================
-- 5. Create index for faster pending bans queries
-- ============================================================================

-- Index for pending status lookup
ALTER TABLE vigilance_x.pending_bans
ADD INDEX IF NOT EXISTS idx_pending_status status TYPE set(10) GRANULARITY 1;

-- Index for IP lookup in pending
ALTER TABLE vigilance_x.pending_bans
ADD INDEX IF NOT EXISTS idx_pending_ip ip TYPE bloom_filter() GRANULARITY 1;

-- ============================================================================
-- 6. Migrate existing bans to tier 0 with default xgs_group
-- ============================================================================

-- Update existing active bans to tier 0 and default group
ALTER TABLE vigilance_x.ip_ban_status
UPDATE
    current_tier = 0,
    xgs_group = 'grp_VGX-BannedIP'
WHERE status IN ('active', 'permanent') AND current_tier = 0;

-- Update existing permanent bans to tier 3 and permanent group
ALTER TABLE vigilance_x.ip_ban_status
UPDATE
    current_tier = 3,
    xgs_group = 'grp_VGX-BannedPerm'
WHERE status = 'permanent';

-- ============================================================================
-- 7. Comments for documentation
-- ============================================================================

-- D2B v2 Ban Tiers:
-- Tier 0: Initial ban (4 hours)
-- Tier 1: 1st recidive (24 hours)
-- Tier 2: 2nd recidive (7 days)
-- Tier 3+: Permanent

-- GeoZone Types:
-- authorized: Trusted countries - TI check before ban
-- hostile: Untrusted countries - immediate ban on first WAF event
-- neutral: Default processing with standard thresholds

-- XGS Groups:
-- grp_VGX-BannedIP: Temporary bans (Tier 0-2)
-- grp_VGX-BannedPerm: Permanent bans (Tier 3+)
