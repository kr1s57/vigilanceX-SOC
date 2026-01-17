-- Migration 014: WAF Monitored Servers with Country Access Zero Trust
-- Version: 3.57.100
-- Date: 2026-01-16

-- ============================================================================
-- WAF Monitored Servers Table
-- Allows manual addition of web servers and country access policies
-- ============================================================================

CREATE TABLE IF NOT EXISTS vigilance_x.waf_monitored_servers (
    id UUID DEFAULT generateUUIDv4(),
    hostname String,
    display_name String DEFAULT '',
    description String DEFAULT '',
    -- Country Access Policy
    policy_enabled UInt8 DEFAULT 0,
    policy_mode LowCardinality(String) DEFAULT 'none',  -- none, whitecountry, blockcountry
    white_countries Array(String) DEFAULT [],
    block_countries Array(String) DEFAULT [],
    -- WAF Settings
    waf_threshold UInt8 DEFAULT 5,
    custom_ban_reason String DEFAULT '',
    -- Status
    enabled UInt8 DEFAULT 1,
    -- Audit
    created_at DateTime DEFAULT now(),
    created_by String DEFAULT '',
    updated_at DateTime DEFAULT now(),
    -- Version for ReplacingMergeTree
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY (hostname);

-- ============================================================================
-- Indexes for faster queries
-- ============================================================================

-- Index for enabled servers lookup
ALTER TABLE vigilance_x.waf_monitored_servers
ADD INDEX IF NOT EXISTS idx_wms_enabled enabled TYPE set(2) GRANULARITY 1;

-- Index for policy enabled lookup
ALTER TABLE vigilance_x.waf_monitored_servers
ADD INDEX IF NOT EXISTS idx_wms_policy_enabled policy_enabled TYPE set(2) GRANULARITY 1;

-- ============================================================================
-- Comments for documentation
-- ============================================================================

-- Policy Modes:
-- none        : No country policy, uses standard D2B processing
-- whitecountry: Only listed countries can access, all others = immediate ban
-- blockcountry: Listed countries are banned on first WAF detection

-- Ban Reason Format:
-- WhiteCountry: "CountryPolicy: {hostname} - Country {CC} not in whitelist"
-- BlockCountry: "CountryPolicy: {hostname} - Country {CC} is blocked"
