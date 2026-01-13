-- ============================================
-- Migration 009: CrowdSec Blocklist Integration - Phase 1
-- Download and store blocklist IPs locally
-- ============================================

USE vigilance_x;

-- ============================================
-- TABLE: crowdsec_blocklist_config (singleton)
-- Stores CrowdSec Blocklist service configuration
-- ============================================
CREATE TABLE IF NOT EXISTS crowdsec_blocklist_config (
    id UInt8 DEFAULT 1,                              -- Singleton (always 1)

    -- API Configuration
    api_key String DEFAULT '',                       -- CrowdSec Service API Key (Blocklist scope)
    enabled UInt8 DEFAULT 0,                         -- 0 = disabled, 1 = enabled

    -- Sync settings
    sync_interval_minutes UInt16 DEFAULT 120,        -- Sync every N minutes (default: 2h = 120)

    -- Statistics
    last_sync DateTime DEFAULT toDateTime(0),
    total_ips UInt32 DEFAULT 0,
    total_blocklists UInt32 DEFAULT 0,

    -- Metadata
    updated_at DateTime DEFAULT now(),
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY id;

-- Insert default config if not exists
INSERT INTO crowdsec_blocklist_config (id, version)
SELECT 1, 1
WHERE NOT EXISTS (SELECT 1 FROM crowdsec_blocklist_config WHERE id = 1);

-- ============================================
-- TABLE: crowdsec_blocklist_ips
-- Stores IPs from all downloaded blocklists
-- This table should always mirror the latest downloaded files
-- ============================================
CREATE TABLE IF NOT EXISTS crowdsec_blocklist_ips (
    ip String,                                       -- IP address or CIDR
    blocklist_id String,                             -- CrowdSec blocklist ID
    blocklist_label String,                          -- Human-readable name
    first_seen DateTime DEFAULT now(),               -- When first added to our DB
    last_seen DateTime DEFAULT now(),                -- Last time seen in download
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (blocklist_id, ip);

-- ============================================
-- TABLE: crowdsec_sync_history
-- Tracks blocklist sync operations
-- ============================================
CREATE TABLE IF NOT EXISTS crowdsec_sync_history (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),

    -- Blocklist info
    blocklist_id String,
    blocklist_label String,

    -- Sync results
    ips_in_file UInt32 DEFAULT 0,                    -- IPs in downloaded file
    ips_added UInt32 DEFAULT 0,                      -- New IPs added to DB
    ips_removed UInt32 DEFAULT 0,                    -- IPs removed from DB
    duration_ms UInt32 DEFAULT 0,

    -- Status
    success UInt8 DEFAULT 1,                         -- 1 = success, 0 = failed
    error String DEFAULT ''
)
ENGINE = MergeTree()
ORDER BY (timestamp, blocklist_id)
TTL timestamp + INTERVAL 90 DAY;
