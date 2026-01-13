-- ============================================
-- Migration 009: CrowdSec Blocklist Integration
-- Premium blocklist sync to Sophos XGS
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
    sync_interval_hours UInt8 DEFAULT 6,             -- Sync every N hours (1-24)
    xgs_group_name String DEFAULT 'grp_VGX-CrowdSec', -- XGS IP Group name
    enabled_lists Array(String) DEFAULT [],          -- List of blocklist IDs to sync

    -- Statistics
    last_sync DateTime DEFAULT toDateTime(0),
    total_ips UInt32 DEFAULT 0,

    -- Metadata
    updated_at DateTime DEFAULT now(),
    updated_by String DEFAULT 'system',
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY id;

-- Insert default config if not exists
INSERT INTO crowdsec_blocklist_config (id, version)
SELECT 1, 1
WHERE NOT EXISTS (SELECT 1 FROM crowdsec_blocklist_config WHERE id = 1);

-- ============================================
-- TABLE: crowdsec_sync_history
-- Tracks blocklist sync operations
-- ============================================
CREATE TABLE IF NOT EXISTS crowdsec_sync_history (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),

    -- Blocklist info
    blocklist_id String,
    blocklist_name String,

    -- Sync results
    ips_downloaded UInt32 DEFAULT 0,
    ips_added UInt32 DEFAULT 0,
    ips_removed UInt32 DEFAULT 0,
    duration_ms UInt32 DEFAULT 0,

    -- Status
    success UInt8 DEFAULT 1,                         -- 1 = success, 0 = failed
    error String DEFAULT ''
)
ENGINE = MergeTree()
ORDER BY (timestamp, blocklist_id)
TTL timestamp + INTERVAL 90 DAY;                     -- Keep 90 days of history

-- ============================================
-- TABLE: crowdsec_synced_ips
-- Tracks IPs currently synced from CrowdSec
-- ============================================
CREATE TABLE IF NOT EXISTS crowdsec_synced_ips (
    ip String,
    blocklist_id String,
    blocklist_name String,
    synced_at DateTime DEFAULT now(),
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (ip, blocklist_id);
