-- ============================================
-- Migration 008: Log Retention Settings
-- Configurable retention periods per table
-- ============================================

USE vigilance_x;

-- ============================================
-- TABLE: retention_settings (config)
-- Stores configurable retention periods
-- ============================================
CREATE TABLE IF NOT EXISTS retention_settings (
    id UInt8 DEFAULT 1,                          -- Singleton (always 1)

    -- Retention periods in days
    events_retention_days UInt16 DEFAULT 30,     -- Main events table
    modsec_logs_retention_days UInt16 DEFAULT 30,
    firewall_events_retention_days UInt16 DEFAULT 30,
    vpn_events_retention_days UInt16 DEFAULT 30,
    heartbeat_events_retention_days UInt16 DEFAULT 30,
    atp_events_retention_days UInt16 DEFAULT 90,
    antivirus_events_retention_days UInt16 DEFAULT 90,
    ban_history_retention_days UInt16 DEFAULT 365,
    audit_log_retention_days UInt16 DEFAULT 365,

    -- Global toggle
    retention_enabled UInt8 DEFAULT 1,           -- 0 or 1

    -- Cleanup schedule
    last_cleanup DateTime DEFAULT now(),
    cleanup_interval_hours UInt8 DEFAULT 6,      -- Run cleanup every N hours

    -- Metadata
    updated_at DateTime DEFAULT now(),
    updated_by String DEFAULT 'system',
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY id;

-- Insert default settings if not exists
INSERT INTO retention_settings (id, version)
SELECT 1, 1
WHERE NOT EXISTS (SELECT 1 FROM retention_settings WHERE id = 1);
