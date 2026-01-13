-- ============================================
-- Migration 010: API Usage Tracking System
-- Track API requests per provider with quotas
-- ============================================

USE vigilance_x;

-- ============================================
-- TABLE: api_provider_config
-- Configuration for each API provider
-- ============================================
CREATE TABLE IF NOT EXISTS api_provider_config (
    provider_id LowCardinality(String),          -- e.g., 'crowdsec_cti', 'crowdsec_blocklist', 'abuseipdb', 'virustotal'

    -- API Key (encrypted or plain - handled by app)
    api_key String DEFAULT '',

    -- Quota settings
    daily_quota Int32 DEFAULT -1,                -- -1 = unlimited, >0 = max requests per day

    -- Status tracking
    enabled UInt8 DEFAULT 1,                     -- 0 = disabled, 1 = enabled
    last_success DateTime DEFAULT toDateTime(0),
    last_error DateTime DEFAULT toDateTime(0),
    last_error_message String DEFAULT '',

    -- Metadata
    display_name String DEFAULT '',              -- Human readable name
    description String DEFAULT '',
    updated_at DateTime DEFAULT now(),
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY provider_id;

-- ============================================
-- TABLE: api_usage_daily
-- Daily usage counters per provider
-- ============================================
CREATE TABLE IF NOT EXISTS api_usage_daily (
    provider_id LowCardinality(String),
    date Date DEFAULT today(),

    -- Counters
    success_count UInt32 DEFAULT 0,
    error_count UInt32 DEFAULT 0,

    -- Metadata
    updated_at DateTime DEFAULT now()
)
ENGINE = SummingMergeTree()
ORDER BY (provider_id, date)
TTL date + INTERVAL 90 DAY;

-- ============================================
-- TABLE: api_request_log
-- Detailed request log (for debugging)
-- ============================================
CREATE TABLE IF NOT EXISTS api_request_log (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    provider_id LowCardinality(String),

    -- Request details
    endpoint String DEFAULT '',
    success UInt8 DEFAULT 1,
    response_time_ms UInt32 DEFAULT 0,
    error_message String DEFAULT '',

    -- Context
    ip_queried String DEFAULT '',                -- For TI lookups
    triggered_by String DEFAULT ''               -- 'manual', 'detect2ban', 'waf_event', etc.
)
ENGINE = MergeTree()
ORDER BY (timestamp, provider_id)
TTL timestamp + INTERVAL 7 DAY;                  -- Keep 7 days of detailed logs

-- ============================================
-- Insert default provider configurations
-- Keys are empty by default - must be configured via UI
-- ============================================
INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'abuseipdb', 'AbuseIPDB', 'IP abuse reports and threat scoring', 1000, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'abuseipdb');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'virustotal', 'VirusTotal', 'Multi-engine malware scanning', 500, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'virustotal');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'greynoise', 'GreyNoise', 'Internet scanner and noise detection', 500, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'greynoise');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'crowdsec_cti', 'CrowdSec CTI', 'Crowd-sourced threat intelligence', 50, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'crowdsec_cti');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'crowdsec_blocklist', 'CrowdSec Blocklist', 'Premium IP blocklists sync', -1, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'crowdsec_blocklist');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'pulsedive', 'Pulsedive', 'Threat intelligence platform', 100, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'pulsedive');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'criminalip', 'CriminalIP', 'Cyber threat intelligence', 100, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'criminalip');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'shodan_internetdb', 'Shodan InternetDB', 'Internet-wide scanning data', -1, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'shodan_internetdb');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'ipsum', 'IPsum', 'Aggregated threat feeds', -1, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'ipsum');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'otx', 'AlienVault OTX', 'Open Threat Exchange', -1, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'otx');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'threatfox', 'ThreatFox', 'IOC sharing platform', -1, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'threatfox');

INSERT INTO api_provider_config (provider_id, display_name, description, daily_quota, version)
SELECT 'urlhaus', 'URLhaus', 'Malicious URL tracking', -1, 1
WHERE NOT EXISTS (SELECT 1 FROM api_provider_config WHERE provider_id = 'urlhaus');
