-- Migration: Add blocklist tables for Feed Ingester v1.6
-- Stores IPs from public blocklists with dynamic sync support

-- Main blocklist IPs table
ALTER TABLE vigilance_x.ip_ban_status ADD COLUMN IF NOT EXISTS blocklist_count UInt8 DEFAULT 0;
ALTER TABLE vigilance_x.ip_ban_status ADD COLUMN IF NOT EXISTS blocklist_sources Array(String) DEFAULT [];

-- Create blocklist_ips table for tracking IPs across all sources
CREATE TABLE IF NOT EXISTS vigilance_x.blocklist_ips (
    ip IPv4,
    source LowCardinality(String),           -- 'firehol_level1', 'feodo_tracker', etc.
    first_seen DateTime DEFAULT now(),       -- When first added to our DB
    last_seen DateTime DEFAULT now(),        -- Last time seen in source list
    is_active UInt8 DEFAULT 1,               -- 1 = in current list, 0 = removed
    threat_category LowCardinality(String),  -- 'botnet', 'c2', 'spam', 'scanner', 'malware'
    confidence UInt8 DEFAULT 50,             -- 0-100 confidence level
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (source, ip)
SETTINGS index_granularity = 8192;

-- Create index for fast IP lookups across all sources
CREATE TABLE IF NOT EXISTS vigilance_x.blocklist_ip_summary (
    ip IPv4,
    source_count UInt8,                      -- Number of lists containing this IP
    sources Array(String),                   -- List of source names
    categories Array(String),                -- List of threat categories
    max_confidence UInt8,                    -- Highest confidence from any source
    first_seen DateTime,
    last_seen DateTime,
    is_active UInt8,                         -- 1 if in ANY active list
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY ip
SETTINGS index_granularity = 8192;

-- Feed sync status table
CREATE TABLE IF NOT EXISTS vigilance_x.blocklist_feeds (
    source LowCardinality(String),           -- Feed identifier
    url String,                              -- Source URL
    last_sync DateTime DEFAULT now(),
    last_success DateTime,
    ip_count UInt32 DEFAULT 0,               -- Total IPs in feed
    active_count UInt32 DEFAULT 0,           -- Active IPs (not removed)
    added_count UInt32 DEFAULT 0,            -- IPs added in last sync
    removed_count UInt32 DEFAULT 0,          -- IPs removed in last sync
    sync_status LowCardinality(String),      -- 'success', 'error', 'pending'
    error_message String DEFAULT '',
    version UInt64 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY source
SETTINGS index_granularity = 8192;

-- Note: Feeds to be integrated:
-- firehol_level1     - https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
-- firehol_level2     - https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset
-- emerging_threats   - https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
-- feodo_tracker      - https://feodotracker.abuse.ch/downloads/ipblocklist.txt
-- spamhaus_drop      - https://www.spamhaus.org/drop/drop.txt
-- dshield            - https://www.dshield.org/block.txt
-- binary_defense     - https://www.binarydefense.com/banlist.txt
-- ci_army            - https://cinsscore.com/list/ci-badguys.txt
