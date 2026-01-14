-- ============================================
-- Migration 013: Vigimail Checker
-- Email leak monitoring + Domain DNS config check
-- ============================================

USE vigilance_x;

-- ============================================
-- Configuration Table (singleton)
-- ============================================
CREATE TABLE IF NOT EXISTS vigimail_config (
    id UInt8 DEFAULT 1,
    enabled UInt8 DEFAULT 0,
    check_interval_hours UInt8 DEFAULT 24,  -- 6, 12, 24, 48, 168 (7 days)
    hibp_api_key String DEFAULT '',
    leakcheck_api_key String DEFAULT '',
    last_check DateTime DEFAULT toDateTime(0),
    updated_at DateTime DEFAULT now(),
    version UInt64 DEFAULT 1
) ENGINE = ReplacingMergeTree(version) ORDER BY id;

-- Insert default config
INSERT INTO vigimail_config (id, enabled, check_interval_hours, version)
SELECT 1, 0, 24, 1
WHERE NOT EXISTS (SELECT 1 FROM vigimail_config WHERE id = 1);

-- ============================================
-- Domains Table
-- ============================================
CREATE TABLE IF NOT EXISTS vigimail_domains (
    id UUID DEFAULT generateUUIDv4(),
    domain String,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    deleted UInt8 DEFAULT 0,
    version UInt64 DEFAULT 1
) ENGINE = ReplacingMergeTree(version) ORDER BY domain;

-- ============================================
-- Emails Table
-- ============================================
CREATE TABLE IF NOT EXISTS vigimail_emails (
    id UUID DEFAULT generateUUIDv4(),
    email String,
    domain String,
    last_check DateTime DEFAULT toDateTime(0),
    leak_count UInt32 DEFAULT 0,
    status LowCardinality(String) DEFAULT 'pending',  -- pending, clean, leaked
    created_at DateTime DEFAULT now(),
    deleted UInt8 DEFAULT 0,
    version UInt64 DEFAULT 1
) ENGINE = ReplacingMergeTree(version) ORDER BY (domain, email);

-- ============================================
-- Leak Results Table
-- ============================================
CREATE TABLE IF NOT EXISTS vigimail_leaks (
    id UUID DEFAULT generateUUIDv4(),
    email String,
    source LowCardinality(String),  -- hibp, leakcheck
    breach_name String,
    breach_date Nullable(Date),
    data_classes Array(String),     -- passwords, emails, usernames, phone_numbers, etc.
    is_verified UInt8 DEFAULT 0,
    is_sensitive UInt8 DEFAULT 0,
    description String DEFAULT '',
    first_seen DateTime DEFAULT now(),
    last_seen DateTime DEFAULT now()
) ENGINE = MergeTree() ORDER BY (email, source, breach_name);

-- ============================================
-- Domain DNS Check Results Table
-- ============================================
CREATE TABLE IF NOT EXISTS vigimail_domain_checks (
    id UUID DEFAULT generateUUIDv4(),
    domain String,
    check_time DateTime DEFAULT now(),

    -- SPF (Sender Policy Framework)
    spf_exists UInt8 DEFAULT 0,
    spf_record String DEFAULT '',
    spf_valid UInt8 DEFAULT 0,
    spf_issues Array(String),

    -- DKIM (DomainKeys Identified Mail)
    dkim_exists UInt8 DEFAULT 0,
    dkim_selectors Array(String),
    dkim_valid UInt8 DEFAULT 0,
    dkim_issues Array(String),

    -- DMARC (Domain-based Message Authentication)
    dmarc_exists UInt8 DEFAULT 0,
    dmarc_record String DEFAULT '',
    dmarc_policy LowCardinality(String) DEFAULT '',  -- none, quarantine, reject
    dmarc_valid UInt8 DEFAULT 0,
    dmarc_issues Array(String),

    -- MX Records
    mx_exists UInt8 DEFAULT 0,
    mx_records Array(String),

    -- Overall Assessment
    overall_score UInt8 DEFAULT 0,  -- 0-100
    overall_status LowCardinality(String) DEFAULT 'unknown'  -- good, warning, critical
) ENGINE = MergeTree() ORDER BY (domain, check_time) TTL check_time + INTERVAL 90 DAY;

-- ============================================
-- Check History Table (for auditing)
-- ============================================
CREATE TABLE IF NOT EXISTS vigimail_check_history (
    id UUID DEFAULT generateUUIDv4(),
    check_time DateTime DEFAULT now(),
    check_type LowCardinality(String),  -- email_leak, domain_dns, full
    emails_checked UInt32 DEFAULT 0,
    domains_checked UInt32 DEFAULT 0,
    leaks_found UInt32 DEFAULT 0,
    dns_issues_found UInt32 DEFAULT 0,
    duration_ms UInt32 DEFAULT 0,
    success UInt8 DEFAULT 1,
    error String DEFAULT ''
) ENGINE = MergeTree() ORDER BY check_time TTL check_time + INTERVAL 90 DAY;
