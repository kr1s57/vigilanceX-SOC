-- ============================================
-- Migration 011: Add country_code to CrowdSec blocklist IPs
-- Stores country for filtering without GeoIP API calls
-- ============================================

USE vigilance_x;

-- Add country_code column to crowdsec_blocklist_ips
ALTER TABLE crowdsec_blocklist_ips
    ADD COLUMN IF NOT EXISTS country_code LowCardinality(String) DEFAULT '';
