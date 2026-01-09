-- ============================================
-- VIGILANCE X - Migration 006
-- Extended XGS Fields for v3.1.0
-- Adds 27 new fields from XML decoders
-- ============================================

USE vigilance_x;

-- ============================================
-- Device Identification (critical for VX3 binding)
-- ============================================
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_serial_id String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_model String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_name String DEFAULT '';

-- ============================================
-- Log Metadata (deduplication & classification)
-- ============================================
ALTER TABLE events ADD COLUMN IF NOT EXISTS log_id String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS con_id String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS log_component LowCardinality(String) DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS log_subtype LowCardinality(String) DEFAULT '';

-- ============================================
-- TLS/SSL Analysis
-- ============================================
ALTER TABLE events ADD COLUMN IF NOT EXISTS tls_version LowCardinality(String) DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS cipher_suite String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS sni String DEFAULT '';

-- ============================================
-- Threat Intelligence
-- ============================================
ALTER TABLE events ADD COLUMN IF NOT EXISTS threatfeed String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS malware String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS classification LowCardinality(String) DEFAULT '';

-- ============================================
-- VPN Extended Fields
-- ============================================
ALTER TABLE events ADD COLUMN IF NOT EXISTS connection_name String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS remote_network String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS local_network String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS local_ip String DEFAULT '';

-- ============================================
-- Endpoint Health (Synchronized Security)
-- ============================================
ALTER TABLE events ADD COLUMN IF NOT EXISTS ep_uuid String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS ep_name String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS ep_ip String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS ep_health LowCardinality(String) DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS hb_status LowCardinality(String) DEFAULT '';

-- ============================================
-- Email/Anti-Spam
-- ============================================
ALTER TABLE events ADD COLUMN IF NOT EXISTS sender String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS recipient String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS subject String DEFAULT '';

-- ============================================
-- Network Zones
-- ============================================
ALTER TABLE events ADD COLUMN IF NOT EXISTS src_zone LowCardinality(String) DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS dst_zone LowCardinality(String) DEFAULT '';

-- ============================================
-- Indexes for new critical fields
-- ============================================
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_device_serial device_serial_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_tls_version tls_version TYPE set(20) GRANULARITY 4;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_threatfeed threatfeed TYPE bloom_filter GRANULARITY 4;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_ep_health ep_health TYPE set(10) GRANULARITY 4;
