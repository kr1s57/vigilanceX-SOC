-- Migration 015: False Positive Detection System
-- Version: 3.57.118
-- Date: 2026-01-19

-- ============================================================================
-- 1. Add FP detection columns to pending_bans table
-- ============================================================================

-- Add pending_type to distinguish country_policy vs false_positive
ALTER TABLE vigilance_x.pending_bans
ADD COLUMN IF NOT EXISTS pending_type LowCardinality(String) DEFAULT 'country_policy';

-- Add fp_rule_id for ModSec rule ID causing false positive
ALTER TABLE vigilance_x.pending_bans
ADD COLUMN IF NOT EXISTS fp_rule_id String DEFAULT '';

-- Add fp_uri for URI pattern causing false positive
ALTER TABLE vigilance_x.pending_bans
ADD COLUMN IF NOT EXISTS fp_uri String DEFAULT '';

-- Add fp_hostname for target hostname
ALTER TABLE vigilance_x.pending_bans
ADD COLUMN IF NOT EXISTS fp_hostname String DEFAULT '';

-- Add fp_match_count for identical pattern occurrences
ALTER TABLE vigilance_x.pending_bans
ADD COLUMN IF NOT EXISTS fp_match_count UInt32 DEFAULT 0;

-- ============================================================================
-- 2. Add index for pending_type lookup
-- ============================================================================

ALTER TABLE vigilance_x.pending_bans
ADD INDEX IF NOT EXISTS idx_pending_type pending_type TYPE set(10) GRANULARITY 1;

-- ============================================================================
-- 3. Documentation
-- ============================================================================

-- False Positive Detection:
-- When same IP triggers 10+ identical attacks (same rule_id + same URI):
-- - Likely a misconfigured application or strict ModSec filtering
-- - Example: Mattermost client repeatedly hitting download/upload rules
-- - These IPs are flagged as potential false positives for admin review
--
-- pending_type values:
-- - country_policy: IP from authorized country requiring admin approval
-- - false_positive: Detected as potential FP based on repeated identical attacks
