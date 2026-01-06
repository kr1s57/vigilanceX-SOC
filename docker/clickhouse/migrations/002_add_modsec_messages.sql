-- Migration: Add modsec_messages column to events table
-- This stores the ModSecurity rule messages alongside the rule IDs
-- for better WAF event display in the frontend

ALTER TABLE vigilance_x.events
ADD COLUMN IF NOT EXISTS modsec_messages Array(String) DEFAULT [];

-- Note: The modsec_messages array is kept in sync with modsec_rule_ids
-- Each index in modsec_messages corresponds to the same index in modsec_rule_ids
-- Example: modsec_rule_ids = ['920320', '930130']
--          modsec_messages = ['Missing User Agent Header', 'Restricted File Access Attempt']
