-- Migration 012: CrowdSec Blocklist Proxy Mode
-- Adds support for using VigilanceKey as a proxy for blocklist downloads
-- instead of directly accessing CrowdSec API

-- Add use_proxy column to crowdsec_blocklist_config
ALTER TABLE vigilance_x.crowdsec_blocklist_config
ADD COLUMN IF NOT EXISTS use_proxy UInt8 DEFAULT 0;

-- Add proxy_server_url column to crowdsec_blocklist_config
ALTER TABLE vigilance_x.crowdsec_blocklist_config
ADD COLUMN IF NOT EXISTS proxy_server_url String DEFAULT '';

-- Comments for documentation
COMMENT ON COLUMN vigilance_x.crowdsec_blocklist_config.use_proxy IS 'Whether to use VigilanceKey as proxy for blocklist downloads (0=direct, 1=proxy)';
COMMENT ON COLUMN vigilance_x.crowdsec_blocklist_config.proxy_server_url IS 'VigilanceKey server URL when using proxy mode';
