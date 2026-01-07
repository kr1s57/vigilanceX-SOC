-- Migration: Add v1.6 Threat Intel provider columns
-- Adds support for GreyNoise, IPSum, CriminalIP, and Pulsedive providers
-- Also adds infrastructure detection flags (VPN, Proxy, Benign, Blocklist count)

-- v1.6 Provider scores
ALTER TABLE vigilance_x.ip_threat_scores
ADD COLUMN IF NOT EXISTS greynoise_score Int32 DEFAULT 0;

ALTER TABLE vigilance_x.ip_threat_scores
ADD COLUMN IF NOT EXISTS ipsum_score Int32 DEFAULT 0;

ALTER TABLE vigilance_x.ip_threat_scores
ADD COLUMN IF NOT EXISTS criminalip_score Int32 DEFAULT 0;

ALTER TABLE vigilance_x.ip_threat_scores
ADD COLUMN IF NOT EXISTS pulsedive_score Int32 DEFAULT 0;

-- v1.6 Infrastructure detection flags
ALTER TABLE vigilance_x.ip_threat_scores
ADD COLUMN IF NOT EXISTS is_benign UInt8 DEFAULT 0;

ALTER TABLE vigilance_x.ip_threat_scores
ADD COLUMN IF NOT EXISTS is_vpn UInt8 DEFAULT 0;

ALTER TABLE vigilance_x.ip_threat_scores
ADD COLUMN IF NOT EXISTS is_proxy UInt8 DEFAULT 0;

ALTER TABLE vigilance_x.ip_threat_scores
ADD COLUMN IF NOT EXISTS in_blocklists Int32 DEFAULT 0;

-- Note: Provider value descriptions:
-- greynoise_score:   GreyNoise Community API - reduces false positives (benign scanners like Shodan, Googlebot)
-- ipsum_score:       IPSum aggregated blocklists - if IP is in 3+ blocklists, high threat signal
-- criminalip_score:  Criminal IP - excellent C2 server, VPN, Proxy detection
-- pulsedive_score:   Pulsedive - IOC correlation, threat actors, campaigns
-- is_benign:         GreyNoise RIOT dataset - known benign service (reduces threat score)
-- is_vpn:            CriminalIP VPN detection
-- is_proxy:          CriminalIP Proxy detection
-- in_blocklists:     IPSum - number of blocklists containing this IP
