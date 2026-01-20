// Event types
export interface Event {
  event_id: string
  timestamp: string
  log_type: string
  category: string
  sub_category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  mitre_technique?: string  // v3.57.113: MITRE ATT&CK technique ID (T1190, T1059, etc.)
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  action: string
  rule_id: string
  rule_name: string
  hostname: string
  user_name: string
  url: string
  http_method: string
  http_status: number
  user_agent: string
  geo_country: string
  geo_city: string
  geo_asn: number
  geo_org: string
  message: string
  reason: string
  raw_log?: string
  sophos_id: string
  ingested_at: string
  modsec_rule_ids?: string[]
  modsec_messages?: string[]
}

// Stats types
export interface EventStats {
  total_events: number
  blocked_events: number
  block_rate: number
  unique_ips: number
  critical_events: number
  high_events: number
  medium_events: number
  low_events: number
}

export interface TimelinePoint {
  time: string
  total_events: number
  blocked_events: number
  unique_ips: number
}

export interface TopAttacker {
  ip: string
  attack_count: number
  blocked_count: number
  unique_rules: number
  categories: string[]
  country: string
  threat_score?: number
}

export interface TopTarget {
  hostname: string
  url?: string
  attack_count: number
  unique_ips: number
}

// Ban types
export interface BanStatus {
  ip: string
  status: 'active' | 'expired' | 'permanent' | 'conditional' | 'pending_approval' | 'ban_waf_hzone' | 'ban_waf_zone' | 'ban_waf_pending'
  ban_count: number
  first_ban: string
  last_ban: string
  expires_at: string | null
  reason: string
  trigger_rule: string
  synced_xgs: boolean
  created_by: string
  country?: string // Country code for flag display
  // D2B v2 Fields
  current_tier?: number // 0=initial, 1=1st recidiv, 2=2nd recidiv, 3+=permanent
  conditional_until?: string | null // End of conditional survey period
  geo_zone?: string // authorized, hostile, neutral
  threat_score_at_ban?: number // Threat score when banned
  xgs_group?: string // grp_VGX-BannedIP or grp_VGX-BannedPerm
}

export interface BanHistory {
  id: string
  timestamp: string
  ip: string
  action: 'ban' | 'unban' | 'unban_immunity' | 'unban_conditional' | 'extend' | 'permanent' | 'expire' | 'escalate' | 'approve' | 'reject'
  duration_hours: number | null
  reason: string
  source: string  // manual, detect2ban, threat_intel, policy
  performed_by: string
  synced_xgs: boolean
  // D2B v2 Fields
  tier?: number
  geo_zone?: string
  threat_score?: number
  xgs_group?: string
}

export interface BanStats {
  total_active_bans: number
  total_permanent_bans: number
  total_expired_bans: number
  bans_last_24h: number
  unbans_last_24h: number
  recidivist_ips: number
  // D2B v2 Stats
  pending_approval?: number
  conditional_survey?: number
}

// D2B v2 - GeoZone Configuration
export interface GeoZoneConfig {
  enabled: boolean
  authorized_countries: string[]
  hostile_countries: string[]
  default_policy: 'authorized' | 'hostile' | 'neutral'
  waf_threshold_hzone: number  // Events before ban for hostile zone
  waf_threshold_zone: number   // Events before TI check for authorized zone
  threat_score_threshold: number // Min score to auto-ban in authorized zone
}

// D2B v2 - Pending Ban
// v3.57.118: Added FP detection fields
export interface PendingBan {
  id: string
  ip: string
  country: string
  geo_zone: string
  threat_score: number
  threat_sources: string[]
  event_count: number
  first_event: string
  last_event: string
  trigger_rule: string
  reason: string
  status: 'pending' | 'approved' | 'rejected' | 'expired'
  created_at: string
  reviewed_at?: string | null
  reviewed_by?: string
  review_note?: string
  // v3.57.118: FP detection fields
  pending_type: 'country_policy' | 'false_positive' | ''
  fp_rule_id?: string
  fp_uri?: string
  fp_hostname?: string
  fp_match_count?: number
}

// v3.57.118: Added FP and country policy counts
export interface PendingBanStats {
  total_pending: number
  high_threat: number    // Score >= 70
  medium_threat: number  // Score 30-69
  low_threat: number     // Score < 30
  oldest_pending?: string | null
  false_positive_count: number  // v3.57.118: FP detections
  country_policy_count: number  // v3.57.118: Country policy detections
}

// Threat types
export interface ThreatScore {
  ip: string
  aggregated_score: number
  total_score: number
  reputation_score: number
  activity_score: number
  severity_score: number
  confidence: number
  is_malicious: boolean
  threat_level: 'critical' | 'high' | 'medium' | 'low' | 'minimal' | 'none'
  categories: string[] | null
  sources: string[] | null
  tags: string[] | null
  country: string
  asn: string
  isp: string
  is_tor: boolean
  is_vpn?: boolean
  is_proxy?: boolean
  is_benign?: boolean
  is_c2?: boolean
  abuseipdb_score: number
  abuseipdb_reports: number
  abuseipdb_is_tor: boolean
  virustotal_score: number
  virustotal_positives: number
  virustotal_total: number
  otx_score: number
  alienvault_pulses: number
  malware_families?: string[]
  adversaries?: string[]
  first_seen: string
  last_seen: string
  last_checked: string
  total_attacks: number
  // v2.9.5: New providers
  in_blocklists?: number
  open_ports?: number[]
  vulnerabilities?: string[]
  // v2.9.6: CrowdSec
  crowdsec?: {
    found: boolean
    reputation?: string
    confidence?: string
    background_noise_score?: number
    ip_range_score?: number
    behaviors?: string[]
    classifications?: string[]
    mitre_techniques?: string[]
    normalized_score?: number
  }
  background_noise?: number
  subnet_score?: number
  mitre_techniques?: string[]
  behaviors?: string[]
  tiers_queried?: number[]
}

export interface ThreatStats {
  total_tracked: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  tor_exit_nodes: number
  checks_last_24h: number
  configured_providers: string[]
  cache_stats: {
    size: number
    hits: number
    misses: number
    hit_rate: number
    ttl: string
  }
}

export interface ThreatProvider {
  name: string
  configured: boolean
  available?: boolean  // Optional - not always returned by backend
  description?: string  // v1.6: Provider description
  tier?: number         // v2.9.5: Provider tier (1=unlimited, 2=moderate, 3=limited)
  requires_key?: boolean // v2.9.5: Whether API key is required
}

export interface IPGeolocation {
  ip: string
  country_code: string
  country_name: string
  city: string
  region: string
  latitude: number
  longitude: number
  asn: number
  org: string
  is_proxy: boolean
  is_hosting: boolean
  is_tor: boolean
}

// Anomaly types
export interface AnomalySpike {
  id: string
  detected_at: string
  anomaly_type: string
  metric_name: string
  current_value: number
  baseline_value: number
  deviation_sigma: number
  affected_ips: string[]
  affected_rules: string[]
  description: string
  is_acknowledged: boolean
}

export interface NewIPDetected {
  ip: string
  first_seen: string
  detection_window: string
  first_log_type: string
  first_category: string
  first_severity: string
  event_count_24h: number
  geo_country: string
  threat_score: number
  is_risky: boolean
}

// API Response types
export interface Pagination {
  total: number
  limit: number
  offset: number
  has_more: boolean
}

export interface PaginatedResponse<T> {
  data: T[]
  pagination: Pagination
}

export interface OverviewResponse {
  stats: EventStats
  by_log_type: Record<string, number>
  top_attackers: TopAttacker[]
  top_targets: TopTarget[]
}

// Filter types
export interface EventFilters {
  log_type?: string
  category?: string
  severity?: string
  src_ip?: string
  dst_ip?: string
  hostname?: string
  rule_id?: string
  action?: string
  start_time?: string
  end_time?: string
  search?: string
  limit?: number
  offset?: number
}

// ModSec types
export interface ModSecLog {
  id: string
  timestamp: string
  unique_id: string
  src_ip: string
  src_port: number
  hostname: string
  uri: string
  rule_id: string
  rule_file: string
  rule_msg: string
  rule_severity: string
  rule_data: string
  crs_version: string
  paranoia_level: number
  attack_type: string
  total_score: number
  is_blocking: boolean
  tags: string[]
  raw_log?: string
  ingested_at: string
}

export interface ModSecRule {
  rule_id: string
  rule_msg: string
  rule_severity: string
  rule_file: string
  rule_data: string
  attack_type: string
  paranoia_level: number
  tags: string[]
}

export interface ModSecRequestGroup {
  unique_id: string
  timestamp: string
  src_ip: string
  hostname: string
  uri: string
  total_score: number
  is_blocked: boolean
  rule_count: number
  rules: ModSecRule[]
  geo_country?: string
  geo_city?: string
}

export interface ModSecLogFilters {
  src_ip?: string
  hostname?: string
  rule_id?: string
  attack_type?: string
  unique_id?: string
  start_time?: string
  end_time?: string
  search?: string
  limit?: number
  offset?: number
}

// WebSocket types
export type WSMessageType =
  | 'new_event'
  | 'ban_update'
  | 'threat_alert'
  | 'anomaly'
  | 'stats_update'

export interface WSMessage<T = unknown> {
  type: WSMessageType
  payload: T
  time: string
}

// Report types
export interface DBStats {
  database_size: string
  total_events: number
  events_by_type: Record<string, number>
  date_range_start: string
  date_range_end: string
  table_stats: TableStat[]
}

export interface TableStat {
  table_name: string
  row_count: number
  size: string
}

export interface ReportConfig {
  type: 'daily' | 'weekly' | 'monthly' | 'custom'
  format: 'pdf' | 'xml'
  start_date?: string
  end_date?: string
  modules?: string[]
}

export interface ReportPreview {
  report_type: string
  period: string
  start_date: string
  end_date: string
  generated_at: string
  db_stats: DBStats | null
  event_stats: ReportEventStats | null
  threat_stats: ReportThreatStats | null
  ban_stats: ReportBanStats | null
  modsec_stats: ReportModSecStats | null
  vpn_stats: ReportVPNStats | null
}

export interface ReportEventStats {
  total_events: number
  blocked_events: number
  block_rate: number
  unique_ips: number
  critical_events: number
  high_events: number
  medium_events: number
  low_events: number
  events_by_type: Record<string, number>
  events_by_severity: Record<string, number>
  events_by_action: Record<string, number>
  top_attackers: ReportAttacker[]
  top_targets: ReportTarget[]
  top_rules: ReportRule[]
  top_countries: ReportCountry[]
}

export interface ReportAttacker {
  ip: string
  attack_count: number
  blocked_count: number
  unique_rules: number
  categories: string[]
  country: string
}

export interface ReportTarget {
  hostname: string
  url: string
  attack_count: number
  unique_ips: number
}

export interface ReportRule {
  rule_id: string
  rule_msg: string
  trigger_count: number
  unique_ips: number
}

export interface ReportCountry {
  country: string
  attack_count: number
  unique_ips: number
}

export interface ReportThreatStats {
  total_tracked: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  tor_exit_nodes: number
}

export interface ReportBanStats {
  active_bans: number
  permanent_bans: number
  expired_bans: number
  new_bans: number
  unbans: number
}

export interface ReportModSecStats {
  total_logs: number
  blocking_logs: number
  unique_rules: number
  top_attack_types: ReportAttackType[]
  top_triggered_rules: ReportRule[]
}

export interface ReportAttackType {
  type: string
  count: number
}

export interface ReportVPNStats {
  total_events: number
  connections: number
  disconnections: number
  auth_failures: number
  unique_users: number
  total_bytes_in: number
  total_bytes_out: number
}

// Status types
export interface SyslogStatus {
  last_event_time: string
  events_last_hour: number
  is_receiving: boolean
  seconds_since_last: number
}

// Critical Alert types
export interface CriticalAlert {
  event_id: string
  timestamp: string
  log_type: string
  category: string
  severity: string
  src_ip: string
  dst_ip: string
  hostname: string
  rule_id: string
  rule_name: string
  message: string
  action: string
  country: string
}

// Zone Traffic types (v3.1 - XGS Parser)
export interface ZoneTraffic {
  src_zone: string
  dst_zone: string
  event_count: number
  blocked_count: number
  allowed_count: number
  unique_ips: number
  critical_count: number
  high_count: number
  block_rate: number
}

export interface ZoneTrafficStats {
  flows: ZoneTraffic[]
  total_flows: number
  unique_zones: string[]
}

// Geoblocking types (v2.0)
export interface GeoBlockRule {
  id: string
  rule_type: 'country_block' | 'country_watch' | 'asn_block' | 'asn_watch'
  target: string
  action: 'block' | 'watch' | 'boost'
  score_modifier: number
  reason: string
  is_active: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface GeoBlockRuleRequest {
  rule_type: string
  target: string
  action: string
  score_modifier: number
  reason: string
  created_by?: string
}

export interface GeoLocation {
  ip: string
  country_code: string
  country_name: string
  city: string
  region: string
  asn: number
  as_org: string
  is_vpn: boolean
  is_proxy: boolean
  is_tor: boolean
  is_datacenter: boolean
  latitude: number
  longitude: number
  last_updated: string
}

export interface GeoCheckResult {
  ip: string
  geo_location: GeoLocation | null
  matched_rules: GeoBlockRule[]
  total_score_boost: number
  should_block: boolean
  block_reason?: string
  risk_factors: string[]
}

export interface GeoBlockStats {
  total_rules: number
  active_rules: number
  rules_by_type: Record<string, number>
  rules_by_action: Record<string, number>
  blocked_countries: string[] | null
  watched_countries: string[] | null
  blocked_asns: number[] | null
}

export interface HighRiskCountry {
  country_code: string
  country_name: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  base_score: number
  reason: string
}

// Soft Whitelist types (v2.0)
export interface WhitelistEntry {
  ip: string
  cidr_mask: number
  type: 'hard' | 'soft' | 'monitor'
  reason: string
  description: string
  score_modifier: number
  alert_only: boolean
  expires_at: string | null
  tags: string[]
  added_by: string
  created_at: string
  created_by: string
  is_active: boolean
}

export interface WhitelistRequest {
  ip: string
  cidr_mask?: number
  type: 'hard' | 'soft' | 'monitor'
  reason: string
  description?: string
  score_modifier?: number
  alert_only?: boolean
  duration_days?: number | null
  tags?: string[]
  added_by?: string
}

export interface WhitelistCheckResult {
  is_whitelisted: boolean
  entry?: WhitelistEntry
  effective_type: 'none' | 'hard' | 'soft' | 'monitor'
  score_modifier: number
  allow_auto_ban: boolean
  alert_required: boolean
}

export interface WhitelistStats {
  total: number
  by_type: Record<string, number>
}

// Freshness Score & Combined Risk Assessment types (v2.0)
export interface ScoreComponents {
  threat_intel: number
  threat_intel_weight: number
  blocklist: number
  blocklist_weight: number
  freshness: number
  freshness_weight: number
  geolocation: number
  geolocation_weight: number
  whitelist_reduction: number
}

export interface FreshnessInfo {
  days_since_last_seen: number
  is_recent: boolean
  is_stale: boolean
  multiplier: number
  reason: string
}

export interface RiskAssessment {
  ip: string
  threat_score: number
  threat_level: string
  threat_sources: number
  is_tor: boolean
  is_vpn: boolean
  is_proxy: boolean
  is_benign: boolean
  in_ipsum_lists: number
  tags: string[]
  country: string
  in_blocklists: boolean
  blocklist_count: number
  blocklist_sources: string[] | null
  blocklist_categories: string[] | null
  blocklist_max_confidence: number
  blocklist_last_seen?: string
  whitelist_status?: {
    is_whitelisted: boolean
    type: string
    score_modifier: number
    allow_auto_ban: boolean
  }
  combined_score: number
  combined_risk: string
  recommend_ban: boolean
  scoring_confidence: number
  score_components: ScoreComponents
  freshness?: FreshnessInfo
}

export interface ScoringWeights {
  threat_intel: number
  blocklist: number
  freshness: number
  geolocation: number
}

export interface FreshnessConfig {
  decay_factor: number
  min_multiplier: number
  max_multiplier: number
  recent_activity_boost_days: number
  recent_activity_boost: number
  stale_threshold_days: number
}

// ==============================================
// Vigimail Checker Types (v3.54)
// ==============================================

export interface VigimailConfig {
  enabled: boolean
  check_interval_hours: number
  hibp_api_key: string
  leakcheck_api_key: string
  last_check: string
}

export interface VigimailDomain {
  id: string
  domain: string
  created_at: string
  updated_at: string
}

export interface VigimailEmail {
  id: string
  email: string
  domain: string
  last_check: string
  leak_count: number
  status: 'pending' | 'clean' | 'leaked'
  created_at: string
}

export interface VigimailLeak {
  id: string
  email: string
  source: 'hibp' | 'leakcheck'
  breach_name: string
  breach_date: string | null
  data_classes: string[]
  is_verified: boolean
  is_sensitive: boolean
  description?: string
  first_seen: string
  last_seen: string
}

export interface DomainDNSCheck {
  id: string
  domain: string
  check_time: string
  // SPF
  spf_exists: boolean
  spf_record: string
  spf_valid: boolean
  spf_issues: string[]
  // DKIM
  dkim_exists: boolean
  dkim_selectors: string[]
  dkim_valid: boolean
  dkim_issues: string[]
  // DMARC
  dmarc_exists: boolean
  dmarc_record: string
  dmarc_policy: 'none' | 'quarantine' | 'reject' | ''
  dmarc_valid: boolean
  dmarc_issues: string[]
  // MX
  mx_exists: boolean
  mx_records: string[]
  // Overall
  overall_score: number
  overall_status: 'good' | 'warning' | 'critical' | 'unknown'
}

export interface VigimailStatus {
  enabled: boolean
  worker_running: boolean
  last_check: string
  next_check: string
  total_domains: number
  total_emails: number
  total_leaks: number
  emails_with_leaks: number
  domains_at_risk: number
  hibp_configured: boolean
  leakcheck_configured: boolean
}

export interface VigimailStats {
  total_domains: number
  total_emails: number
  total_leaks: number
  emails_clean: number
  emails_leaked: number
  emails_pending: number
  leaks_by_source: Record<string, number>
  domains_by_status: Record<string, number>
}

export interface VigimailCheckHistory {
  id: string
  check_type: 'email' | 'domain' | 'all'
  check_time: string
  domains_checked: number
  emails_checked: number
  leaks_found: number
  duration_ms: number
}

// ==============================================
// TrackIP Types (v3.56 - IP/Hostname Tracking)
// ==============================================

export interface TrackIPQuery {
  query: string
  query_type: 'ip' | 'hostname'
  start_time?: string
  end_time?: string
  limit: number
}

export interface TrackIPTimeRange {
  start: string
  end: string
}

export interface TrackIPSummary {
  total_events: number
  categories_found: number
  first_seen?: string
  last_seen?: string
  unique_hostnames: string[]
  unique_dst_ips: string[]
  top_ports: number[]
  severity_breakdown: Record<string, number>
}

export interface TrackIPCategoryResult {
  count: number
  events: unknown[]
}

export interface TrackIPGeoInfo {
  country_code: string
  country_name: string
  city: string
  asn: number
  org: string
}

export interface TrackIPResponse {
  query: string
  query_type: 'ip' | 'hostname'
  time_range: TrackIPTimeRange
  summary: TrackIPSummary
  categories: Record<string, TrackIPCategoryResult>
  geo_info?: TrackIPGeoInfo
}

// Category-specific event types
export interface TrackIPWAFEvent {
  event_id: string
  timestamp: string
  log_type: string
  category: string
  severity: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  hostname: string
  url: string
  rule_id: string
  rule_name: string
  action: string
  message: string
}

export interface TrackIPModSecEvent {
  id: string
  timestamp: string
  unique_id: string
  src_ip: string
  hostname: string
  uri: string
  rule_id: string
  rule_msg: string
  attack_type: string
  total_score: number
  is_blocking: boolean
}

export interface TrackIPFirewallEvent {
  event_id: string
  timestamp: string
  rule_name: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  action: string
  src_zone: string
  dst_zone: string
  bytes: number
  application: string
}

export interface TrackIPVPNEvent {
  event_id: string
  timestamp: string
  event_type: string
  vpn_type: string
  user_name: string
  src_ip: string
  assigned_ip?: string
  duration_seconds: number
  bytes_in: number
  bytes_out: number
  geo_country?: string
}

export interface TrackIPATPEvent {
  event_id: string
  timestamp: string
  src_ip: string
  dst_ip: string
  threat_name: string
  threat_type: string
  severity: string
  action: string
  url: string
  user_name?: string
}

export interface TrackIPAntivirusEvent {
  event_id: string
  timestamp: string
  src_ip: string
  dst_ip: string
  malware_name: string
  malware_type: string
  action: string
  file_name: string
  file_path?: string
}

export interface TrackIPHeartbeatEvent {
  event_id: string
  timestamp: string
  endpoint_name: string
  endpoint_ip: string
  health_status: string
  os_type?: string
}
