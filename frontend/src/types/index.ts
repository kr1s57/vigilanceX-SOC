// Event types
export interface Event {
  event_id: string
  timestamp: string
  log_type: string
  category: string
  sub_category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
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
  raw_log?: string
  sophos_id: string
  ingested_at: string
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
  status: 'active' | 'expired' | 'permanent'
  ban_count: number
  first_ban: string
  last_ban: string
  expires_at: string | null
  reason: string
  trigger_rule: string
  synced_xgs: boolean
  created_by: string
}

export interface BanHistory {
  id: string
  timestamp: string
  ip: string
  action: 'ban' | 'unban' | 'extend' | 'permanent'
  previous_status: string
  new_status: string
  duration_hours: number | null
  reason: string
  performed_by: string
}

export interface BanStats {
  total_active_bans: number
  total_permanent_bans: number
  total_expired_bans: number
  bans_last_24h: number
  unbans_last_24h: number
  recidivist_ips: number
}

// Threat types
export interface ThreatScore {
  ip: string
  total_score: number
  reputation_score: number
  activity_score: number
  severity_score: number
  is_malicious: boolean
  threat_level: 'critical' | 'high' | 'medium' | 'low' | 'minimal'
  categories: string[]
  sources: string[]
  abuseipdb_score: number
  abuseipdb_reports: number
  virustotal_positives: number
  alienvault_pulses: number
  last_checked: string
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
