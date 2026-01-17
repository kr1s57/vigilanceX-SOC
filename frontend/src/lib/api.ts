import axios from 'axios'
import type {
  Event,
  EventFilters,
  PaginatedResponse,
  OverviewResponse,
  TimelinePoint,
  TopAttacker,
  TopTarget,
  ZoneTrafficStats,
  BanStatus,
  BanStats,
  BanHistory,
  ThreatScore,
  ThreatStats,
  ThreatProvider,
  AnomalySpike,
  NewIPDetected,
  ModSecLog,
  ModSecRequestGroup,
  ModSecLogFilters,
  DBStats,
  ReportConfig,
  ReportPreview,
  SyslogStatus,
  CriticalAlert,
  GeoBlockRule,
  GeoBlockRuleRequest,
  GeoLocation,
  GeoCheckResult,
  GeoBlockStats,
  HighRiskCountry,
  WhitelistEntry,
  WhitelistRequest,
  WhitelistCheckResult,
  WhitelistStats,
  RiskAssessment
} from '@/types'

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api'

export const api = axios.create({
  baseURL: `${API_BASE_URL}/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle auth errors - don't redirect here, let AuthContext handle it
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Don't auto-redirect on 401 - let components handle authentication state
    // This prevents flickering and allows proper React Router navigation
    return Promise.reject(error)
  }
)

// Events API
export const eventsApi = {
  list: async (filters: EventFilters & { limit?: number; offset?: number }) => {
    const params = new URLSearchParams()
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== '') {
        params.append(key, String(value))
      }
    })
    const response = await api.get<PaginatedResponse<Event>>(`/events?${params}`)
    return response.data
  },

  get: async (id: string) => {
    const response = await api.get<{ data: Event }>(`/events/${id}`)
    return response.data.data
  },

  timeline: async (period: string = '24h', interval: string = 'hour') => {
    const response = await api.get<{ data: TimelinePoint[] }>('/events/timeline', {
      params: { period, interval }
    })
    return response.data.data
  },

  hostnames: async (logType: string = 'WAF') => {
    const response = await api.get<{ data: string[] }>('/events/hostnames', {
      params: { log_type: logType }
    })
    return response.data.data
  },
}

// Stats API
export const statsApi = {
  overview: async (period: string = '24h') => {
    const response = await api.get<OverviewResponse>('/stats/overview', {
      params: { period }
    })
    return response.data
  },

  topAttackers: async (period: string = '24h', limit: number = 10) => {
    const response = await api.get<{ data: TopAttacker[] }>('/stats/top-attackers', {
      params: { period, limit }
    })
    return response.data.data
  },

  topTargets: async (period: string = '24h', limit: number = 10) => {
    const response = await api.get<{ data: TopTarget[] }>('/stats/top-targets', {
      params: { period, limit }
    })
    return response.data.data
  },

  zoneTraffic: async (period: string = '24h', limit: number = 20) => {
    const response = await api.get<ZoneTrafficStats>('/stats/zone-traffic', {
      params: { period, limit }
    })
    return response.data
  },
}

// Geo API
export const geoApi = {
  heatmap: async (period: string = '24h', attackTypes?: string[], dateRange?: { start: string; end: string }) => {
    const params: Record<string, string> = { period }
    if (attackTypes && attackTypes.length > 0) {
      params.attack_types = attackTypes.join(',')
    }
    // v3.53.105: Support custom date range
    if (dateRange) {
      params.start_time = dateRange.start
      params.end_time = dateRange.end
    }
    const response = await api.get<{ data: Array<{ country: string; count: number; unique_ips: number }> }>('/geo/heatmap', {
      params
    })
    return response.data.data
  },
}

// Bans API
export const bansApi = {
  list: async () => {
    const response = await api.get<{ data: BanStatus[] }>('/bans')
    return response.data.data
  },

  get: async (ip: string) => {
    const response = await api.get<{ data: BanStatus }>(`/bans/${ip}`)
    return response.data.data
  },

  create: async (data: { ip: string; reason: string; duration_days?: number; permanent?: boolean }) => {
    const response = await api.post<{ data: BanStatus }>('/bans', data)
    return response.data.data
  },

  delete: async (ip: string, immunityHours?: number) => {
    const params = immunityHours ? `?immunity_hours=${immunityHours}` : ''
    await api.delete(`/bans/${ip}${params}`)
  },

  extend: async (ip: string, days: number) => {
    const response = await api.put<{ data: BanStatus }>(`/bans/${ip}/extend`, { duration_days: days })
    return response.data.data
  },

  makePermanent: async (ip: string) => {
    const response = await api.put<{ data: BanStatus }>(`/bans/${ip}/permanent`)
    return response.data.data
  },

  history: async (ip: string) => {
    const response = await api.get<{ data: BanHistory[] }>(`/bans/${ip}/history`)
    return response.data.data
  },

  stats: async () => {
    const response = await api.get<BanStats>('/bans/stats')
    return response.data
  },

  sync: async () => {
    await api.post('/bans/sync')
  },

  xgsStatus: async () => {
    const response = await api.get<{ connected: boolean; host: string; total_in_group: number }>('/bans/xgs-status')
    return response.data
  },
}

// Detect2Ban API (v3.51 - Automated threat detection engine)
export interface Detect2BanStatus {
  enabled: boolean
  running: boolean
  scenario_count: number
  loaded_scenarios: string[]
  check_interval: string
}

export const detect2banApi = {
  getStatus: async () => {
    const response = await api.get<Detect2BanStatus>('/detect2ban/status')
    return response.data
  },

  enable: async () => {
    const response = await api.post<{ success: boolean; message: string; status: string }>('/detect2ban/enable')
    return response.data
  },

  disable: async () => {
    const response = await api.post<{ success: boolean; message: string; status: string }>('/detect2ban/disable')
    return response.data
  },

  toggle: async () => {
    const response = await api.post<{ success: boolean; message: string; status: string }>('/detect2ban/toggle')
    return response.data
  },

  getScenarios: async () => {
    const response = await api.get<{ scenarios: Array<{ name: string; description: string; enabled: boolean }> }>('/detect2ban/scenarios')
    return response.data.scenarios
  },
}

// Whitelist API
export const whitelistApi = {
  list: async () => {
    const response = await api.get<{ data: Array<{ ip: string; reason?: string; added_by?: string; created_at: string }> }>('/whitelist')
    return response.data.data
  },

  add: async (ip: string, reason: string) => {
    const response = await api.post('/whitelist', { ip, reason, added_by: 'web_ui' })
    return response.data
  },

  remove: async (ip: string) => {
    await api.delete(`/whitelist/${ip}`)
  },
}

// Threats API
export const threatsApi = {
  list: async (limit: number = 20) => {
    const response = await api.get<ThreatScore[]>('/threats/', { params: { limit } })
    return response.data
  },

  stats: async () => {
    const response = await api.get<ThreatStats>('/threats/stats')
    return response.data
  },

  providers: async () => {
    const response = await api.get<ThreatProvider[]>('/threats/providers')
    return response.data
  },

  byLevel: async (level: string, limit: number = 50) => {
    const response = await api.get<ThreatScore[]>(`/threats/level/${level}`, { params: { limit } })
    return response.data
  },

  check: async (ip: string) => {
    const response = await api.get<ThreatScore>(`/threats/check/${ip}`)
    return response.data
  },

  score: async (ip: string) => {
    const response = await api.get<ThreatScore>(`/threats/score/${ip}`)
    return response.data
  },

  shouldBan: async (ip: string) => {
    const response = await api.get<{ should_ban: boolean; reason: string }>(`/threats/should-ban/${ip}`)
    return response.data
  },

  clearCache: async () => {
    await api.post('/threats/cache/clear')
  },

  // Combined risk assessment with freshness scoring (v2.0)
  riskAssessment: async (ip: string) => {
    const response = await api.get<RiskAssessment>(`/threats/risk/${ip}`)
    return response.data
  },
}

// Anomalies API
export const anomaliesApi = {
  list: async () => {
    const response = await api.get<{ data: AnomalySpike[] }>('/anomalies')
    return response.data.data
  },

  newIPs: async () => {
    const response = await api.get<{ data: NewIPDetected[] }>('/anomalies/new-ips')
    return response.data.data
  },

  acknowledge: async (id: string) => {
    await api.put(`/anomalies/${id}/acknowledge`)
  },
}

// Health API
export const healthApi = {
  check: async () => {
    const response = await api.get('/health')
    return response.data
  },
}

// ModSec API
export const modsecApi = {
  getLogs: async (filters: ModSecLogFilters = {}) => {
    const params = new URLSearchParams()
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== '') {
        params.append(key, String(value))
      }
    })
    const response = await api.get<PaginatedResponse<ModSecLog>>(`/modsec/logs?${params}`)
    return response.data
  },

  getGroupedLogs: async (filters: ModSecLogFilters = {}) => {
    const params = new URLSearchParams()
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== '') {
        params.append(key, String(value))
      }
    })
    const response = await api.get<PaginatedResponse<ModSecRequestGroup>>(`/modsec/logs/grouped?${params}`)
    return response.data
  },

  getHostnames: async () => {
    const response = await api.get<string[]>('/modsec/hostnames')
    return response.data
  },

  getRuleStats: async (period: string = '24h') => {
    const response = await api.get<Array<{
      rule_id: string
      rule_msg: string
      trigger_count: number
      unique_ips: number
      unique_targets: number
    }>>('/modsec/rules/stats', { params: { period } })
    return response.data
  },

  getAttackTypeStats: async (period: string = '24h') => {
    const response = await api.get<Array<{
      attack_type: string
      count: number
      unique_ips: number
    }>>('/modsec/attacks/stats', { params: { period } })
    return response.data
  },

  getStats: async () => {
    const response = await api.get<{
      last_sync: string
      entries_fetched: number
      events_updated: number
      last_error: string
      is_running: boolean
      is_configured: boolean
    }>('/modsec/stats')
    return response.data
  },

  syncNow: async () => {
    const response = await api.post('/modsec/sync')
    return response.data
  },

  testConnection: async () => {
    const response = await api.get<{ status: string; message: string }>('/modsec/test')
    return response.data
  },
}

// Reports API
export const reportsApi = {
  getDBStats: async () => {
    const response = await api.get<DBStats>('/reports/stats')
    return response.data
  },

  getPreview: async (config: ReportConfig) => {
    const params = new URLSearchParams()
    params.append('type', config.type)
    if (config.start_date) params.append('start_date', config.start_date)
    if (config.end_date) params.append('end_date', config.end_date)
    if (config.modules) {
      config.modules.forEach(m => params.append('modules', m))
    }
    const response = await api.get<ReportPreview>(`/reports/preview?${params}`)
    return response.data
  },

  generate: async (config: ReportConfig) => {
    const params = new URLSearchParams()
    params.append('type', config.type)
    params.append('format', config.format)
    if (config.start_date) params.append('start_date', config.start_date)
    if (config.end_date) params.append('end_date', config.end_date)
    if (config.modules) {
      config.modules.forEach(m => params.append('modules', m))
    }

    const response = await api.get(`/reports/generate?${params}`, {
      responseType: 'blob'
    })

    // Create download link
    const blob = new Blob([response.data], {
      type: config.format === 'pdf' ? 'application/pdf' : 'application/xml'
    })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url

    // Get filename from Content-Disposition header or generate one
    const contentDisposition = response.headers['content-disposition']
    let filename = `vigilancex_report_${config.type}.${config.format}`
    if (contentDisposition) {
      const match = contentDisposition.match(/filename=(.+)/)
      if (match) {
        filename = match[1]
      }
    }

    link.download = filename
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)

    return { success: true, filename }
  },

  sendByEmail: async (config: ReportConfig & { email: string }) => {
    const response = await api.post<{ success: boolean; message: string; filename: string }>(
      '/reports/send-email',
      {
        type: config.type,
        format: config.format,
        start_date: config.start_date,
        end_date: config.end_date,
        modules: config.modules,
        email: config.email,
      }
    )
    return response.data
  },
}

// Status API
export const statusApi = {
  syslog: async () => {
    const response = await api.get<SyslogStatus>('/status/syslog')
    return response.data
  },
}

// Alerts API
export const alertsApi = {
  critical: async (limit: number = 20, period?: string) => {
    const response = await api.get<{ data: CriticalAlert[]; count: number }>('/alerts/critical', {
      params: { limit, period }
    })
    return response.data
  },
}

// Geoblocking API (v2.0)
export const geoblockingApi = {
  // Rules management
  listRules: async (type?: string) => {
    const params = type ? { type } : {}
    const response = await api.get<{ data: GeoBlockRule[]; count: number }>('/geoblocking/rules', { params })
    return response.data
  },

  createRule: async (rule: GeoBlockRuleRequest) => {
    const response = await api.post<{ data: GeoBlockRule; message: string }>('/geoblocking/rules', rule)
    return response.data
  },

  updateRule: async (id: string, rule: Partial<GeoBlockRule>) => {
    const response = await api.put<{ data: GeoBlockRule; message: string }>(`/geoblocking/rules/${id}`, rule)
    return response.data
  },

  deleteRule: async (id: string) => {
    const response = await api.delete<{ message: string; id: string }>(`/geoblocking/rules/${id}`)
    return response.data
  },

  // Stats
  getStats: async () => {
    const response = await api.get<GeoBlockStats>('/geoblocking/stats')
    return response.data
  },

  // IP checks
  checkIP: async (ip: string) => {
    const response = await api.get<GeoCheckResult>(`/geoblocking/check/${ip}`)
    return response.data
  },

  lookupIP: async (ip: string) => {
    const response = await api.get<GeoLocation>(`/geoblocking/lookup/${ip}`)
    return response.data
  },

  // Country lists
  getBlockedCountries: async () => {
    const response = await api.get<{ blocked_countries: string[]; count: number }>('/geoblocking/countries/blocked')
    return response.data
  },

  getWatchedCountries: async () => {
    const response = await api.get<{ watched_countries: string[]; count: number }>('/geoblocking/countries/watched')
    return response.data
  },

  getHighRiskCountries: async () => {
    const response = await api.get<{ high_risk_countries: HighRiskCountry[]; count: number }>('/geoblocking/countries/high-risk')
    return response.data
  },

  // Cache
  refreshCache: async () => {
    const response = await api.post<{ message: string }>('/geoblocking/cache/refresh')
    return response.data
  },
}

// System Whitelist Entry type (protected IPs like DNS, CDN)
export interface SystemWhitelistEntry {
  ip: string
  name: string
  provider: string
  category: string
  description: string
}

// Config API (v2.3 - Plugin configuration)
export const configApi = {
  test: async (pluginId: string, fields: Record<string, string>) => {
    const response = await api.post<{ success: boolean; message: string; status: string }>('/config/test', {
      plugin_id: pluginId,
      fields,
    })
    return response.data
  },

  save: async (pluginId: string, fields: Record<string, string>) => {
    const response = await api.post<{ saved: boolean; test: { success: boolean; message: string; status: string }; message: string }>('/config/save', {
      plugin_id: pluginId,
      fields,
    })
    return response.data
  },

  get: async () => {
    const response = await api.get<Record<string, Record<string, string>>>('/config')
    return response.data
  },

  // v3.53.104 - Clear/disconnect plugin configuration
  clear: async (pluginId: string) => {
    const response = await api.delete<{ success: boolean; message: string; plugin_id: string }>(`/config/${pluginId}`)
    return response.data
  },

  // System whitelist (v2.3 - Protected IPs that should never be blocked)
  getSystemWhitelist: async () => {
    const response = await api.get<{
      entries: SystemWhitelistEntry[]
      by_category: Record<string, SystemWhitelistEntry[]>
      ips: string[]
      count: number
    }>('/config/system-whitelist')
    return response.data
  },

  checkSystemWhitelist: async (ip: string) => {
    const response = await api.get<{
      is_protected: boolean
      entry?: SystemWhitelistEntry
      message: string
    }>(`/config/system-whitelist/check/${ip}`)
    return response.data
  },
}

// Auth types (v2.6)
export interface UserInfo {
  id: string
  username: string
  role: 'admin' | 'audit'
}

export interface LoginResponse {
  token: string
  expires_at: number
  user: UserInfo
}

export interface User {
  id: string
  username: string
  email?: string
  role: 'admin' | 'audit'
  is_active: boolean
  last_login?: string
  created_at: string
  updated_at: string
}

export interface CreateUserRequest {
  username: string
  password: string
  email?: string
  role: 'admin' | 'audit'
}

export interface UpdateUserRequest {
  email?: string
  role?: 'admin' | 'audit'
  is_active?: boolean
}

// Auth API (v2.6)
export const authApi = {
  login: async (username: string, password: string): Promise<LoginResponse> => {
    const response = await api.post<LoginResponse>('/auth/login', { username, password })
    return response.data
  },

  logout: async (): Promise<void> => {
    await api.post('/auth/logout')
  },

  me: async (): Promise<{ user: UserInfo }> => {
    const response = await api.get<{ user: UserInfo }>('/auth/me')
    return response.data
  },

  changePassword: async (oldPassword: string, newPassword: string): Promise<void> => {
    await api.post('/auth/change-password', {
      old_password: oldPassword,
      new_password: newPassword
    })
  },
}

// Users API (v2.6 - Admin only)
export const usersApi = {
  list: async (): Promise<{ users: User[]; count: number }> => {
    const response = await api.get<{ users: User[]; count: number }>('/users')
    return response.data
  },

  get: async (id: string): Promise<User> => {
    const response = await api.get<User>(`/users/${id}`)
    return response.data
  },

  create: async (request: CreateUserRequest): Promise<User> => {
    const response = await api.post<User>('/users', request)
    return response.data
  },

  update: async (id: string, request: UpdateUserRequest): Promise<User> => {
    const response = await api.put<User>(`/users/${id}`, request)
    return response.data
  },

  delete: async (id: string): Promise<void> => {
    await api.delete(`/users/${id}`)
  },

  resetPassword: async (id: string, newPassword: string): Promise<void> => {
    await api.post(`/users/${id}/reset-password`, { new_password: newPassword })
  },
}

// License Types (v2.9 + v3.2)
export interface LicenseStatus {
  licensed: boolean
  status: string
  customer_name?: string
  expires_at?: string
  days_remaining?: number
  grace_mode: boolean
  features: string[]
  hardware_id?: string
  // v3.0: Firewall binding info
  binding_version?: string
  firewall_serial?: string
  firewall_model?: string
  firewall_name?: string
  secure_binding?: boolean
  // v3.2: Fresh Deploy info
  deployment_type?: 'manual' | 'fresh_deploy'
  firewall_detected?: boolean
  ask_pro_available?: boolean
  needs_fresh_deploy?: boolean
  // v3.55.116: For update check
  latest_vgx_version?: string
}

export interface LicenseActivateResponse {
  success: boolean
  message?: string
  license?: LicenseStatus
}

export interface LicenseInfo extends LicenseStatus {
  license_key?: string
  max_firewalls?: number
}

// v3.2: Fresh Deploy types
export interface FreshDeployRequest {
  email: string
  hostname?: string
}

export interface FreshDeployResponse {
  success: boolean
  message?: string
  error?: string
  license?: {
    licensed: boolean
    status: string
    customer_name?: string
    expires_at?: string
    days_remaining?: number
    features?: string[]
    deployment_type?: string
    firewall_detected: boolean
    ask_pro_available: boolean
  }
}

export interface AskProResponse {
  success: boolean
  message?: string
  error?: string
  license?: {
    status: string
    ask_pro_available: boolean
  }
}

export interface SyncFirewallResponse {
  success: boolean
  message?: string
  error?: string
  license?: {
    status: string
    firewall_detected: boolean
    ask_pro_available: boolean
  }
}

// License API (v2.9 + v3.2)
export const licenseApi = {
  getStatus: async (): Promise<LicenseStatus> => {
    const response = await api.get<LicenseStatus>('/license/status')
    return response.data
  },

  activate: async (licenseKey: string): Promise<LicenseActivateResponse> => {
    const response = await api.post<LicenseActivateResponse>('/license/activate', {
      license_key: licenseKey
    })
    return response.data
  },

  getInfo: async (): Promise<LicenseInfo> => {
    const response = await api.get<LicenseInfo>('/license/info')
    return response.data
  },

  forceValidate: async (): Promise<LicenseActivateResponse> => {
    const response = await api.post<LicenseActivateResponse>('/license/validate')
    return response.data
  },

  // v3.2: Fresh Deploy methods
  freshDeploy: async (request: FreshDeployRequest): Promise<FreshDeployResponse> => {
    const response = await api.post<FreshDeployResponse>('/license/fresh-deploy', request)
    return response.data
  },

  askPro: async (): Promise<AskProResponse> => {
    const response = await api.post<AskProResponse>('/license/ask-pro')
    return response.data
  },

  syncFirewall: async (): Promise<SyncFirewallResponse> => {
    const response = await api.post<SyncFirewallResponse>('/license/sync-firewall')
    return response.data
  },
}

// Notification Settings Types (v3.3)
export interface NotificationSettings {
  smtp_configured: boolean
  daily_report_enabled: boolean
  daily_report_time: string
  weekly_report_enabled: boolean
  weekly_report_day: number
  weekly_report_time: string
  monthly_report_enabled: boolean
  monthly_report_day: number
  monthly_report_time: string
  report_recipients: string[] // Email addresses for scheduled reports
  waf_detection_enabled: boolean
  waf_blocked_enabled: boolean
  new_ban_enabled: boolean
  critical_alert_enabled: boolean
  min_severity_level: string
  specific_event_ids: string[]
}

export interface NotificationStatus {
  configured: boolean
  status: string
  host: string
}

// SMTP Config Types (v3.5)
export interface SMTPConfig {
  host: string
  port: number
  security: string
  from_email: string
  username: string
  password: string
  recipients: string[]
}

// Notifications API (v3.3 - Email notifications, v3.5 - SMTP config persistence)
export const notificationsApi = {
  getSettings: async (): Promise<NotificationSettings> => {
    const response = await api.get<NotificationSettings>('/notifications/settings')
    return response.data
  },

  updateSettings: async (settings: Partial<NotificationSettings>): Promise<{ success: boolean; message: string; settings: NotificationSettings }> => {
    const response = await api.put<{ success: boolean; message: string; settings: NotificationSettings }>('/notifications/settings', settings)
    return response.data
  },

  sendTestEmail: async (recipients?: string[]): Promise<{ success: boolean; message: string }> => {
    const response = await api.post<{ success: boolean; message: string }>('/notifications/test-email', { recipients })
    return response.data
  },

  getStatus: async (): Promise<NotificationStatus> => {
    const response = await api.get<NotificationStatus>('/notifications/status')
    return response.data
  },

  // v3.5: SMTP config persistence
  getSMTPConfig: async (): Promise<{ configured: boolean; config?: SMTPConfig }> => {
    const response = await api.get<{ configured: boolean; config?: SMTPConfig }>('/notifications/smtp-config')
    return response.data
  },

  updateSMTPConfig: async (config: SMTPConfig): Promise<{ success: boolean; message: string }> => {
    const response = await api.put<{ success: boolean; message: string }>('/notifications/smtp-config', config)
    return response.data
  },
}

// GeoZone API (v3.52 - D2B v2 Geographic zone classification)
export interface GeoZoneConfig {
  enabled: boolean
  authorized_countries: string[]
  hostile_countries: string[]
  default_policy: 'authorized' | 'hostile' | 'neutral'
  waf_threshold_hzone: number
  waf_threshold_zone: number
  threat_score_threshold: number
}

export const geozoneApi = {
  // Get current GeoZone configuration
  getConfig: async (): Promise<GeoZoneConfig> => {
    const response = await api.get<GeoZoneConfig>('/geozone/config')
    return response.data
  },

  // Update GeoZone configuration
  updateConfig: async (config: Partial<GeoZoneConfig>): Promise<{ success: boolean; message: string; config: GeoZoneConfig }> => {
    const response = await api.put<{ success: boolean; message: string; config: GeoZoneConfig }>('/geozone/config', config)
    return response.data
  },

  // Classify a country code into a zone
  classifyCountry: async (country: string): Promise<{ country: string; zone: string; enabled: boolean }> => {
    const response = await api.get<{ country: string; zone: string; enabled: boolean }>('/geozone/classify', {
      params: { country }
    })
    return response.data
  },

  // Get list of authorized and hostile countries
  getCountryList: async (): Promise<{ enabled: boolean; authorized_countries: string[]; hostile_countries: string[]; default_policy: string }> => {
    const response = await api.get<{ enabled: boolean; authorized_countries: string[]; hostile_countries: string[]; default_policy: string }>('/geozone/countries')
    return response.data
  },

  // Add country to authorized list
  addAuthorizedCountry: async (country: string): Promise<{ success: boolean; message: string; country: string }> => {
    const response = await api.post<{ success: boolean; message: string; country: string }>('/geozone/countries/authorized', { country })
    return response.data
  },

  // Remove country from authorized list
  removeAuthorizedCountry: async (country: string): Promise<{ success: boolean; message: string; country: string }> => {
    const response = await api.delete<{ success: boolean; message: string; country: string }>('/geozone/countries/authorized', {
      params: { country }
    })
    return response.data
  },

  // Add country to hostile list
  addHostileCountry: async (country: string): Promise<{ success: boolean; message: string; country: string }> => {
    const response = await api.post<{ success: boolean; message: string; country: string }>('/geozone/countries/hostile', { country })
    return response.data
  },
}

// Retention API (v3.52 - Log retention and cleanup settings)
export interface RetentionSettings {
  events_retention_days: number
  modsec_logs_retention_days: number
  firewall_events_retention_days: number
  vpn_events_retention_days: number
  heartbeat_events_retention_days: number
  atp_events_retention_days: number
  antivirus_events_retention_days: number
  ban_history_retention_days: number
  audit_log_retention_days: number
  retention_enabled: boolean
  cleanup_interval_hours: number
  last_cleanup: string
  updated_at: string
  updated_by: string
}

export interface RetentionStatus {
  worker_running: boolean
  enabled: boolean
  last_cleanup: string
  next_cleanup: string
  interval_hours: number
}

export interface StorageStats {
  total_bytes: number
  used_bytes: number
  available_bytes: number
  used_percent: number
  tables_size: Record<string, number>
}

export interface CleanupResult {
  success: boolean
  start_time: string
  end_time: string
  total_deleted: number
  table_stats: Array<{
    table_name: string
    rows_deleted: number
    rows_before: number
    duration_ms: number
    retention_days: number
  }>
  error?: string
}

export const retentionApi = {
  // Get current retention settings
  getSettings: async (): Promise<RetentionSettings> => {
    const response = await api.get<RetentionSettings>('/retention/settings')
    return response.data
  },

  // Update retention settings
  updateSettings: async (settings: Partial<RetentionSettings>): Promise<{ success: boolean; message: string; settings: RetentionSettings }> => {
    const response = await api.put<{ success: boolean; message: string; settings: RetentionSettings }>('/retention/settings', settings)
    return response.data
  },

  // Get retention service status
  getStatus: async (): Promise<RetentionStatus> => {
    const response = await api.get<RetentionStatus>('/retention/status')
    return response.data
  },

  // Get storage statistics
  getStorageStats: async (): Promise<StorageStats> => {
    const response = await api.get<StorageStats>('/retention/storage')
    return response.data
  },

  // Trigger manual cleanup
  runCleanup: async (): Promise<CleanupResult> => {
    const response = await api.post<CleanupResult>('/retention/cleanup')
    return response.data
  },
}

// CrowdSec Blocklist API (v3.53 - Premium blocklist sync)
export interface CrowdSecBlocklistConfig {
  enabled: boolean
  api_key: string
  sync_interval_hours: number
  xgs_group_name: string
  enabled_lists: string[]
  last_sync: string
  total_ips: number
}

export interface CrowdSecBlocklistInfo {
  id: string
  name: string
  label: string
  description: string
  ip_count: number
  subscribers: number
  is_private: boolean
  created_at: string
  updated_at: string
}

export interface CrowdSecSyncResult {
  blocklist_id: string
  blocklist_name: string
  ips_downloaded: number
  ips_synced: number
  ips_new: number
  ips_removed: number
  duration_ms: number
  synced_at: string
  error?: string
}

export interface CrowdSecSyncHistory {
  id: string
  timestamp: string
  blocklist_id: string
  blocklist_name: string
  ips_downloaded: number
  ips_added: number
  ips_removed: number
  duration_ms: number
  success: boolean
  error?: string
}

export const crowdsecBlocklistApi = {
  // Get current config
  getConfig: async (): Promise<CrowdSecBlocklistConfig> => {
    const response = await api.get<CrowdSecBlocklistConfig>('/crowdsec/blocklist/config')
    return response.data
  },

  // Update config
  updateConfig: async (config: Partial<CrowdSecBlocklistConfig>): Promise<{ success: boolean; message: string }> => {
    const response = await api.put<{ success: boolean; message: string }>('/crowdsec/blocklist/config', config)
    return response.data
  },

  // Test API connection
  testConnection: async (): Promise<{ success: boolean; message: string }> => {
    const response = await api.post<{ success: boolean; message: string }>('/crowdsec/blocklist/test')
    return response.data
  },

  // List available blocklists
  listBlocklists: async (): Promise<{ subscribed: CrowdSecBlocklistInfo[]; available: CrowdSecBlocklistInfo[] }> => {
    const response = await api.get<{ subscribed: CrowdSecBlocklistInfo[]; available: CrowdSecBlocklistInfo[] }>('/crowdsec/blocklist/lists')
    return response.data
  },

  // Get service status
  getStatus: async (): Promise<{
    configured: boolean
    enabled: boolean
    sync_running: boolean
    last_sync: string
    total_ips: number
    group_name: string
    enabled_lists?: string[]
  }> => {
    const response = await api.get('/crowdsec/blocklist/status')
    return response.data
  },

  // Get sync history
  getHistory: async (): Promise<{ history: CrowdSecSyncHistory[] }> => {
    const response = await api.get<{ history: CrowdSecSyncHistory[] }>('/crowdsec/blocklist/history')
    return response.data
  },

  // Sync all enabled blocklists
  syncAll: async (): Promise<{ success: boolean; results: CrowdSecSyncResult[] }> => {
    const response = await api.post<{ success: boolean; results: CrowdSecSyncResult[] }>('/crowdsec/blocklist/sync')
    return response.data
  },

  // Sync a specific blocklist
  syncBlocklist: async (blocklistId: string, name?: string): Promise<{ success: boolean; result: CrowdSecSyncResult }> => {
    const params = name ? `?name=${encodeURIComponent(name)}` : ''
    const response = await api.post<{ success: boolean; result: CrowdSecSyncResult }>(`/crowdsec/blocklist/sync/${blocklistId}${params}`)
    return response.data
  },

  // v3.53: Neural-Sync - Get paginated IP list
  getIPsPaginated: async (params: {
    page?: number
    page_size?: number
    search?: string
    blocklist_id?: string
    country?: string
  }): Promise<{
    IPs: Array<{
      ip: string
      blocklist_id: string
      blocklist_label: string
      first_seen: string
      last_seen: string
      country_code: string
      country_name: string
    }>
    Total: number
    Page: number
    PageSize: number
    TotalPages: number
  }> => {
    const queryParams = new URLSearchParams()
    if (params.page) queryParams.append('page', String(params.page))
    if (params.page_size) queryParams.append('page_size', String(params.page_size))
    if (params.search) queryParams.append('search', params.search)
    if (params.blocklist_id) queryParams.append('blocklist_id', params.blocklist_id)
    if (params.country) queryParams.append('country', params.country)
    const response = await api.get(`/crowdsec/blocklist/ips/list?${queryParams}`)
    return response.data
  },

  // v3.53: Neural-Sync - Get blocklist summary
  getBlocklistsSummary: async (): Promise<{
    blocklists: Array<{
      id: string
      label: string
      ip_count: number
    }>
  }> => {
    const response = await api.get('/crowdsec/blocklist/summary')
    return response.data
  },

  // v3.53: Neural-Sync - Get unique countries from IPs
  getUniqueCountries: async (): Promise<{
    countries: Array<{
      code: string
      name?: string
    }>
    needs_enrichment: boolean
  }> => {
    const response = await api.get('/crowdsec/blocklist/countries')
    return response.data
  },

  // v3.53: Enrich existing IPs with country codes
  enrichCountries: async (): Promise<{
    success: boolean
    enriched: number
    remaining: number
    message: string
  }> => {
    const response = await api.post('/crowdsec/blocklist/enrich')
    return response.data
  },
}

// v3.53.104: Neural-Sync API (VigilanceKey Proxy blocklists)
export interface NeuralSyncConfig {
  enabled: boolean
  server_url: string
  license_key: string
  hardware_id: string
  configured: boolean
}

export interface NeuralSyncStatus {
  enabled: boolean
  configured: boolean
  connected: boolean
  server_url: string
  total_blocklists: number
  total_ips: number
  last_sync?: string
  error?: string
}

export interface NeuralSyncIP {
  ip: string
  blocklist_id: string
  blocklist_label: string
  country_code: string
}

export interface NeuralSyncBlocklist {
  id: string
  name: string
  label: string
  description: string
  ip_count: number
  last_sync?: string
  enabled: boolean
}

export const neuralSyncApi = {
  // Get Neural-Sync configuration
  getConfig: async (): Promise<NeuralSyncConfig> => {
    const response = await api.get<NeuralSyncConfig>('/neural-sync/config')
    return response.data
  },

  // Update Neural-Sync configuration
  updateConfig: async (config: { server_url: string; license_key: string; hardware_id: string }): Promise<{ success: boolean; message: string }> => {
    const response = await api.put<{ success: boolean; message: string }>('/neural-sync/config', config)
    return response.data
  },

  // Test Neural-Sync connection
  testConnection: async (): Promise<{ success: boolean; message: string }> => {
    const response = await api.post<{ success: boolean; message: string }>('/neural-sync/test')
    return response.data
  },

  // Get Neural-Sync status
  getStatus: async (): Promise<NeuralSyncStatus> => {
    const response = await api.get<NeuralSyncStatus>('/neural-sync/status')
    return response.data
  },

  // List available blocklists from VigilanceKey
  listBlocklists: async (): Promise<{ blocklists: NeuralSyncBlocklist[]; total: number; error?: string }> => {
    const response = await api.get<{ blocklists: NeuralSyncBlocklist[]; total: number; error?: string }>('/neural-sync/blocklists')
    return response.data
  },

  // Get IPs from VigilanceKey blocklists
  getIPs: async (params: {
    page?: number
    page_size?: number
    blocklist_id?: string
    country?: string
    search?: string
  }): Promise<{
    ips: NeuralSyncIP[]
    total: number
    page: number
    page_size: number
    total_pages: number
    error?: string
  }> => {
    const response = await api.get('/neural-sync/ips', { params })
    return response.data
  },
}

// Soft Whitelist API (v2.0)
export const softWhitelistApi = {
  // List all whitelisted IPs (optional filter by type)
  list: async (type?: 'hard' | 'soft' | 'monitor') => {
    const params = type ? { type } : {}
    const response = await api.get<{ data: WhitelistEntry[] }>('/whitelist', { params })
    return response.data
  },

  // Get whitelist statistics by type
  stats: async () => {
    const response = await api.get<WhitelistStats>('/whitelist/stats')
    return response.data
  },

  // Check if an IP is whitelisted (detailed info)
  check: async (ip: string) => {
    const response = await api.get<WhitelistCheckResult>(`/whitelist/check/${ip}`)
    return response.data
  },

  // Add IP to whitelist
  add: async (request: WhitelistRequest) => {
    const response = await api.post<{ message: string; ip: string; type: string }>('/whitelist', request)
    return response.data
  },

  // Update whitelist entry
  update: async (ip: string, entry: Partial<WhitelistEntry>) => {
    const response = await api.put<{ message: string; ip: string }>(`/whitelist/${ip}`, entry)
    return response.data
  },

  // Remove from whitelist
  remove: async (ip: string) => {
    const response = await api.delete<{ message: string; ip: string }>(`/whitelist/${ip}`)
    return response.data
  },
}

// API Provider Status (v3.53 - Integration tracking with quotas)
export interface APIProviderConfig {
  provider_id: string
  api_key: string
  daily_quota: number // -1 = unlimited
  enabled: boolean
  last_success: string
  last_error: string
  last_error_message: string
  display_name: string
  description: string
  updated_at: string
}

export interface APIProviderStatus {
  config: APIProviderConfig
  today_success: number
  today_errors: number
  quota_used: number
  quota_max: number // -1 = unlimited
  has_error: boolean
}

export const integrationsApi = {
  // Get all providers status
  getProviders: async (): Promise<{ providers: APIProviderStatus[] }> => {
    const response = await api.get<{ providers: APIProviderStatus[] }>('/integrations/providers')
    return response.data
  },

  // Get single provider status
  getProvider: async (providerId: string): Promise<APIProviderStatus> => {
    const response = await api.get<APIProviderStatus>(`/integrations/providers/${providerId}`)
    return response.data
  },

  // Update provider configuration
  updateProvider: async (providerId: string, config: {
    api_key?: string
    daily_quota?: number
    enabled?: boolean
  }): Promise<{ success: boolean; message: string }> => {
    const response = await api.put<{ success: boolean; message: string }>(`/integrations/providers/${providerId}`, config)
    return response.data
  },
}

// ==============================================
// Vigimail Checker API (v3.54)
// ==============================================

import type { VigimailConfig, VigimailDomain, VigimailEmail, VigimailLeak, DomainDNSCheck, VigimailStatus, VigimailStats, VigimailCheckHistory } from '../types'

export const vigimailApi = {
  // Configuration
  getConfig: async (): Promise<VigimailConfig> => {
    const response = await api.get<VigimailConfig>('/vigimail/config')
    return response.data
  },

  updateConfig: async (config: Partial<VigimailConfig>): Promise<{ success: boolean; message: string }> => {
    const response = await api.put<{ success: boolean; message: string }>('/vigimail/config', config)
    return response.data
  },

  getStatus: async (): Promise<VigimailStatus> => {
    const response = await api.get<VigimailStatus>('/vigimail/status')
    return response.data
  },

  getStats: async (): Promise<VigimailStats> => {
    const response = await api.get<VigimailStats>('/vigimail/stats')
    return response.data
  },

  // Domains
  listDomains: async (): Promise<{ domains: VigimailDomain[]; count: number }> => {
    const response = await api.get<{ domains: VigimailDomain[]; count: number }>('/vigimail/domains')
    return response.data
  },

  addDomain: async (domain: string): Promise<VigimailDomain> => {
    const response = await api.post<VigimailDomain>('/vigimail/domains', { domain })
    return response.data
  },

  deleteDomain: async (domain: string): Promise<{ success: boolean; message: string }> => {
    const response = await api.delete<{ success: boolean; message: string }>(`/vigimail/domains/${encodeURIComponent(domain)}`)
    return response.data
  },

  getDomainDNS: async (domain: string): Promise<DomainDNSCheck> => {
    const response = await api.get<DomainDNSCheck>(`/vigimail/domains/${encodeURIComponent(domain)}/dns`)
    return response.data
  },

  checkDomain: async (domain: string): Promise<DomainDNSCheck> => {
    const response = await api.post<DomainDNSCheck>(`/vigimail/domains/${encodeURIComponent(domain)}/check`)
    return response.data
  },

  // Emails
  listEmails: async (domain?: string): Promise<{ emails?: VigimailEmail[]; emails_by_domain?: Record<string, VigimailEmail[]>; count?: number; total_count?: number }> => {
    const params = domain ? `?domain=${encodeURIComponent(domain)}` : ''
    const response = await api.get<{ emails?: VigimailEmail[]; emails_by_domain?: Record<string, VigimailEmail[]>; count?: number; total_count?: number }>(`/vigimail/emails${params}`)
    return response.data
  },

  addEmail: async (email: string): Promise<VigimailEmail> => {
    const response = await api.post<VigimailEmail>('/vigimail/emails', { email })
    return response.data
  },

  deleteEmail: async (email: string): Promise<{ success: boolean; message: string }> => {
    const response = await api.delete<{ success: boolean; message: string }>(`/vigimail/emails/${encodeURIComponent(email)}`)
    return response.data
  },

  getEmailLeaks: async (email: string): Promise<{ email: string; leaks: VigimailLeak[]; count: number }> => {
    const response = await api.get<{ email: string; leaks: VigimailLeak[]; count: number }>(`/vigimail/emails/${encodeURIComponent(email)}/leaks`)
    return response.data
  },

  checkEmail: async (email: string): Promise<{ email: string; leaks: VigimailLeak[]; count: number; status: string }> => {
    const response = await api.post<{ email: string; leaks: VigimailLeak[]; count: number; status: string }>(`/vigimail/emails/${encodeURIComponent(email)}/check`)
    return response.data
  },

  // Bulk operations
  checkAll: async (): Promise<VigimailCheckHistory> => {
    const response = await api.post<VigimailCheckHistory>('/vigimail/check-all')
    return response.data
  },
}

// ==============================================
// TrackIP API (v3.56 - IP/Hostname Tracking)
// ==============================================

import type { TrackIPResponse } from '../types'

export const trackIPApi = {
  // Search for IP or hostname activity across all log tables
  search: async (params: {
    query: string
    start_time?: string
    end_time?: string
    period?: '1h' | '24h' | '7d' | '30d'
    limit?: number
    offset?: number    // For pagination
    category?: string  // For loading specific category only
  }): Promise<TrackIPResponse> => {
    const queryParams = new URLSearchParams()
    queryParams.append('query', params.query)
    if (params.start_time) queryParams.append('start_time', params.start_time)
    if (params.end_time) queryParams.append('end_time', params.end_time)
    if (params.period) queryParams.append('period', params.period)
    if (params.limit) queryParams.append('limit', String(params.limit))
    if (params.offset) queryParams.append('offset', String(params.offset))
    if (params.category) queryParams.append('category', params.category)

    const response = await api.get<TrackIPResponse>(`/track-ip?${queryParams}`)
    return response.data
  },
}

// ==============================================
// WAF Servers API (v3.57 - WAF Monitored Servers with Country Access Zero Trust)
// ==============================================

export interface WAFMonitoredServer {
  id: string
  hostname: string
  display_name: string
  description: string
  policy_enabled: boolean
  policy_mode: 'none' | 'whitecountry' | 'blockcountry'
  white_countries: string[]
  block_countries: string[]
  waf_threshold: number
  custom_ban_reason: string
  enabled: boolean
  created_at: string
  created_by: string
  updated_at: string
}

export interface WAFServerRequest {
  hostname: string
  display_name?: string
  description?: string
  policy_enabled?: boolean
  policy_mode?: 'none' | 'whitecountry' | 'blockcountry'
  white_countries?: string[]
  block_countries?: string[]
  waf_threshold?: number
  custom_ban_reason?: string
  enabled?: boolean
}

export interface PolicyCheckResult {
  should_ban: boolean
  ban_reason: string
  policy_hit: string
}

export const wafServersApi = {
  // List all configured WAF servers
  list: async (): Promise<{ data: WAFMonitoredServer[]; total: number }> => {
    const response = await api.get<{ data: WAFMonitoredServer[]; total: number }>('/waf-servers')
    return response.data
  },

  // Get server by hostname
  get: async (hostname: string): Promise<{ data: WAFMonitoredServer }> => {
    const response = await api.get<{ data: WAFMonitoredServer }>(`/waf-servers/${encodeURIComponent(hostname)}`)
    return response.data
  },

  // Create a new WAF server
  create: async (server: WAFServerRequest): Promise<{ success: boolean; message: string; data: WAFMonitoredServer }> => {
    const response = await api.post<{ success: boolean; message: string; data: WAFMonitoredServer }>('/waf-servers', server)
    return response.data
  },

  // Update an existing WAF server
  update: async (hostname: string, server: Partial<WAFServerRequest>): Promise<{ success: boolean; message: string; data: WAFMonitoredServer }> => {
    const response = await api.put<{ success: boolean; message: string; data: WAFMonitoredServer }>(`/waf-servers/${encodeURIComponent(hostname)}`, server)
    return response.data
  },

  // Delete a WAF server
  delete: async (hostname: string, deleteLogs: boolean = false): Promise<{ success: boolean; message: string }> => {
    const response = await api.delete<{ success: boolean; message: string }>(
      `/waf-servers/${encodeURIComponent(hostname)}?delete_logs=${deleteLogs}`
    )
    return response.data
  },

  // Get list of configured hostnames only
  getHostnames: async (): Promise<{ data: string[]; total: number }> => {
    const response = await api.get<{ data: string[]; total: number }>('/waf-servers/hostnames')
    return response.data
  },

  // Check country policy for a hostname
  checkPolicy: async (hostname: string, country: string): Promise<{
    hostname: string
    country: string
    policy_enabled: boolean
    policy_mode: string
    result: PolicyCheckResult
  }> => {
    const response = await api.get(`/waf-servers/${encodeURIComponent(hostname)}/check-policy`, {
      params: { country }
    })
    return response.data
  },
}

