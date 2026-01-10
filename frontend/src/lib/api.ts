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
  heatmap: async (period: string = '24h') => {
    const response = await api.get<{ data: Array<{ country: string; count: number; unique_ips: number }> }>('/geo/heatmap', {
      params: { period }
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

  delete: async (ip: string) => {
    await api.delete(`/bans/${ip}`)
  },

  extend: async (ip: string, days: number) => {
    const response = await api.put<{ data: BanStatus }>(`/bans/${ip}/extend`, { duration_days: days })
    return response.data.data
  },

  makePermanent: async (ip: string) => {
    const response = await api.put<{ data: BanStatus }>(`/bans/${ip}/permanent`)
    return response.data.data
  },

  history: async (ip?: string) => {
    const url = ip ? `/bans/history/${ip}` : '/bans/history'
    const response = await api.get<{ data: BanHistory[] }>(url)
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
  critical: async (limit: number = 20) => {
    const response = await api.get<{ data: CriticalAlert[]; count: number }>('/alerts/critical', {
      params: { limit }
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

// Notifications API (v3.3 - Email notifications)
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
