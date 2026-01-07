import axios from 'axios'
import type {
  Event,
  EventFilters,
  PaginatedResponse,
  OverviewResponse,
  TimelinePoint,
  TopAttacker,
  TopTarget,
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
  HighRiskCountry
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

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('auth_token')
      window.location.href = '/login'
    }
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
