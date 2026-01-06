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
  AnomalySpike,
  NewIPDetected
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
  score: async (ip: string) => {
    const response = await api.get<{ data: ThreatScore }>(`/threats/score/${ip}`)
    return response.data.data
  },

  refresh: async (ip: string) => {
    const response = await api.post<{ data: ThreatScore }>(`/threats/refresh/${ip}`)
    return response.data.data
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
