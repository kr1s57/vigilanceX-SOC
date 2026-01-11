import { create } from 'zustand'

// Country centroids for attack flow origins (major attacking countries)
export const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
  'US': [37.0902, -95.7129],
  'CN': [35.8617, 104.1954],
  'RU': [55.7558, 37.6173],
  'IN': [20.5937, 78.9629],
  'BR': [-14.2350, -51.9253],
  'DE': [51.1657, 10.4515],
  'FR': [46.6034, 1.8883],
  'GB': [55.3781, -3.4360],
  'NL': [52.1326, 5.2913],
  'UA': [48.3794, 31.1656],
  'KR': [35.9078, 127.7669],
  'JP': [36.2048, 138.2529],
  'IR': [32.4279, 53.6880],
  'VN': [14.0583, 108.2772],
  'ID': [-0.7893, 113.9213],
  'TH': [15.8700, 100.9925],
  'PK': [30.3753, 69.3451],
  'BD': [23.6850, 90.3563],
  'NG': [9.0820, 8.6753],
  'EG': [26.8206, 30.8025],
  'TR': [38.9637, 35.2433],
  'MX': [23.6345, -102.5528],
  'AR': [-38.4161, -63.6167],
  'CO': [4.5709, -74.2973],
  'ZA': [-30.5595, 22.9375],
  'PL': [51.9194, 19.1451],
  'IT': [41.8719, 12.5674],
  'ES': [40.4637, -3.7492],
  'CA': [56.1304, -106.3468],
  'AU': [-25.2744, 133.7751],
  'SG': [1.3521, 103.8198],
  'HK': [22.3193, 114.1694],
  'TW': [23.6978, 120.9605],
  'MY': [4.2105, 101.9758],
  'PH': [12.8797, 121.7740],
  'SA': [23.8859, 45.0792],
  'AE': [23.4241, 53.8478],
  'IL': [31.0461, 34.8516],
  'RO': [45.9432, 24.9668],
  'CZ': [49.8175, 15.4730],
  'SE': [60.1282, 18.6435],
  'NO': [60.4720, 8.4689],
  'FI': [61.9241, 25.7482],
  'DK': [56.2639, 9.5018],
  'AT': [47.5162, 14.5501],
  'CH': [46.8182, 8.2275],
  'BE': [50.5039, 4.4699],
  'PT': [39.3999, -8.2245],
  'GR': [39.0742, 21.8243],
  'HU': [47.1625, 19.5033],
  'BG': [42.7339, 25.4858],
  'LU': [49.8153, 6.1296],
  // Unknown/default
  'XX': [0, 0],
}

// Target infrastructure location (Luxembourg by default)
export const TARGET_LOCATION = {
  lat: 49.6116,
  lng: 6.1319,
  name: 'Infrastructure'
}

export type MapPeriod = 'live' | '24h' | '7d' | '30d'

// Attack type definitions with colors
export type AttackType = 'waf' | 'ips' | 'malware' | 'threat'

export const ATTACK_TYPE_CONFIG: Record<AttackType, { label: string; color: string; description: string }> = {
  waf: {
    label: 'WAF',
    color: 'rgba(249, 115, 22, 0.8)', // Orange
    description: 'Web Application Firewall (SQL Injection, XSS, Bot)',
  },
  ips: {
    label: 'IPS/IDS',
    color: 'rgba(239, 68, 68, 0.8)', // Red
    description: 'Intrusion Prevention/Detection System',
  },
  malware: {
    label: 'Malware',
    color: 'rgba(168, 85, 247, 0.8)', // Purple
    description: 'Anti-Virus, Malware Detection',
  },
  threat: {
    label: 'Threat',
    color: 'rgba(34, 197, 94, 0.8)', // Green (for C&C, Botnet)
    description: 'Advanced Threat, C&C, Botnet',
  },
}

export interface CountryAttackStats {
  countryCode: string
  countryName: string
  count: number
  uniqueIps: number
  threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'minimal'
  centroid: [number, number]
}

export interface AttackFlow {
  id: string
  sourceCountry: string
  sourceLat: number
  sourceLng: number
  targetLat: number
  targetLng: number
  timestamp: Date
  intensity: number // 1-10 based on attack volume
  color: string
}

export interface TopAttackerInfo {
  ip: string
  attackCount: number
  blockedCount: number
  country: string
  threatScore?: number
  categories: string[]
}

export interface AttackMapState {
  // Period selection
  period: MapPeriod
  setPeriod: (period: MapPeriod) => void

  // Attack type filters
  activeAttackTypes: Set<AttackType>
  toggleAttackType: (type: AttackType) => void
  setAttackTypes: (types: AttackType[]) => void

  // Country stats data
  countryStats: Map<string, CountryAttackStats>
  setCountryStats: (stats: CountryAttackStats[]) => void

  // Attack flows for animation
  attackFlows: AttackFlow[]
  setAttackFlows: (flows: AttackFlow[]) => void
  addAttackFlow: (flow: AttackFlow) => void
  clearOldFlows: () => void

  // Live attack queue
  liveAttacks: AttackFlow[]
  addLiveAttack: (attack: AttackFlow) => void

  // Selected country for modal
  selectedCountry: string | null
  setSelectedCountry: (code: string | null) => void
  selectedCountryDetails: {
    topAttackers: TopAttackerInfo[]
    attackTypes: { type: string; count: number }[]
  } | null
  setSelectedCountryDetails: (details: { topAttackers: TopAttackerInfo[]; attackTypes: { type: string; count: number }[] } | null) => void

  // Loading state
  loading: boolean
  setLoading: (loading: boolean) => void

  // Connection state
  isConnected: boolean
  setIsConnected: (connected: boolean) => void

  // Stats
  totalAttacks: number
  setTotalAttacks: (total: number) => void

  // Reset
  reset: () => void
}

// Get threat level based on attack count
export function getThreatLevel(count: number, maxCount: number): CountryAttackStats['threatLevel'] {
  const ratio = count / Math.max(maxCount, 1)
  if (ratio > 0.7) return 'critical'
  if (ratio > 0.4) return 'high'
  if (ratio > 0.2) return 'medium'
  if (ratio > 0.05) return 'low'
  return 'minimal'
}

// Get color for threat level
export function getThreatColor(level: CountryAttackStats['threatLevel']): string {
  switch (level) {
    case 'critical': return 'rgba(239, 68, 68, 0.8)'
    case 'high': return 'rgba(249, 115, 22, 0.7)'
    case 'medium': return 'rgba(234, 179, 8, 0.6)'
    case 'low': return 'rgba(34, 197, 94, 0.5)'
    case 'minimal': return 'rgba(59, 130, 246, 0.3)'
    default: return 'rgba(107, 114, 128, 0.3)'
  }
}

// Get intensity for flow animation (1-10)
export function getFlowIntensity(count: number, maxCount: number): number {
  return Math.max(1, Math.min(10, Math.ceil((count / Math.max(maxCount, 1)) * 10)))
}

export const useAttackMapStore = create<AttackMapState>((set) => ({
  // Period
  period: '24h',
  setPeriod: (period) => {
    sessionStorage.setItem('attackMapPeriod', period)
    set({ period })
  },

  // Attack type filters (all enabled by default)
  activeAttackTypes: new Set<AttackType>(['waf', 'ips', 'malware', 'threat']),
  toggleAttackType: (type) => set(state => {
    const newSet = new Set(state.activeAttackTypes)
    if (newSet.has(type)) {
      newSet.delete(type)
    } else {
      newSet.add(type)
    }
    // Save to sessionStorage
    sessionStorage.setItem('attackMapTypes', Array.from(newSet).join(','))
    return { activeAttackTypes: newSet }
  }),
  setAttackTypes: (types) => {
    const newSet = new Set<AttackType>(types)
    sessionStorage.setItem('attackMapTypes', types.join(','))
    set({ activeAttackTypes: newSet })
  },

  // Country stats
  countryStats: new Map(),
  setCountryStats: (stats) => {
    const map = new Map<string, CountryAttackStats>()
    stats.forEach(stat => map.set(stat.countryCode, stat))
    set({ countryStats: map })
  },

  // Attack flows
  attackFlows: [],
  setAttackFlows: (flows) => set({ attackFlows: flows }),
  addAttackFlow: (flow) => set(state => ({
    attackFlows: [...state.attackFlows, flow].slice(-100) // Keep last 100 flows
  })),
  clearOldFlows: () => set(state => ({
    attackFlows: state.attackFlows.filter(f =>
      Date.now() - f.timestamp.getTime() < 30000 // Keep flows from last 30 seconds
    )
  })),

  // Live attacks
  liveAttacks: [],
  addLiveAttack: (attack) => set(state => ({
    liveAttacks: [...state.liveAttacks, attack].slice(-50) // Keep last 50
  })),

  // Selected country
  selectedCountry: null,
  setSelectedCountry: (code) => set({ selectedCountry: code }),
  selectedCountryDetails: null,
  setSelectedCountryDetails: (details) => set({ selectedCountryDetails: details }),

  // Loading
  loading: false,
  setLoading: (loading) => set({ loading }),

  // Connection
  isConnected: false,
  setIsConnected: (connected) => set({ isConnected: connected }),

  // Stats
  totalAttacks: 0,
  setTotalAttacks: (total) => set({ totalAttacks: total }),

  // Reset
  reset: () => set({
    countryStats: new Map(),
    attackFlows: [],
    liveAttacks: [],
    selectedCountry: null,
    selectedCountryDetails: null,
    loading: false,
    totalAttacks: 0,
  }),
}))

// Initialize period from sessionStorage
const savedPeriod = sessionStorage.getItem('attackMapPeriod') as MapPeriod | null
if (savedPeriod && ['live', '24h', '7d', '30d'].includes(savedPeriod)) {
  useAttackMapStore.getState().setPeriod(savedPeriod)
}
