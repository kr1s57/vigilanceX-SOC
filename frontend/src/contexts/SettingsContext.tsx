import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { configApi, SystemWhitelistEntry } from '@/lib/api'

// Settings types
export interface AppSettings {
  // Display
  theme: 'dark' | 'light' | 'system' | 'futuristic' // v3.57.109: Added futuristic theme
  language: 'fr' | 'en'
  dateFormat: '24h' | '12h'
  numberFormat: 'fr' | 'en'
  defaultPeriod: '1h' | '24h' | '7d' | '30d'
  iconStyle: 'mono' | 'color' // v2.3: Icon style option
  timezone: string // v3.5: Timezone setting (e.g., 'Europe/Paris', 'UTC')
  showDashboardClock: boolean // v3.5: Show clock on dashboard

  // Dashboard & Refresh
  refreshInterval: 15 | 30 | 60 | 0 // 0 = manual
  topAttackersCount: 5 | 10 | 20
  animationsEnabled: boolean

  // Notifications
  notificationsEnabled: boolean
  soundEnabled: boolean
  alertThreshold: 'critical' | 'critical+high'

  // Security
  sessionTimeout: 15 | 30 | 60 | 0 // 0 = never
  maskSensitiveIPs: boolean
  hideSystemIPs: boolean // v2.3: Hide protected system IPs from logs
}

const defaultSettings: AppSettings = {
  // Display
  theme: 'dark',
  language: 'fr',
  dateFormat: '24h',
  numberFormat: 'fr',
  defaultPeriod: '24h',
  iconStyle: 'mono',
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'Europe/Paris', // Auto-detect or default
  showDashboardClock: true,

  // Dashboard & Refresh
  refreshInterval: 30,
  topAttackersCount: 10,
  animationsEnabled: true,

  // Notifications
  notificationsEnabled: true,
  soundEnabled: false,
  alertThreshold: 'critical+high',

  // Security
  sessionTimeout: 30,
  maskSensitiveIPs: false,
  hideSystemIPs: true, // Default: hide system IPs
}

interface SettingsContextType {
  settings: AppSettings
  updateSettings: (newSettings: Partial<AppSettings>) => void
  resetSettings: () => void
  // System whitelist helpers
  systemWhitelistIPs: string[]
  systemWhitelistEntries: SystemWhitelistEntry[]
  isSystemIP: (ip: string) => boolean
  shouldShowIP: (ip: string) => boolean // Returns false if IP should be hidden
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined)

const STORAGE_KEY = 'vigilancex-settings'

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(() => {
    // Load from localStorage on init
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) {
        return { ...defaultSettings, ...JSON.parse(stored) }
      }
    } catch (e) {
      console.error('Failed to load settings:', e)
    }
    return defaultSettings
  })

  // System whitelist state
  const [systemWhitelistIPs, setSystemWhitelistIPs] = useState<string[]>([])
  const [systemWhitelistEntries, setSystemWhitelistEntries] = useState<SystemWhitelistEntry[]>([])

  // Load system whitelist when authenticated
  useEffect(() => {
    const loadSystemWhitelist = async () => {
      // Only load if we have an auth token
      const token = localStorage.getItem('auth_token')
      if (!token) return

      try {
        const data = await configApi.getSystemWhitelist()
        setSystemWhitelistIPs(data.ips)
        setSystemWhitelistEntries(data.entries)
      } catch (error) {
        // Silently fail - IPs will show normally if whitelist can't load
        // This happens during logout or token expiry
      }
    }
    loadSystemWhitelist()

    // Re-run when token changes (login/logout)
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'auth_token') {
        if (e.newValue) {
          loadSystemWhitelist()
        } else {
          // Clear on logout
          setSystemWhitelistIPs([])
          setSystemWhitelistEntries([])
        }
      }
    }
    window.addEventListener('storage', handleStorageChange)
    return () => window.removeEventListener('storage', handleStorageChange)
  }, [])

  // Save to localStorage when settings change
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
  }, [settings])

  // Apply theme
  useEffect(() => {
    const root = document.documentElement

    // v3.57.109: Clear all theme classes first
    root.classList.remove('dark', 'light', 'futuristic')

    if (settings.theme === 'system') {
      const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches
      root.classList.add(isDark ? 'dark' : 'light')
    } else if (settings.theme === 'futuristic') {
      // v3.57.109: Futuristic theme - also needs dark base styles
      root.classList.add('dark', 'futuristic')
    } else {
      root.classList.add(settings.theme)
    }
  }, [settings.theme])

  const updateSettings = (newSettings: Partial<AppSettings>) => {
    setSettings(prev => ({ ...prev, ...newSettings }))
  }

  const resetSettings = () => {
    setSettings(defaultSettings)
    localStorage.removeItem(STORAGE_KEY)
  }

  // Check if an IP is in the system whitelist
  const isSystemIP = useCallback((ip: string): boolean => {
    return systemWhitelistIPs.includes(ip)
  }, [systemWhitelistIPs])

  // Check if an IP should be shown (based on settings and whitelist)
  const shouldShowIP = useCallback((ip: string): boolean => {
    if (!settings.hideSystemIPs) return true
    // Filter invalid/system IPs (0.0.0.0, localhost, etc.)
    if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '::1' || ip === '') return false
    return !systemWhitelistIPs.includes(ip)
  }, [settings.hideSystemIPs, systemWhitelistIPs])

  return (
    <SettingsContext.Provider value={{
      settings,
      updateSettings,
      resetSettings,
      systemWhitelistIPs,
      systemWhitelistEntries,
      isSystemIP,
      shouldShowIP
    }}>
      {children}
    </SettingsContext.Provider>
  )
}

export function useSettings() {
  const context = useContext(SettingsContext)
  if (!context) {
    throw new Error('useSettings must be used within a SettingsProvider')
  }
  return context
}

// Helper hook for formatted values
export function useFormatters() {
  const { settings } = useSettings()

  const formatNumber = (num: number): string => {
    if (settings.numberFormat === 'fr') {
      return num.toLocaleString('fr-FR')
    }
    return num.toLocaleString('en-US')
  }

  const formatDateTime = (date: Date | string): string => {
    const d = typeof date === 'string' ? new Date(date) : date
    const locale = settings.language === 'fr' ? 'fr-FR' : 'en-US'

    if (settings.dateFormat === '24h') {
      return d.toLocaleString(locale, {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
      })
    }
    return d.toLocaleString(locale, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true
    })
  }

  const formatTime = (date: Date | string): string => {
    const d = typeof date === 'string' ? new Date(date) : date
    const locale = settings.language === 'fr' ? 'fr-FR' : 'en-US'

    return d.toLocaleTimeString(locale, {
      hour: '2-digit',
      minute: '2-digit',
      hour12: settings.dateFormat === '12h'
    })
  }

  const maskIP = (ip: string): string => {
    if (!settings.maskSensitiveIPs) return ip
    // Mask last octet for IPv4
    const parts = ip.split('.')
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.***`
    }
    return ip
  }

  return { formatNumber, formatDateTime, formatTime, maskIP }
}
