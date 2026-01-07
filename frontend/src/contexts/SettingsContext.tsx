import { createContext, useContext, useState, useEffect, ReactNode } from 'react'

// Settings types
export interface AppSettings {
  // Display
  theme: 'dark' | 'light' | 'system'
  language: 'fr' | 'en'
  dateFormat: '24h' | '12h'
  numberFormat: 'fr' | 'en'
  defaultPeriod: '1h' | '24h' | '7d' | '30d'

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
}

const defaultSettings: AppSettings = {
  // Display
  theme: 'dark',
  language: 'fr',
  dateFormat: '24h',
  numberFormat: 'fr',
  defaultPeriod: '24h',

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
}

interface SettingsContextType {
  settings: AppSettings
  updateSettings: (newSettings: Partial<AppSettings>) => void
  resetSettings: () => void
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

  // Save to localStorage when settings change
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
  }, [settings])

  // Apply theme
  useEffect(() => {
    const root = document.documentElement

    if (settings.theme === 'system') {
      const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches
      root.classList.toggle('dark', isDark)
      root.classList.toggle('light', !isDark)
    } else {
      root.classList.toggle('dark', settings.theme === 'dark')
      root.classList.toggle('light', settings.theme === 'light')
    }
  }, [settings.theme])

  const updateSettings = (newSettings: Partial<AppSettings>) => {
    setSettings(prev => ({ ...prev, ...newSettings }))
  }

  const resetSettings = () => {
    setSettings(defaultSettings)
    localStorage.removeItem(STORAGE_KEY)
  }

  return (
    <SettingsContext.Provider value={{ settings, updateSettings, resetSettings }}>
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
