import { createContext, useContext, useState, useEffect, useCallback, useRef, ReactNode } from 'react'
import { licenseApi, LicenseStatus } from '@/lib/api'
import { useAuth } from './AuthContext'

interface LicenseContextType {
  status: LicenseStatus | null
  isLicensed: boolean
  isLoading: boolean
  error: string | null
  activate: (licenseKey: string) => Promise<void>
  refresh: () => Promise<void>
  syncWithServer: () => Promise<void>
  // v3.2: Fresh Deploy methods
  needsFreshDeploy: boolean
  freshDeploy: (email: string, hostname?: string) => Promise<void>
  askProLicense: () => Promise<void>
  syncFirewall: () => Promise<void>
}

const LicenseContext = createContext<LicenseContextType | undefined>(undefined)

export function LicenseProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<LicenseStatus | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { isAuthenticated } = useAuth()
  const prevAuthRef = useRef<boolean | null>(null)

  const refresh = useCallback(async () => {
    try {
      setError(null)
      const data = await licenseApi.getStatus()
      setStatus(data)
    } catch (err) {
      // If we can't reach the server, assume unlicensed
      setStatus({
        licensed: false,
        status: 'error',
        grace_mode: false,
        features: []
      })
      setError(err instanceof Error ? err.message : 'Failed to check license status')
    } finally {
      setIsLoading(false)
    }
  }, [])

  const activate = useCallback(async (licenseKey: string) => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await licenseApi.activate(licenseKey)
      if (result.success && result.license) {
        setStatus(result.license)
      } else {
        throw new Error(result.message || 'Activation failed')
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Activation failed'
      setError(message)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [])

  // Force sync with license server - validates license and updates status
  const syncWithServer = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await licenseApi.forceValidate()
      if (result.license) {
        setStatus(result.license)
      } else if (!result.success) {
        // License validation failed (revoked, expired, etc.)
        setStatus({
          licensed: false,
          status: result.message || 'invalid',
          grace_mode: false,
          features: []
        })
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to sync with license server')
      // Refresh local status
      await refresh()
    } finally {
      setIsLoading(false)
    }
  }, [refresh])

  // v3.2: Fresh Deploy - register a trial license
  const freshDeploy = useCallback(async (email: string, hostname?: string) => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await licenseApi.freshDeploy({ email, hostname })
      if (result.success && result.license) {
        // Update status with trial license info
        setStatus({
          licensed: result.license.licensed,
          status: result.license.status,
          customer_name: result.license.customer_name,
          expires_at: result.license.expires_at,
          days_remaining: result.license.days_remaining,
          features: result.license.features || [],
          grace_mode: false,
          deployment_type: result.license.deployment_type as 'manual' | 'fresh_deploy',
          firewall_detected: result.license.firewall_detected,
          ask_pro_available: result.license.ask_pro_available,
          needs_fresh_deploy: false
        })
      } else {
        throw new Error(result.error || result.message || 'Fresh deploy failed')
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Fresh deploy failed'
      setError(message)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [])

  // v3.2: Ask Pro License - request pro license upgrade
  const askProLicense = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await licenseApi.askPro()
      if (result.success && result.license) {
        setStatus(prev => prev ? {
          ...prev,
          status: result.license!.status,
          ask_pro_available: result.license!.ask_pro_available
        } : prev)
      } else {
        throw new Error(result.error || result.message || 'Ask Pro request failed')
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Ask Pro request failed'
      setError(message)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [])

  // v3.2: Sync Firewall - send firewall info to license server
  const syncFirewall = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await licenseApi.syncFirewall()
      if (result.success && result.license) {
        setStatus(prev => prev ? {
          ...prev,
          status: result.license!.status,
          firewall_detected: result.license!.firewall_detected,
          ask_pro_available: result.license!.ask_pro_available
        } : prev)
      } else {
        throw new Error(result.error || result.message || 'Sync firewall failed')
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Sync firewall failed'
      setError(message)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [])

  // Initial load
  useEffect(() => {
    refresh()
  }, [refresh])

  // Watch for authentication changes (login/logout)
  // v3.55.112: Fix license persistence issue after logout
  useEffect(() => {
    // Skip on initial mount
    if (prevAuthRef.current === null) {
      prevAuthRef.current = isAuthenticated
      return
    }

    // Detect auth state change
    if (prevAuthRef.current !== isAuthenticated) {
      prevAuthRef.current = isAuthenticated

      if (!isAuthenticated) {
        // User logged out - reset license state so it re-checks on next login
        setStatus(null)
        setError(null)
        setIsLoading(true)
      } else {
        // User logged in - refresh license status from backend
        refresh()
      }
    }
  }, [isAuthenticated, refresh])

  // Refresh periodically (every 5 minutes)
  useEffect(() => {
    const interval = setInterval(refresh, 5 * 60 * 1000)
    return () => clearInterval(interval)
  }, [refresh])

  const isLicensed = status?.licensed ?? false
  const needsFreshDeploy = status?.needs_fresh_deploy ?? (status === null || status.status === 'not_activated')

  return (
    <LicenseContext.Provider value={{
      status,
      isLicensed,
      isLoading,
      error,
      activate,
      refresh,
      syncWithServer,
      // v3.2: Fresh Deploy
      needsFreshDeploy,
      freshDeploy,
      askProLicense,
      syncFirewall
    }}>
      {children}
    </LicenseContext.Provider>
  )
}

export function useLicense() {
  const context = useContext(LicenseContext)
  if (!context) {
    throw new Error('useLicense must be used within a LicenseProvider')
  }
  return context
}
