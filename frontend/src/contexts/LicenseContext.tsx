import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { licenseApi, LicenseStatus } from '@/lib/api'

interface LicenseContextType {
  status: LicenseStatus | null
  isLicensed: boolean
  isLoading: boolean
  error: string | null
  activate: (licenseKey: string) => Promise<void>
  refresh: () => Promise<void>
  syncWithServer: () => Promise<void>
}

const LicenseContext = createContext<LicenseContextType | undefined>(undefined)

export function LicenseProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<LicenseStatus | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

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

  // Initial load
  useEffect(() => {
    refresh()
  }, [refresh])

  // Refresh periodically (every 5 minutes)
  useEffect(() => {
    const interval = setInterval(refresh, 5 * 60 * 1000)
    return () => clearInterval(interval)
  }, [refresh])

  const isLicensed = status?.licensed ?? false

  return (
    <LicenseContext.Provider value={{
      status,
      isLicensed,
      isLoading,
      error,
      activate,
      refresh,
      syncWithServer
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
