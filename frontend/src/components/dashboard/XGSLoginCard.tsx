// v3.57.103: XGS Login Activity card for Dashboard
import { useState, useEffect } from 'react'
import {
  LogIn,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Clock,
  User,
  Globe
} from 'lucide-react'
import { eventsApi } from '@/lib/api'
import { cn, getCountryFlag } from '@/lib/utils'
import type { Event } from '@/types'

interface XGSLoginCardProps {
  refreshInterval?: number
}

interface XGSLogin {
  timestamp: string
  username: string
  src_ip: string
  success: boolean
  country?: string
  message?: string
}

export function XGSLoginCard({ refreshInterval = 0 }: XGSLoginCardProps) {
  const [logins, setLogins] = useState<XGSLogin[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  async function fetchData() {
    try {
      setError(null)

      // Query events for XGS admin logins
      // These come through as log_type=Event with category containing authentication info
      // Search for admin/login related events
      const response = await eventsApi.list({
        log_type: 'Event',
        search: 'admin',
        limit: 100,
        offset: 0
      })

      const events = response.data || []

      // Transform events to login format
      const loginEvents: XGSLogin[] = events
        .filter((e: Event) => {
          // Filter for authentication-related events
          const msg = (e.message || '').toLowerCase()
          const cat = (e.category || '').toLowerCase()
          return msg.includes('login') ||
                 msg.includes('authentication') ||
                 msg.includes('admin') ||
                 cat.includes('admin') ||
                 cat.includes('auth')
        })
        .map((e: Event) => {
          const msg = (e.message || '').toLowerCase()
          const action = (e.action || '').toLowerCase()
          const isSuccess = action === 'allow' ||
                           action === 'success' ||
                           msg.includes('success') ||
                           msg.includes('logged in')

          return {
            timestamp: e.timestamp,
            username: e.user_name || 'unknown',
            src_ip: e.src_ip,
            success: isSuccess,
            country: e.geo_country,
            message: e.message
          }
        })
        .slice(0, 50) // Limit to 50 entries for display

      setLogins(loginEvents)
    } catch (err) {
      setError('Failed to load XGS logins')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()

    if (refreshInterval > 0) {
      const interval = setInterval(fetchData, refreshInterval * 1000)
      return () => clearInterval(interval)
    }
  }, [refreshInterval])

  if (loading && logins.length === 0) {
    return (
      <div className="bg-card rounded-xl border p-6">
        <div className="flex items-center gap-2 mb-4">
          <LogIn className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold">XGS Logins</h3>
        </div>
        <div className="flex items-center justify-center h-48">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
        </div>
      </div>
    )
  }

  if (error && logins.length === 0) {
    return (
      <div className="bg-card rounded-xl border p-6">
        <div className="flex items-center gap-2 mb-4">
          <LogIn className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold">XGS Logins</h3>
        </div>
        <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
          <p className="text-sm">{error}</p>
          <button
            onClick={fetchData}
            className="mt-2 flex items-center gap-1 text-xs hover:text-foreground"
          >
            <RefreshCw className="w-3 h-3" />
            Retry
          </button>
        </div>
      </div>
    )
  }

  const hasLogins = logins.length > 0
  const failedCount = logins.filter(l => !l.success).length
  const successCount = logins.filter(l => l.success).length

  return (
    <div className="bg-card rounded-xl border p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <LogIn className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold">XGS Logins</h3>
        </div>
        {hasLogins && (
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-green-500" />
              {successCount}
            </span>
            {failedCount > 0 && (
              <span className="flex items-center gap-1 text-red-500">
                <XCircle className="w-3 h-3" />
                {failedCount} failed
              </span>
            )}
          </div>
        )}
      </div>

      {!hasLogins ? (
        <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
          <LogIn className="w-12 h-12 opacity-30 mb-2" />
          <p className="text-sm">No login events found</p>
          <p className="text-xs mt-1">Admin login attempts will appear here</p>
        </div>
      ) : (
        <div className="space-y-1 max-h-[280px] overflow-y-auto pr-2 scrollbar-thin">
          {logins.map((login, index) => (
            <LoginRow key={`${login.timestamp}-${index}`} login={login} />
          ))}
        </div>
      )}
    </div>
  )
}

function LoginRow({ login }: { login: XGSLogin }) {
  const isRecent = new Date(login.timestamp).getTime() > Date.now() - 3600000 // Last hour

  return (
    <div
      className={cn(
        "flex items-center gap-3 p-2 rounded-lg transition-colors",
        login.success
          ? "bg-muted/30 hover:bg-muted/50"
          : "bg-red-500/10 border border-red-500/20 hover:bg-red-500/15"
      )}
    >
      {/* Status indicator */}
      <div className="shrink-0">
        {login.success ? (
          <CheckCircle2 className="w-4 h-4 text-green-500" />
        ) : (
          <XCircle className="w-4 h-4 text-red-500" />
        )}
      </div>

      {/* User info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <User className="w-3 h-3 text-muted-foreground" />
          <span className={cn(
            "font-medium text-sm truncate",
            !login.success && "text-red-400"
          )}>
            {login.username}
          </span>
          {!login.success && (
            <span className="px-1.5 py-0.5 bg-red-500/20 text-red-500 text-[10px] rounded font-medium">
              FAILED
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span className="font-mono">{login.src_ip}</span>
          {login.country && (
            <span className="flex items-center gap-1">
              <Globe className="w-3 h-3" />
              {getCountryFlag(login.country)}
            </span>
          )}
        </div>
      </div>

      {/* Timestamp */}
      <div className="text-right shrink-0">
        <div className="flex items-center gap-1 text-xs text-muted-foreground">
          <Clock className="w-3 h-3" />
          <span className={cn(isRecent && "text-foreground")}>
            {new Date(login.timestamp).toLocaleTimeString('fr-FR', {
              hour: '2-digit',
              minute: '2-digit'
            })}
          </span>
        </div>
        <div className="text-[10px] text-muted-foreground">
          {new Date(login.timestamp).toLocaleDateString('fr-FR', {
            day: '2-digit',
            month: '2-digit'
          })}
        </div>
      </div>
    </div>
  )
}
