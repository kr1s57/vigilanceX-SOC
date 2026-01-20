// v3.57.105: XGS Login Activity card with pagination
// v3.57.116: Filter VGX auto-connections, add clickable success/failed filters
import { useState, useEffect, useMemo } from 'react'
import {
  LogIn,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Clock,
  User,
  ChevronLeft,
  ChevronRight,
  Filter
} from 'lucide-react'
import { eventsApi } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { Event } from '@/types'

interface XGSLoginCardProps {
  refreshInterval?: number
}

interface XGSLogin {
  timestamp: string
  username: string
  src_ip: string
  success: boolean
  message?: string
}

// v3.57.116: Filter types for login display
type LoginFilter = 'all' | 'success' | 'failed'

// v3.57.116: VGX auto-connection patterns to exclude from display
// These are automated connections from VGX for log sync, not real user logins
const VGX_AUTO_PATTERNS = {
  // ModSec sync uses admin via SSH from VGX server
  modsecSync: { username: 'admin', srcIpPrefix: '10.56.125.', method: 'ssh' },
  // API service account for XGS API calls
  apiService: { username: 'api_service_soc' }
}

const ITEMS_PER_PAGE = 10
const MAX_ENTRIES = 200

export function XGSLoginCard({ refreshInterval = 0 }: XGSLoginCardProps) {
  const [logins, setLogins] = useState<XGSLogin[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  const [filter, setFilter] = useState<LoginFilter>('all') // v3.57.116: Filter state

  async function fetchData() {
    try {
      setError(null)

      // v3.57.112: Query multiple log types to catch all authentication events
      // XGS authentication logs use: Admin (Admin Login/Logout), Authentication, VPN
      const [adminResponse, authResponse, vpnResponse] = await Promise.all([
        eventsApi.list({ log_type: 'Admin', limit: MAX_ENTRIES, offset: 0 }).catch(() => ({ data: [] })),
        eventsApi.list({ log_type: 'Authentication', limit: MAX_ENTRIES, offset: 0 }).catch(() => ({ data: [] })),
        eventsApi.list({ log_type: 'VPN', limit: MAX_ENTRIES, offset: 0 }).catch(() => ({ data: [] }))
      ])

      // Combine all events
      const allEvents = [
        ...(adminResponse.data || []),
        ...(authResponse.data || []),
        ...(vpnResponse.data || [])
      ]

      // Transform events to login format
      // v3.57.112: Filter based on category for login-related events
      // v3.57.116: Exclude VGX auto-connections (ModSec sync, API service)
      const loginEvents: XGSLogin[] = allEvents
        .filter((e: Event) => {
          // Filter for authentication-related events
          const cat = (e.category || '').toLowerCase()
          const msg = (e.message || '').toLowerCase()
          return cat.includes('login') ||
                 cat.includes('logout') ||
                 cat.includes('auth') ||
                 cat.includes('connection') ||
                 cat.includes('disconnection') ||
                 msg.includes('login') ||
                 msg.includes('authentication') ||
                 msg.includes('logged')
        })
        .map((e: Event) => {
          const cat = (e.category || '').toLowerCase()
          const msg = (e.message || '').toLowerCase()
          const action = (e.action || '').toLowerCase()

          // Determine success based on category and action
          const isSuccess = cat.includes('success') ||
                           cat.includes('login') && !cat.includes('fail') ||
                           cat.includes('connection') && !cat.includes('fail') ||
                           action === 'allow' ||
                           msg.includes('success') ||
                           msg.includes('logged in')

          return {
            timestamp: e.timestamp,
            username: e.user_name || 'admin',
            src_ip: e.src_ip || '0.0.0.0',
            success: isSuccess,
            message: e.message || e.category
          }
        })
        // v3.57.116: Filter out VGX automated connections
        .filter((login: XGSLogin) => {
          const msg = (login.message || '').toLowerCase()

          // Exclude api_service_soc (VGX API account)
          if (login.username === VGX_AUTO_PATTERNS.apiService.username) {
            return false
          }

          // Exclude admin SSH connections from VGX server (ModSec sync)
          // These are automated every 30s and clutter the real login monitoring
          if (login.username === VGX_AUTO_PATTERNS.modsecSync.username &&
              login.src_ip.startsWith(VGX_AUTO_PATTERNS.modsecSync.srcIpPrefix) &&
              msg.includes('ssh')) {
            return false
          }

          return true
        })
        // Sort by timestamp descending
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, MAX_ENTRIES)

      setLogins(loginEvents)
      setCurrentPage(1) // Reset to first page on refresh
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

  // v3.57.116: Filter logins based on selected filter
  const filteredLogins = useMemo(() => {
    switch (filter) {
      case 'success':
        return logins.filter(l => l.success)
      case 'failed':
        return logins.filter(l => !l.success)
      default:
        return logins
    }
  }, [logins, filter])

  // Pagination calculations (now based on filtered logins)
  const totalPages = Math.ceil(filteredLogins.length / ITEMS_PER_PAGE)
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE
  const endIndex = startIndex + ITEMS_PER_PAGE
  const currentLogins = filteredLogins.slice(startIndex, endIndex)

  const goToPage = (page: number) => {
    if (page >= 1 && page <= totalPages) {
      setCurrentPage(page)
    }
  }

  // v3.57.116: Handle filter change
  const handleFilterChange = (newFilter: LoginFilter) => {
    setFilter(newFilter === filter ? 'all' : newFilter) // Toggle off if same filter clicked
    setCurrentPage(1) // Reset to page 1 when filter changes
  }

  // Generate page numbers to display
  const getPageNumbers = () => {
    const pages: (number | string)[] = []
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i)
    } else {
      if (currentPage <= 3) {
        pages.push(1, 2, 3, 4, '...', totalPages)
      } else if (currentPage >= totalPages - 2) {
        pages.push(1, '...', totalPages - 3, totalPages - 2, totalPages - 1, totalPages)
      } else {
        pages.push(1, '...', currentPage - 1, currentPage, currentPage + 1, '...', totalPages)
      }
    }
    return pages
  }

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
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <LogIn className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold">XGS Logins</h3>
          {/* v3.57.116: Show active filter indicator */}
          {filter !== 'all' && (
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Filter className="w-3 h-3" />
              {filter === 'success' ? 'Success only' : 'Failed only'}
            </span>
          )}
        </div>
        {hasLogins && (
          <div className="flex items-center gap-2 text-xs">
            {/* v3.57.116: Clickable success badge */}
            <button
              onClick={() => handleFilterChange('success')}
              className={cn(
                "flex items-center gap-1 px-2 py-1 rounded-full transition-all cursor-pointer",
                filter === 'success'
                  ? "bg-green-500/30 text-green-400 ring-1 ring-green-500"
                  : "bg-green-500/10 text-green-500 hover:bg-green-500/20"
              )}
              title="Click to filter success logins"
            >
              <CheckCircle2 className="w-3 h-3" />
              <span className="font-medium">{successCount}</span>
            </button>

            {/* v3.57.116: Clickable failed badge */}
            <button
              onClick={() => handleFilterChange('failed')}
              className={cn(
                "flex items-center gap-1 px-2 py-1 rounded-full transition-all cursor-pointer",
                filter === 'failed'
                  ? "bg-red-500/30 text-red-400 ring-1 ring-red-500"
                  : failedCount > 0
                    ? "bg-red-500/10 text-red-500 hover:bg-red-500/20"
                    : "bg-muted text-muted-foreground"
              )}
              title="Click to filter failed logins"
            >
              <XCircle className="w-3 h-3" />
              <span className="font-medium">{failedCount}</span>
            </button>
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
        <>
          {/* Login list */}
          <div className="space-y-1">
            {currentLogins.map((login, index) => (
              <LoginRow key={`${login.timestamp}-${index}`} login={login} />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-1 mt-4 pt-3 border-t border-border">
              <button
                onClick={() => goToPage(currentPage - 1)}
                disabled={currentPage === 1}
                className={cn(
                  "p-1 rounded hover:bg-muted transition-colors",
                  currentPage === 1 && "opacity-50 cursor-not-allowed"
                )}
              >
                <ChevronLeft className="w-4 h-4" />
              </button>

              {getPageNumbers().map((page, idx) => (
                typeof page === 'number' ? (
                  <button
                    key={idx}
                    onClick={() => goToPage(page)}
                    className={cn(
                      "w-7 h-7 text-xs rounded transition-colors",
                      currentPage === page
                        ? "bg-primary text-primary-foreground"
                        : "hover:bg-muted"
                    )}
                  >
                    {page}
                  </button>
                ) : (
                  <span key={idx} className="px-1 text-muted-foreground">...</span>
                )
              ))}

              <button
                onClick={() => goToPage(currentPage + 1)}
                disabled={currentPage === totalPages}
                className={cn(
                  "p-1 rounded hover:bg-muted transition-colors",
                  currentPage === totalPages && "opacity-50 cursor-not-allowed"
                )}
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function LoginRow({ login }: { login: XGSLogin }) {
  return (
    <div
      className={cn(
        "flex items-center gap-2 p-2 rounded text-sm transition-colors",
        login.success
          ? "bg-muted/30 hover:bg-muted/50"
          : "bg-red-500/10 hover:bg-red-500/15"
      )}
    >
      {/* Status */}
      <div className="shrink-0">
        {login.success ? (
          <span className="px-1.5 py-0.5 bg-green-500/20 text-green-500 text-[10px] font-bold rounded">
            OK
          </span>
        ) : (
          <span className="px-1.5 py-0.5 bg-red-500/20 text-red-500 text-[10px] font-bold rounded">
            FAIL
          </span>
        )}
      </div>

      {/* User */}
      <div className="flex items-center gap-1 min-w-[80px]">
        <User className="w-3 h-3 text-muted-foreground" />
        <span className={cn(
          "font-medium truncate",
          !login.success && "text-red-400"
        )}>
          {login.username}
        </span>
      </div>

      {/* IP */}
      <span className="font-mono text-xs text-muted-foreground flex-1 truncate">
        {login.src_ip}
      </span>

      {/* Timestamp */}
      <div className="flex items-center gap-1 text-xs text-muted-foreground shrink-0">
        <Clock className="w-3 h-3" />
        <span>
          {new Date(login.timestamp).toLocaleDateString('fr-FR', {
            day: '2-digit',
            month: '2-digit'
          })}
        </span>
        <span>
          {new Date(login.timestamp).toLocaleTimeString('fr-FR', {
            hour: '2-digit',
            minute: '2-digit'
          })}
        </span>
      </div>
    </div>
  )
}
