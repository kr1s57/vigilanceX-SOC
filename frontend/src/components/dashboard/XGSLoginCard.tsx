// v3.57.105: XGS Login Activity card with pagination
import { useState, useEffect } from 'react'
import {
  LogIn,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Clock,
  User,
  ChevronLeft,
  ChevronRight
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

const ITEMS_PER_PAGE = 10
const MAX_ENTRIES = 200

export function XGSLoginCard({ refreshInterval = 0 }: XGSLoginCardProps) {
  const [logins, setLogins] = useState<XGSLogin[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [currentPage, setCurrentPage] = useState(1)

  async function fetchData() {
    try {
      setError(null)

      // Query events for XGS admin logins
      // These come through as log_type=Event with category containing authentication info
      const response = await eventsApi.list({
        log_type: 'Event',
        search: 'admin',
        limit: MAX_ENTRIES,
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
                 msg.includes('logon') ||
                 cat.includes('admin') ||
                 cat.includes('auth')
        })
        .map((e: Event) => {
          const msg = (e.message || '').toLowerCase()
          const action = (e.action || '').toLowerCase()
          const isSuccess = action === 'allow' ||
                           action === 'success' ||
                           msg.includes('success') ||
                           msg.includes('logged in') ||
                           msg.includes('authenticated')

          return {
            timestamp: e.timestamp,
            username: e.user_name || 'unknown',
            src_ip: e.src_ip,
            success: isSuccess,
            message: e.message
          }
        })
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

  // Pagination calculations
  const totalPages = Math.ceil(logins.length / ITEMS_PER_PAGE)
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE
  const endIndex = startIndex + ITEMS_PER_PAGE
  const currentLogins = logins.slice(startIndex, endIndex)

  const goToPage = (page: number) => {
    if (page >= 1 && page <= totalPages) {
      setCurrentPage(page)
    }
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
                {failedCount}
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
