import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bell, RefreshCw, Wifi, WifiOff, Server, ServerOff, AlertTriangle, X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useWebSocket, useRealtimeEvents } from '@/hooks/useWebSocket'
import { statusApi, alertsApi } from '@/lib/api'
import type { SyslogStatus, CriticalAlert } from '@/types'

export function Header() {
  const navigate = useNavigate()
  const { isConnected } = useWebSocket()
  const [lastUpdate, setLastUpdate] = useState(new Date())
  const [syslogStatus, setSyslogStatus] = useState<SyslogStatus | null>(null)
  const [criticalAlerts, setCriticalAlerts] = useState<CriticalAlert[]>([])
  const [readAlertIds, setReadAlertIds] = useState<Set<string>>(new Set())
  const [showNotifications, setShowNotifications] = useState(false)
  const notificationRef = useRef<HTMLDivElement>(null)

  // Update timestamp when new events arrive
  useRealtimeEvents(() => {
    setLastUpdate(new Date())
  })

  // Fetch syslog status and critical alerts
  useEffect(() => {
    async function fetchStatus() {
      try {
        const [syslog, alerts] = await Promise.all([
          statusApi.syslog(),
          alertsApi.critical(10)
        ])
        setSyslogStatus(syslog)
        setCriticalAlerts(alerts.data || [])
      } catch (err) {
        console.error('Failed to fetch status:', err)
      }
    }

    fetchStatus()
    const interval = setInterval(fetchStatus, 30000)
    return () => clearInterval(interval)
  }, [])

  // Load read alerts from localStorage
  useEffect(() => {
    const stored = localStorage.getItem('readAlertIds')
    if (stored) {
      try {
        setReadAlertIds(new Set(JSON.parse(stored)))
      } catch {
        // Ignore parse errors
      }
    }
  }, [])

  // Close notifications when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (notificationRef.current && !notificationRef.current.contains(event.target as Node)) {
        setShowNotifications(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Periodic fallback update
  useEffect(() => {
    const interval = setInterval(() => {
      setLastUpdate(new Date())
    }, 30000)
    return () => clearInterval(interval)
  }, [])

  const handleAlertClick = (alert: CriticalAlert) => {
    // Mark as read
    const newReadIds = new Set(readAlertIds)
    newReadIds.add(alert.event_id)
    setReadAlertIds(newReadIds)
    localStorage.setItem('readAlertIds', JSON.stringify([...newReadIds]))

    // Close dropdown
    setShowNotifications(false)

    // Navigate to Attacks Analyzer with IP threat modal
    navigate(`/attacks?src_ip=${encodeURIComponent(alert.src_ip)}`)
  }

  // Count unread alerts
  const unreadAlerts = criticalAlerts.filter(a => !readAlertIds.has(a.event_id))
  const unreadCount = unreadAlerts.length
  const criticalCount = unreadAlerts.filter(a => a.severity === 'critical').length
  const highCount = unreadAlerts.filter(a => a.severity === 'high').length

  return (
    <header className="h-16 bg-card border-b border-border flex items-center justify-between px-6">
      {/* Left side - Page title will be set by each page */}
      <div className="flex items-center gap-4">
        <h2 className="text-lg font-semibold">Security Operations Center</h2>
      </div>

      {/* Right side - Status and actions */}
      <div className="flex items-center gap-4">
        {/* WebSocket connection status */}
        <div className={cn(
          'flex items-center gap-2 px-3 py-1.5 rounded-full text-sm',
          isConnected
            ? 'bg-green-500/10 text-green-500'
            : 'bg-red-500/10 text-red-500'
        )}>
          {isConnected ? (
            <>
              <Wifi className="w-4 h-4" />
              <span>WSocket</span>
            </>
          ) : (
            <>
              <WifiOff className="w-4 h-4" />
              <span>Disconnected</span>
            </>
          )}
        </div>

        {/* Syslog status */}
        <div className={cn(
          'flex items-center gap-2 px-3 py-1.5 rounded-full text-sm',
          syslogStatus?.is_receiving
            ? 'bg-green-500/10 text-green-500'
            : 'bg-red-500/10 text-red-500'
        )}>
          {syslogStatus?.is_receiving ? (
            <>
              <Server className="w-4 h-4" />
              <span>Syslog</span>
            </>
          ) : (
            <>
              <ServerOff className="w-4 h-4" />
              <span>Syslog Off</span>
            </>
          )}
        </div>

        {/* Last update */}
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <RefreshCw className="w-4 h-4" />
          <span>Updated {formatTimeAgo(lastUpdate)}</span>
        </div>

        {/* Notifications */}
        <div className="relative" ref={notificationRef}>
          <button
            className={cn(
              "relative p-2 rounded-lg transition-colors",
              showNotifications ? "bg-muted" : "hover:bg-muted"
            )}
            onClick={() => setShowNotifications(!showNotifications)}
          >
            <Bell className="w-5 h-5" />
            {unreadCount > 0 && (
              <span className={cn(
                "absolute top-1 right-1 w-4 h-4 rounded-full text-xs text-white flex items-center justify-center",
                criticalCount > 0 ? "bg-red-500" : "bg-orange-500"
              )}>
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>

          {/* Notifications dropdown */}
          {showNotifications && (
            <div className="absolute right-0 top-12 w-96 bg-card border border-border rounded-xl shadow-lg z-50 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-border">
                <h3 className="font-semibold">Security Alerts</h3>
                <button
                  onClick={() => setShowNotifications(false)}
                  className="p-1 hover:bg-muted rounded-lg transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Alert summary */}
              {unreadCount > 0 && (
                <div className="px-4 py-2 bg-muted/50 flex items-center gap-4 text-sm">
                  {criticalCount > 0 && (
                    <span className="flex items-center gap-1 text-red-500">
                      <AlertTriangle className="w-3 h-3" />
                      {criticalCount} critical
                    </span>
                  )}
                  {highCount > 0 && (
                    <span className="flex items-center gap-1 text-orange-500">
                      <AlertTriangle className="w-3 h-3" />
                      {highCount} high
                    </span>
                  )}
                  <span className="text-muted-foreground ml-auto">
                    {unreadCount} unread
                  </span>
                </div>
              )}

              <div className="max-h-80 overflow-y-auto">
                {criticalAlerts.length === 0 ? (
                  <div className="px-4 py-8 text-center text-muted-foreground">
                    <Bell className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>No critical alerts</p>
                  </div>
                ) : (
                  criticalAlerts.map((alert) => (
                    <AlertItem
                      key={alert.event_id}
                      alert={alert}
                      isRead={readAlertIds.has(alert.event_id)}
                      onClick={() => handleAlertClick(alert)}
                    />
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* User menu placeholder */}
        <div className="w-8 h-8 bg-muted rounded-full flex items-center justify-center text-sm font-medium">
          A
        </div>
      </div>
    </header>
  )
}

function AlertItem({
  alert,
  isRead,
  onClick
}: {
  alert: CriticalAlert
  isRead: boolean
  onClick: () => void
}) {
  const severityColors = {
    critical: 'border-l-red-500 bg-red-500/5',
    high: 'border-l-orange-500 bg-orange-500/5',
    medium: 'border-l-yellow-500 bg-yellow-500/5',
    low: 'border-l-blue-500 bg-blue-500/5',
  }

  return (
    <div
      onClick={onClick}
      className={cn(
        "px-4 py-3 border-l-4 hover:bg-muted/50 transition-colors cursor-pointer",
        severityColors[alert.severity as keyof typeof severityColors] || 'border-l-gray-500',
        isRead && 'opacity-60'
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            {!isRead && (
              <span className="w-2 h-2 rounded-full bg-blue-500 shrink-0" />
            )}
            <span className={cn(
              "text-xs font-medium px-1.5 py-0.5 rounded uppercase",
              alert.severity === 'critical' ? 'bg-red-500/20 text-red-500' :
              alert.severity === 'high' ? 'bg-orange-500/20 text-orange-500' :
              'bg-yellow-500/20 text-yellow-500'
            )}>
              {alert.severity}
            </span>
            <span className="text-xs text-muted-foreground">{alert.log_type}</span>
          </div>
          <p className="text-sm font-medium truncate">
            {alert.rule_name || alert.message || `Rule ${alert.rule_id}`}
          </p>
          <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
            <span className="font-mono">{alert.src_ip}</span>
            {alert.hostname && (
              <>
                <span>→</span>
                <span className="truncate">{alert.hostname}</span>
              </>
            )}
          </div>
        </div>
        <span className="text-xs text-muted-foreground whitespace-nowrap">
          {formatTimeAgo(new Date(alert.timestamp))}
        </span>
      </div>
    </div>
  )
}

function formatTimeAgo(date: Date): string {
  const seconds = Math.floor((new Date().getTime() - date.getTime()) / 1000)

  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}
