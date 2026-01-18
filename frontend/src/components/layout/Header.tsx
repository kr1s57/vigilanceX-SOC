import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bell, RefreshCw, Wifi, WifiOff, Server, ServerOff, AlertTriangle, X, Shield, ShieldOff, Terminal, TerminalSquare, Monitor } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useWebSocket, useRealtimeEvents } from '@/hooks/useWebSocket'
import { statusApi, alertsApi, detect2banApi, modsecApi, type Detect2BanStatus } from '@/lib/api'
import { useAuth } from '@/contexts/AuthContext'
import { TerminalConsole } from '@/components/TerminalConsole'
import type { SyslogStatus, CriticalAlert } from '@/types'

interface SSHStatus {
  connected: boolean
  message: string
}

export function Header() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const { isConnected } = useWebSocket()
  const [lastUpdate, setLastUpdate] = useState(new Date())
  const [syslogStatus, setSyslogStatus] = useState<SyslogStatus | null>(null)
  const [sshStatus, setSshStatus] = useState<SSHStatus | null>(null)
  const [d2bStatus, setD2bStatus] = useState<Detect2BanStatus | null>(null)
  const [criticalAlerts, setCriticalAlerts] = useState<CriticalAlert[]>([])
  const [readAlertIds, setReadAlertIds] = useState<Set<string>>(new Set())
  const [showNotifications, setShowNotifications] = useState(false)
  const [showTerminal, setShowTerminal] = useState(false) // v3.57.107: Admin Console
  const notificationRef = useRef<HTMLDivElement>(null)

  // Update timestamp when new events arrive
  useRealtimeEvents(() => {
    setLastUpdate(new Date())
  })

  // Fetch syslog status, SSH status, D2B status, and critical alerts
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

      // Fetch SSH status (ModSec test connection)
      try {
        const sshTest = await modsecApi.testConnection()
        setSshStatus({
          connected: sshTest.status === 'ok',
          message: sshTest.message || ''
        })
      } catch {
        setSshStatus({ connected: false, message: 'SSH not configured' })
      }

      // Fetch D2B status separately (requires auth, may fail)
      try {
        const d2b = await detect2banApi.getStatus()
        setD2bStatus(d2b)
      } catch {
        // D2B status requires auth, ignore errors
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
            <Wifi className="w-4 h-4" />
          ) : (
            <WifiOff className="w-4 h-4" />
          )}
          <span>WSocket</span>
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

        {/* SSH status */}
        <div
          className={cn(
            'flex items-center gap-2 px-3 py-1.5 rounded-full text-sm cursor-help',
            sshStatus?.connected
              ? 'bg-green-500/10 text-green-500'
              : 'bg-red-500/10 text-red-500'
          )}
          title={sshStatus?.message || 'SSH status unknown'}
        >
          {sshStatus?.connected ? (
            <Terminal className="w-4 h-4" />
          ) : (
            <TerminalSquare className="w-4 h-4" />
          )}
          <span>SSH</span>
        </div>

        {/* Detect2Ban status */}
        <div
          className={cn(
            'flex items-center gap-2 px-3 py-1.5 rounded-full text-sm cursor-help',
            d2bStatus?.running
              ? 'bg-green-500/10 text-green-500'
              : 'bg-red-500/10 text-red-500'
          )}
          title={d2bStatus ? `Detect2Ban: ${d2bStatus.running ? 'Active' : 'Disabled'} - ${d2bStatus.scenario_count} scenarios loaded` : 'Detect2Ban status unknown'}
        >
          {d2bStatus?.running ? (
            <Shield className="w-4 h-4" />
          ) : (
            <ShieldOff className="w-4 h-4" />
          )}
          <span>D2B</span>
        </div>

        {/* Last update */}
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <RefreshCw className="w-4 h-4" />
          <span>Updated {formatTimeAgo(lastUpdate)}</span>
        </div>

        {/* v3.57.107: Admin Console button - only for admin users */}
        {user?.role === 'admin' && (
          <button
            onClick={() => setShowTerminal(true)}
            className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
            title="Admin Console"
          >
            <Monitor className="w-5 h-5" />
          </button>
        )}

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
          {user?.username?.[0]?.toUpperCase() || 'A'}
        </div>
      </div>

      {/* v3.57.107: Admin Console Modal */}
      <TerminalConsole isOpen={showTerminal} onClose={() => setShowTerminal(false)} />
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
